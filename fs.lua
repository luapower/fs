
--portable filesystem API for LuaJIT
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'fs_test'; return end

local ffi = require'ffi'
local bit = require'bit'
local path = require'path'

local min, max, floor, ceil, log =
	math.min, math.max, math.floor, math.ceil, math.log

local C = ffi.C

local cdef = ffi.cdef
local x64 = ffi.arch == 'x64' or nil
local osx = ffi.os == 'OSX' or nil
local linux = ffi.os == 'Linux' or nil
local win = ffi.abi'win' or nil

--namespaces in which backends can add methods directly.
local fs = {} --fs module namespace
local file = {} --file object methods
local stream = {} --FILE methods
local dir = {} --dir listing object methods

local function update(dt, t)
	for k,v in pairs(t) do dt[k]=v end
	return dt
end

--binding tools --------------------------------------------------------------

local char_ptr_ct = ffi.typeof'char*'
local uint64_ct = ffi.typeof'uint64_t'
local void_ptr_ct = ffi.typeof'void*'
local uintptr_ct = ffi.typeof'uintptr_t'

--assert() with string formatting.
local function assert(v, err, ...)
	if v then return v end
	err = err or 'assertion failed!'
	if select('#',...) > 0 then
		err = string.format(err,...)
	end
	error(err, 2)
end

--next power of two (from glue).
local function nextpow2(x)
	return max(0, 2^(ceil(log(x) / log(2))))
end

--static, auto-growing buffer allocation pattern (from glue, simplified).
local function buffer(ctype)
	local ctype = ffi.typeof(ctype)
	local buf, len = nil, -1
	return function(minlen)
		if minlen > len then
			len = nextpow2(minlen)
			buf = ctype(len)
		end
		return buf, len
	end
end

--error reporting ------------------------------------------------------------

cdef'char *strerror(int errnum);'

local error_classes = {
	[2] = 'not_found', --ENOENT, _open_osfhandle(), _fdopen(), open(), mkdir(),
	                   --rmdir(), opendir(), rename(), unlink()
	[5] = 'io_error', --EIO, readlink()
	[17] = 'already_exists', --EEXIST, open(), mkdir()
	[20] = 'not_found', --ENOTDIR, opendir()
	--[21] = 'access_denied', --EISDIR, unlink()
	[linux and 39 or osx and 66 or ''] = 'not_empty',
		--ENOTEMPTY, rmdir()
	[28] = 'disk_full', --ENOSPC: fallocate()
	[linux and 95 or ''] = 'not_supported', --EOPNOTSUPP: fallocate()

	--[[ --TODO: mmap
	local ENOENT = 2
	local ENOMEM = 12
	local EINVAL = 22
	local EFBIG  = 27
	local ENOSPC = 28
	local EDQUOT = osx and 69 or 122

	local errcodes = {
		[ENOENT] = 'not_found',
		[ENOMEM] = 'out_of_mem',
		[EINVAL] = 'file_too_short',
		[EFBIG] = 'disk_full',
		[ENOSPC] = 'disk_full',
		[EDQUOT] = 'disk_full',
	}
	]]

	--[[
	[12] = 'out_of_mem', --TODO: ENOMEM: mmap
	[22] = 'file_too_short', --TODO: EINVAL: mmap
	[27] = 'disk_full', --TODO: EFBIG
	[osx and 69 or 122] = 'disk_full', --TODO: EDQUOT
	]]
}

local function check_errno(ret, errno)
	if ret then return ret end
	errno = errno or ffi.errno()
	local err = error_classes[errno]
	if not err then
		local s = C.strerror(errno)
		err = s ~= nil and ffi.string(s) or 'Error '..errno
	end
	return ret, err, errno
end

--flags arg parsing ----------------------------------------------------------

--turn a table of boolean options into a bit mask.
local function table_flags(t, masks, strict)
	local bits = 0
	local mask = 0
	for k,v in pairs(t) do
		local flag
		if type(k) == 'string' and v then --flags as table keys: {flag->true}
			flag = k
		elseif type(k) == 'number'
			and floor(k) == k
			and type(v) == 'string'
		then --flags as array: {flag1,...}
			flag = v
		end
		local bitmask = masks[flag]
		if strict then
			assert(bitmask, 'invalid flag: "%s"', tostring(flag))
		end
		if bitmask then
			mask = bit.bor(mask, bitmask)
			if flag then
				bits = bit.bor(bits, bitmask)
			end
		end
	end
	return bits, mask
end

--turn 'opt1 +opt2 -opt3' -> {opt1=true, opt2=true, opt3=false}
local function string_flags(s, masks, strict)
	local t = {}
	for s in s:gmatch'[^ ,]+' do
		local m,s = s:match'^([%+%-]?)(.*)$'
		t[s] = m ~= '-'
	end
	return table_flags(t, masks, strict)
end

--set one or more bits of a value without affecting other bits.
local function setbits(bits, mask, over)
	return over and bit.bor(bits, bit.band(over, bit.bnot(mask))) or bits
end

--cache tuple(options_string, masks_table) -> bits, mask
local cache = {}
local function getcache(s, masks)
	cache[masks] = cache[masks] or {}
	local t = cache[masks][s]
	if not t then return end
	return t[1], t[2]
end
local function setcache(s, masks, bits, mask)
	cache[masks][s] = {bits, mask}
end

local function flags(arg, masks, cur_bits, strict)
	if type(arg) == 'string' then
		local bits, mask = getcache(arg, masks)
		if not bits then
			bits, mask = string_flags(arg, masks, strict)
			setcache(arg, masks, bits, mask)
		end
		return setbits(bits, mask, cur_bits)
	elseif type(arg) == 'table' then
		local bits, mask = table_flags(arg, masks, strict)
		return setbits(bits, mask, cur_bits)
	elseif type(arg) == 'number' then
		return arg
	elseif arg == nil then
		return 0
	else
		assert(false, 'flags expected but "%s" given', type(arg))
	end
end

--file objects ---------------------------------------------------------------

function fs.isfile(f)
	return ffi.istype(file_ct, f)
end

--returns a read(buf, maxsz) -> sz function which reads ahead from file.
function file.buffered_read(f, ctype, bufsize)
	local elem_ct = ffi.typeof(ctype or 'char')
	local ptr_ct = ffi.typeof('$*', elem_ct)
	assert(ffi.sizeof(elem_ct) == 1)
	local buf_ct = ffi.typeof('$[?]', elem_ct)
	local bufsize = bufsize or 4096
	local buf = buf_ct(bufsize)
	local ofs, len = 0, 0
	local eof = false
	return function(dst, sz)
		if not dst then --skip bytes (libjpeg semantics)
			local pos0, err, errcode = f:seek'cur'
			if not pos0 then return nil, err, errcode end
			local pos, err, errcode = f:seek('cur', sz)
			if not pos then return nil, err, errcode end
			return pos - pos0
		end
		local rsz = 0
		while sz > 0 do
			if len == 0 then
				if eof then
					return 0
				end
				ofs = 0
				local len1, err, errcode = f:read(buf, bufsize)
				if not len1 then return nil, err, errcode end
				len = len1
				if len == 0 then
					eof = true
					return rsz
				end
			end
			--TODO: don't copy, read less.
			local n = min(sz, len)
			ffi.copy(ffi.cast(ptr_ct, dst) + rsz, buf + ofs, n)
			ofs = ofs + n
			len = len - n
			rsz = rsz + n
			sz = sz - n
		end
		return rsz
	end
end

--stdio streams --------------------------------------------------------------

cdef[[
typedef struct FILE FILE;
int fclose(FILE*);
]]

local stream_ct = ffi.typeof'struct FILE'

function stream.close(fs)
	local ok = C.fclose(fs) == 0
	if not ok then return check_errno() end
	ffi.gc(fs, nil)
	return true
end

--i/o ------------------------------------------------------------------------

local whences = {set = 0, cur = 1, ['end'] = 2} --FILE_*
function file.seek(f, whence, offset)
	if tonumber(whence) and not offset then --middle arg missing
		whence, offset = 'cur', tonumber(whence)
	end
	whence = whence or 'cur'
	offset = tonumber(offset or 0)
	whence = assert(whences[whence], 'invalid whence: "%s"', whence)
	return f._seek(f, whence, offset)
end

--truncate/getsize/setsize ---------------------------------------------------

--get/set file size implementations in terms of f:seek() and f:truncate().
--to be overwritten by backends if they have better ones.

local function file_getsize(f)
	local curpos, err, errcode = f:seek()
	if not curpos then return nil, err, errcode end
	local size, err, errcode = f:seek'end'
	if not size then return nil, err, errcode end
	if curpos ~= size then
		local _, err, errcode = f:seek('set', curpos)
		if not _ then return nil, err, errcode end
	end
	return size
end

local function file_setsize(f, newsize, opt)
	local curpos, err, errcode = f:seek()
	if not curpos then return nil, err, errcode end
	local _, err, errcode = f:seek('set', newsize)
	if not _ then return nil, err, errcode end
	local _, err, errcode = f:truncate(opt)
	if not _ then return nil, err, errcode end
	local _, err, errcode = f:seek('set', curpos)
	if not _ then return nil, err, errcode end
	return newsize
end

--filesystem operations ------------------------------------------------------

function fs.mkdir(dir, recursive, ...)
	if recursive then
		dir = path.normalize(dir) --avoid creating `dir` in `dir/..` sequences
		local t = {}
		while true do
			local ok, err, errcode = mkdir(dir, ...)
			if ok then break end
			if err ~= 'not_found' then --other problem
				ok = err == 'already_exists' and #t == 0
				return ok, err, errcode
			end
			table.insert(t, dir)
			dir = path.dir(dir)
			if not dir then --reached root
				return ok, err, errcode
			end
		end
		while #t > 0 do
			local dir = table.remove(t)
			local ok, err, errcode = mkdir(dir, ...)
			if not ok then return ok, err, errcode end
		end
		return true
	else
		return mkdir(dir, ...)
	end
end

local function remove(path)
	local type = fs.attr(path, 'type', false)
	if type == 'dir' or (win and type == 'symlink'
		and fs.is(path, 'dir'))
	then
		return rmdir(path)
	end
	return rmfile(path)
end

--TODO: for Windows, this simple algorithm is not correct. On NTFS we
--should be moving all files to a temp folder and deleting them from there.
local function rmdir_recursive(dir)
	for file, d, errcode in fs.dir(dir) do
		if not file then
			return file, d, errcode
		end
		local filepath = path.combine(dir, file)
		local ok, err, errcode
		local realtype = d:attr('type', false)
		if realtype == 'dir' then
			ok, err, errcode = rmdir_recursive(filepath)
		elseif win and realtype == 'symlink' and fs.is(filepath, 'dir') then
			ok, err, errcode = rmdir(filepath)
		else
			ok, err, errcode = rmfile(filepath)
		end
		if not ok then
			d:close()
			return ok, err, errcode
		end
	end
	return rmdir(dir)
end

function fs.remove(dirfile, recursive)
	if recursive then
		--not recursing if the dir is a symlink, unless it has an endsep!
		if not path.endsep(dirfile) then
			local type, err, errcode = fs.attr(dirfile, 'type', false)
			if not type then return nil, err, errcode end
			if type == 'symlink' then
				if win and fs.is(dirfile, 'dir') then
					return rmdir(dirfile)
				end
				return rmfile(dirfile)
			end
		end
		return rmdir_recursive(dirfile)
	else
		return remove(dirfile)
	end
end

function fs.cd(path)
	if path then
		return chdir(path)
	else
		return getcwd()
	end
end

--symlinks -------------------------------------------------------------------

local function readlink_recursive(link, maxdepth)
	if not fs.is(link, 'symlink') then
		return link
	end
	if maxdepth == 0 then
		return nil, 'not_found'
	end
	local target, err, errcode = readlink(link)
	if not target then
		return nil, err, errcode
	end
	if path.isabs(target) then
		link = target
	else --relative symlinks are relative to their own dir
		local link_dir = path.dir(link)
		if not link_dir then
			return nil, 'not_found'
		elseif link_dir == '.' then
			link_dir = ''
		end
		link = path.combine(link_dir, target)
	end
	return readlink_recursive(link, maxdepth - 1)
end

function fs.readlink(link)
	return readlink_recursive(link, 32)
end

--common paths ---------------------------------------------------------------

function fs.exedir()
	return path.dir(fs.exepath())
end

--file attributes ------------------------------------------------------------

function file.attr(f, attr)
	if type(attr) == 'table' then
		return file_attr_set(f, attr)
	else
		return file_attr_get(f, attr)
	end
end

local function attr_args(attr, deref)
	if type(attr) == 'boolean' then --middle arg missing
		attr, deref = nil, attr
	end
	if deref == nil then
		deref = true --deref by default
	end
	return attr, deref
end

function fs.attr(path, ...)
	local attr, deref = attr_args(...)
	if attr == 'target' then
		--NOTE: posix doesn't need a type check here, but Windows does
		if not win or fs.is(path, 'symlink') then
			return readlink(path)
		else
			return nil --no error for non-symlink files
		end
	end
	if type(attr) == 'table' then
		return fs_attr_set(path, attr, deref)
	else
		return fs_attr_get(path, attr, deref)
	end
end

function fs.is(path, type, deref)
	if type == 'symlink' then
		deref = false
	end
	local ftype, err, errcode = fs.attr(path, 'type', deref)
	if not type and not ftype and err == 'not_found' then
		return false
	elseif not type and ftype then
		return true
	elseif not ftype then
		return nil, err, errcode
	else
		return ftype == type
	end
end

--directory listing ----------------------------------------------------------

local function dir_check(dir)
	assert(not dir:closed(), 'dir closed')
	assert(dir_ready(dir), 'dir not ready')
end

function fs.dir(dir, dot_dirs)
	dir = dir or '.'
	if dot_dirs then
		return fs_dir(dir)
	else --wrap iterator to skip `.` and `..` entries
		local next, dir = fs_dir(dir)
		local function wrapped_next(dir)
			while true do
				local file, err, errcode = next(dir)
				if file == nil then
					return nil
				elseif not file then
					return false, err, errcode
				elseif file ~= '.' and file ~= '..' then
					return file, dir
				end
			end
		end
		return wrapped_next, dir
	end
end

function dir.path(dir)
	return path.combine(dir:dir(), dir:name())
end

function dir.name(dir)
	dir_check(dir)
	return dir_name(dir)
end

local function dir_is_symlink(dir)
	return dir_attr_get(dir, 'type', false) == 'symlink'
end

function dir.attr(dir, ...)
	dir_check(dir)
	local attr, deref = attr_args(...)
	if attr == 'target' then
		if dir_is_symlink(dir) then
			return readlink(dir:path())
		else
			return nil --no error for non-symlink files
		end
	end
	if type(attr) == 'table' then
		return fs_attr_set(dir:path(), attr, deref)
	elseif not attr or (deref and dir_is_symlink(dir)) then
		return fs_attr_get(dir:path(), attr, deref)
	else
		local val, found = dir_attr_get(dir, attr)
		if found == false then --attr not found in state
			return fs_attr_get(dir:path(), attr)
		else
			return val
		end
	end
end

function dir.is(dir, type, deref)
	if type == 'symlink' then
		deref = false
	end
	return dir:attr('type', deref) == type
end

--memory mapping -------------------------------------------------------------

function fs.aligned_size(size, dir) --dir can be 'l' or 'r' (default: 'r')
	if ffi.istype(uint64_ct, size) then --an uintptr_t on x64
		local pagesize = fs.pagesize()
		local hi, lo = split_uint64(size)
		local lo = fs.aligned_size(lo, dir)
		return join_uint64(hi, lo)
	else
		local pagesize = fs.pagesize()
		if not (dir and dir:find'^l') then --align to the right
			size = size + pagesize - 1
		end
		return bit.band(size, bit.bnot(pagesize - 1))
	end
end

function fs.aligned_addr(addr, dir)
	return ffi.cast(void_ptr_ct,
		fs.aligned_size(ffi.cast(uintptr_ct, addr), dir))
end

local function map_check_tagname(tagname)
	assert(tagname, 'no tagname given')
	assert(not tagname:find'[/\\]', 'invalid tagname')
	return tagname
end

--[[
local function protect(map, offset, size)
	local offset = offset or 0
	assert(offset >= 0 and offset < map.size, 'offset out of bounds')
	local size = min(size or map.size, map.size - offset)
	assert(size >= 0, 'negative size')
	local addr = ffi.cast('const char*', map.addr) + offset
	fs.protect(addr, size)
end
]]

local function map_access_args(access)
	assert(not access:find'[^rwcx]', 'invalid access flags')
	local write = access:find'w' and true or false
	local copy = access:find'c' and true or false
	local exec = access:find'x' and true or false
	assert(not (write and copy), 'invalid access flags')
	return write, exec, copy
end

local function map_args(t,...)

	--dispatch args
	local file, access, size, offset, addr, tagname
	if type(t) == 'table' then
		file, access, size, offset, addr, tagname =
			t.file, t.access, t.size, t.offset, t.addr, t.tagname
	else
		file, access, size, offset, addr, tagname = t, ...
	end

	--apply defaults/convert
	local access = access or ''
	local offset = file and offset or 0
	local addr = addr and ffi.cast(void_ptr_ct, addr)
	local access_write, access_exec, access_copy = map_access_args(access)

	--check
	assert(file or size, 'file and/or size expected')
	assert(not (file and tagname), 'cannot have both file and tagname')
	assert(not size or size > 0, 'size must be > 0')
	assert(offset >= 0, 'offset must be >= 0')
	assert(offset == fs.aligned_size(offset), 'offset not page-aligned')
	assert(not addr or addr ~= nil, 'addr can\'t be zero')
	assert(not addr or addr == fs.aligned_addr(addr),
		'addr not page-aligned')
	if tagname then check_tagname(tagname) end

	return file, access_write, access_exec, access_copy,
		size, offset, addr, tagname
end

function fs.map(...)
	return fs_map(map_args(...))
end

function file.mirror_map(f, t, ...)
	local size, times, addr
	if type(t) == 'table' then
		size, times, addr = t.size, t.times, t.addr
	else
		size, times, addr = t, ...
	end
	return fs.mirror_map(f, size, times, addr)
end

function fs.mirror_map(f, ...)

	--dispatch args
	local file, size, times, addr
	if type(t) == 'table' then
		file, size, times, addr = t.file, t.size, t.times, t.addr
	else
		file, size, times, addr = t, ...
	end

	--apply defaults/convert/check
	local size = fs.aligned_size(size or fs.pagesize())
	local times = times or 2
	local access = 'w'
	assert(times > 0, 'times must be > 0')

	local retries = -1
	local max_retries = 100
	::try_again::
	retries = retries + 1
	if retries > max_retries then
		return nil, 'maximum retries reached', 'max_retries'
	end

	--try to allocate a contiguous block
	local map, err, errcode = fs.map{
		file = file,
		size = size * times,
		access = access,
		addr = addr,
	}
	if not map then
		return nil, err, errcode
	end

	--now free it so we can allocate it again in chunks all pointing at
	--the same offset 0 in the file, thus mirroring the same data.
	local maps = {addr = map.addr, size = size}
	map:free()

	local addr = ffi.cast(char_ptr_ct, maps.addr)

	function maps:free()
		for _,map in ipairs(self) do
			map:free()
		end
	end

	for i = 1, times do
		local map, err, errcode = fs.map{
			file = file,
			size = size,
			addr = addr + (i - 1) * size,
			access = access,
		}
		if not map then
			maps:free()
			goto try_again
		end
		maps[i] = map
	end

	return maps
end

--memory streams -------------------------------------------------------------

local vfile = {}

function fs.open_buffer(buf, sz, mode)
	sz = sz or #buf
	mode = mode or 'r'
	assert(mode == 'r' or mode == 'w', 'invalid mode: "%s"', mode)
	local f = {
		buffer = ffi.cast(char_ptr_ct, buf),
		size = sz,
		offset = 0,
		mode = mode,
		_buffer = buf, --anchor it
		__index = vfile,
	}
	return setmetatable(f, f)
end

function vfile.close(f) f._closed = true; return true end
function vfile.closed(f) return f._closed end

function vfile.flush(f)
	if f._closed then
		return nil, 'access_denied'
	end
	return true
end

function vfile.read(f, buf, sz)
	if f._closed then
		return nil, 'access_denied'
	end
	sz = min(max(0, sz), max(0, f.size - f.offset))
	ffi.copy(buf, f.buffer + f.offset, sz)
	f.offset = f.offset + sz
	return sz
end

function vfile.write(f, buf, sz)
	if f._closed then
		return nil, 'access_denied'
	end
	if f.mode ~= 'w' then
		return nil, 'access_denied'
	end
	sz = min(max(0, sz), max(0, f.size - f.offset))
	ffi.copy(f.buffer + f.offset, buf, sz)
	f.offset = f.offset + sz
	return sz
end

vfile.seek = file.seek

function vfile._seek(f, whence, offset)
	if whence == 1 then --cur
		offset = f.offset + offset
	elseif whence == 2 then --end
		offset = f.size + offset
	end
	offset = max(offset, 0)
	f.offset = offset
	return offset
end

function vfile:truncate()
	if f.offset > f.size then
		return nil, 'access_denied'
	end
	f.size = f.offset
	return true
end

vfile.buffered_read = file.buffered_read

if win then ------------------------------------------------------------------

--types, consts, utils -------------------------------------------------------

if x64 then
	cdef'typedef int64_t ULONG_PTR;'
else
	cdef'typedef int32_t ULONG_PTR;'
end

cdef[[
typedef void           VOID, *PVOID, *LPVOID;
typedef VOID*          HANDLE, *PHANDLE;
typedef unsigned short WORD;
typedef unsigned long  DWORD, *PDWORD, *LPDWORD;
typedef unsigned int   UINT;
typedef int            BOOL;
typedef ULONG_PTR      SIZE_T;
typedef const void*    LPCVOID;
typedef char*          LPSTR;
typedef const char*    LPCSTR;
typedef wchar_t        WCHAR;
typedef WCHAR*         LPWSTR;
typedef const WCHAR*   LPCWSTR;
typedef BOOL           *LPBOOL;
typedef void*          HMODULE;
typedef unsigned char  UCHAR;
typedef unsigned short USHORT;
typedef long           LONG;
typedef unsigned long  ULONG;
typedef long long      LONGLONG;

typedef union {
	struct {
		DWORD LowPart;
		LONG HighPart;
	};
	struct {
		DWORD LowPart;
		LONG HighPart;
	} u;
	LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct {
	DWORD  nLength;
	LPVOID lpSecurityDescriptor;
	BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
]]

local INVALID_HANDLE_VALUE = ffi.cast('HANDLE', -1)

local wbuf = buffer'WCHAR[?]'
local libuf = ffi.new'LARGE_INTEGER[1]'

local m = ffi.new[[
	union {
		struct { uint32_t lo; uint32_t hi; };
		uint64_t x;
	}
]]
local function split_uint64(x)
	m.x = x
	return m.hi, m.lo
end
local function join_uint64(hi, lo)
	m.hi, m.lo = hi, lo
	return m.x
end

--error reporting ------------------------------------------------------------

cdef[[
DWORD GetLastError(void);

DWORD FormatMessageA(
	DWORD dwFlags,
	LPCVOID lpSource,
	DWORD dwMessageId,
	DWORD dwLanguageId,
	LPSTR lpBuffer,
	DWORD nSize,
	va_list *Arguments
);
]]

local FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000

local errbuf = buffer'char[?]'

local error_classes = {
	[0x002] = 'not_found', --ERROR_FILE_NOT_FOUND, CreateFileW
	[0x003] = 'not_found', --ERROR_PATH_NOT_FOUND, CreateDirectoryW
	[0x005] = 'access_denied', --ERROR_ACCESS_DENIED, CreateFileW
	[0x050] = 'already_exists', --ERROR_FILE_EXISTS, CreateFileW
	[0x091] = 'not_empty', --ERROR_DIR_NOT_EMPTY, RemoveDirectoryW
	[0x0b7] = 'already_exists', --ERROR_ALREADY_EXISTS, CreateDirectoryW
	[0x10B] = 'not_found', --ERROR_DIRECTORY, FindFirstFileW

	--TODO: mmap
	[0x0008] = 'file_too_short', --readonly file too short
	[0x0057] = 'out_of_mem', --size or address too large
	[0x0070] = 'disk_full',
	[0x01E7] = 'out_of_mem', --address in use
	[0x03ee] = 'file_too_short', --file has zero size
	[0x05af] = 'out_of_mem', --swapfile too short

}

local function check(ret, err)
	if ret then return ret end
	err = err or C.GetLastError()
	local msg = error_classes[err]
	if not msg then
		local buf, bufsz = errbuf(512)
		local sz = C.FormatMessageA(
			FORMAT_MESSAGE_FROM_SYSTEM, nil, err, 0, buf, bufsz, nil)
		msg = sz > 0 and ffi.string(buf, sz):gsub('[\r\n]+$', '') or 'Error '..err
	end
	return ret, msg, err
end

--utf16/utf8 conversion ------------------------------------------------------

cdef[[
int MultiByteToWideChar(
	UINT     CodePage,
	DWORD    dwFlags,
	LPCSTR   lpMultiByteStr,
	int      cbMultiByte,
	LPWSTR   lpWideCharStr,
	int      cchWideChar
);
int WideCharToMultiByte(
	UINT     CodePage,
	DWORD    dwFlags,
	LPCWSTR  lpWideCharStr,
	int      cchWideChar,
	LPSTR    lpMultiByteStr,
	int      cbMultiByte,
	LPCSTR   lpDefaultChar,
	LPBOOL   lpUsedDefaultChar
);
]]

local CP_UTF8 = 65001

local wcsbuf = buffer'WCHAR[?]'

local function wcs(s, msz, wbuf) --string -> WCHAR[?]
	msz = msz and msz + 1 or #s + 1
	wbuf = wbuf or wcsbuf
	local wsz = C.MultiByteToWideChar(CP_UTF8, 0, s, msz, nil, 0)
	assert(wsz > 0) --should never happen otherwise
	local buf = wbuf(wsz)
	local sz = C.MultiByteToWideChar(CP_UTF8, 0, s, msz, buf, wsz)
	assert(sz == wsz) --should never happen otherwise
	return buf
end

local mbsbuf = buffer'char[?]'

local function mbs(ws, wsz, mbuf) --WCHAR* -> string
	wsz = wsz and wsz + 1 or -1
	mbuf = mbuf or mbsbuf
	local msz = C.WideCharToMultiByte(
		CP_UTF8, 0, ws, wsz, nil, 0, nil, nil)
	assert(msz > 0) --should never happen otherwise
	local buf = mbuf(msz)
	local sz = C.WideCharToMultiByte(
		CP_UTF8, 0, ws, wsz, buf, msz, nil, nil)
	assert(sz == msz) --should never happen otherwise
	return ffi.string(buf, sz-1)
end

--open/close -----------------------------------------------------------------

cdef[[
HANDLE CreateFileW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
);
BOOL CloseHandle(HANDLE hObject);
]]

--CreateFile access rights flags
local t = {
	--FILE_* (specific access rights)
	list_directory           = 1, --dirs:  allow listing
	read_data                = 1, --files: allow reading data
	add_file                 = 2, --dirs:  allow creating files
	write_data               = 2, --files: allow writting data
	add_subdirectory         = 4, --dirs:  allow creating subdirs
	append_data              = 4, --files: allow appending data
	create_pipe_instance     = 4, --pipes: allow creating a pipe
	delete_child          = 0x40, --dirs:  allow deleting dir contents
	traverse              = 0x20, --dirs:  allow traversing (not effective)
	execute               = 0x20, --exes:  allow exec'ing
	read_attributes       = 0x80, --allow reading attrs
	write_attributes     = 0x100, --allow setting attrs
	read_ea                  = 8, --allow reading extended attrs
	write_ea              = 0x10, --allow writting extended attrs
	--object's standard access rights
	delete       = 0x00010000,
	read_control = 0x00020000, --allow r/w the security descriptor
	write_dac    = 0x00040000,
	write_owner  = 0x00080000,
	synchronize  = 0x00100000,
	--STANDARD_RIGHTS_*
	standard_rights_required = 0x000F0000,
	standard_rights_read     = 0x00020000, --read_control
	standard_rights_write    = 0x00020000, --read_control
	standard_rights_execute  = 0x00020000, --read_control
	standard_rights_all      = 0x001F0000,
	--GENERIC_*
	generic_read    = 0x80000000,
	generic_write   = 0x40000000,
	generic_execute = 0x20000000,
	generic_all     = 0x10000000,
}
--FILE_ALL_ACCESS
t.all_access = bit.bor(
	t.standard_rights_required,
	t.synchronize,
	0x1ff)
--FILE_GENERIC_*
t.read = bit.bor(
	t.standard_rights_read,
	t.read_data,
   t.read_attributes,
	t.read_ea,
	t.synchronize)
t.write = bit.bor(
	t.standard_rights_write,
	t.write_data,
   t.write_attributes,
	t.write_ea,
	t.append_data,
	t.synchronize)
t.execute = bit.bor(
	t.standard_rights_execute,
	t.read_attributes,
	t.execute,
	t.synchronize)
local access_bits = t

--CreateFile sharing flags
local sharing_bits = {
	--FILE_SHARE_*
	read   = 0x00000001, --allow us/others to read
	write  = 0x00000002, --allow us/others to write
	delete = 0x00000004, --allow us/others to delete or rename
}

--CreateFile creation disposition flags
local creation_bits = {
	create_new        = 1, --create or fail
	create_always     = 2, --open or create + truncate
	open_existing     = 3, --open or fail
	open_always       = 4, --open or create
	truncate_existing = 5, --open + truncate or fail
}

local FILE_ATTRIBUTE_NORMAL = 0x00000080 --for when no bits are set

--CreateFile flags & attributes
local attr_bits = {
	--FILE_ATTRIBUTE_*
	readonly      = 0x00000001,
	hidden        = 0x00000002,
	system        = 0x00000004,
	archive       = 0x00000020,
	temporary     = 0x00000100,
	sparse_file   = 0x00000200,
	reparse_point = 0x00000400,
	compressed    = 0x00000800,
	directory     = 0x00000010,
	device        = 0x00000040,
	--offline     = 0x00001000, --reserved (used by Remote Storage)
	not_indexed   = 0x00002000, --FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	encrypted     = 0x00004000,
	--virtual     = 0x00010000, --reserved
}

local flag_bits = {
	--FILE_FLAG_*
	write_through        = 0x80000000,
	overlapped           = 0x40000000,
	no_buffering         = 0x20000000,
	random_access        = 0x10000000,
	sequential_scan      = 0x08000000,
	delete_on_close      = 0x04000000,
	backup_semantics     = 0x02000000,
	posix_semantics      = 0x01000000,
	open_reparse_point   = 0x00200000,
	open_no_recall       = 0x00100000,
	first_pipe_instance  = 0x00080000,
}

local str_opt = {
	r = {
		access = 'read',
		creation = 'open_existing',
		flags = 'backup_semantics'},
	w = {
		access = 'write file_read_attributes',
		creation = 'create_always',
		flags = 'backup_semantics'},
	['r+'] = {
		access = 'read write',
		creation = 'open_existing',
		flags = 'backup_semantics'},
	['w+'] = {
		access = 'read write',
		creation = 'create_always',
		flags = 'backup_semantics'},
}

--expose this because the frontend will set its metatype at the end.
cdef[[
struct file_t {
	HANDLE handle;
};
]]
file_ct = ffi.typeof'struct file_t'

function fs.open(path, opt)
	opt = opt or 'r'
	if type(opt) == 'string' then
		opt = assert(str_opt[opt], 'invalid option %s', opt)
	end
	local access   = flags(opt.access or 'read', access_bits)
	local sharing  = flags(opt.sharing or 'read', sharing_bits)
	local creation = flags(opt.creation or 'open_existing', creation_bits)
	local attrbits = flags(opt.attrs, attr_bits)
	attrbits = attrbits == 0 and FILE_ATTRIBUTE_NORMAL or attrbits
	local flagbits = flags(opt.flags, flag_bits)
	local attflags = bit.bor(attrbits, flagbits)
	local h = C.CreateFileW(
		wcs(path), access, sharing, nil, creation, attflags, nil)
	if h == INVALID_HANDLE_VALUE then return check() end
	return ffi.gc(file_ct(h), file.close)
end

function file.closed(f)
	return f.handle == INVALID_HANDLE_VALUE
end

function file.close(f)
	if f:closed() then return end
	local ret = C.CloseHandle(f.handle)
	if ret == 0 then return check(false) end
	f.handle = INVALID_HANDLE_VALUE
	ffi.gc(f, nil)
	return true
end

function fs.wrap_handle(h)
	return file_ct(h)
end

cdef[[
int _fileno(struct FILE *stream);
HANDLE _get_osfhandle(int fd);
]]

function fs.wrap_fd(fd)
	local h = C._get_osfhandle(fd)
	if h == nil then return check_errno() end
	return fs.wrap_handle(h)
end

function fs.fileno(file)
	local fd = C._fileno(file)
	return check_errno(fd ~= -1 and fd or nil)
end

function fs.wrap_file(file)
	local fd, err, errno = fs.fileno(file)
	if not fd then return nil, err, errno end
	return fs.wrap_fd(fd)
end

--pipes ----------------------------------------------------------------------

cdef[[
BOOL CreatePipe(
	PHANDLE               hReadPipe,
	PHANDLE               hWritePipe,
	LPSECURITY_ATTRIBUTES lpPipeAttributes,
	DWORD                 nSize
);
BOOL SetHandleInformation(
	HANDLE hObject,
	DWORD  dwMask,
	DWORD  dwFlags
);
HANDLE CreateNamedPipeW(
  LPWSTR                lpName,
  DWORD                 dwOpenMode,
  DWORD                 dwPipeMode,
  DWORD                 nMaxInstances,
  DWORD                 nOutBufferSize,
  DWORD                 nInBufferSize,
  DWORD                 nDefaultTimeOut,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
]]

local HANDLE_FLAG_INHERIT = 1

local access = {
}

--NOTE: FILE_FLAG_FIRST_PIPE_INSTANCE == WRITE_OWNER wtf?
local pipe_flag_bits = update({
	r               = 0x00000001, --PIPE_ACCESS_INBOUND
	w               = 0x00000002, --PIPE_ACCESS_OUTBOUND
	rw              = 0x00000003, --PIPE_ACCESS_DUPLEX
	single_instance = 0x00080000, --FILE_FLAG_FIRST_PIPE_INSTANCE
	write_through   = 0x80000000, --FILE_FLAG_WRITE_THROUGH
	overlapped      = 0x40000000, --FILE_FLAG_OVERLAPPED
	write_dac       = 0x00040000, --WRITE_DAC
	write_owner     = 0x00080000, --WRITE_OWNER
	system_security = 0x01000000, --ACCESS_SYSTEM_SECURITY
}, flag_bits)

function fs.pipe(name, opt)
	local sa = ffi.new'SECURITY_ATTRIBUTES'
	sa.nLength = ffi.sizeof(sa)
	sa.bInheritHandle = true
	local hs = ffi.new'HANDLE[2]'
	if type(name) == 'table' then
		name, opt = name.name, name
	end
	opt = opt or {}
	if name then --named pipe
		local h = C.CreateNamedPipeW(
			wcs(name),
			flags(opt, pipe_flag_bits, 0, true),
			0, --nothing interesting here
			opt.max_instances or 255,
			opt.write_buffer_size or 8192,
			opt.read_buffer_size or 8192,
			opt.timeout or 0,
			sa)
		if h == INVALID_HANDLE_VALUE then
			return check()
		end
		return ffi.gc(fs.wrap_handle(h), file.close)
	else --unnamed pipe, return both ends
		if C.CreatePipe(hs, hs+1, sa, 0) == 0 then
			return check()
		end
		C.SetHandleInformation(hs[0], HANDLE_FLAG_INHERIT, 0)
		C.SetHandleInformation(hs[1], HANDLE_FLAG_INHERIT, 0)
		local rf = ffi.gc(fs.wrap_handle(hs[0]), file.close)
		local wf = ffi.gc(fs.wrap_handle(hs[1]), file.close)
		return rf, wf
	end
end

--stdio streams --------------------------------------------------------------

cdef[[
FILE *_fdopen(int fd, const char *mode);
int _open_osfhandle (HANDLE osfhandle, int flags);
]]

function file.stream(f, mode)
	local flags = 0
	local fd = C._open_osfhandle(f.handle, flags)
	if fd == -1 then return check_errno() end
	local fs = C._fdopen(fd, mode)
	if fs == nil then return check_errno() end
	ffi.gc(f, nil) --fclose() will close the handle
	ffi.gc(fs, stream.close)
	return fs
end

--i/o ------------------------------------------------------------------------

cdef[[
BOOL ReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	void*        lpOverlapped
);

BOOL WriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	void*        lpOverlapped
);

BOOL FlushFileBuffers(HANDLE hFile);

BOOL SetFilePointerEx(
	HANDLE         hFile,
	LARGE_INTEGER  liDistanceToMove,
	PLARGE_INTEGER lpNewFilePointer,
	DWORD          dwMoveMethod
);
]]

local dwbuf = ffi.new'DWORD[1]'

function file.read(f, buf, sz)
	local ok = C.ReadFile(f.handle, buf, sz, dwbuf, nil) ~= 0
	if not ok then return check() end
	return dwbuf[0]
end

function file.write(f, buf, sz)
	local ok = C.WriteFile(f.handle, buf, sz, dwbuf, nil) ~= 0
	if not ok then return check() end
	return dwbuf[0]
end

function file.flush(f)
	return check(C.FlushFileBuffers(f.handle) ~= 0)
end

local ofsbuf = ffi.new'LARGE_INTEGER[1]'
function file._seek(f, whence, offset)
	ofsbuf[0].QuadPart = offset
	local ok = C.SetFilePointerEx(f.handle, ofsbuf[0], libuf, whence) ~= 0
	if not ok then return check() end
	return tonumber(libuf[0].QuadPart)
end

--truncate/getsize/setsize ---------------------------------------------------

cdef[[
BOOL SetEndOfFile(HANDLE hFile);
BOOL GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize);
]]

--NOTE: seeking beyond file size and then truncating the file incurs no delay
--on NTFS, but that's not because the file becomes sparse (it doesn't, and
--disk space _is_ reserved), but because the extra zero bytes are not written
--until the first write call _that requires it_. This is a good optimization
--since usually the file will be written sequentially after the truncation
--in which case those extra zero bytes will never get a chance to be written.
function file.truncate(f, opt)
	return check(C.SetEndOfFile(f.handle) ~= 0)
end

function file_getsize(f)
	local ok = C.GetFileSizeEx(f.handle, libuf) ~= 0
	if not ok then return check() end
	return tonumber(libuf[0].QuadPart)
end

--filesystem operations ------------------------------------------------------

cdef[[
BOOL CreateDirectoryW(LPCWSTR, LPSECURITY_ATTRIBUTES);
BOOL RemoveDirectoryW(LPCWSTR);
int SetCurrentDirectoryW(LPCWSTR lpPathName);
DWORD GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
BOOL DeleteFileW(LPCWSTR lpFileName);
BOOL MoveFileExW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	DWORD   dwFlags
);
]]

function mkdir(path)
	return check(C.CreateDirectoryW(wcs(path), nil) ~= 0)
end

function rmdir(path)
	return check(C.RemoveDirectoryW(wcs(path)) ~= 0)
end

function chdir(path)
	return check(C.SetCurrentDirectoryW(wcs(path)) ~= 0)
end

function getcwd()
	local sz = C.GetCurrentDirectoryW(0, nil)
	if sz == 0 then return check() end
	local buf = wbuf(sz)
	local sz = C.GetCurrentDirectoryW(sz, buf)
	if sz == 0 then return check() end
	return mbs(buf, sz)
end

function rmfile(path)
	return check(C.DeleteFileW(wcs(path)) ~= 0)
end

local move_bits = {
	--MOVEFILE_*
	replace_existing      =  0x1,
	copy_allowed          =  0x2,
	delay_until_reboot    =  0x4,
	fail_if_not_trackable = 0x20,
	write_through         =  0x8, --for when copy_allowed
}

--TODO: MoveFileExW is actually NOT atomic.
--Use SetFileInformationByHandle with FILE_RENAME_INFO and ReplaceIfExists
--which is atomic and also works on open handles which is even more atomic :)
local default_move_opt = 'replace_existing write_through' --posix
function fs.move(oldpath, newpath, opt)
	return check(C.MoveFileExW(
		wcs(oldpath),
		wcs(newpath, nil, wbuf),
		flags(opt or default_move_opt, move_bits)
	) ~= 0)
end

--symlinks & hardlinks -------------------------------------------------------

cdef[[
BOOL CreateSymbolicLinkW (
	LPCWSTR lpSymlinkFileName,
	LPCWSTR lpTargetFileName,
	DWORD dwFlags
);
BOOL CreateHardLinkW(
	LPCWSTR lpFileName,
	LPCWSTR lpExistingFileName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

BOOL DeviceIoControl(
	HANDLE       hDevice,
	DWORD        dwIoControlCode,
	LPVOID       lpInBuffer,
	DWORD        nInBufferSize,
	LPVOID       lpOutBuffer,
	DWORD        nOutBufferSize,
	LPDWORD      lpBytesReturned,
	void*        lpOverlapped
);
]]

local SYMBOLIC_LINK_FLAG_DIRECTORY = 0x1

function fs.mksymlink(link_path, target_path, is_dir)
	local flags = is_dir and SYMBOLIC_LINK_FLAG_DIRECTORY or 0
	return check(C.CreateSymbolicLinkW(
		wcs(link_path),
		wcs(target_path, nil, wbuf),
		flags) ~= 0)
end

function fs.mkhardlink(link_path, target_path)
	return check(C.CreateHardLinkW(
		wcs(link_path),
		wcs(target_path, nil, wbuf),
		nil) ~= 0)
end

do
	local function CTL_CODE(DeviceType, Function, Method, Access)
		return bit.bor(
			bit.lshift(DeviceType, 16),
			bit.lshift(Access, 14),
			bit.lshift(Function, 2),
			Method)
	end
	local FILE_DEVICE_FILE_SYSTEM = 0x00000009
	local METHOD_BUFFERED         = 0
	local FILE_ANY_ACCESS         = 0
	local FSCTL_GET_REPARSE_POINT = CTL_CODE(
		FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS)

	local readlink_opt = {
		access = 'read',
		sharing = 'read write delete',
		creation = 'open_existing',
		flags = 'backup_semantics open_reparse_point',
		attrs = 'reparse_point',
	}

	local REPARSE_DATA_BUFFER = ffi.typeof[[
		struct {
			ULONG  ReparseTag;
			USHORT ReparseDataLength;
			USHORT Reserved;
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG  Flags;
			WCHAR  PathBuffer[?];
		}
	]]

	local szbuf = ffi.new'DWORD[1]'
	local buf, sz = nil, 128

	local ERROR_INSUFFICIENT_BUFFER = 122
	local ERROR_MORE_DATA = 234

	function readlink(path)
		local f, err, errcode = fs.open(path, readlink_opt)
		if not f then return nil, err, errcode end
		::again::
		local buf = buf or REPARSE_DATA_BUFFER(sz)
		local ok = C.DeviceIoControl(
			f.handle, FSCTL_GET_REPARSE_POINT, nil, 0,
			buf, ffi.sizeof(buf), szbuf, nil) ~= 0
		if not ok then
			local err = C.GetLastError()
			if err == ERROR_INSUFFICIENT_BUFFER or err == ERROR_MORE_DATA then
				buf, sz = nil, sz * 2
				goto again
			end
			f:close()
			return check(false)
		end
		f:close()
		return mbs(
			buf.PathBuffer + buf.SubstituteNameOffset / 2,
			buf.SubstituteNameLength / 2)
	end
end

--common paths ---------------------------------------------------------------

cdef[[
DWORD GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer);
DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
]]

function fs.homedir()
	return os.getenv'USERPROFILE'
end

function fs.tmpdir()
	local buf, bufsz = wbuf(256)
	local sz = C.GetTempPathW(bufsz, buf)
	if sz == 0 then return check() end
	if sz > bufsz then
		buf, bufsz = wbuf(sz)
		local sz = C.GetTempPathW(bufsz, buf)
		assert(sz <= bufsz)
		if sz == 0 then return check() end
	end
	return mbs(buf, sz-1) --strip trailing '\'
end

function fs.appdir(appname)
	local dir = os.getenv'LOCALAPPDATA'
	return dir and dir..'\\'..appname
end

local ERROR_INSUFFICIENT_BUFFER = 122

function fs.exepath()
	local buf, bufsz = wbuf(256)
	::again::
	local sz = C.GetModuleFileNameW(hmodule, buf, bufsz)
	if sz < 0 then
		if GetLastError() == ERROR_INSUFFICIENT_BUFFER then
			buf, bufsz = wbuf(bufsz * 2)
			goto again
		else
			return check(false)
		end
	end
	return mbs(buf, sz)
end

--file attributes ------------------------------------------------------------

cdef[[
typedef struct {
	DWORD dwLowDateTime;
	DWORD dwHighDateTime;
} FILETIME;

typedef struct {
	DWORD    dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	DWORD    dwVolumeSerialNumber;
	DWORD    nFileSizeHigh;
	DWORD    nFileSizeLow;
	DWORD    nNumberOfLinks;
	DWORD    nFileIndexHigh;
	DWORD    nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION, *LPBY_HANDLE_FILE_INFORMATION;

BOOL GetFileInformationByHandle(
	HANDLE                       hFile,
	LPBY_HANDLE_FILE_INFORMATION lpFileInformation
);

typedef enum {
	FileBasicInfo                   = 0,
	FileStandardInfo                = 1,
	FileNameInfo                    = 2,
	FileRenameInfo                  = 3,
	FileDispositionInfo             = 4,
	FileAllocationInfo              = 5,
	FileEndOfFileInfo               = 6,
	FileStreamInfo                  = 7,
	FileCompressionInfo             = 8,
	FileAttributeTagInfo            = 9,
	FileIdBothDirectoryInfo         = 10,
	FileIdBothDirectoryRestartInfo  = 11,
	FileIoPriorityHintInfo          = 12,
	FileRemoteProtocolInfo          = 13,
	FileFullDirectoryInfo           = 14,
	FileFullDirectoryRestartInfo    = 15,
	FileStorageInfo                 = 16,
	FileAlignmentInfo               = 17,
	FileIdInfo                      = 18,
	FileIdExtdDirectoryInfo         = 19,
	FileIdExtdDirectoryRestartInfo  = 20,
} FILE_INFO_BY_HANDLE_CLASS;

typedef struct {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	DWORD         FileAttributes;
} FILE_BASIC_INFO, *PFILE_BASIC_INFO;

BOOL GetFileInformationByHandleEx(
	HANDLE                    hFile,
	FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
	LPVOID                    lpFileInformation,
	DWORD                     dwBufferSize
);

BOOL SetFileInformationByHandle(
	HANDLE                    hFile,
	FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
	LPVOID                    lpFileInformation,
	DWORD                     dwBufferSize
);

typedef enum {
    GetFileExInfoStandard
} GET_FILEEX_INFO_LEVELS;

DWORD GetFinalPathNameByHandleW(
	HANDLE hFile,
	LPWSTR lpszFilePath,
	DWORD  cchFilePath,
	DWORD  dwFlags
);
]]

--FILETIME stores time in hundred-nanoseconds from `1601-01-01 00:00:00`.
--timestamp stores the time in seconds from `1970-01-01 00:00:00`.

local TS_FT_DIFF = 11644473600 --seconds

local function filetime(ts) --convert timestamp -> FILETIME
	return (ts + TS_FT_DIFF) * 1e7
end

local function timestamp(ft) --convert FILETIME as uint64 -> timestamp
	return tonumber(ft) * 1e-7 - TS_FT_DIFF
end

local function ft_timestamp(filetime) --convert FILETIME -> timestamp
	return timestamp(filetime.dwHighDateTime * 2^32 + filetime.dwLowDateTime)
end

local function filesize(high, low)
	return high * 2^32 + low
end

local function attrbit(bits, k)
	if k ~= 'directory' and k ~= 'device' and attr_bits[k] then
		return bit.band(attr_bits[k], bits) ~= 0
	end
end

local function attrbits(bits, t)
	for name in pairs(attr_bits) do
		t[name] = attrbit(bits, name) or nil
	end
	return t
end

local changeable_attr_bits = {
	--FILE_ATTRIBUTE_* flags which can be changed directly
	readonly    = attr_bits.readonly,
	hidden      = attr_bits.hidden,
	system      = attr_bits.system,
	archive     = attr_bits.archive,
	temporary   = attr_bits.temporary,
	not_indexed = attr_bits.not_indexed,
}
local function set_attrbits(cur_bits, t)
	cur_bits = cur_bits == FILE_ATTRIBUTE_NORMAL and 0 or cur_bits
	local bits = flags(t, changeable_attr_bits, cur_bits, false)
	return bits == 0 and FILE_ATTRIBUTE_NORMAL or bits
end

local IO_REPARSE_TAG_SYMLINK = 0xA000000C

local function is_symlink(bits, reparse_tag)
	return bit.band(bits, attr_bits.reparse_point) ~= 0
		and (not reparse_tag or reparse_tag == IO_REPARSE_TAG_SYMLINK)
end

local function filetype(bits, reparse_tag)
	return
		is_symlink(bits, reparse_tag) and 'symlink'
		or bit.band(bits, attr_bits.directory) ~= 0 and 'dir'
		or bit.band(bits, attr_bits.device) ~= 0    and 'dev'
		or 'file'
end

local file_info_ct = ffi.typeof'BY_HANDLE_FILE_INFORMATION'
local info
local function file_get_info(f)
	info = info or file_info_ct()
	local ok = C.GetFileInformationByHandle(f.handle, info) ~= 0
	if not ok then return check() end
	return info
end

local file_basic_info_ct = ffi.typeof'FILE_BASIC_INFO'
local binfo
local function file_get_basic_info(f)
	binfo = binfo or file_basic_info_ct()
	local ok = C.GetFileInformationByHandleEx(
		f.handle, C.FileBasicInfo, binfo, ffi.sizeof(binfo)) ~= 0
	if not ok then return check() end
	return binfo
end

local function file_set_basic_info(f, binfo)
	return check(C.SetFileInformationByHandle(
		f.handle, C.FileBasicInfo, binfo, ffi.sizeof(binfo)) ~= 0)
end

local binfo_getters = {
	type = function(binfo) return filetype(binfo.FileAttributes) end,
	btime = function(binfo)
		return timestamp(binfo.CreationTime.QuadPart)
	end,
	atime = function(binfo)
		return timestamp(binfo.LastAccessTime.QuadPart)
	end,
	mtime = function(binfo)
		return timestamp(binfo.LastWriteTime.QuadPart) end,
	ctime = function(binfo)
		return timestamp(binfo.ChangeTime.QuadPart)
	end,
}

local info_getters = {
	volume = function(info)
		return info.dwVolumeSerialNumber
	end,
	size = function(info)
		return filesize(info.nFileSizeHigh, info.nFileSizeLow)
	end,
	nlink = function(info) return info.nNumberOfLinks end,
	id = function(info)
		return join_uint64(info.nFileIndexHigh, info.nFileIndexLow)
	end,
}

local function file_attr_get_all(f)
	local binfo, err, errcode = file_get_basic_info(f)
	if not binfo then return nil, err, errcode end
	local info, err, errcode = file_get_info(f)
	if not info then return nil, err, errcode end
	local t = attrbits(binfo.FileAttributes, {})
	for k, get in pairs(binfo_getters) do
		t[k] = get(binfo) or nil
	end
	for k, get in pairs(info_getters) do
		t[k] = get(info) or nil
	end
	return t
end

function file_attr_get(f, k)
	if not k then
		return file_attr_get_all(f)
	end
	local val = attrbit(0, k)
	if val ~= nil then
		local binfo, err, errcode = file_get_basic_info(f)
		if not binfo then return nil, err, errcode end
		return attrbit(binfo.FileAttributes)
	end
	local get = binfo_getters[k]
	if get then
		local binfo, err, errcode = file_get_basic_info(f)
		if not binfo then return nil, err, errcode end
		return get(binfo)
	end
	local get = info_getters[k]
	if get then
		local info, err, errcode = file_get_info(f)
		if not info then return nil, err, errcode end
		return get(info)
	end
	return nil
end

local function set_filetime(ft, ts)
	return ts and filetime(ts) or ft
end
function file_attr_set(f, t)
	local binfo, err, errcode = file_get_basic_info(f)
	if not binfo then return nil, err, errcode end
	binfo.FileAttributes = set_attrbits(binfo.FileAttributes, t)
	binfo.CreationTime.QuadPart   =
		set_filetime(binfo.CreationTime.QuadPart, t.btime)
	binfo.LastAccessTime.QuadPart =
		set_filetime(binfo.LastAccessTime.QuadPart, t.atime)
	binfo.LastWriteTime.QuadPart  =
		set_filetime(binfo.LastWriteTime.QuadPart, t.mtime)
	binfo.ChangeTime.QuadPart     =
		set_filetime(binfo.ChangeTime.QuadPart, t.ctime)
	return file_set_basic_info(f, binfo)
end

function with_open_file(path, open_opt, func, ...)
	local f, err, errcode = fs.open(path, open_opt)
	if not f then return nil, err, errcode end
	local ret, err, errcode = func(f, ...)
	if ret == nil and err then return nil, err, errcode end
	local ok, err, errcode = f:close()
	if not ok then return nil, err, errcode end
	return ret
end

local open_opt = {
	access = 'read_attributes',
	sharing = 'read write delete',
	creation = 'open_existing',
	flags = 'backup_semantics', --for opening directories
}
local open_opt_symlink = {
	access = 'read_attributes',
	sharing = 'read write delete',
	creation = 'open_existing',
	flags = 'backup_semantics open_reparse_point',
	attrs = 'reparse_point',
}
function fs_attr_get(path, k, deref)
	local opt = deref and open_opt or open_opt_symlink
	return with_open_file(path, opt, file_attr_get, k)
end

local open_opt = {
	access = 'write_attributes',
	sharing = 'read write delete',
	creation = 'open_existing',
}
local open_opt_symlink = {
	access = 'write_attributes',
	sharing = 'read write delete',
	creation = 'open_existing',
	flags = 'backup_semantics open_reparse_point',
	attrs = 'reparse_point',
}
function fs_attr_set(path, t, deref)
	local opt = deref and open_opt or open_opt_symlink
	return with_open_file(path, opt, file_attr_set, t)
end

--directory listing ----------------------------------------------------------

cdef[[
enum {
	MAX_PATH = 260
};

typedef struct {
	DWORD dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	DWORD nFileSizeHigh;
	DWORD nFileSizeLow;
	DWORD dwReserved0; // reparse tag
	DWORD dwReserved1;
	WCHAR cFileName[MAX_PATH];
	WCHAR cAlternateFileName[14];
} WIN32_FIND_DATAW, *LPWIN32_FIND_DATAW;

HANDLE FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
BOOL FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
BOOL FindClose(HANDLE);
]]

dir_ct = ffi.typeof[[
	struct {
		HANDLE _handle;
		WIN32_FIND_DATAW _fdata;
		DWORD _errcode; // return `false, err, errcode` on the next iteration
		int  _loaded;   // _fdata is loaded for the next iteration
		int  _dirlen;
		char _dir[?];
	}
]]

function dir.close(dir)
	if dir:closed() then return end
	local ok = C.FindClose(dir._handle) ~= 0
	dir._handle = INVALID_HANDLE_VALUE --ignore failure, prevent double-close
	ffi.gc(dir, nil)
	return check(ok)
end

function dir.closed(dir)
	return dir._handle == INVALID_HANDLE_VALUE
end

function dir_ready(dir)
	return not (dir._loaded == 1 or dir._errcode ~= 0)
end

local ERROR_NO_MORE_FILES = 18

function dir_name(dir)
	return mbs(dir._fdata.cFileName)
end

function dir.dir(dir)
	return ffi.string(dir._dir, dir._dirlen)
end

function dir.next(dir)
	if dir:closed() then
		if dir._errcode ~= 0 then
			local errcode = dir._errcode
			dir._errcode = 0
			return check(false, errcode)
		end
		return nil
	end
	if dir._loaded == 1 then
		dir._loaded = 0
		return dir:name(), dir
	else
		local ret = C.FindNextFileW(dir._handle, dir._fdata)
		if ret ~= 0 then
			return dir:name(), dir
		else
			local errcode = C.GetLastError()
			dir:close()
			if errcode == ERROR_NO_MORE_FILES then
				return nil
			end
			return check(false, errcode)
		end
	end
end

function fs_dir(path)
	assert(not path:find'[%*%?]') --no globbing allowed
	local dir = dir_ct(#path)
	dir._dirlen = #path
	ffi.copy(dir._dir, path, #path)
	dir._handle = C.FindFirstFileW(wcs(path .. '\\*'), dir._fdata)
	if dir._handle == INVALID_HANDLE_VALUE then
		dir._errcode = C.GetLastError()
	else
		dir._loaded = 1
	end
	return dir.next, dir
end

function dir_attr_get(dir, attr)
	if attr == 'type' then
		return filetype(dir._fdata.dwFileAttributes, dir._fdata.dwReserved0)
	elseif attr == 'atime' then
		return ft_timestamp(dir._fdata.ftLastAccessTime)
	elseif attr == 'mtime' then
		return ft_timestamp(dir._fdata.ftLastWriteTime)
	elseif attr == 'btime' then
		return ft_timestamp(dir._fdata.ftCreationTime)
	elseif attr == 'size' then
		return filesize(dir._fdata.nFileSizeHigh, dir._fdata.nFileSizeLow)
	elseif attr == 'dosname' then
		local s = mbs(dir._fdata.cAlternateFileName)
		return s ~= '' and s or nil
	else
		local val = attrbit(dir._fdata.dwFileAttributes, attr)
		if val ~= nil then return val end
		return nil, false --not found
	end
end

--memory mapping -------------------------------------------------------------

ffi.cdef[[
typedef struct {
	WORD wProcessorArchitecture;
	WORD wReserved;
	DWORD dwPageSize;
	LPVOID lpMinimumApplicationAddress;
	LPVOID lpMaximumApplicationAddress;
	LPDWORD dwActiveProcessorMask;
	DWORD dwNumberOfProcessors;
	DWORD dwProcessorType;
	DWORD dwAllocationGranularity;
	WORD wProcessorLevel;
	WORD wProcessorRevision;
} SYSTEM_INFO, *LPSYSTEM_INFO;

VOID GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
]]

local pagesize
function fs.pagesize()
	if not pagesize then
		local sysinfo = ffi.new'SYSTEM_INFO'
		C.GetSystemInfo(sysinfo)
		pagesize = sysinfo.dwAllocationGranularity
	end
	return pagesize
end

ffi.cdef[[
HANDLE CreateFileMappingW(
	HANDLE hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD flProtect,
	DWORD dwMaximumSizeHigh,
	DWORD dwMaximumSizeLow,
	LPCWSTR *lpName
);

HANDLE OpenFileMappingW(
  DWORD   dwDesiredAccess,
  BOOL    bInheritHandle,
  LPCWSTR lpName
);

void* MapViewOfFileEx(
	HANDLE hFileMappingObject,
	DWORD dwDesiredAccess,
	DWORD dwFileOffsetHigh,
	DWORD dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap,
	LPVOID lpBaseAddress
);

BOOL UnmapViewOfFile(LPCVOID lpBaseAddress);

BOOL FlushViewOfFile(
	LPCVOID lpBaseAddress,
	SIZE_T dwNumberOfBytesToFlush
);

BOOL VirtualProtect(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect);
]]

local A = {
	page_noaccess                = 0x0001,
	page_readonly                = 0x0002,
	page_readwrite               = 0x0004,
	page_writecopy               = 0x0008, --no file auto-grow with this!
	page_execute                 = 0x0010,
	page_execute_read            = 0x0020, --xp sp2+
	page_execute_readwrite       = 0x0040, --xp sp2+
	page_execute_writecopy       = 0x0080, --vista sp1+
	page_guard                   = 0x0100,
	page_nocache                 = 0x0200,
	page_writecombine            = 0x0400,
	section_query                = 0x0001,
	section_map_write            = 0x0002,
	section_map_read             = 0x0004,
	section_map_execute          = 0x0008,
	section_extend_size          = 0x0010,
	section_map_execute_explicit = 0x0020, --xp sp2+
	file_map_write               = 0x0002, --section_map_write
	file_map_read                = 0x0004, --section_map_read
	file_map_copy                = 0x00000001,
	file_map_reserve             = 0x80000000,
	file_map_execute             = 0x0020, --execute_explicit, xp sp2+
}

local function protect_bits(access_write, access_exec, access_copy)
	return bit.bor(
		access_exec
			and (access_write
				and A.page_execute_readwrite
				or A.page_execute_read)
			or (access_write
				and A.page_readwrite
				or A.page_readonly))
end

function fs_map(file, write, exec, copy, size, offset, addr, tagname)

	if type(file) == 'string' then
		local open_opt = {
			access = 'read execute ' ..
				(write and 'write' or ''),
			sharing = 'read write delete',
			creation = write and 'open_always' or 'open_existing',
		}
		local f, err, errno = fs.open(file, open_opt)
		if not f then return nil, err, errno end
	else
		assert(fs.isfile(file), 'invalid file argument')
	end

	local protect = protect_bits(write, exec)
	local mhi, mlo = split_uint64(size or 0) --0 means whole file
	local tagname = tagname and wcs('Local\\'..tagname)
	local filemap
	if false then
		--TODO: test shared memory (see if OpenFileMappingW is needed)
		--filemap = C.OpenFileMappingW(tagname)
	else
		filemap = C.CreateFileMappingW(
			file and file.handle or INVALID_HANDLE_VALUE,
			nil, protect, mhi, mlo, tagname)
	end

	if filemap == nil then
		--convert `file_too_short` error into `out_of_mem` error when
		--opening the swap file.
		if not file and err == ERROR_NOT_ENOUGH_MEMORY then
			err = ERROR_COMMITMENT_LIMIT
		end
		return check(err)
	end

	local access = bit.bor(
		not write and not copy and A.file_map_read or 0,
		write and A.file_map_write or 0,
		copy and A.file_map_copy or 0,
		exec and A.section_map_execute or 0)
	local ohi, olo = split_uint64(offset)
	local baseaddr = addr

	local addr = C.MapViewOfFileEx(
		filemap, access, ohi, olo, size or 0, baseaddr)

	if addr == nil then
		local err = C.GetLastError()
		close(filemap)
		closefile()
		return reterr(err)
	end

	local function free()
		C.UnmapViewOfFile(addr)
		close(filemap)
		closefile()
	end

	local function flush(self, async, addr, sz)
		if type(async) ~= 'boolean' then --async arg is optional
			async, addr, sz = false, async, addr
		end
		local addr = mmap.aligned_addr(addr or self.addr, 'left')
		local ok = C.FlushViewOfFile(addr, sz or 0) ~= 0
		if not ok then return reterr() end
		if not async then
			local ok = C.FlushFileBuffers(file) ~= 0
			if not ok then return reterr() end
		end
		return true
	end

	--if size wasn't given, get the file size so that the user always knows
	--the actual size of the mapped memory.
	if not size then
		local filesize, errmsg, errcode = mmap.filesize(file)
		if not filesize then return nil, errmsg, errcode end
		size = filesize - offset
	end

	local function unlink() --no-op
		assert(tagname, 'no tagname given')
	end

	return {addr = addr, size = size, free = free, flush = flush,
		unlink = unlink, protect = protect}

end

function fs.unlink_mapfile(tagname) --no-op
	map_check_tagname(tagname)
end

function fs.protect(addr, size, access)
	local write, exec = map_access_args(access or 'x')
	local protect = protect_bits(write, exec)
	local old = ffi.new'DWORD[1]'
	local ok = C.VirtualProtect(addr, size, prot, old) ~= 0
	if not ok then return reterr() end
	return true
end

elseif linux or osx then -----------------------------------------------------

--POSIX does not define an ABI and platfoms have different cdefs thus we have
--to limit support to the platforms and architectures we actually tested for.
assert(linux or osx, 'platform not Linux or OSX')
assert(x64 or ffi.arch == 'x86', 'arch not x86 or x64')

--types, consts, utils -------------------------------------------------------

cdef[[
typedef size_t ssize_t; // for older luajit
typedef unsigned int mode_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef size_t time_t;
typedef int64_t off64_t;
]]

if linux then
	cdef'long syscall(int number, ...);' --stat, fstat, lstat
elseif osx then
	cdef'int fcntl(int fd, int cmd, ...);' --fallocate
end

check = check_errno

local cbuf = buffer'char[?]'

local function parse_perms(s, base)
	if type(s) == 'string' then
		local unixperms = require'unixperms'
		return unixperms.parse(s, base)
	else --pass-through
		return s or tonumber(666, 8), false
	end
end

--open/close -----------------------------------------------------------------

cdef[[
int open(const char *pathname, int flags, mode_t mode);
int close(int fd);
]]

local o_bits = {
	--Linux & OSX
	rdonly    = osx and 0x000000 or 0x000000, --access: read only
	wronly    = osx and 0x000001 or 0x000001, --access: write only
	rdwr      = osx and 0x000002 or 0x000002, --access: read + write
	accmode   = osx and 0x000003 or 0x000003, --access: ioctl() only
	append    = osx and 0x000008 or 0x000400, --append mode: write() at eof
	trunc     = osx and 0x000400 or 0x000200, --truncate the file on opening
	creat     = osx and 0x000200 or 0x000040, --create if not exist
	excl      = osx and 0x000800 or 0x000080, --create or fail (needs 'creat')
	nofollow  = osx and 0x000100 or 0x020000, --fail if file is a symlink
	directory = osx and 0x100000 or 0x010000, --open if directory or fail
	nonblock  = osx and 0x000004 or 0x000800, --non-blocking (not for files)
	async     = osx and 0x000040 or 0x002000, --enable signal-driven I/O
	sync      = osx and 0x000080 or 0x101000, --enable _file_ sync
	fsync     = osx and 0x000080 or 0x101000, --'sync'
	dsync     = osx and 0x400000 or 0x001000, --enable _data_ sync
	noctty    = osx and 0x020000 or 0x000100, --prevent becoming ctty
	cloexec   = osx and     2^24 or 0x080000, --set close-on-exec
	--Linux only
	direct    = linux and 0x004000, --don't cache writes
	noatime   = linux and 0x040000, --don't update atime
	rsync     = linux and 0x101000, --'sync'
	path      = linux and 0x200000, --open only for fd-level ops
   tmpfile   = linux and 0x410000, --create anon temp file (Linux 3.11+)
	--OSX only
	shlock    = osx and 0x000010, --get a shared lock
	exlock    = osx and 0x000020, --get an exclusive lock
	evtonly   = osx and 0x008000, --open for events only (allows unmount)
	symlink   = osx and 0x200000, --open the symlink itself
}

local str_opt = {
	r = {flags = 'rdonly'},
	w = {flags = 'creat wronly trunc'},
	['r+'] = {flags = 'rdwr'},
	['w+'] = {flags = 'creat rdwr'},
}

--expose this because the frontend will set its metatype on it at the end.
cdef[[
struct file_t {
	int fd;
};
]]
file_ct = ffi.typeof'struct file_t'

function fs.open(path, opt)
	opt = opt or 'r'
	if type(opt) == 'string' then
		opt = assert(str_opt[opt], 'invalid mode %s', opt)
	end
	local flags = flags(opt.flags or 'rdonly', o_bits)
	local mode = parse_perms(opt.perms)
	local fd = C.open(path, flags, mode)
	if fd == -1 then return check() end
	return ffi.gc(file_ct(fd), file.close)
end

function file.closed(f)
	return f.fd == -1
end

function file.close(f)
	if f:closed() then return end
	local ok = C.close(f.fd) == 0
	f.fd = -1 --ignore failure
	ffi.gc(f, nil)
	return check(ok)
end

function fs.wrap_fd(fd)
	return file_ct(fd)
end

cdef[[
int fileno(struct FILE *stream);
]]

function fs.fileno(file)
	local fd = C.fileno(file)
	return check(fd ~= -1 and fd or nil)
end

function fs.wrap_file(file)
	local fd = C.fileno(file)
	if fd == -1 then return check() end
	return fs.wrap_fd(fd)
end

--pipes ----------------------------------------------------------------------

cdef[[
int pipe(int[2]);
int fcntl(int fd, int cmd, ...);
int mkfifo(const char *pathname, mode_t mode);
]]

function fs.pipe(path, mode)
	if type(path) == 'table' then
		path, mode = path.path, path
	end
	mode = parse_perms(mode)
	if path then
		return check(C.mkfifo(path, mode) ~= 0)
	else --unnamed pipe
		local fds = ffi.new'int[2]'
		if C.pipe(fds) ~= 0 then
			return check()
		end
		return
			ffi.gc(fs.wrap_fd(fds[0]), file.close),
			ffi.gc(fs.wrap_fd(fds[1]), file.close)
	end
end

--stdio streams --------------------------------------------------------------

cdef'FILE *fdopen(int fd, const char *mode);'

function file.stream(f, mode)
	local fs = C.fdopen(f.fd, mode)
	if fs == nil then return check() end
	ffi.gc(f, nil) --fclose() will close the handle
	ffi.gc(fs, stream.close)
	return fs
end

--i/o ------------------------------------------------------------------------

cdef(string.format([[
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int fsync(int fd);
int64_t lseek(int fd, int64_t offset, int whence) asm("lseek%s");
]], linux and '64' or ''))

function file.read(f, buf, sz)
	local szread = C.read(f.fd, buf, sz)
	if szread == -1 then return check() end
	return tonumber(szread)
end

function file.write(f, buf, sz)
	local szwr = C.write(f.fd, buf, sz)
	if szwr == -1 then return check() end
	return tonumber(szwr)
end

function file.flush(f)
	return check(C.fsync(f.fd) == 0)
end

function file._seek(f, whence, offset)
	local offs = C.lseek(f.fd, offset, whence)
	if offs == -1 then return check() end
	return tonumber(offs)
end

--truncate/getsize/setsize ---------------------------------------------------

cdef[[
int ftruncate(int fd, int64_t length);
]]

--NOTE: ftruncate() creates a sparse file (and so would seeking to size-1
--and writing '\0'), so we need fallocate() to reserve disk space. OTOH,
--fallocate() only works on ext4. On all other filesystems

local fallocate

if osx then

	local F_PREALLOCATE    = 42
	local F_ALLOCATECONTIG = 2
	local F_PEOFPOSMODE    = 3
	local F_ALLOCATEALL    = 4

	local fstore_ct = ffi.typeof[[
		struct {
			uint32_t fst_flags;
			int      fst_posmode;
			off64_t  fst_offset;
			off64_t  fst_length;
			off64_t  fst_bytesalloc;
		}
	]]

	local void = ffi.typeof'void*'
	local store
	function fallocate(fd, size)
		store = store or fstore_ct(F_ALLOCATECONTIG, F_PEOFPOSMODE, 0, 0)
		store.fst_bytesalloc = size
		local ret = C.fcntl(fd, F_PREALLOCATE, ffi.cast(void, store))
		if ret == -1 then --too fragmented, allocate non-contiguous space
			store.fst_flags = F_ALLOCATEALL
			local ret = C.fcntl(fd, F_PREALLOCATE, ffi.cast(void, store))
			if ret == -1 then return check() end
		end
		return true
	end

else

	cdef[[
	int fallocate64(int fd, int mode, off64_t offset, off64_t len);
	int posix_fallocate64(int fd, off64_t offset, off64_t len);
	]]

	function fallocate(fd, size, emulate)
		if emulate then
			return check(C.posix_fallocate64(fd, 0, size) == 0)
		else
			return check(C.fallocate64(fd, 0, 0, size) == 0)
		end
	end

end

local ENOSPC = 28 --no space left on device

function file_setsize(f, size, opt)
	opt = opt or 'fallocate emulate' --emulate Windows behavior
	if opt:find'fallocate' then
		local cursize, err, errno = file_getsize(f)
		if not cursize then return nil, err, errno end
		local ok, err, errno = fallocate(f.fd, size, opt:find'emulate')
		if not ok then
			if errno == ENOSPC then
				--when fallocate() fails because disk is full, a file is still
				--created filling up the entire disk, so shrink back the file
				--to its original size. this is courtesy: we don't check to see
				--if this fails or not, and we return the original error code.
				C.ftruncate(fd, cursize)
			end
			if opt:find'fail' then
				return nil, err, errno
			end
		end
	end
	return check(C.ftruncate(f.fd, size) == 0)
end

function file.truncate(f, opt)
	local size, err, errno = f:seek()
	if not size then return nil, err, errno end
	return file_setsize(f, size, opt)
end

--filesystem operations ------------------------------------------------------

cdef[[
int mkdir(const char *pathname, mode_t mode);
int rmdir(const char *pathname);
int chdir(const char *path);
char *getcwd(char *buf, size_t size);
int unlink(const char *pathname);
int rename(const char *oldpath, const char *newpath);
]]

function mkdir(path, perms)
	return check(C.mkdir(path, perms or 0x1ff) == 0)
end

function rmdir(path)
	return check(C.rmdir(path) == 0)
end

function chdir(path)
	return check(C.chdir(path) == 0)
end

local ERANGE = 34

function getcwd()
	while true do
		local buf, sz = cbuf(256)
		if C.getcwd(buf, sz) == nil then
			if ffi.errno() ~= ERANGE then
				return check()
			else
				buf, sz = cbuf(sz * 2)
			end
		end
		return ffi.string(buf)
	end
end

function rmfile(path)
	return check(C.unlink(path) == 0)
end

function fs.move(oldpath, newpath)
	return check(C.rename(oldpath, newpath) == 0)
end

--hardlinks & symlinks -------------------------------------------------------

cdef[[
int link(const char *oldpath, const char *newpath);
int symlink(const char *oldpath, const char *newpath);
ssize_t readlink(const char *path, char *buf, size_t bufsize);
]]

function fs.mksymlink(link_path, target_path)
	return check(C.symlink(target_path, link_path) == 0)
end

function fs.mkhardlink(link_path, target_path)
	return check(C.link(target_path, link_path) == 0)
end

local EINVAL = 22

function readlink(link_path)
	local buf, sz = cbuf(256)
	::again::
	local len = C.readlink(link_path, buf, sz)
	if len == -1 then
		if ffi.errno() == EINVAL then --make it legit: no symlink, no target
			return nil
		end
		return check()
	end
	if len >= sz then --we don't know if sz was enough
		buf, sz = cbuf(sz * 2)
		goto again
	end
	return ffi.string(buf, len)
end

--common paths ---------------------------------------------------------------

function fs.homedir()
	return os.getenv'HOME'
end

function fs.tmpdir()
	return os.getenv'TMPDIR' or '/tmp'
end

function fs.appdir(appname)
	local dir = fs.homedir()
	return dir and string.format('%s/.%s', dir, appname)
end

if osx then

	cdef'int _NSGetExecutablePath(char* buf, uint32_t* bufsize);'

	function fs.exepath()
		local buf, sz = cbuf(256)
		local out_sz = ffi.new('uint32_t[1]', sz)
		::again::
		if C._NSGetExecutablePath(buf, out_sz) ~= 0 then
			buf, sz = cbuf(out_sz[0])
			goto again
		end
		return (ffi.string(buf, sz):gsub('//', '/'))
	end

else

	function fs.exepath()
		return readlink'/proc/self/exe'
	end

end

--file attributes ------------------------------------------------------------

if linux and x64 then cdef[[
struct stat {
	uint64_t st_dev;
	uint64_t st_ino;
	uint64_t st_nlink;
	uint32_t st_mode;
	uint32_t st_uid;
	uint32_t st_gid;
	uint32_t __pad0;
	uint64_t st_rdev;
	int64_t  st_size;
	int64_t  st_blksize;
	int64_t  st_blocks;
	uint64_t st_atime;
	uint64_t st_atime_nsec;
	uint64_t st_mtime;
	uint64_t st_mtime_nsec;
	uint64_t st_ctime;
	uint64_t st_ctime_nsec;
	int64_t  __unused[3];
};
]]
elseif linux then cdef[[
struct stat { // NOTE: 64bit version
	uint64_t st_dev;
	uint8_t  __pad0[4];
	uint32_t __st_ino;
	uint32_t st_mode;
	uint32_t st_nlink;
	uint32_t st_uid;
	uint32_t st_gid;
	uint64_t st_rdev;
	uint8_t  __pad3[4];
	int64_t  st_size;
	uint32_t st_blksize;
	uint64_t st_blocks;
	uint32_t st_atime;
	uint32_t st_atime_nsec;
	uint32_t st_mtime;
	uint32_t st_mtime_nsec;
	uint32_t st_ctime;
	uint32_t st_ctime_nsec;
	uint64_t st_ino;
};
]] elseif osx then cdef[[
struct stat { // NOTE: 64bit version
	uint32_t st_dev;
	uint16_t st_mode;
	uint16_t st_nlink;
	uint64_t st_ino;
	uint32_t st_uid;
	uint32_t st_gid;
	uint32_t st_rdev;
	// NOTE: these were `struct timespec`
	time_t   st_atime;
	long     st_atime_nsec;
	time_t   st_mtime;
	long     st_mtime_nsec;
	time_t   st_ctime;
	long     st_ctime_nsec;
	time_t   st_btime; // birth-time i.e. creation time
	long     st_btime_nsec;
	int64_t  st_size;
	int64_t  st_blocks;
	int32_t  st_blksize;
	uint32_t st_flags;
	uint32_t st_gen;
	int32_t  st_lspare;
	int64_t  st_qspare[2];
};
int fstat64(int fd, struct stat *buf);
int stat64(const char *path, struct stat *buf);
int lstat64(const char *path, struct stat *buf);
]]
end

local fstat, stat, lstat

local file_types = {
	[0xc000] = 'socket',
	[0xa000] = 'symlink',
	[0x8000] = 'file',
	[0x6000] = 'blockdev',
	[0x2000] = 'chardev',
	[0x4000] = 'dir',
	[0x1000] = 'pipe',
}
local function st_type(mode)
	local type = bit.band(mode, 0xf000)
	return file_types[type]
end

local function st_perms(mode)
	return bit.band(mode, bit.bnot(0xf000))
end

local function st_time(s, ns)
	return tonumber(s) + tonumber(ns) * 1e-9
end

local stat_getters = {
	type    = function(st) return st_type(st.st_mode) end,
	dev     = function(st) return tonumber(st.st_dev) end,
	inode   = function(st) return st.st_ino end, --unfortunately, 64bit inode
	nlink   = function(st) return tonumber(st.st_nlink) end,
	perms   = function(st) return st_perms(st.st_mode) end,
	uid     = function(st) return st.st_uid end,
	gid     = function(st) return st.st_gid end,
	rdev    = function(st) return tonumber(st.st_rdev) end,
	size    = function(st) return tonumber(st.st_size) end,
	blksize = function(st) return tonumber(st.st_blksize) end,
	blocks  = function(st) return tonumber(st.st_blocks) end,
	atime   = function(st) return st_time(st.st_atime, st.st_atime_nsec) end,
	mtime   = function(st) return st_time(st.st_mtime, st.st_mtime_nsec) end,
	ctime   = function(st) return st_time(st.st_ctime, st.st_ctime_nsec) end,
	btime   = osx and
				 function(st) return st_time(st.st_btime, st.st_btime_nsec) end,
}

local stat_ct = ffi.typeof'struct stat'
local st
local function wrap(stat_func)
	return function(arg, attr)
		st = st or stat_ct()
		local ok = stat_func(arg, st) == 0
		if not ok then return check() end
		if attr then
			local get = stat_getters[attr]
			return get and get(st)
		else
			local t = {}
			for k, get in pairs(stat_getters) do
				t[k] = get(st)
			end
			return t
		end
	end
end
if linux then
	local void = ffi.typeof'void*'
	local int = ffi.typeof'int'
	fstat = wrap(function(f, st)
		return C.syscall(x64 and 5 or 197,
			ffi.cast(int, f.fd), ffi.cast(void, st))
	end)
	stat = wrap(function(path, st)
		return C.syscall(x64 and 4 or 195,
			ffi.cast(void, path), ffi.cast(void, st))
	end)
	lstat = wrap(function(path, st)
		return C.syscall(x64 and 6 or 196,
			ffi.cast(void, path), ffi.cast(void, st))
	end)
elseif osx then
	fstat = wrap(function(f, st) return C.fstat64(f.fd, st) end)
	stat = wrap(C.stat64)
	lstat = wrap(C.lstat64)
end

local utimes, futimes, lutimes

if linux then

	cdef[[
	struct timespec {
		time_t tv_sec;
		long   tv_nsec;
	};
	int futimens(int fd, const struct timespec times[2]);
	int utimensat(int dirfd, const char *path, const struct timespec times[2], int flags);
	]]

	local UTIME_OMIT = bit.lshift(1,30)-2

	local function set_timespec(ts, t)
		if ts then
			t.tv_sec = ts
			t.tv_nsec = (ts - math.floor(ts)) * 1e9
		else
			t.tv_sec = 0
			t.tv_nsec = UTIME_OMIT
		end
	end

	local AT_FDCWD = -100

	local ts_ct = ffi.typeof'struct timespec[2]'
	local ts
	function futimes(f, atime, mtime)
		ts = ts or ts_ct()
		set_timespec(atime, ts[0])
		set_timespec(mtime, ts[1])
		return check(C.futimens(f.fd, ts) == 0)
	end

	function utimes(path, atime, mtime)
		ts = ts or ts_ct()
		set_timespec(atime, ts[0])
		set_timespec(mtime, ts[1])
		return check(C.utimensat(AT_FDCWD, path, ts, 0) == 0)
	end

	local AT_SYMLINK_NOFOLLOW = 0x100

	function lutimes(path, atime, mtime)
		ts = ts or ts_ct()
		set_timespec(atime, ts[0])
		set_timespec(mtime, ts[1])
		return check(C.utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW) == 0)
	end

elseif osx then

	cdef[[
	struct timeval {
		time_t  tv_sec;
		int32_t tv_usec; // ignored by futimes()
	};
	int futimes(int fd, const struct timeval times[2]);
	int utimes(const char *path, const struct timeval times[2]);
	int lutimes(const char *path, const struct timeval times[2]);
	]]

	local function set_timeval(ts, t)
		t.tv_sec = ts
		t.tv_usec = (ts - math.floor(ts)) * 1e7 --apparently ignored
	end

	--TODO: find a way to change btime too (probably with CF or Cocoa, which
	--means many more LOC and more BS for setting one more integer).
	local tv_ct = ffi.typeof'struct timeval[2]'
	local tv
	local function wrap(utimes_func, stat_func)
		return function(arg, atime, mtime)
			tv = tv or tv_ct()
			if not atime or not mtime then
				local t, err, errno = stat_func(arg)
				if not t then return nil, err, errno end
				atime = atime or t.atime
				mtime = mtime or t.mtime
			end
			set_timeval(atime, tv[0])
			set_timeval(mtime, tv[1])
			return check(utimes_func(arg, tv) == 0)
		end
	end
	futimes = wrap(function(f, tv) return C.futimes(f.fd, tv) end, fstat)
	utimes = wrap(C.utimes, stat)
	lutimes = wrap(C.lutimes, lstat)

end

cdef[[
int fchmod(int fd,           mode_t mode);
int  chmod(const char *path, mode_t mode);
int lchmod(const char *path, mode_t mode);
]]

local function wrap(chmod_func, stat_func)
	return function(arg, perms)
		local cur_perms
		local _, is_rel = parse_perms(perms)
		if is_rel then
			local cur_perms, err, errno = stat_func(arg, 'perms')
			if not cur_perms then return nil, err, errno end
		end
		local mode = parse_perms(perms, cur_perms)
		return chmod_func(f.fd, mode) == 0
	end
end
local fchmod = wrap(function(f, mode) return C.fchmod(f.fd, mode) end, fstat)
local chmod = wrap(C.chmod, stat)
local lchmod = wrap(C.lchmod, lstat)

cdef[[
int fchown(int fd,           uid_t owner, gid_t group);
int  chown(const char *path, uid_t owner, gid_t group);
int lchown(const char *path, uid_t owner, gid_t group);
]]

local function wrap(chown_func)
	return function(arg, uid, gid)
		return chown_func(arg, uid or -1, gid or -1) == 0
	end
end
local fchown = wrap(function(f, uid, gid) return C.fchown(f.fd, uid, gid) end)
local chown = wrap(C.chown)
local lchown = wrap(C.lchown)

file_attr_get = fstat

function fs_attr_get(path, attr, deref)
	local stat = deref and stat or lstat
	return stat(path, attr)
end

local function wrap(chmod_func, chown_func, utimes_func)
	return function(arg, t)
		local ok, err, errno
		if t.perms then
			ok, err, errno = chmod_func(arg, t.perms)
			if not ok then return nil, err, errno end
		end
		if t.uid or t.gid then
			ok, err, errno = chown_func(arg, t.uid, t.gid)
			if not ok then return nil, err, errno end
		end
		if t.atime or t.mtime then
			ok, err, errno = utimes_func(arg, t.atime, t.mtime)
			if not ok then return nil, err, errno end
		end
		return ok --returns nil without err if no attr was set
	end
end

file_attr_set = wrap(fchmod, fchown, futimes)

fs_attr_set_deref = wrap(chmod, chown, utimes)
fs_attr_set_symlink = wrap(lchmod, lchown, lutimes)

function fs_attr_set(path, t, deref)
	local set = deref and fs_attr_set_deref or fs_attr_set_symlink
	return set(path, t)
end

--directory listing ----------------------------------------------------------

if linux then cdef[[
struct dirent { // NOTE: 64bit version
	uint64_t        d_ino;
	int64_t         d_off;
	unsigned short  d_reclen;
	unsigned char   d_type;
	char            d_name[256];
};
]] elseif osx then cdef[[
struct dirent { // NOTE: 64bit version
	uint64_t d_ino;
	uint64_t d_seekoff;
	uint16_t d_reclen;
	uint16_t d_namlen;
	uint8_t  d_type;
	char     d_name[1024];
};
]] end

cdef(string.format([[
typedef struct DIR DIR;
DIR *opendir(const char *name);
struct dirent *readdir(DIR *dirp) asm("%s");
int closedir(DIR *dirp);
]], linux and 'readdir64' or osx and 'readdir$INODE64'))

dir_ct = ffi.typeof[[
	struct {
		DIR *_dirp;
		struct dirent* _dentry;
		int  _errno;
		int  _dirlen;
		char _dir[?];
	}
]]

function dir.close(dir)
	if dir:closed() then return end
	local ok = C.closedir(dir._dirp) == 0
	dir._dirp = nil --ignore failure, prevent double-close
	ffi.gc(dir, nil)
	return check(ok)
end

function dir_ready(dir)
	return dir._dentry ~= nil
end

function dir.closed(dir)
	return dir._dirp == nil
end

function dir_name(dir)
	return ffi.string(dir._dentry.d_name)
end

function dir.dir(dir)
	return ffi.string(dir._dir, dir._dirlen)
end

function dir.next(dir)
	if dir:closed() then
		if dir._errno ~= 0 then
			local errno = dir._errno
			dir._errno = 0
			return check(false, errno)
		end
		return nil
	end
	ffi.errno(0)
	dir._dentry = C.readdir(dir._dirp)
	if dir._dentry ~= nil then
		return dir:name(), dir
	else
		local errno = ffi.errno()
		dir:close()
		if errno == 0 then
			return nil
		end
		return check(false, errno)
	end
end

function fs_dir(path)
	local dir = dir_ct(#path)
	dir._dirlen = #path
	ffi.copy(dir._dir, path, #path)
	dir._dirp = C.opendir(path)
	if dir._dirp == nil then
		dir._errno = ffi.errno()
	end
	return dir.next, dir
end

--dirent.d_type consts
local DT_UNKNOWN = 0
local DT_FIFO    = 1
local DT_CHR     = 2
local DT_DIR     = 4
local DT_BLK     = 6
local DT_REG     = 8
local DT_LNK     = 10
local DT_SOCK    = 12

local dt_types = {
	dir      = DT_DIR,
	file     = DT_REG,
	symlink  = DT_LNK,
	blockdev = DT_BLK,
	chardev  = DT_CHR,
	pipe     = DT_FIFO,
	socket   = DT_SOCK,
	unknown  = DT_UNKNOWN,
}

local dt_names = {
	[DT_DIR]  = 'dir',
	[DT_REG]  = 'file',
	[DT_LNK]  = 'symlink',
	[DT_BLK]  = 'blockdev',
	[DT_CHR]  = 'chardev',
	[DT_FIFO] = 'pipe',
	[DT_SOCK] = 'socket',
	[DT_UNKNOWN] = 'unknown',
}

function dir_attr_get(dir, attr)
	if attr == 'type' and dir._dentry.d_type == DT_UNKNOWN then
		--some filesystems (eg. VFAT) require this extra call to get the type.
		local type, err, errcode = lstat(dir:path(), 'type')
		if not type then
			return false, nil, err, errcode
		end
		local dt = dt_types[type]
		dir._dentry.d_type = dt --cache it
	end
	if attr == 'type' then
		return dt_names[dir._dentry.d_type]
	elseif attr == 'inode' then
		return dir._dentry.d_ino
	else
		return nil, false
	end
end

--memory mapping -------------------------------------------------------------

if linux then
	cdef'int __getpagesize();'
elseif osx then
	cdef'int getpagesize();'
end
fs.pagesize = linux and C.__getpagesize or C.getpagesize

cdef[[
int shm_open(const char *name, int oflag, mode_t mode);
int shm_unlink(const char *name);
]]

local librt = C
if linux then
	local ok, rt = pcall(ffi.load, 'rt')
	if ok then librt = rt end
end

local function open(path, write, exec, shm)
	local oflags = write and bit.bor(O_RDWR, O_CREAT) or O_RDONLY
	local perms = oct'444' +
		(write and oct'222' or 0) +
		(exec and oct'111' or 0)
	local open = shm and librt.shm_open or C.open
	local fd = open(path, oflags, perms)
	if fd == -1 then return reterr() end
	return fd
end

cdef(string.format([[
void* mmap(void *addr, size_t length, int prot, int flags,
	int fd, off64_t offset) asm("%s");
int munmap(void *addr, size_t length);
int msync(void *addr, size_t length, int flags);
int mprotect(void *addr, size_t len, int prot);
]], osx and 'mmap' or 'mmap64'))

--mmap() access flags
local PROT_READ  = 1
local PROT_WRITE = 2
local PROT_EXEC  = 4

--mmap() flags
local MAP_SHARED  = 1
local MAP_PRIVATE = 2 --copy-on-write
local MAP_FIXED   = 0x0010
local MAP_ANON    = osx and 0x1000 or 0x0020

--msync() flags
local MS_ASYNC      = 1
local MS_INVALIDATE = 2
local MS_SYNC       = osx and 0x0010 or 4

local function protect_bits(write, exec, copy)
	return bit.bor(
		PROT_READ,
		bit.bor(
			(write or copy) and PROT_WRITE or 0,
			exec and PROT_EXEC or 0))
end

function fs_map(file, write, exec, copy, size, offset, addr, tagname)

	local fd, close
	if type(file) == 'string' then
		local errmsg, errcode
		fd, errmsg, errcode = open(file, write, exec)
		if not fd then return nil, errmsg, errcode end
	elseif tagname then
		tagname = '/'..tagname
		local errmsg, errcode
		fd, errmsg, errcode = open(tagname, write, exec, true)
		if not fd then return nil, errmsg, errcode end
	end
	local f = fs.wrap_fd(fd)

	--emulate Windows behavior for missing size and size mismatches.
	if file then
		if not size then --if size not given, assume entire file
			local filesize, errmsg, errcode = f:attr'size'
			if not filesize then
				if close then close() end
				return nil, errmsg, errcode
			end
			--32bit OSX allows mapping on 0-sized files, dunno why
			if filesize == 0 then
				if close then close() end
				return nil, 'file_too_short'
			end
			size = filesize - offset
		elseif write then --if writable file too short, extend it
			local filesize = f:attr'size'
			if filesize < offset + size then
				local ok, err, errcode = f:seek(offset + size)
				if not ok then
					if close then close() end
					return nil, errmsg, errcode
				end
				local ok, errmsg, errcode = f:truncate()
				if not ok then
					if close then close() end
					return nil, errmsg, errcode
				end
			end
		else --if read/only file too short
			local filesize, errmsg, errcode = mmap.filesize(fd)
			if not filesize then
				if close then close() end
				return nil, errmsg, errcode
			end
			if filesize < offset + size then
				return nil, 'file_too_short'
			end
		end
	elseif write then
		--NOTE: lseek() is not defined for shm_open()'ed fds
		local ok = C.ftruncate(fd, size) == 0
		if not ok then return check() end
	end

	--flush the buffers before mapping to see the current view of the file.
	if file then
		local ret = C.fsync(fd)
		if ret == -1 then
			local err = ffi.errno()
			if close then close() end
			return reterr(err)
		end
	end

	local protect = protect_bits(write, exec, copy)

	local flags = bit.bor(
		copy and MAP_PRIVATE or MAP_SHARED,
		fd and 0 or MAP_ANON,
		addr and MAP_FIXED or 0)

	local addr = C.mmap(addr, size, protect, flags, fd or -1, offset)

	local ok = ffi.cast('intptr_t', addr) ~= -1
	if not ok then
		local err = ffi.errno()
		if close then close() end
		return reterr(err)
	end

	local function flush(self, async, addr, sz)
		if type(async) ~= 'boolean' then --async arg is optional
			async, addr, sz = false, async, addr
		end
		local addr = fs.aligned_addr(addr or self.addr, 'left')
		local flags = bit.bor(async and MS_ASYNC or MS_SYNC, MS_INVALIDATE)
		local ok = C.msync(addr, sz or self.size, flags) ~= 0
		if not ok then return reterr() end
		return true
	end

	local function free()
		C.munmap(addr, size)
		if close then close() end
	end

	local function unlink()
		assert(tagname, 'no tagname given')
		librt.shm_unlink(tagname)
	end

	return {addr = addr, size = size, free = free, flush = flush,
		unlink = unlink, protect = protect}
end

function fs.protect(addr, size, access)
	local write, exec = parse_access(access or 'x')
	local protect = protect_bits(write, exec)
	checkz(C.mprotect(addr, size, protect))
end

function fs.unlink_mapfile(tagname)
	librt.shm_unlink('/'..check_tagname(tagname))
end

else
	error'platform not Windows, Linux or OSX'
end

ffi.metatype(file_ct, {__index = file})
ffi.metatype(stream_ct, {__index = stream})
ffi.metatype(dir_ct, {__index = dir, __gc = dir.close})

return fs
