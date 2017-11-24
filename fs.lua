
--portable filesystem API for LuaJIT
--Written by Cosmin Apreutesei. Public Domain.

local ffi = require'ffi'
local bit = require'bit'

local win = ffi.os == 'Windows'
local osx = ffi.os == 'OSX'
local x64 = ffi.arch == 'x64'
local C = ffi.C
local cdef = ffi.cdef

local fs = {C = C}

--common types and consts ----------------------------------------------------

if win then

	if x64 then
		cdef'typedef int64_t ULONG_PTR;'
	else
		cdef'typedef int32_t ULONG_PTR;'
	end

	cdef[[
	typedef void*          HANDLE;
	typedef int16_t        WORD;
	typedef int32_t        DWORD, *PDWORD, *LPDWORD;
	typedef uint32_t       UINT;
	typedef int            BOOL;
	typedef ULONG_PTR      SIZE_T;
	typedef void           VOID, *LPVOID;
	typedef const void*    LPCVOID;
	typedef char*          LPSTR;
	typedef const char*    LPCSTR;
	typedef wchar_t*       LPWSTR;
	typedef const wchar_t* LPCWSTR;
	typedef BOOL           *LPBOOL;

	// for mkdir(); not yet used.
	typedef struct {
		DWORD  nLength;
		LPVOID lpSecurityDescriptor;
		BOOL   bInheritHandle;
	} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
	]]

else

	cdef[[
	enum {
		ERANGE = 34
	};

   typedef unsigned int mode_t;
	typedef size_t time_t;
	]]

end


--ffi utils ------------------------------------------------------------------

local function str(buf, sz)
	return s ~= nil and ffi.string(buf, sz) or nil
end

local cbuf = ffi.typeof'char[?]'

local pathbuf

if not win then
	local MAX_PATH = 4096
	local buf, bufsz
	function pathbuf(sz) --keep an ever-increasing buffer
		if sz == true then --double it
			sz = (bufsz or MAX_PATH) * 2
		else --use it
			sz = sz or bufsz or MAX_PATH
		end
		if not bufsz or sz > bufsz then
			buf, bufsz = cbuf(sz), sz
		end
		return buf, bufsz
	end
end

--error reporting ------------------------------------------------------------

local check

if win then

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

	function check(ret)
		if ret then return ret end
		local errcode = C.GetLastError()
		local bufsize = 256
		local buf = cbuf(bufsize)
		local sz = C.FormatMessageA(
			FORMAT_MESSAGE_FROM_SYSTEM,
			nil, errcode, 0, buf, bufsize, nil
		)
		if sz == 0 then return nil, 'Unknown Error' end
		return nil, str(buf, sz), errcode
	end

else

	cdef[[
	char *strerror(int errnum);
	]]

	function check(ret)
		if ret then return ret end
		local errno = errno or ffi.errno()
		return nil, str(C.strerror(errno)), errno
	end

end

local function assert_check(ret)
	if ret then return ret end
	local _, err = check(false)
	error(err, 2)
end

--utf16/utf8 conversion ------------------------------------------------------

local wcs, mbs, wbuf

if win then

	wbuf = ffi.typeof'wchar_t[?]'

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

	function wcs(s)
		local sz = C.MultiByteToWideChar(CP_UTF8, 0, s, #s + 1, nil, 0)
		local buf = wbuf(sz)
		C.MultiByteToWideChar(CP_UTF8, 0, s, #s + 1, buf, sz)
		return buf
	end

	function mbs(ws)
		local sz = C.WideCharToMultiByte(CP_UTF8, 0, ws, -1, nil, 0, nil, nil)
		if sz == 0 then --conversion error
			local _, err = check(false)
			error(err)
		end
		local buf = cbuf(sz)
		local sz = C.WideCharToMultiByte(CP_UTF8, 0, ws, -1, buf, sz, nil, nil)
		return str(buf, sz-1) --sz includes null terminator
	end

end

--stdio: opening / closing ---------------------------------------------------

cdef[[
typedef struct FILE FILE;
]]

local file = {}

function fs.type(file) --'file'
	return ffi.istype(file, 'FILE*')
end

function file.fileno(file)

end

function file.close(file)

end

function file.handle(file)

end

local function open_filename(filename, ...)

end

local function open_fd(fd, ...)

end

local function open_handle(handle, ...)

end

local function tie(file, ...)
	if not file then return nil, ... end
	ffi.gc(file, file.close)
	return file
end

function fs.open(file, ...)
	if type(file) == 'string' then --filename
		return tie(open_filename(file, ...))
	elseif type(file) == 'number' then --fd
		return tie(open_fd(file, ...))
	elseif ffi.istype(file, 'HANDLE') then
		return tie(open_handle(file, ...))
	end
end

--seeking --------------------------------------------------------------------

cdef[[
int feof(FILE*);
]]

function file.eof(file)
	return C.feof(file) ~= 0
end


--sync i/o -------------------------------------------------------------------

cdef[[
size_t fread  (void*, size_t, size_t, FILE*);
size_t fwrite (const void*, size_t, size_t, FILE*);
]]

function nullread(file, len)
	local cur0, err, errno = file:seek()
	if not cur0 then return nil, err, errno end
	local cur, err, errno = file:seek('cur', len)
	if not cur then return nil, err, errno end
	return cur - cur0
end

function file.read(file, buf, len)
	if len == 0 then return 0 end
	assert(len >= 1, 'invalid size')
	if not buf then
		return nullread(file, len)
	else
		local readlen = tonumber(C.fread(buf, 1, len, file))
		return ret((readlen == len or file:eof()) and readlen)
	end
end

function file.write(file, buf, len)
	len = len or #buf
	if len == 0 then return true end
	assert(len >= 1, 'invalid size')
	local wlen = tonumber(C.fwrite(buf, 1, len, file))
	return ret(wlen == len)
end

--async i/o ------------------------------------------------------------------


--mmap -----------------------------------------------------------------------


--file attributes ------------------------------------------------------------

if win then

	cdef[[

	]]

else

	cdef[[

	]]

end


function fs.drive(file)

end

function fs.dev(file)

end

function fs.inode(file)

end

function fs.mode(file)
	--file, dir, link, socket, pipe, char device, block device, other
end

function fs.linknum(file)

end

function fs.uid(file, newuid)

end

function fs.gid(file, newgid)

end

function fs.devtype(file)

end

function fs.atime(file, newatime)

end

function fs.mtime(file, newmtime)

end

function fs.ctime(file, newctime)

end

local function getsize(file)

end

local function setsize(file, newsize)

end

function fs.size(file, newsize)
	if newsize then
		return setsize(file, newsize)
	else
		return getsize(file)
	end
end

function fs.perms(file, newperms)

end

function fs.blocks(file)

end

function fs.blksize(file)

end

function fs.setmode(file, mode)
	local binary = assert(mode:match'^[bt]', 'invalid mode') == 'b'
	if win then
		--
	else
		return true, 'binary'
	end
end

--atime and mtime ------------------------------------------------------------

if win then

else

	local utimebuf = ffi.typeof[[
	struct {
		time_t actime;
		time_t modtime;
	};
	]]

	cdef[[
	int utime(const char *file, const struct utimebuf *times);
	]]

	function fs.touch(path, atime, mtime)
		local buf
		if atime then --if not given, atime and mtime are set to current time
			mtime = mtime or atime
			buf = utimebuf()
			buf.actime = atime
			buf.modtime = mtime
		end
		return check(C.utime(path, buf) == 0)
	end

end

--mkdir/rmdir ----------------------------------------------------------------

if win then

	cdef[[
	BOOL CreateDirectory(
		LPCWSTR lpPathName,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);
	BOOL RemoveDirectory(LPCWSTR lpPathName);
	]]

	function fs.mkdir(path)
		return check(C.CreateDirectory(wcs(path)) ~= 0)
	end

	function fs.rmdir(path)
		return check(C.RemoveDirectory(wcs(path)) ~= 0)
	end

else

	cdef[[
	int rmdir(const char *pathname);
   int mkdir(const char *pathname, mode_t mode);
	]]

	function fs.mkdir(path, mode)
		return check(C.mkdir(path, mode or 0x1ff) == 0)
	end

	function fs.rmdir(path)
		return check(C.rmdir(path) == 0)
	end

end

--directory listing ----------------------------------------------------------

if win then

	function fs.dir(path)
		--
	end

else

	local dirent_def
	if osx then
		dirent_def = [[
			/* _DARWIN_FEATURE_64_BIT_INODE is NOT defined here? */
			struct dirent {
				uint32_t d_ino;
				uint16_t d_reclen;
				uint8_t  d_type;
				uint8_t  d_namlen;
				char     d_name[256];
			};
		]]
	else
		dirent_def = cdef[[
			struct dirent {
				int64_t  d_ino;
				size_t   d_off;
				uint16_t d_reclen;
				uint8_t  d_type;
				char     d_name[256];
			};
		]]
	end

	cdef[[
	typedef struct  __dirstream DIR;
	DIR *opendir(const char *name);
	struct dirent *readdir(DIR *dirp);
	int closedir(DIR *dirp);
	]]

	local dir = {}

	function dir.close(dir)
		if dir._dentry == nil then return end
		C.closedir(dir._dentry)
		dir._dentry = nil
	end

	function dir.next(dir)
		assert(dir._dentry ~= nil, 'directory closed')
		local entry = C.readdir(dir._dentry)
		if entry ~= nil then
			return str(entry.d_name)
		else
			dir:close()
			return nil
		end
	end

	local dir_obj = ffi.metatype([[
		struct {
			DIR *_dentry;
		}
		]], {__index = dir, __gc = dir.close})

	function fs.dir(path)
		local dentry = C.opendir(path)
		assert_check(dentry ~= nil)
		local dir_obj = dir_obj()
		dir_obj._dentry = dentry
		return dir.next, dir_obj
	end

end

--current directory ----------------------------------------------------------

local chdir, getdir

if win then

	cdef[[
	int SetCurrentDirectoryW(LPCWSTR lpPathName);
	DWORD GetCurrentDirectoryW(
		DWORD  nBufferLength,
		LPWSTR lpBuffer
	);
	]]

	function chdir(path)
		return check(C.SetCurrentDirectoryW(wcs(path)) ~= 0)
	end

	function getcwd()
		local sz = C.GetCurrentDirectoryW(0, nil)
		if sz == 0 then return check(false) end
		local buf = wbuf(sz)
		local sz = C.GetCurrentDirectoryW(buf, sz)
		if sz == 0 then return check(false) end
		return mbs(buf, sz)
	end

else

	cdef[[
	int chdir(const char *path);
	char *getcwd(char *buf, size_t size);
	]]

	function chdir(path)
		return check(C.chdir(path) == 0)
	end

	function getcwd()
		while true do
			local buf, sz = pathbuf()
			if getcwd(buf, sz) == nil then
				if ffi.errno() ~= C.ERANGE then
					return check(false)
				else
					buf, sz = pathbuf(true)
				end
			end
			return str(buf, sz)
		end
	end

end

function fs.pwd(path)
	if path then
		return chdir(path)
	else
		return getcwd()
	end
end

--file locking ---------------------------------------------------------------

function fs.lock(fd)

end

function fs.unlock(fd)

end

--hardlinks & symlinks -------------------------------------------------------

local get_link_target, set_symlink_target
local set_link_target, set_symlink_target

if win then


else

	cdef[[
	int link(const char *oldpath, const char *newpath);
	int symlink(const char *oldpath, const char *newpath);
	]]

	function set_symlink_target(file, target)
		return check(C.symlink(file, target) == 0)
	end

	function set_link_target(file, target)
		return check(C.link(file, target) == 0)
	end

	function get_link_target(file)

	end

	function get_symlink_target(file)

	end

end

function fs.symlink(file, target)
	if not target then
		return get_symlink_target(file)
	else
		return set_symlink_target(file, target)
	end
end

function fs.link(file, target)
	if not target then
		return get_link_target(file)
	else
		return set_link_target(file, target)
	end
end

--path manipulation ----------------------------------------------------------

--make path canonical:
-- remove dots
-- follow symlinks relative to pwd
function fs.path(path, pwd)

end

function fs.abspath(path, pwd)
	pwd = pwd or fs.pwd()
end

function fs.relpath(path, pwd)
	pwd = pwd or fs.pwd()

end

function fs.realpath(path)

end

--filesystem common paths ----------------------------------------------------

function fs.homedir()

end

function fs.tmpdir()

end

function fs.exedir()

end

return fs
