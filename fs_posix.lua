
--portable filesystem API for LuaJIT / POSIX API
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'fs_test'; return end

local ffi = require'ffi'
local bit = require'bit'
setfenv(1, require'fs_backend')

local C   = ffi.C
local x64  = ffi.arch == 'x64'
local cdef = ffi.cdef
local osx   = ffi.os == 'OSX'
local linux = ffi.os == 'Linux'

assert(linux or osx, 'platform not Linux or OSX')

--ffi tools ------------------------------------------------------------------

check = check_errno
assert_check = assert_check_errno

local cbuf = mkbuf'char'

--common types and consts ----------------------------------------------------

cdef[[
typedef unsigned int mode_t;
typedef size_t time_t;
]]

--open/close/remove ----------------------------------------------------------

fs.remove = os.remove

--mkdir/rmdir ----------------------------------------------------------------

cdef[[
int rmdir(const char *pathname);
int mkdir(const char *pathname, mode_t mode);
]]

function mkdir(path, perms)
	return check(C.mkdir(path, perms or 0x1ff) == 0)
end

function rmdir(path)
	return check(C.rmdir(path) == 0)
end

--directory listing ----------------------------------------------------------

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
	if dir:closed() then return end
	local ret = C.closedir(dir._dentry)
	dir._dentry = nil
	return check(ret == 0)
end

function dir.closed(dir)
	return dir._dentry == nil
end

function dir.next(dir)
	assert(not dir:closed(), 'directory closed')
	local entry = C.readdir(dir._dentry)
	if entry ~= nil then
		--TODO: also read file type to distinguish dirs from files
		return str(entry.d_name)
	else
		local errno = ffi.errno()
		dir:close()
		return check(false, errno)
	end
end

local dir_obj = ffi.metatype([[
	struct {
		DIR *_dentry;
	}
	]], {__index = dir, __gc = dir.close})

function fs.dir(path)
	path = path or fs.pwd()
	local dentry = C.opendir(path)
	assert_check(dentry ~= nil)
	local dir = dir_obj()
	dir._dentry = dentry
	return dir.next, dir
end

--current directory ----------------------------------------------------------

cdef[[
int chdir(const char *path);
char *getcwd(char *buf, size_t size);
]]

function chdir(path)
	return check(C.chdir(path) == 0)
end

local ERANGE = 34

function getcwd()
	while true do
		local buf, sz = cbuf()
		if getcwd(buf, sz) == nil then
			if ffi.errno() ~= ERANGE then
				return check()
			else
				buf, sz = cbuf(sz * 2)
			end
		end
		return str(buf, sz)
	end
end

--file attributes ------------------------------------------------------------

function drive(path)

end

function dev(path)

end

function inode(path)

end

function filetype(path)
	--file, dir, link, socket, pipe, char device, block device, other
end

function linknum(path)

end

function uid(path, newuid)

end

function gid(path, newgid)

end

function devtype(path)

end

function atime(path, newatime)

end

function mtime(path, newmtime)

end

function ctime(path, newctime)

end

local function getsize(path)

end

local function setsize(path, newsize)

end

function grow(path, newsize)

end

function shrink(path, newsize)

end

function size(path, newsize)
	if newsize then
		return setsize(path, newsize)
	else
		return getsize(path)
	end
end

local function perms_arg(perms, old_perms)
	if type(perms) == 'string' then
		if perms:find'^[0-7]+$' then
			perms = tonumber(perms, 8)
		else
			assert(not perms:find'[^%+%-ugorwx]', 'invalid permissions')
			--TODO: parse perms
		end
	else
		return perms
	end
end

function perms(path, newperms)
	if newperms then
		newperms = perms_arg(newperms, perms(path))
		--
	else
		--
	end
end

function blocks(path)

end

function blksize(path)

end

--atime and mtime ------------------------------------------------------------

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


--hardlinks & symlinks -------------------------------------------------------

cdef[[
int link(const char *oldpath, const char *newpath);
int symlink(const char *oldpath, const char *newpath);
]]

function set_symlink_target(link_path, target_path)
	return check(C.symlink(target_path, link_path) == 0)
end

function set_link_target(link_path, target_path)
	return check(C.link(target_path, link_path) == 0)
end

function get_link_target(link_path)

end

function get_symlink_target(link_path)

end

--file replacing -------------------------------------------------------------

replace = os.rename

--text/binary mode -----------------------------------------------------------

function set_textmode(f, mode)
	return true, 'binary'
end

function textmode(f, mode)
	local mode = assert(mode:match'^[bt]', 'invalid mode')
	return settextmode(f, mode)
end
file.textmode = texmode
