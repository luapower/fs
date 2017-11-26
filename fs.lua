
--portable filesystem API for LuaJIT
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'fs_test'; return end

local ffi = require'ffi'

local backend = require'fs_backend'
local backends = {
	Windows = 'fs_win',
	OSX     = 'fs_posix',
	Linux   = 'fs_posix',
}
require(assert(backends[ffi.os], 'unsupported platform'))

local fs = backend.fs
local file = backend.file

--TODO: add buffered I/O here or do it in a separate module?
file.read = backend.read
file.write = backend.write

local whences = {set = 0, cur = 1, ['end'] = 2}
function file.seek(f, whence, offset)
	if tonumber(whence) and not offset then
		whence, offset = 'cur', tonumber(whence)
	end
	whence = assert(whences[whence or 'cur'], 'invalid whence %s', whence)
	return backend.seek(f, whence, offset or 0)
end

--TODO: implement recursive mkdir/rmdir
fs.mkdir = backend.mkdir
fs.rmdir = backend.rmdir

function fs.pwd(path)
	if path then
		return backend.chdir(path)
	else
		return backend.getcwd()
	end
end

function fs.drive(path)

end

function fs.dev(path)

end

function fs.inode(path)

end

function fs.type(path)
	--file, dir, link, socket, pipe, char device, block device, other
end

function fs.linknum(path)

end

function fs.uid(path, newuid)

end

function fs.gid(path, newgid)

end

function fs.devtype(path)

end

function fs.atime(path, newatime)

end

function fs.mtime(path, newmtime)

end

function fs.ctime(path, newctime)

end

local function getsize(path)

end

local function setsize(path, newsize)

end

function fs.grow(path, newsize)

end

function fs.shrink(path, newsize)

end

function fs.size(path, newsize)
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

function fs.perms(path, newperms)
	if newperms then
		newperms = perms_arg(newperms, fs.perms(path))
		--
	else
		--
	end
end

function fs.blocks(path)

end

function fs.blksize(path)

end

function fs.symlink(link_path, target_path)
	if not target then
		return backend.get_symlink_target(link_path)
	else
		return backend.set_symlink_target(link_path, target_path)
	end
end

function fs.hardlink(link_path, target_path)
	if not target then
		return backend.get_link_target(link_path)
	else
		return backend.set_link_target(link_path, target_path)
	end
end

function fs.link(link_path, target_path, symlink)
	local f = symlink and fs.symlink or fs.hardlink
	return f(link_path, target_path)
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
	-- we should check if the path exists on windows
end

function fs.readlink(path)

end

--filesystem common paths ----------------------------------------------------

function fs.homedir()

end

function fs.tmpdir()

end

function fs.exedir()

end

--metatypes ------------------------------------------------------------------

ffi.metatype(backend.file_ct, {__index = file})

return fs
