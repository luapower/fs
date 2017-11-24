---
tagline: portable filesystem API
---

## `local fs = require'fs'`

Filesystem API for Windows, Linux and OSX. Features:

  * utf8 filenames
  * cdata buffer-based I/O
  * memory mapping
  * uniform error reporting

## API

-------------------------------------------- -----------------------------------------------
__file objects__
`fs.open(path, mode) -> f`
`fs.type(f) -> 'file'`
`f:fileno() -> fd`
`f:handle() -> HANDLE`
`f:close()`
`f:settextmode('b'|'t')`
__streams__
`f:read(...) -> readlen`
`f:write(...)`
`f:seek([whence] [, offset]) -> pos`
`f:size([newsize]) -> size`
`f:eof() -> true|false`
`f:flush()`
`f:lines() -> iter() -> s`
`f:setvbuf(mode[, size])`
__file attributes__
`fs.type(path) -> type`
`fs.drive(path) -> drive_letter`
`fs.dev(path) -> device_path`
`fs.inode(path) -> inode`
`fs.linknum(path) -> n`
`fs.uid(path[, newuid]) -> uid`
`fs.gid(path[, newgid]) -> gid`
`fs.devtype(path) -> ?`
`fs.atime(path[, newatime]) -> atime`
`fs.mtime(path[, newmtime]) -> mtime`
`fs.ctime(path[, newctime]) -> ctime`
`fs.size(path[, newsize]) -> size`
`fs.perms(path[, newperms]) -> perms`
`fs.blocks(path) -> n`
`fs.blksize(path) -> size`
`fs.touch(path[, atime[, mtime]])`
__directories__
`fs.dir() -> dir, next
`dir:next() -> name|nil`
`dir:close()`
`dir:closed() -> true|false`
`fs.pwd([newpwd]) -> path`
__locking__
`fs.lock(path)`
`fs.unlock(path)`
__symlinks & hardlinks__
`fs.hardlink(target, path)`
`fs.symlink(target, path)`
`fs.link(target, patn[, symbolic])`
__paths__
`fs.abspath(path) -> path`
`fs.relpath(path) -> path`
`fs.realpath(path) -> path`
`fs.readlink(path) -> path`
__common paths__
`fs.homedir() -> path`
`fs.tmpdir() -> path`
`fs.exedir() -> path`
-------------------------------------------- -----------------------------------------------
