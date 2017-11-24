local ffi = require'ffi'
local fs = require'fs'
local posix = ffi.os ~= 'Windows'

local eq = assert.are.same
local is_nil = assert.is_nil
local is_not_nil = assert.is_not_nil
local is_true = assert.is_true
local has_error = assert.has_error

local attr_names = {
	'access',
	'change',
	'dev',
	'gid',
	'ino',
	'mode',
	'modification',
	'nlink',
	'permissions',
	'rdev',
	'size',
	'uid'
}
if posix then
	local extra_attrs = {'blksize', 'blocks'}
	for i = 1, #extra_attrs do
		table.insert(attr_names, extra_attrs[i])
	end
end

describe('lfs', function()
	describe('#attributes', function()

		it('with attribute name', function()
			for i = 1, #attr_names do
				local attr = attr_names[i]
				local info = fs.attributes('.', attr)
				eq(fs.attributes('.', attr), info,
				   attr..' is not equal')
			end
		end)

		it('with attributes table', function()
			local tab = {"table", "for", "attributes"}
			local info = fs.attributes('.', tab)
			eq(fs.attributes('.', tab), info)
		end)

		it('with nonexisted file', function()
			local info, err = fs.attributes('nonexisted')
			is_nil(info)
			eq('No such file or directory', err)
		end)

		it('with nonexisted attribute', function()
			has_error(function() fs.attributes('.', 'nonexisted') end,
				"invalid attribute name 'nonexisted'")
			if not posix then
				has_error(function() fs.attributes('.', 'blocks') end,
					"invalid attribute name 'blocks'")
			end
		end)
	end)

	describe('#symlinkattributes', function()
		local symlink = 'lfs_ffi.lua.link'

		it('link failed', function()
			if posix then
				local res, err = fs.link('xxx', symlink)
				is_nil(res)
				eq(err, 'No such file or directory')
			end
		end)

		it('hard link', function()
			local _, err = fs.link('lfs_ffi.lua', symlink)
			is_nil(err)
			eq(fs.attributes(symlink, 'mode'), 'file')
			eq(fs.symlinkattributes(symlink, 'mode'), 'file')
		end)

		it('soft link', function()
			if posix then
				local _, err = fs.link('lfs_ffi.lua', symlink, true)
				is_nil(err)
				eq(fs.attributes(symlink, 'mode'), 'file')
				eq(fs.symlinkattributes(symlink, 'mode'), 'link')
			end
		end)

		it('without argument', function()
			fs.link('lfs_ffi.lua', symlink, true)
			local info = fs.symlinkattributes(symlink)
			local expected_info = fs.symlinkattributes(symlink)
			for k, v in pairs(expected_info) do
				eq(v, info[k], k..'is not equal')
			end
		end)

		it('with attribute name', function()
			fs.link('lfs_ffi.lua', symlink, true)
			for i = 1, #attr_names do
				local attr = attr_names[i]
				local info = fs.symlinkattributes(symlink, attr)
				eq(fs.symlinkattributes(symlink, attr), info,
				   attr..' is not equal')
			end
		end)

		it('add target field', function()
			if posix then
				fs.link('lfs_ffi.lua', symlink, true)
				eq('lfs_ffi.lua', fs.symlinkattributes(symlink, 'target'))
				eq('lfs_ffi.lua', fs.symlinkattributes(symlink).target)
			end
		end)

		after_each(function()
			os.remove(symlink)
		end)
	end)

	describe('#setmode', function()
		local fh
		before_each(function()
			fh = io.open('lfs_ffi.lua')
		end)

		it('setmode', function()
			local ok, mode = fs.setmode(fh, 'binary')
			is_true(ok)
			if posix then
				-- On posix platform, always return 'binary'
				eq('binary', mode)
			else
				eq( 'text', mode)
				local _
				_, mode = fs.setmode(fh, 'text')
				eq('binary', mode)
			end
		end)

		if not posix then
			it('setmode incorrect mode', function()
				has_error(function() fs.setmode(fh, 'bin') end, 'setmode: invalid mode')
			end)

			it('setmode incorrect file', function()
				has_error(function() fs.setmode('file', 'binary') end, 'setmode: invalid file')
			end)
		end
	end)

	describe('#dir', function()
		it('mkdir', function()
			fs.mkdir('test')
		end)

		it('return err if mkdir failed', function()
			local res, err = fs.mkdir('test')
			is_nil(res)
			eq('File exists', err)
		end)

		it('raise error if open dir failed', function()
			if posix then
				has_error(function() fs.dir('nonexisted') end,
					"cannot open nonexisted : No such file or directory")
			else
				-- Like vanilla lfs, we only check path's length in Windows
				local ok, msg = pcall(function() fs.dir(('12345'):rep(64)) end)
				is_true(not ok)
				is_not_nil(msg:find('path too long'))
			end
		end)

		if posix or os.getenv('CI') ~= 'True' then
			it('iterate dir', function()
				local _, dir_obj = fs.dir('test')
				local names = {}
				while true do
					local name = dir_obj:next()
					if not name then break end
					names[#names + 1] = name
				end
				table.sort(names)
				eq({'.', '..'}, names)
				is_true(dir_obj.closed)
			end)

			it('iterate dir via iterator', function()
				local iter, dir_obj = fs.dir('test')
				local names = {}
				while true do
					local name = iter(dir_obj)
					if not name then break end
					names[#names + 1] = name
				end
				table.sort(names)
				eq({'.', '..'}, names)
				is_true(dir_obj.closed)
			end)
		end

		it('close', function()
			local _, dir_obj = fs.dir('.')
			dir_obj:close()
			has_error(function() dir_obj:next() end, "closed directory")
		end)

		it('chdir and currentdir', function()
			fs.chdir('test')
			local cur_dir = fs.currentdir()
			fs.chdir('..')
			assert.is_not_nil(cur_dir:find('test$'))
		end)

		it('return err if chdir failed', function()
			local res, err = fs.chdir('nonexisted')
			is_nil(res)
			eq('No such file or directory', err)
		end)

		it('rmdir', function()
			fs.rmdir('test')
		end)

		it('return err if rmdir failed', function()
			local res, err = fs.rmdir('test')
			is_nil(res)
			eq('No such file or directory', err)
		end)
	end)

	describe('#touch', function()
		local touched = 'temp'

		before_each(function()
			local f = io.open(touched, 'w')
			f:write('a')
			f:close()
		end)

		after_each(function()
			os.remove(touched)
		end)

		it('touch failed', function()
			local _, err = fs.touch('nonexisted', 1)
			eq('No such file or directory', err)
		end)

		it('set atime', function()
			local _, err = fs.touch(touched, 1)
			is_nil(err)
			eq(fs.attributes(touched, 'access'), 1)
		end)

		it('set both atime and mtime', function()
			local _, err = fs.touch(touched, 1, 2)
			is_nil(err)
			eq(fs.attributes(touched, 'access'), 1)
			eq(fs.attributes(touched, 'modification'), 2)
		end)
	end)

	-- Just smoke testing
	describe('#lock', function()
		local fh
		setup(function()
			fh = io.open('temp.txt', 'w')
			fh:write('1234567890')
			fh:close()
		end)

		before_each(function()
			fh = io.open('temp.txt', 'r+')
		end)

		it('lock', function()
			local _, err = fs.lock(fh, 'r', 2, 8)
			is_nil(err)
		end)

		it('lock exclusively', function()
			if posix then
				local _, err = fs.lock(fh, 'w')
				is_nil(err)
			end
		end)

		it('lock: invalid mode', function()
			has_error(function() fs.lock('temp.txt', 'u') end, 'lock: invalid mode')
		end)

		it('lock: invalid file', function()
			has_error(function() fs.lock('temp.txt', 'w') end, 'lock: invalid file')
		end)

		it('unlock', function()
			local _, err = fs.lock(fh, 'w', 4, 9)
			is_nil(err)
			if posix then
				_, err = fs.unlock(fh, 3, 11)
				is_nil(err)
			else
				_, err = fs.unlock(fh, 3, 11)
				eq('Permission denied', err)
				_, err = fs.unlock(fh, 4, 9)
				is_nil(err)
			end
		end)

		it('unlock: invalid file', function()
			has_error(function() fs.unlock('temp.txt') end, 'unlock: invalid file')
		end)

		after_each(function()
			fh:close()
		end)

		teardown(function()
			os.remove('temp.txt')
		end)
	end)

	describe('#lock_dir', function()
		it('lock_dir', function()
			if true then
				local _, err = fs.lock_dir('.')
				is_nil(err)
				_, err = fs.lock_dir('.')
				assert.is_not_nil(err)
			end
			-- The old lock should be free during gc
			collectgarbage()

			local lock = fs.lock_dir('.')
			lock:free()
			local _, err = fs.lock_dir('.')
			is_nil(err)
		end)
	end)
end)


--[[
#!/usr/bin/env lua5.1

local tmp = "/tmp"
local sep = string.match (package.config, "[^\n]+")
local upper = ".."

local lfs = require"lfs"
print (lfs._VERSION)

io.write(".")
io.flush()

function attrdir (path)
        for file in lfs.dir(path) do
                if file ~= "." and file ~= ".." then
                        local f = path..sep..file
                        print ("\t=> "..f.." <=")
                        local attr = lfs.attributes (f)
                        assert (type(attr) == "table")
                        if attr.mode == "directory" then
                                attrdir (f)
                        else
                                for name, value in pairs(attr) do
                                        print (name, value)
                                end
                        end
                end
        end
end

-- Checking changing directories
local current = assert (lfs.currentdir())
local reldir = string.gsub (current, "^.*%"..sep.."([^"..sep.."])$", "%1")
assert (lfs.chdir (upper), "could not change to upper directory")
assert (lfs.chdir (reldir), "could not change back to current directory")
assert (lfs.currentdir() == current, "error trying to change directories")
assert (lfs.chdir ("this couldn't be an actual directory") == nil, "could change to a non-existent directory")

io.write(".")
io.flush()

-- Changing creating and removing directories
local tmpdir = current..sep.."lfs_tmp_dir"
local tmpfile = tmpdir..sep.."tmp_file"
-- Test for existence of a previous lfs_tmp_dir
-- that may have resulted from an interrupted test execution and remove it
if lfs.chdir (tmpdir) then
    assert (lfs.chdir (upper), "could not change to upper directory")
    assert (os.remove (tmpfile), "could not remove file from previous test")
    assert (lfs.rmdir (tmpdir), "could not remove directory from previous test")
end

io.write(".")
io.flush()

-- tries to create a directory
assert (lfs.mkdir (tmpdir), "could not make a new directory")
local attrib, errmsg = lfs.attributes (tmpdir)
if not attrib then
        error ("could not get attributes of file `"..tmpdir.."':\n"..errmsg)
end
local f = io.open(tmpfile, "w")
f:close()

io.write(".")
io.flush()

-- Change access time
local testdate = os.time({ year = 2007, day = 10, month = 2, hour=0})
assert (lfs.touch (tmpfile, testdate))
local new_att = assert (lfs.attributes (tmpfile))
assert (new_att.access == testdate, "could not set access time")
assert (new_att.modification == testdate, "could not set modification time")

io.write(".")
io.flush()

-- Change access and modification time
local testdate1 = os.time({ year = 2007, day = 10, month = 2, hour=0})
local testdate2 = os.time({ year = 2007, day = 11, month = 2, hour=0})

assert (lfs.touch (tmpfile, testdate2, testdate1))
local new_att = assert (lfs.attributes (tmpfile))
assert (new_att.access == testdate2, "could not set access time")
assert (new_att.modification == testdate1, "could not set modification time")

io.write(".")
io.flush()

-- Checking link (does not work on Windows)
if lfs.link (tmpfile, "_a_link_for_test_", true) then
  assert (lfs.attributes"_a_link_for_test_".mode == "file")
  assert (lfs.symlinkattributes"_a_link_for_test_".mode == "link")
  assert (lfs.symlinkattributes"_a_link_for_test_".target == tmpfile)
  assert (lfs.symlinkattributes("_a_link_for_test_", "target") == tmpfile)
  assert (lfs.link (tmpfile, "_a_hard_link_for_test_"))
  assert (lfs.attributes (tmpfile, "nlink") == 2)
  assert (os.remove"_a_link_for_test_")
  assert (os.remove"_a_hard_link_for_test_")
end

io.write(".")
io.flush()

-- Checking text/binary modes (only has an effect in Windows)
local f = io.open(tmpfile, "w")
local result, mode = lfs.setmode(f, "binary")
assert(result) -- on non-Windows platforms, mode is always returned as "binary"
result, mode = lfs.setmode(f, "text")
assert(result and mode == "binary")
f:close()
local ok, err = pcall(lfs.setmode, f, "binary")
assert(not ok, "could setmode on closed file")
assert(err:find("closed file"), "bad error message for setmode on closed file")

io.write(".")
io.flush()

-- Restore access time to current value
assert (lfs.touch (tmpfile, attrib.access, attrib.modification))
new_att = assert (lfs.attributes (tmpfile))
assert (new_att.access == attrib.access)
assert (new_att.modification == attrib.modification)

io.write(".")
io.flush()

-- Check consistency of lfs.attributes values
local attr = lfs.attributes (tmpfile)
for key, value in pairs(attr) do
  assert (value == lfs.attributes (tmpfile, key),
          "lfs.attributes values not consistent")
end

-- Check that lfs.attributes accepts a table as second argument
local attr2 = {}
lfs.attributes(tmpfile, attr2)
for key, value in pairs(attr2) do
  assert (value == lfs.attributes (tmpfile, key),
          "lfs.attributes values with table argument not consistent")
end

-- Check that extra arguments are ignored
lfs.attributes(tmpfile, attr2, nil)

-- Remove new file and directory
assert (os.remove (tmpfile), "could not remove new file")
assert (lfs.rmdir (tmpdir), "could not remove new directory")
assert (lfs.mkdir (tmpdir..sep.."lfs_tmp_dir") == nil, "could create a directory inside a non-existent one")

io.write(".")
io.flush()

-- Trying to get attributes of a non-existent file
local attr_ok, err, errno = lfs.attributes("this couldn't be an actual file")
assert(attr_ok == nil, "could get attributes of a non-existent file")
assert(type(err) == "string", "failed lfs.attributes did not return an error message")
assert(type(errno) == "number", "failed lfs.attributes did not return error code")
assert (type(lfs.attributes (upper)) == "table", "couldn't get attributes of upper directory")

io.write(".")
io.flush()

-- Stressing directory iterator
count = 0
for i = 1, 4000 do
        for file in lfs.dir (tmp) do
                count = count + 1
        end
end

io.write(".")
io.flush()

-- Stressing directory iterator, explicit version
count = 0
for i = 1, 4000 do
  local iter, dir = lfs.dir(tmp)
  local file = dir:next()
  while file do
    count = count + 1
    file = dir:next()
  end
  assert(not pcall(dir.next, dir))
end

io.write(".")
io.flush()

-- directory explicit close
local iter, dir = lfs.dir(tmp)
dir:close()
assert(not pcall(dir.next, dir))
print"Ok!"
]]
