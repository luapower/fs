local ffi = require'ffi'
local fs = require'fs'
local win = ffi.abi'win'
local posix = not win

local test_file = 'fs_test.tmp'

local test = setmetatable({}, {__newindex = function(t, k, v)
	rawset(t, k, v)
	rawset(t, #t+1, k)
end})

local testfile = 'media/fs/testfile'

function test.open_close()
	local f = assert(fs.open'fs_test.lua')
	assert(fs.isfile(f))
	assert(not f:closed())
	assert(f:close())
	assert(f:closed())
end

function test.read_write()
	local sz = 4096
	local buf = ffi.new('uint8_t[?]', sz)

	--write some patterns
	local f = assert(fs.open(test_file, 'w'))
	for i=0,sz-1 do
		buf[i] = i
	end
	for i=1,4 do
		assert(f:write(buf, sz))
	end
	assert(f:close())

	--read them back
	local f = assert(fs.open(test_file))
	local t = {}
	while true do
		local readsz = assert(f:read(buf, sz))
		if readsz == 0 then break end
		t[#t+1] = ffi.string(buf, readsz)
	end
	assert(f:close())

	--check them out
	local s = table.concat(t)
	for i=1,#s do
		assert(s:byte(i) == (i-1) % 256)
	end

	assert(os.remove(test_file))
end

function test.open_modes()
	--TODO:
	local f = assert(fs.open(test_file, 'w'))
	f:close()
end

function test.stream()
	local f = assert(assert(fs.open(test_file, 'w')):stream('w'))
	f:close()
	local f = assert(assert(fs.open(test_file, 'r')):stream('r'))
	f:close()
end

function test.seek()
	local f = assert(fs.open(test_file, 'w'))

	--test large file support by seeking out-of-bounds
	local newpos = 2^51 + 113
	local pos = assert(f:seek('set', newpos))
	assert(pos == newpos)
	local pos = assert(f:seek(-100))
	assert(pos == newpos -100)
	local pos = assert(f:seek('end', 100))
	assert(pos == 100)

	--write some data and check again
	local newpos = 1024^2
	local buf = ffi.new'char[1]'
	local pos = assert(f:seek('set', newpos))
	assert(pos == newpos) --seeked outside
	buf[0] = 0xaa
	f:write(buf, 1) --write outside cur
	local pos = assert(f:seek())
	assert(pos == newpos + 1) --cur advanced
	local pos = assert(f:seek('end'))
	assert(pos == newpos + 1) --end updated
	assert(f:close())

	assert(os.remove(test_file))
end

function test.truncate_seek()
	--truncate/grow
	local f = assert(fs.open(test_file, 'w'))
	local newpos = 1024^2
	local pos = assert(f:seek(newpos))
	assert(pos == newpos)
	assert(f:truncate())
	local pos = assert(f:seek())
	assert(pos == newpos)
	assert(f:close())

	--now check size
	local f = assert(fs.open(test_file, 'r+'))
	local pos = assert(f:seek'end')
	assert(pos == newpos)
	--truncate/shrink
	local pos = assert(f:seek('end', -100))
	assert(f:truncate())
	assert(pos == newpos - 100)
	assert(f:close())

	--now check size
	local f = assert(fs.open(test_file, 'r'))
	local pos = assert(f:seek'end')
	assert(pos == newpos - 100)
	assert(f:close())

	assert(os.remove(test_file))
end



--[[
--stdio opening/closing

function test.stdio_open_close_type_fileno_handle()
	local f = assert(fs.open'fs_test.lua')
	assert(fs.isfile(f))
	assert(f:fileno() > 2)
	if win then
		assert(f:handle())
	end
	f:close()
end

function test.open_fd()

end

function test.open_handle()

end
]]

function test.pwd_mkdir_rmdir()
	local pwd = assert(fs.pwd())
	assert(fs.mkdir'fs_test_dir') --relative paths should work
	assert(fs.pwd'fs_test_dir')   --relative paths should work
	assert(fs.pwd(pwd))
	assert(fs.pwd() == pwd)
	assert(fs.rmdir'fs_test_dir') --relative paths should work
end

function test.dir()
	local found
	local n = 0
	for file in fs.dir() do
		found = found or file == 'fs_test.lua'
		n = n + 1
		--print(file)
	end
	assert(n >= 3) -- at least '.', '..' and 'fs_test.lua'
	print(string.format('found %d dir/file entries in pwd', n))
	assert(found, 'fs_test.lua not found in pwd')
end

function test.pwd()
	local pwd = fs.pwd()
	local dir = posix and '/home' or 'C:\\Windows'
	assert(fs.pwd(dir))
	assert(fs.pwd() == dir)
	fs.pwd(pwd)
	assert(fs.pwd() == pwd)
end

--[=[
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



------------- lfs tests



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
]=]

if not ... or ... == 'fs_test' then
	--run all tests in the order in which they appear in the code.
	for i,k in ipairs(test) do
		print('test '..k)
		local ok, err = xpcall(test[k], debug.traceback)
		if not ok then
			print(err)
		end
	end
else
	test[...]()
end
