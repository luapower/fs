
--portable filesystem API for LuaJIT / backend utils
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'fs_test'; return end

local ffi = require'ffi'
local bit = require'bit'

local C = ffi.C
local cdef = ffi.cdef

local backend = setmetatable({}, {__index = _G})
setfenv(1, backend)

fs = {} --fs namespace: backends can add functions in it directly.
file = {} --file object methods: backends can add methods in it directly.

--assert() with string formatting (this should be a Lua built-in).
function assert(v, err, ...)
	if v then return v end
	err = err or 'assertion failed!'
	if select('#',...) > 0 then
		err = string.format(err,...)
	end
	error(err, 2)
end

function str(buf, sz)
	return buf ~= nil and ffi.string(buf, sz) or nil
end

--return a function which reuses an ever-increasing buffer
function mkbuf(ctype, min_sz)
	ctype = ffi.typeof('$[?]', ffi.typeof(ctype))
	min_sz = min_sz or 256
	assert(min_sz > 0)
	local buf, bufsz
	return function(sz)
		sz = sz or bufsz or min_sz
		assert(sz > 0)
		if not bufsz or sz > bufsz then
			buf, bufsz = ctype(sz), sz
		end
		return buf, bufsz
	end
end

--error reporting

cdef[[
char *strerror(int errnum);
]]

function check_errno(ret, errno)
	if ret then return ret end
	errno = errno or ffi.errno()
	return ret, str(C.strerror(errno)), errno
end

function assert_checker(check)
	return function(ret, errcode)
		if ret then return ret end
		local _, err, errcode = check(errcode)
		if errcode then
			error(string.format('OS Error %d: %s', errcode, err), 2)
		else
			error(err, 2)
		end
	end
end

assert_check_errno = assert_checker(check_errno)

function flags(arg, masks)
	if type(arg) == 'string' then
		if not arg:find'[ ,]' then
			return assert(masks[arg], 'invalid flag %s', arg)
		end
		local t = {}
		for s in arg:gmatch'[^ ,]+' do
			t[#t+1] = s
		end
		return flags(t, masks)
	elseif type(arg) == 'number' then
		return arg
	elseif type(arg) == 'table' then
		local mask = 0
		for k,v in pairs(arg) do
			local flag
			if type(k) == 'string' and v then --{flag->true}
				flag = k
			elseif
				type(k) == 'number'
				and math.floor(k) == k
				and type(v) == 'string'
			then --{flag1,...}
				flag = v
			end
			if flag then
				local m = assert(masks[flag], 'invalid flag %s', flag)
				mask = bit.bor(mask, m)
			end
		end
		return mask
	elseif arg == nil then
		return 0
	else
		assert(false, 'flags expected but %s given', type(arg))
	end
end

return backend
