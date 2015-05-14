local ret = {}
local begintime = tonumber(ARGV[1])
local endtime = tonumber(ARGV[2])
for i2,key in ipairs(KEYS) do
	local t = redis.call('lrange', key, 0, -1)
	for index,value in ipairs(t) do
		local json = cjson.decode(value)
		local timestamp = tonumber(json['time'])
		if timestamp >= begintime and timestamp <= endtime then
			ret[#ret+1] = value
		end
	end
end
return ret
