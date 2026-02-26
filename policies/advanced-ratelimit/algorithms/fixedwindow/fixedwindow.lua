-- Fixed Window clamp script
-- KEYS[1]: rate limit key
-- ARGV[1]: limit
-- ARGV[2]: requested cost
-- ARGV[3]: ttl_millis
-- ARGV[4]: clamp (1 = clamp consumption, 0 = consume only if fully allowed)

local key = KEYS[1]
local limit = tonumber(ARGV[1])
local requested = tonumber(ARGV[2]) or 0
local ttl_millis = tonumber(ARGV[3])
local clamp = tonumber(ARGV[4]) == 1

if requested < 0 then
    requested = 0
end

local current = redis.call('GET', key)
if current == false then
    current = 0
else
    current = tonumber(current)
end

local remaining_before = limit - current
if remaining_before < 0 then
    remaining_before = 0
end

local consumed = 0
local allowed = 0

if requested <= remaining_before then
    consumed = requested
    allowed = 1
elseif clamp then
    consumed = remaining_before
    allowed = 0
end

if consumed > 0 then
    if current == 0 then
        redis.call('SET', key, current + consumed, 'PX', ttl_millis)
    else
        redis.call('INCRBY', key, consumed)
    end
end

local new_count = current + consumed
local remaining = limit - new_count
if remaining < 0 then
    remaining = 0
end

local overflow = requested - consumed

-- Return: {allowed, remaining, new_count, consumed, overflow}
return {allowed, remaining, new_count, consumed, overflow}
