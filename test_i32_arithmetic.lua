---@param a integer
---@param b integer
---@return integer
local function i32_sub(a, b)
    local res = a - b
    if res > 0x7FFFFFFF then
        res = res - 0x100000000
    elseif res < -0x80000000 then
        res = res + 0x100000000
    end
    return res
end

-- Should match rust i32 sub
assert(i32_sub( 10,            5         ) ==  5         );
assert(i32_sub(-10,           -5         ) == -5         );
assert(i32_sub(-5,             10        ) == -15        );
assert(i32_sub( 0x7FFFFFFF,   -1         ) == -0x80000000);
assert(i32_sub(-0x80000000,    1         ) ==  0x7FFFFFFF);
assert(i32_sub( 0,             1         ) == -1         );
assert(i32_sub(-1,            -1         ) ==  0         );
assert(i32_sub( 0,            -1         ) ==  1         );
assert(i32_sub( 123456789,     98765432  ) ==  24691357  );
assert(i32_sub(-2147483648,   -2147483648) ==  0         );

---@param a integer
---@param b integer
---@return integer
local function i32_add(a, b)
    local res = a + b
    if res > 0x7FFFFFFF then
        res = res - 0x100000000
    elseif res < -0x80000000 then
        res = res + 0x100000000
    end
    return res
end

-- Not enought tests but whatever
assert(i32_add( 1,           2        ) ==  3         );
assert(i32_add( 0x7FFFFFFF,  1        ) == -0x80000000);
assert(i32_add(-1,          -1        ) == -2         );
assert(i32_add(-0x80000000, -1        ) ==  0x7FFFFFFF);
assert(i32_add( 123456789,   987654321) ==  1111111110);