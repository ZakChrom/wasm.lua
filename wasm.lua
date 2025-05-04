---@return integer
local function read_leb128(file, size)
    local segment_bits = 0x7f;
    local continue_bits = 0x80;
    local value = 0;
    local i = 0;
    local bytes = math.ceil(size / 7)
    while i < bytes do
        local byte = string.byte(assert(file:read(1)), 1, 1);
        value = value | (((byte & segment_bits)) << (i * 7));
        i = i + 1;
        if (byte & continue_bits) ~= continue_bits then
            return value;
        end
    end
    return value;
end

---@return integer
local function get_num(data, bytes)
    local n = 0
    local m = 1

    for i=1,bytes do
        local byte = assert(string.byte(data, i, i))
        n = n + byte * m
        m = m * 256
    end
    return n
end

local printf = function(s, ...)
    return io.write(s:format(...))
end

-- local function u32_to_i32(n)
--     if (n & (1 << 31)) ~= 0 then
--         return -(n & ((2^31)-1))
--     else
--         return n
--     end
-- end

---@param u integer
---@param bits integer
---@return integer
local function u_to_s(u, bits)
    local limit = 2^(bits - 1)
    if u >= limit then
        return u - 2^bits
    else
        return u
    end
end

---@param s integer
---@param bits integer
---@return integer
local function s_to_u(s, bits)
    assert(bits == 32 or bits == 64);
    if s < 0 then
        return s + 2^bits
    else
        return s
    end
end

-- local function new_s_to_u(s, bits)
--     local b = tostring(bits//8);
--     return string.unpack("I" .. b, string.pack("i" .. b, s))
-- end

-- for i = -100, 100 do
--     local a = s_to_u(i, 64);
--     local b = new_s_to_u(i, 64);
--     print(a, b)
--     assert(a == b);
-- end
-- error()

-- https://stackoverflow.com/questions/9168058/how-to-dump-a-table-to-console
local function tprint(tbl, indent)
    if not indent then indent = 0 end
    for k, v in pairs(tbl) do
        local formatting = string.rep("  ", indent) .. k .. ": "
        if type(v) == "table" then
            print(formatting)
            tprint(v, indent+1)
        elseif type(v) == 'boolean' then
            print(formatting .. tostring(v))
        elseif type(v) == nil then
            print(formatting .. "nil")
        else
            print(formatting .. v)
        end
    end
end

---@alias ValueType "i32"|"i64"|"f32"|"f64"|"v128"|"funcref"|"externref"
---@return ValueType
local function read_value_type(file)
    local type = file:read(1):byte(1, 1);
    if type == 0x7f then
        return "i32"
    elseif type == 0x7e then
        return "i64"
    elseif type == 0x7d then
        return "f32"
    elseif type == 0x7c then
        return "f64"
    elseif type == 0x7b then
        return "v128"
    elseif type == 0x70 then
        return "funcref"
    elseif type == 0x6f then
        return "externref"
    else
        printf("0x%02X\n", type)
        error("invalid type")
    end
end

---@return [ValueType]
local function read_result_type(file)
    local size = read_leb128(file, 32);
    local values = {}
    for i = 1, size do
        local valtype = read_value_type(file)
        table.insert(values, valtype);
    end
    return values
end

---@class (exact) FuncType
---@field args [ValueType]
---@field result [ValueType]

---@return FuncType
local function read_func_type(file)
    assert(file:read(1):byte(1, 1) == 0x60);
    local args = read_result_type(file)
    local result = read_result_type(file)
    return {
        args = args,
        result = result
    }
end

---@return [FuncType]
local function read_type_section(file, max_len)
    local size = read_leb128(file, 32);
    local funcs = {};
    for i = 1, size do
        table.insert(funcs, read_func_type(file))
    end

    return funcs
end

---@class (exact) Import
---@field module string
---@field name string
---@field desc { type: string, value: integer }

---@param file file*
---@return Import
local function read_import(file)
    local module = file:read(read_leb128(file, 32));
    local name = file:read(read_leb128(file, 32));
    local type = file:read(1):byte(1, 1);
    if type == 0x00 then
        local value = read_leb128(file, 32);
        return {
            module = module,
            name = name,
            desc = {
                type = "func",
                value = value
            }
        }
    else
        error("todo")
    end
end

---@return [Import]
local function read_import_section(file, max_len)
    local size = read_leb128(file, 32);
    local imports = {};
    for i = 1, size do
        table.insert(imports, read_import(file))
    end

    return imports
end

---@return [integer]
local function read_func_section(file, max_len)
    local size = read_leb128(file, 32);
    local funcs = {};
    for i = 1, size do
        table.insert(funcs, read_leb128(file, 32))
    end

    return funcs
end

---@return "funcref"|"externref"
local function read_reftype(file)
    local type = file:read(1):byte(1, 1);
    if type == 0x70 then
        return "funcref"
    elseif type == 0x6f then
        return "externref"
    else
        error("invalid reftype")
    end
end

---@alias Limits { min: integer, max: integer? }
---@return Limits
local function read_limits(file)
    local has_max = file:read(1):byte(1, 1);
    assert(has_max == 0 or has_max == 1);
    local min = read_leb128(file, 32);
    local max;
    if has_max == 1 then
        max = read_leb128(file, 32);
    end
    return {
        min = min,
        max = max
    }
end

---@return { et: "funcref"|"externref", lim: Limits}
local function read_table_section(file, max_len)
    local size = read_leb128(file, 32);
    local tables = {};
    for i = 1, size do
        local et = read_reftype(file);
        local lim = read_limits(file)
        table.insert(tables, {
            et = et,
            lim = lim,
        })
    end

    return tables
end

---@param file file*
---@return [Limits]
local function read_mem_section(file, max_len)
    local size = read_leb128(file, 32);
    local mems = {};
    for i = 1, size do
        table.insert(mems, read_limits(file))
    end

    return mems
end

---@param file file*
---@param amount integer
---@return string
local function peek(file, amount)
    local pos = file:seek("cur", 0)
    local data = file:read(amount);
    file:seek("set", pos);
    return data;
end

---@return (ValueType|integer)?
local function read_block_type(file)
    local thing = peek(file, 1):byte(1, 1);
    if thing == 0x40 then
        file:read(1);
        return nil
    end
    if thing == 0x7f then
        return "i32"
    elseif thing == 0x7e then
        return "i64"
    elseif thing == 0x7d then
        return "f32"
    elseif thing == 0x7c then
        return "f64"
    elseif thing == 0x7b then
        return "v128"
    elseif thing == 0x70 then
        return "funcref"
    elseif thing == 0x6f then
        return "externref"
    else
        error("todo");
        return u_to_s(read_leb128(file, 33), 33);
    end

    -- local t = read_value_type(file);
    -- local x = read_leb128(file, 33);
    -- return {
    --     t = t,
    --     x = x,
    -- }
end

---@alias Instruction [integer, ...]

---@type { [string]: fun(file*): Instruction}
local instparsetable = {
    [0x00] = function(file) return {0x00} end, -- unreachable
    [0x01] = function(file) return {0x01} end, -- nop
    [0x41] = function(file) return {0x41, u_to_s(read_leb128(file, 32), 32)} end, -- i32.const
    [0x23] = function(file) return {0x23, read_leb128(file, 32)} end, -- global.get
    [0x21] = function(file) return {0x21, read_leb128(file, 32)} end, -- local.set
    [0x20] = function(file) return {0x20, read_leb128(file, 32)} end, -- local.get
    [0x6b] = function(file) return {0x6b} end, -- i32.sub
    [0x36] = function(file) -- i32.store
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x36, { align = align, offset = offset }}
    end,
    [0x28] = function(file) -- i32.load
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x28, { align = align, offset = offset }}
    end,
    [0x0f] = function(file) return {0x0f} end, -- return
    [0x10] = function(file) return {0x10, read_leb128(file, 32)} end, -- call
    [0x45] = function(file) return {0x45} end, -- i32.eqz
    [0x0d] = function(file) return {0x0d, read_leb128(file, 32)} end, -- br_if
    [0x22] = function(file) return {0x22, read_leb128(file, 32)} end, -- local.tee
    [0x2d] = function(file) -- i32.load8_u
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x2d, { align = align, offset = offset }}
    end,
    [0x3a] = function(file) -- i32.store8
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x3a, { align = align, offset = offset }}
    end,
    [0x24] = function(file) return {0x24, read_leb128(file, 32)} end, -- global.set
    [0x1a] = function(file) return {0x1a} end, -- drop
    [0x47] = function(file) return {0x47} end, -- i32.ne
    [0x6a] = function(file) return {0x6a} end, -- i32.add
    [0x42] = function(file) return {0x42, u_to_s(read_leb128(file, 64), 64)} end, -- i64.const
    [0x37] = function(file) -- i64.store
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x37, { align = align, offset = offset }}
    end,
    [0x4e] = function(file) return {0x4e} end, -- i32.ge_s
    [0x0c] = function(file) return {0x0c, read_leb128(file, 32)} end, -- br
    [0x4a] = function(file) return {0x4a} end, -- i32.gt_s
    [0x1b] = function(file) return {0x1b} end, -- select
    [0x6d] = function(file) return {0x6d} end, -- i32.div_s
    [0x6c] = function(file) return {0x6c} end, -- i32.mul
    [0x46] = function(file) return {0x46} end, -- i32.eq
    [0x74] = function(file) return {0x74} end, -- i32.shl
    [0x71] = function(file) return {0x71} end, -- i32.and
    [0x48] = function(file) return {0x48} end, -- i32.lt_s
    [0x72] = function(file) return {0x72} end, -- i32.or
    [0x73] = function(file) return {0x73} end, -- i32.xor
    [0x4c] = function(file) return {0x4c} end, -- i32.le_s
    [0x4d] = function(file) return {0x4d} end, -- i32.le_u
    [0x7f] = function(file) return {0x7f} end, -- i64.div_s
    [0x0e] = function(file) -- br_table
        local size = read_leb128(file, 32);
        local labels = {}
        for i = 1, size do
            table.insert(labels, read_leb128(file, 32))
        end
        local default = read_leb128(file, 32);
        return {0x0e, { labels = labels, default = default }}
    end,
    [0x75] = function(file) return {0x75} end, -- i32.shr_s
    [0x49] = function(file) return {0x49} end, -- i32.lt_u
    [0x4b] = function(file) return {0x4b} end, -- i32.gt_u
    [0x2c] = function(file) -- i32.load8_s
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x2c, { align = align, offset = offset }}
    end,
    [0x29] = function(file) -- i64.load
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x29, { align = align, offset = offset }}
    end,
    [0x4f] = function(file) return {0x4f } end, -- i32.ge_u
    [0x51] = function(file) return {0x51 } end, -- i64.eq
    [0x76] = function(file) return {0x76 } end, -- i32.shr_u
    [0x52] = function(file) return {0x52 } end, -- i64.ne
    [0x7c] = function(file) return {0x7c } end, -- i64.add
    [0x11] = function(file) -- call_indirect
        local typeidx = read_leb128(file, 32);
        local tableidx = read_leb128(file, 32);
        return {0x11, {
            type = typeidx,
            table = tableidx
        }}
    end,
    [0x3b] = function(file) -- i32.store16
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x3b, {
            align = align,
            offset = offset
        }}
    end,
    [0x6f] = function(file) return {0x6f} end, -- i32.rem_s
    [0xa7] = function(file) return {0xa7} end, -- i32.wrap_i64
    [0x08] = function(file) return {0x08} end, -- throw
    [0xac] = function(file) return {0xac} end, -- i64.extend_i32_s
    [0x7e] = function(file) return {0x7e} end, -- i64.mul
    [0x7d] = function(file) return {0x7d} end, -- i64.sub
    [0x2f] = function(file) -- i32.load16_u
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x2f, {
            align = align,
            offset = offset
        }}
    end,
    [0xad] = function(file) return {0xad} end, -- i64.extend_i32_u
    [0x88] = function(file) return {0x88} end, -- i64.shr_u
    [0x39] = function(file) -- f64.store
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x39, {
            align = align,
            offset = offset
        }}
    end,
    [0x55] = function(file) return {0x55} end, -- i64.gt_s
    [0xbf] = function(file) return {0xbf} end, -- f64.reinterpret_i64
    [0x64] = function(file) return {0x64} end, -- f64.gt
    [0x61] = function(file) return {0x61} end, -- f64.eq
    [0xc0] = function(file) return {0xc0} end, -- i32.extend8_s
    [0x3e] = function(file) -- i64.store32
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x3e, {
            align = align,
            offset = offset
        }}
    end,
    [0x6e] = function(file) return {0x6e} end, -- i32.div_u
    [0x50] = function(file) return {0x50} end, -- i64.eqz
    [0x2e] = function(file) -- i32.load16_s
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x2e, {
            align = align,
            offset = offset
        }}
    end,
    [0xb8] = function(file) return {0xb8} end, -- f64.convert_i32_u
    [0x44] = function(file) return {0x44, file:read(8)} end, -- f64.const -- TODO: parse float actually
    [0x63] = function(file) return {0x63} end, -- f64.lt
    [0x66] = function(file) return {0x66} end, -- f64.ge
    [0xab] = function(file) return {0xab} end, -- i32.trunc_f64_u
    [0x86] = function(file) return {0x86} end, -- i64.shl
    [0x84] = function(file) return {0x84} end, -- i64.or
    [0x77] = function(file) return {0x77} end, -- i32.rotl
    [0x57] = function(file) return {0x57} end, -- i64.le_s
    [0x35] = function(file) -- i64.load32_u
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x35, {
            align = align,
            offset = offset
        }}
    end,
    [0x53] = function(file) return {0x53} end, -- i64.lt_s
    [0x59] = function(file) return {0x59} end, -- i64.ge_s
    [0x80] = function(file) return {0x80} end, -- i64.div_u
    [0x34] = function(file) -- i64.load32_s
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x34, {
            align = align,
            offset = offset
        }}
    end,
    [0x81] = function(file) return {0x81} end, -- i64.rem_s
    [0x54] = function(file) return {0x54} end, -- i64.lt_u
    [0x85] = function(file) return {0x85} end, -- i64.xor
    [0x83] = function(file) return {0x83} end, -- i64.and
    [0x56] = function(file) return {0x56} end, -- i64.gt_u
    [0x70] = function(file) return {0x70} end, -- i32.rem_u
    [0x2b] = function(file) -- f64.load
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x2b, {
            align = align,
            offset = offset
        }}
    end,
    [0x9a] = function(file) return {0x9a} end, -- f64.neg
    [0xbd] = function(file) return {0xbd} end, -- i64.reinterpret_f64
    [0xc1] = function(file) return {0xc1} end, -- i32.extend16_s
    [0x67] = function(file) return {0x67} end, -- i32.clz
    [0x68] = function(file) return {0x68} end, -- i32.ctz
    [0x3f] = function(file) -- memory.size
        file:read(1);
        return {0x3f}
    end,
    [0x40] = function(file) -- memory.grow
        file:read(1);
        return {0x40}
    end,
    [0xa2] = function(file) return {0xa2} end, -- f64.mul
    [0xa0] = function(file) return {0xa0} end, -- f64.add
    [0xa1] = function(file) return {0xa1} end, -- f64.sub
    [0x62] = function(file) return {0x62} end, -- f64.ne
    [0xa3] = function(file) return {0xa3} end, -- f64.div
    [0xb7] = function(file) return {0xb7} end, -- f64.convert_i32_s
    [0x5a] = function(file) return {0x5a} end, -- i64.ge_u
    [0x3c] = function(file) -- i64.store8
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x3c, {
            align = align,
            offset = offset
        }}
    end,
    [0x99] = function(file) return {0x99} end, -- f64.abs
    [0xaa] = function(file) return {0xaa} end, -- i32.trunc_f64_s
    [0x32] = function(file) -- i64.store16_s
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x32, {
            align = align,
            offset = offset
        }}
    end,
    [0x33] = function(file) -- i64.store16_u
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x33, {
            align = align,
            offset = offset
        }}
    end,
    [0x30] = function(file) -- i64.load8_s
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x30, {
            align = align,
            offset = offset
        }}
    end,
    [0x31] = function(file) -- i64.load8_u
        local align = read_leb128(file, 32);
        local offset = read_leb128(file, 32);
        return {0x31, {
            align = align,
            offset = offset
        }}
    end,
    [0x58] = function(file) return {0x58} end,-- i64.le_u
    [0xb2] = function(file) return {0xb2} end,-- f32.convert_i32_s
    [0x43] = function(file) return {0x43, file:read(4) } end, -- f32.const -- TODO: parse floats
    [0x94] = function(file) return {0x94} end,-- f32.mul
    [0xbb] = function(file) return {0xbb} end,-- f64.promote_f32
    [0xa6] = function(file) return {0xa6} end,-- f64.copysign
    [0x9d] = function(file) return {0x9d} end,-- f64.trunc
    [0xb6] = function(file) return {0xb6} end,-- f32.demote_f64
    [0xfc] = function(file) -- misc
        local thing = read_leb128(file, 32);
        if thing == 11 then
            file:read(1);
            return {"memory.fill"}
        elseif thing == 10 then
            file:read(2);
            return {"memory.copy"}
        else
            error(string.format("todo: MISC %d\n", thing))
        end
    end,
    [0x87] = function(file) return {0x87} end, -- i64.shr_s
}

---@param file file*
---@param only_constants boolean
---@param endthing integer?
---@return [Instruction]
local function read_expr(file, only_constants, endthing)
    if endthing == nil then endthing = 0x0B end

    local instructions = {}
    while true do
        local thing = file:read(1):byte(1, 1);
        if thing == endthing then
            break
        end
        if only_constants then
            assert(thing == 0x41 or thing == 0x42 or thing == 0x43 or thing == 0x44);
        end

        if thing == 0x02 then
            local type = read_block_type(file);
            assert(type == nil); -- TODO: Support block returns
            local expr = read_expr(file, false);
            table.insert(instructions, { 0x02, { -- block
                type = type,
                expr = expr
            }});
        elseif thing == 0x03 then
            local type = read_block_type(file);
            local expr = read_expr(file, false);
            table.insert(instructions, {0x03, { -- loop
                type = type,
                expr = expr
            }});
        else
            if instparsetable[thing] then
                table.insert(instructions, instparsetable[thing](file))
            else
                printf("0x%02X\n", thing)
                error("todo")
            end
        end

    end
    return instructions
end

---@class (exact) Global
---@field type ValueType
---@field mut boolean
---@field expr [Instruction]

---@return [Global]
local function read_global_section(file, max_len)
    local size = read_leb128(file, 32);
    local globals = {};
    for i = 1, size do
        local type = read_value_type(file);
        local mut = file:read(1):byte(1, 1);
        assert(mut == 0 or mut == 1);
        if mut == 1 then mut = true;
        else mut = false; end
        local expr = read_expr(file, true);

        table.insert(globals, {
            type = type,
            mut = mut,
            expr = expr
        })
    end

    return globals
end

---@class ExportDesc
---@field type "func"|"table"|"mem"|"global"
---@field id integer

---@return ExportDesc
local function read_export_desc(file)
    local type = file:read(1):byte(1, 1);
    if type == 0x00 then
        return { type = "func", id = read_leb128(file, 32) }
    elseif type == 0x01 then
        return { type = "table", id = read_leb128(file, 32) }
    elseif type == 0x02 then
        return { type = "mem", id = read_leb128(file, 32) }
    elseif type == 0x03 then
        return { type = "global", id = read_leb128(file, 32) }
    else
        error("invalid type")
    end
end

---@return [{ name: string, desc: ExportDesc }]
local function read_export_section(file, max_len)
    local size = read_leb128(file, 32);
    local mems = {};
    for i = 1, size do
        local name = file:read(read_leb128(file, 32));
        local desc = read_export_desc(file)
        table.insert(mems, {
            name = name,
            desc = desc
        })
    end

    return mems
end

---@return string
local function read_element_section(file, max_len)
    return file:read(max_len) -- Fuck this
    -- local size = read_leb128(file, 32);
    -- local elements = {};
    -- for i = 1, size do
        
    --     table.insert(elements, {})
    -- end

    -- return elements
end

---@class Function
---@field type "data"|"parsed"

---@class Function.data: Function
---@field data string

---@class Function.parsed: Function
---@field expr [Instruction]
---@field locals [ValueType]

---@param data string
---@return Function.parsed
local function parse_function(data)
    -- Fuck you im using a temp file
    local file = assert(io.open("tmp", "wb"))
    file:write(data)
    file:close();
    file = assert(io.open("tmp", "rb"))

    local amount_of_clocals = read_leb128(file, 32);
    local locals = {};
    for j = 1, amount_of_clocals do
        local n = read_leb128(file, 32);
        local t = read_value_type(file);
        for k = 1, n do
            table.insert(locals, t);
        end
    end
    local e = read_expr(file --[[@as file*]], false);
    file:close();
    return {
        type = "parsed",
        expr = e,
        locals = locals,
    }
end

---@return [Function.data]
local function read_code_section(file, max_len)
    local size = read_leb128(file, 32);
    local codes = {};
    for i = 1, size do
        -- Dont parse data until needed
        table.insert(codes, {
            type = "data",
            data = file:read(read_leb128(file, 32));
        })
    end

    return codes
end

---@return ({ expr: [Instruction], data: string, mem_idx: integer })[]
local function read_data_section(file, max_len)
    local size = read_leb128(file, 32);
    local data = {};
    for i = 1, size do
        local type = read_leb128(file, 32);
        local e;
        local b;
        local x;
        assert(type ~= 1); -- TODO: Support passive ones. Cant be bothered rn
        if type == 0 then
            e = read_expr(file, true);
            b = file:read(read_leb128(file, 32));
        elseif type == 1 then
            b = file:read(read_leb128(file, 32));
        elseif type == 2 then
            x = read_leb128(file, 32);
            e = read_expr(file, true);
            b = file:read(read_leb128(file, 32));
        else
            error("invalid type")
        end
        table.insert(data, {
            expr = e,
            data = b,
            mem_idx = x,
        })
    end

    return data
end

---@param file file*
---@param type integer
---@return any
local function read_section(file, type)
    local size = read_leb128(file, 32);
    printf("Section: %d %d\n", type, size)
    if type == 0 then -- Custom sections
        return {file:read(size)};
    end

    if type == 1 then
        return read_type_section(file, size);
    elseif type == 2 then
        return read_import_section(file, size);
    elseif type == 3 then
        return read_func_section(file, size);
    elseif type == 4 then
        return read_table_section(file, size);
    elseif type == 5 then
        return read_mem_section(file, size);
    elseif type == 6 then
        return read_global_section(file, size);
    elseif type == 7 then
        return read_export_section(file, size);
    elseif type == 8 then
        return read_leb128(file, 32)
    elseif type == 9 then
        return read_element_section(file, size)
    elseif type == 10 then
        return read_code_section(file, size);
    elseif type == 11 then
        return read_data_section(file, size);
    else
        error("todo")
    end
end

local memory = {};

local function write_memory(addr, v)
    memory[addr] = v & 0xff
end

local function write_mem_i32(addr, value)
    write_memory(addr    ,  value        & 0xff);
    write_memory(addr + 1, (value >> 8 ) & 0xff);
    write_memory(addr + 2, (value >> 16) & 0xff);
    write_memory(addr + 3, (value >> 24) & 0xff);
end

local function write_mem_i64(addr, value)
    write_memory(addr    ,  value        & 0xff);
    write_memory(addr + 1, (value >> 8 ) & 0xff);
    write_memory(addr + 2, (value >> 16) & 0xff);
    write_memory(addr + 3, (value >> 24) & 0xff);
    write_memory(addr + 4, (value >> 32) & 0xff);
    write_memory(addr + 5, (value >> 40) & 0xff);
    write_memory(addr + 6, (value >> 48) & 0xff);
    write_memory(addr + 7, (value >> 56) & 0xff);
end

local function read_memory(addr)
    return memory[addr] or 0
end

local function read_mem_i32(addr)
    local b0 = read_memory(addr);
    local b1 = read_memory(addr + 1);
    local b2 = read_memory(addr + 2);
    local b3 = read_memory(addr + 3);
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
end

local function read_mem_i64(addr)
    local b0 = read_memory(addr);
    local b1 = read_memory(addr + 1);
    local b2 = read_memory(addr + 2);
    local b3 = read_memory(addr + 3);
    local b4 = read_memory(addr + 4);
    local b5 = read_memory(addr + 5);
    local b6 = read_memory(addr + 6);
    local b7 = read_memory(addr + 7);
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
end

-- Tests in test_i32_arithmetic.lua
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

---@param n_func_imports integer
---@param func integer
---@param stack ([ValueType, any])[]
---@return ([ValueType, any])[]
local function call_imported(sections, n_func_imports, func, stack, functions, globals)
    local import = sections[2][func + 1]
    assert(import.desc.type == "func");
    if import.module == "env" then
        if import.name == "print" then
            assert(#stack > 0);
            local num = table.remove(stack, #stack);
            assert(num[1] == "i32");
            printf("print: %d\n", num[2]);
            return {}
        end
    elseif import.module == "wasi_snapshot_preview1" then
        if import.name == "environ_sizes_get" then
            assert(#stack > 1);
            local env_buf_size = table.remove(stack, #stack);
            assert(env_buf_size[1] == "i32");
            local envc = table.remove(stack, #stack);
            assert(envc[1] == "i32");
            -- TODO: Custom env
            write_mem_i32(envc[2], 0);
            write_mem_i32(env_buf_size[2], 0);
            print(envc[2], env_buf_size[2])
            return {{"i32", 0}}
        elseif import.name == "args_sizes_get" then
            assert(#stack > 1);
            local argv_buf_size = table.remove(stack, #stack);
            assert(argv_buf_size[1] == "i32");
            local argc = table.remove(stack, #stack);
            assert(argc[1] == "i32");
            -- TODO: Custom args
            write_mem_i32(argc[2], 1);
            write_mem_i32(argv_buf_size[2], #"vim\0");
            return {{"i32", 0}}
        elseif import.name == "args_get" then
            assert(#stack > 1);
            local argv_buf = table.remove(stack, #stack);
            assert(argv_buf[1] == "i32");
            local argv = table.remove(stack, #stack);
            assert(argv[1] == "i32");
             -- TODO: Custom args
            write_mem_i32(argv[2], argv_buf[2])
            write_memory(argv_buf[2], 118)
            write_memory(argv_buf[2] + 1, 105);
            write_memory(argv_buf[2] + 2, 109);
            write_memory(argv_buf[2] + 3, 0);
            return {{"i32", 0}}
        elseif import.name == "proc_exit" then
            printf("proc_exit with %d\n", stack[#stack][2]);
            os.exit(stack[#stack][2])
        elseif import.name == "fd_fdstat_get" then
            assert(#stack > 1);
            local stat_ptr = table.remove(stack, #stack);
            assert(stat_ptr[1] == "i32");
            local fd = table.remove(stack, #stack);
            assert(fd[1] == "i32");

            local filetype = {
                unknown = 0,
                block_device = 1,
                character_device = 2,
                directory = 3,
                regular_file = 4,
                socket_dgram = 5,
                socket_stream = 6,
                symbolic_link = 7 -- Not implemented yet in wasi i think
            }

            local rights = {
                fd_read = 1 << 1,
                fd_write = 1 << 6
            }
            
            if fd[2] == 0 or fd[2] == 1 or fd[2] == 2 then
                write_memory(stat_ptr[2] + 0, filetype.character_device)
                write_memory(stat_ptr[2] + 1, 0)
                write_memory(stat_ptr[2] + 2, 0)
                write_memory(stat_ptr[2] + 3, 0)
            
                if fd == 0 then
                    write_mem_i64(stat_ptr[2] + 8, rights.fd_read)
                else
                    write_mem_i64(stat_ptr[2] + 8, rights.fd_write)
                end
            
                write_mem_i64(stat_ptr[2] + 16, 0)
                return {{"i32", 0}}
            else
                print(fd)
                error("todo")
            end
        end
    end
    tprint(import)
    error("unknown import")
end

if table.copy == nil then
    ---@generic T
    ---@param t T
    ---@return T
    ---@diagnostic disable-next-line: duplicate-set-field
    function table.copy(t)
        if type(t) == "table" then
            local nt = {}
            for k, v in pairs(t) do nt[k] = table.copy(v) end
            return nt
        else
            return t
        end
    end
end

local function_depth = 0;

---@param n_func_imports integer
---@param func integer
---@param arguments ([ValueType, any])[]
---@return ([ValueType, any])[]
local function call_func(sections, n_func_imports, func, arguments, functions, globals)
    function_depth = function_depth + 1
    for i = 1, function_depth do
        printf("  ");
    end
    print(func)
    local func_thing = assert(functions[func + 1]);
    local typedata = func_thing.func;
    if func_thing.type == "import" then
        function_depth = function_depth - 1
        return call_imported(sections, n_func_imports, func, arguments, functions, globals)
    end

    local code = sections[10][func - n_func_imports + 1]
    if code.type == "data" then
        -- TODO: Not saving the parsed stuff back into section rn
        -- Id rather have it be slow than use alot of memory
        code = parse_function(code.data)
    end

    assert(#arguments == #(typedata.args));
    assert((#(typedata.result)) <= 1);
    for i = 1, #arguments do
        assert(arguments[i][1] == typedata.args[i])
    end

    local locals = table.copy(arguments); -- Idk if i have to copy. If its by ref then i think i do
    local blocks = {{
        type = nil,
        pc = 1,
        stack = {},
        expr = code.expr,
    }};

    for i = 1, #(code.locals) do
        table.insert(locals, {code.locals[i], nil})
    end

    while true do
        if blocks[#blocks].pc > #(blocks[#blocks].expr) then
            if #blocks > 1 then
                if blocks[#blocks].thing == "loop" then
                    blocks[#blocks].pc = 1;
                else
                    assert(blocks[#blocks].type == nil) -- TODO: Support block types
                    table.remove(blocks, #blocks);
                    -- If a function ends with a blocks end return
                    if #blocks == 1 and blocks[#blocks].pc > #blocks[#blocks].expr then
                        break
                    end
                end
            else
                break
            end
        end
        
        local cur_block = blocks[#blocks];
        local stack = cur_block.stack;
        local inst = cur_block.expr[cur_block.pc];
        local opcode = inst[1];
        local data = inst[2];

        if opcode == 0x41 then -- i32.const
            table.insert(stack, {"i32", data});
        elseif opcode == 0x21 then -- local.set
            assert(#stack > 0);
            local v = table.remove(stack, #stack);
            assert(locals[data + 1][1] == v[1]);
            locals[data + 1] = v;
        elseif opcode == 0x20 then -- local.get
            assert(locals[data + 1] ~= nil);
            assert(locals[data + 1][2] ~= nil);
            table.insert(stack, locals[data + 1]);
        elseif opcode == 0x10 then -- call
            local called_func = assert(functions[data + 1]);
            assert(#stack >= #(called_func.func.args));
            local called_func_arguments = {};
            -- Isnt required but i dont feel like working out the math to get the values from stack directly
            -- Not that this program is very memory efficient anyway
            local temp = {}
            for i = 1, #(called_func.func.args) do
                table.insert(temp, table.remove(stack, #stack));
            end
            for i = 1, #(called_func.func.args) do
                table.insert(
                    called_func_arguments,
                    temp[1 + #(called_func.func.args) - i]
                )
            end
            local results = call_func(sections, n_func_imports, data, called_func_arguments, functions, globals);
            for i = 1, #results do
                table.insert(stack, results[i])
            end
        elseif opcode == 0x0f then -- return
            break
        elseif opcode == 0x23 then -- global.get
            local g = globals[data + 1];
            table.insert(stack, {g.type, g.value});
        elseif opcode == 0x6b then -- i32.sub
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            table.insert(stack, {"i32", i32_sub(a[2], b[2])});
        elseif opcode == 0x22 then -- local.tee
            assert(#stack > 0);
            local v = table.remove(stack, #stack);
            assert(locals[data + 1][1] == v[1]);
            locals[data + 1] = v;
            table.insert(stack, v);
        elseif opcode == 0x24 then -- global.set
            assert(#stack > 0);
            local g = globals[data + 1];
            assert(g.mut == true);
            local v = table.remove(stack, #stack);
            assert(v[1] == g.type);
            g.value = v[2];
        elseif opcode == 0x36 then -- i32.store
            assert(#stack > 1);
            local v = table.remove(stack, #stack);
            assert(v[1] == "i32");
            local addr = table.remove(stack, #stack);
            assert(addr[1] == "i32");
            write_mem_i32(data.offset + addr[2], v[2]);
        elseif opcode == 0x28 then -- i32.load
            assert(#stack > 0);
            local addr = table.remove(stack, #stack);
            assert(addr[1] == "i32");
            local thing = read_mem_i32(data.offset + addr[2]);
            table.insert(stack, {"i32", thing});
        elseif opcode == 0x6a then -- i32.add
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            table.insert(stack, {"i32", i32_add(a[2], b[2])});
        elseif opcode == 0x02 then -- block
            assert(data.type == nil); -- TODO: Support block types
            table.insert(blocks, {
                type = data.type,
                pc = 1,
                stack = {},
                expr = data.expr,
            });
        elseif opcode == 0x0d then -- br_if
            assert(#stack > 0);
            local v = table.remove(stack, #stack);
            assert(v[1] == "i32");
            assert(data < #blocks);
            if v[2] ~= 0 then
                for i = 0, data do
                    table.remove(blocks, #blocks);
                end
            end
        elseif opcode == 0x45 then -- i32.eqz
            assert(#stack > 0)
            local v = table.remove(stack, #stack);
            assert(v[1] == "i32");
            if v[2] == 0 then
                table.insert(stack, {"i32", 1})
            else
                table.insert(stack, {"i32", 0})
            end
        elseif opcode == 0x74 then -- i32.shl
            assert(#stack > 1);
            local amount = table.remove(stack, #stack);
            assert(amount[1] == "i32");
            local v = table.remove(stack, #stack);
            assert(v[1] == "i32");
            assert(amount[2] >= 0);
            table.insert(stack, {"i32", u_to_s(s_to_u(v[2], 32) << s_to_u(amount[2], 32), 32)});
        elseif opcode == 0x0c then -- br
            assert(data < #blocks);
            for i = 0, data do
                table.remove(blocks, #blocks);
            end
        elseif opcode == 0x71 then -- i32.and
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            table.insert(stack, {"i32", a[2] & b[2]}); -- TODO: Test
        elseif opcode == 0x42 then -- i64.const
            assert(math.type(data) ~= "float");
            table.insert(stack, {"i64", data});
        elseif opcode == 0x37 then -- i64.store
            assert(#stack > 1);
            local v = table.remove(stack, #stack);
            assert(v[1] == "i64");
            local addr = table.remove(stack, #stack);
            assert(addr[1] == "i32");
            write_mem_i64(data.offset + addr[2], v[2]);
        elseif opcode == 0x73 then -- i32.xor
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            table.insert(stack, {"i32", a[2] ~ b[2]}); -- TODO: Test
        elseif opcode == 0x49 then -- i32.lt_u
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            if s_to_u(a[2], 32) < s_to_u(b[2], 32) then
                table.insert(stack, {"i32", 1})
            else
                table.insert(stack, {"i32", 0})
            end
        elseif opcode == 0x03 then -- loop
            assert(data.type == nil); -- TODO: Support block types
            table.insert(blocks, {
                type = data.type,
                pc = 1,
                stack = {},
                expr = data.expr,
                thing = "loop"
            });
        elseif opcode == 0x47 then -- i32.ne
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            if a[2] ~= b[2] then
                table.insert(stack, {"i32", 1})
            else
                table.insert(stack, {"i32", 0})
            end
        elseif opcode == 0x72 then -- i32.or
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            table.insert(stack, {"i32", a[2] | b[2]}); -- TODO: Test
        elseif opcode == 0x4b then -- i32.gt_u
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            if s_to_u(a[2], 32) > s_to_u(b[2], 32) then
                table.insert(stack, {"i32", 1})
            else
                table.insert(stack, {"i32", 0})
            end
        elseif opcode == 0x1b then -- select
            assert(#stack > 2);
            local c = table.remove(stack, #stack);
            assert(c[1] == "i32");
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            if c ~= 0 then
                table.insert(stack, a);
            else
                table.insert(stack, b);
            end
        elseif opcode == 0x76 then -- i32.shr_u
            assert(#stack > 1);
            local amount = table.remove(stack, #stack);
            assert(amount[1] == "i32");
            local v = table.remove(stack, #stack);
            assert(v[1] == "i32");
            assert(amount[2] >= 0);
            table.insert(stack, {"i32", u_to_s(s_to_u(v[2], 32) >> s_to_u(amount[2], 32), 32)});
        elseif opcode == 0x4d then -- i32.le_u
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            if s_to_u(a[2], 32) <= s_to_u(b[2], 32) then
                table.insert(stack, {"i32", 1})
            else
                table.insert(stack, {"i32", 0})
            end
        elseif opcode == 0xad then -- i64.extend_i32_u
            assert(#stack > 0);
            local v = table.remove(stack, #stack);
            assert(v[1] == "i32");
            table.insert(stack, {"i64", v[2]});
        elseif opcode == 0x7e then -- i64.mul
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i64");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i64");
            table.insert(stack, {"i64", (a[2] * b[2]) & 0xffffffffffffffff})
        elseif opcode == 0xa7 then -- i32.wrap_i64
            assert(#stack > 0);
            local v = table.remove(stack, #stack);
            assert(v[1] == "i64");
            table.insert(stack, {"i32", u_to_s(s_to_u(v[2], 64) & 0xffffffff, 32)})
        elseif opcode == 0x2d then -- i32.load8_u
            assert(#stack > 0);
            local addr = table.remove(stack, #stack);
            assert(addr[1] == "i32");
            table.insert(stack, {"i32", read_memory(addr[2])});
        elseif opcode == 0xfc then
            error("invalid")
        elseif opcode == "memory.fill" then
            assert(#stack > 2);
            local amount = table.remove(stack, #stack);
            assert(amount[1] == "i32");
            local value = table.remove(stack, #stack);
            assert(value[1] == "i32");
            local ptr = table.remove(stack, #stack);
            assert(ptr[1] == "i32");
            for i = 1, amount[2] do
                write_memory(ptr[2] + i - 1, value[2]);
            end
        elseif opcode == 0x1a then -- drop
            assert(#stack > 0);
            table.remove(stack, #stack);
        elseif opcode == 0x4a then -- i32.gt_s
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            if a[2] > b[2] then
                table.insert(stack, {"i32", 1})
            else
                table.insert(stack, {"i32", 0})
            end
        elseif opcode == 0x4e then -- i32.ge_s
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            if a[2] >= b[2] then
                table.insert(stack, {"i32", 1})
            else
                table.insert(stack, {"i32", 0})
            end
        elseif opcode == 0x6d then -- i32.div_s
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            assert(b[2] ~= 0);
            -- TODO: Docs say that its undefined if the division results in 2^N - 1
            -- Idk why thats not allowed
            table.insert(stack, {"i32", a[2] // b[2]})
        elseif opcode == 0x6c then -- i32.mul
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            table.insert(stack, {"i32", (a[2] * b[2]) & 0xffffffff});
        elseif opcode == 0x3a then -- i32.store8
            assert(#stack > 1);
            local v = table.remove(stack, #stack);
            assert(v[1] == "i32");
            local addr = table.remove(stack, #stack);
            assert(addr[1] == "i32");
            write_memory(data.offset + addr[2], v[2] & 0xff);
        elseif opcode == 0x29 then -- i64.load
            assert(#stack > 0);
            local addr = table.remove(stack, #stack);
            assert(addr[1] == "i32");
            table.insert(stack, {"i64", read_mem_i64(addr[2])});
        elseif opcode == 0x46 then -- i32.eq
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            if a[2] == b[2] then
                table.insert(stack, {"i32", 1})
            else
                table.insert(stack, {"i32", 0})
            end
        elseif opcode == "memory.copy" then
            assert(#stack > 2);
            local len = table.remove(stack, #stack);
            assert(len[1] == "i32");
            local src = table.remove(stack, #stack);
            assert(src[1] == "i32");
            local dest = table.remove(stack, #stack);
            assert(dest[1] == "i32");
            ---@diagnostic disable-next-line: redefined-local
            local dest = dest[2];
            ---@diagnostic disable-next-line: redefined-local
            local src = src[2];
            ---@diagnostic disable-next-line: redefined-local
            local len = len[2];
            if len > 0 then
                -- If not overlapping use forward else backward copy
                if dest < src or dest >= src + len then
                    for i = 0, len - 1 do
                        local byte = read_memory(src + i)
                        write_memory(dest + i, byte)
                    end
                else
                    for i = len - 1, 0, -1 do
                        local byte = read_memory(src + i)
                        write_memory(dest + i, byte)
                    end
                end
            end
        elseif opcode == 0x48 then -- i32.lt_s
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            if a[2] < b[2] then
                table.insert(stack, {"i32", 1})
            else
                table.insert(stack, {"i32", 0})
            end
        elseif opcode == 0x4f then -- i32.ge_u
            assert(#stack > 1);
            local b = table.remove(stack, #stack);
            assert(b[1] == "i32");
            local a = table.remove(stack, #stack);
            assert(a[1] == "i32");
            if s_to_u(a[2], 32) >= s_to_u(b[2], 32) then
                table.insert(stack, {"i32", 1})
            else
                table.insert(stack, {"i32", 0})
            end
        else
            if type(opcode) == "number" then
                error(string.format("todo: 0x%02X", opcode))
            else
                error(string.format("todo: %s", opcode))
            end
        end

        cur_block.pc = cur_block.pc + 1;
    end

    local cur_block = blocks[#blocks];
    assert(#cur_block.stack >= #(typedata.result));
    local temp = {}
    local results = {};
    for i = 1, #(typedata.result) do
        table.insert(temp, table.remove(cur_block.stack, #cur_block.stack));
    end
    for i = 1, #(typedata.result) do
        table.insert(
            results,
            temp[1 + #(typedata.result) - i]
        )
    end
    function_depth = function_depth - 1
    return results
end

---@param expr [Instruction]
---@return [ValueType, any]
local function eval_const(expr)
    assert(#expr == 1); -- TODO: Allow more than 1 instruction?
    if expr[1][1] == 0x41 then -- i32.const
        return {"i32", expr[1][2]}
    else
        error("todo")
    end
end

local file = assert(io.open("/home/calion/Programming/vim/src/vim", "rb"));

-- why is it just not wasm bruh
assert(assert(file:read(4)) == "\0asm");
local wasm_version = get_num(assert(file:read(4)), 4);
assert(wasm_version == 1);
printf("Wasm version: %d\n", wasm_version);

local sections = {}

while true do
    local section_type = file:read(1);
    if section_type == nil then break end;
    section_type = section_type:byte(1, 1);
    local stuff = read_section(file --[[@as file*]], section_type);
    sections[section_type] = stuff;
    -- if section_type ~= 9 and section_type ~= 10 and section_type ~= 11 and section_type ~= 0 then
    --     if type(stuff) == "table" then tprint(stuff)
    --     else print(stuff) end
    -- end
end

local start
if sections[8] then
    start = sections[8]
else
    for i = 1, #(sections[7]) do
        local func = sections[7][i];
        if func.name == "_start" and func.desc.type == "func" then
            start = func.desc.id
        end
    end
end
assert(start ~= nil)
print("Found start function:", start)
-- for i = 1, #(sections[3]) do
--     local thing = sections[3][i]
--     if thing == 9 then
--         print(i)
--     end
-- end

local functions = {}
local n_func_imports = 0;
if sections[2] ~= nil then
    for i = 1, #(sections[2]) do
        local import = sections[2][i]
        if import.desc.type == "func" then
            table.insert(functions, {
                type = "import",
                func = sections[1][import.desc.value + 1]
            });
        end
        n_func_imports = n_func_imports + 1;
    end
end
for i = 1, #(sections[3]) do
    local func = sections[3][i];
    table.insert(functions, {
        type = "wasm",
        func = sections[1][func + 1]
    });
end

local globals = {};
for i = 1, #(sections[6]) do
    local global = sections[6][i];
    local value = eval_const(global.expr);
    assert(value[1] == global.type);
    table.insert(globals, {
        -- @field type ValueType
        -- @field mut boolean
        -- @field expr [Instruction]
        type = global.type,
        mut = global.mut,
        value = value[2];
    });
end

if sections[11] then
    for i = 1, #(sections[11]) do
        local data = sections[11][i];
        assert(data.expr ~= nil); -- Dont support passive
        -- Wasm doesnt support multible memories currently so its here so i dont forget
        assert(data.mem_idx == 0 or data.mem_idx == nil)
        local thing = eval_const(data.expr);
        assert(thing[1] == "i32") -- TODO: Support other ones?
        local offset = thing[2];
        for j = 1, #(data.data) do
            write_memory(offset + j - 1, string.sub(data.data, j, j):byte(1, 1))
        end
    end
end

local results = call_func(sections, n_func_imports, start, {}, functions, globals)
print("_start exited with results:")
tprint(results)

os.exit()

-- TODO: Maybe replace all indexes by index + 1
-- Then i dont have to do + 1 when i use the indexes