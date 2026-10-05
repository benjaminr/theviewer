-- tlv.lua: a parser for generic tag-length-value sequences.
--
-- Parsers work at one offset: `looks_like` is a cheap check on the first
-- bytes, and `parse` returns a finding with a field tree (or nil). This one
-- accepts a sequence of elements, each a 1-byte tag and a 1-byte length,
-- that fills at least 16 bytes exactly. It is deliberately permissive, so it
-- reports a low confidence; a real format-specific parser would do better.

local MIN_TOTAL = 16

-- Walk elements from offset 0; returns the fields and the total length, or
-- nil if the sequence is malformed.
local function walk(window)
  local fields = {}
  local offset = 0
  local n = window:len()
  while offset + 2 <= n do
    local tag, len = window:u8(offset), window:u8(offset + 1)
    if offset + 2 + len > n then
      return nil
    end
    fields[#fields + 1] = {
      name = string.format("tag 0x%02X", tag),
      offset = offset,
      len = 2 + len,
      value = string.format("%d bytes", len),
      children = {
        { name = "tag", offset = offset, len = 1, value = tostring(tag) },
        { name = "length", offset = offset + 1, len = 1, value = tostring(len) },
        { name = "value", offset = offset + 2, len = len, value = "" },
      },
    }
    offset = offset + 2 + len
    if #fields > 256 then
      return nil
    end
  end
  if offset ~= n or offset < MIN_TOTAL then
    return nil
  end
  return fields, offset
end

theviewer.register_parser{
  id = "tlv",
  name = "Generic TLV sequence",
  looks_like = function(window)
    -- Only the first 64 bytes arrive here, so just sanity-check the first
    -- element: a length that fits.
    local len = window:u8(1)
    return len ~= nil and len + 2 <= window:len()
  end,
  parse = function(window, base)
    local fields, total = walk(window)
    if not fields then
      return nil
    end
    return {
      id = "tlv",
      start = 0,
      len = total,
      category = "Structure",
      title = "TLV sequence",
      detail = string.format("%d elements", #fields),
      confidence = 0.4,
      fields = fields,
    }
  end,
}
