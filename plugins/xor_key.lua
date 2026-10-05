-- xor_key.lua: an encoding codec that XORs every byte with a fixed key.
--
-- XOR with a key is its own inverse, so `decode` and `encode` are the same
-- operation. `detect` returns false on purpose: there is no way to tell
-- XOR-masked bytes from anything else, so this codec is only offered when
-- you ask the viewer to probe the bytes at the cursor.

local KEY = 0x55

local function xor_bytes(text)
  local out = {}
  for i = 1, #text do
    out[i] = string.char(text:byte(i) ~ KEY)
  end
  return table.concat(out)
end

theviewer.register_codec{
  id = "xor-55",
  name = "XOR with 0x55",
  kind = "encoding",
  detect = function(window)
    return false
  end,
  decode = function(window, max_out)
    local n = math.min(window:len(), max_out)
    return xor_bytes(window:bytes(0, n)), n
  end,
  encode = xor_bytes,
}
