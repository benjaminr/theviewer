-- base64.lua: an *encoding* codec.
--
-- Encoding codecs change how bytes are represented without compressing
-- them. This one lets you decode a base64 run in place (or into a new
-- document) and encode a selection back.
--
-- `detect` runs on the bytes at the cursor and decides whether this codec
-- applies; `decode` returns the decoded string (or nil) and how many input
-- bytes it consumed; `encode` is optional and returns the encoded string.

local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local value_of = {}
for i = 1, #alphabet do
  value_of[alphabet:sub(i, i)] = i - 1
end

local MIN_RUN = 32

-- Length of the run of base64 characters (plus '=' padding) at the start.
local function run_length(window)
  local n = 0
  for i = 1, window:len() do
    local byte = window:byte(i)
    local ch = string.char(byte)
    if value_of[ch] or ch == "=" then
      n = n + 1
    else
      break
    end
  end
  return n
end

local function decode(window, max_out)
  local n = run_length(window)
  if n < 4 then
    return nil
  end
  local text = window:bytes(0, n)
  local out = {}
  local bits, count = 0, 0
  for i = 1, #text do
    local ch = text:sub(i, i)
    if ch == "=" then
      break
    end
    bits = (bits << 6) | value_of[ch]
    count = count + 6
    if count >= 8 then
      count = count - 8
      out[#out + 1] = string.char((bits >> count) & 0xFF)
      if #out >= max_out then
        break
      end
    end
  end
  return table.concat(out), n
end

local function encode(data)
  local out = {}
  for i = 1, #data, 3 do
    local a, b, c = data:byte(i, i + 2)
    local n = (a << 16) | ((b or 0) << 8) | (c or 0)
    out[#out + 1] = alphabet:sub((n >> 18) + 1, (n >> 18) + 1)
    out[#out + 1] = alphabet:sub(((n >> 12) & 63) + 1, ((n >> 12) & 63) + 1)
    out[#out + 1] = b and alphabet:sub(((n >> 6) & 63) + 1, ((n >> 6) & 63) + 1) or "="
    out[#out + 1] = c and alphabet:sub((n & 63) + 1, (n & 63) + 1) or "="
  end
  return table.concat(out)
end

theviewer.register_codec{
  id = "base64",
  name = "Base64 text",
  kind = "encoding",
  detect = function(window)
    return run_length(window) >= MIN_RUN
  end,
  decode = decode,
  encode = encode,
}
