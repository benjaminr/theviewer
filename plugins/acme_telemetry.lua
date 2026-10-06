-- acme_telemetry.lua: a plugin that listens to what other tools learn and
-- offers a method of its own, for a made-up protocol.
--
-- "ACME telemetry" frames start with the sync word 7E A5, then a type byte
-- and a length byte. When any tool defines frames (the protocol framing,
-- the packet viewer's splitting rules, a capture), this plugin looks at the
-- first few and, when most start with the sync word, says so on the bus as
-- `protocol.identified`, which the packet viewer and Reference use like a
-- built-in identification. It also registers `acme.decode_frame`, which
-- panels, Ask, the command line and plugins can all call.
--
-- It only ever reads: it declares no edits, so its handler's `api` could
-- not change the document even if it tried. On ordinary files, where no
-- frames start with 7E A5, it publishes nothing.

theviewer.plugin{ name = "acme" }

local SYNC = "7ea5"
-- Frames looked at each time; enough to tell, cheap however many there are.
local SAMPLE = 16

-- Whether the frame at `start` begins with the sync word.
local function starts_with_sync(api, start)
  local ok, head = pcall(api.bytes.read, { start = start, len = 2 })
  return ok and head.data == SYNC
end

theviewer.subscribe("frames.defined", function(message, api)
  local frames = message.payload.frames
  local looked, matched = 0, 0
  for index = 1, math.min(#frames, SAMPLE) do
    looked = looked + 1
    if starts_with_sync(api, frames[index].start) then
      matched = matched + 1
    end
  end
  -- At least two frames, and three in four of those looked at.
  if looked >= 2 and matched * 4 >= looked * 3 then
    api.publish("protocol.identified", {
      frames = frames,
      protocol = "ACME telemetry",
      how = string.format("sync word 7E A5 at the start of %d of %d frames looked at", matched, looked),
    })
  end
end)

theviewer.register_method{
  name = "acme.decode_frame",
  summary = "Decode the ACME telemetry frame at an offset: whether it starts with the sync word 7E A5, its type and its length.",
  params = { start = "integer" },
  run = function(params, api)
    local frame = api.bytes.read{ start = params.start, len = 4 }
    local bytes = theviewer.unhex(frame.data)
    if #bytes < 4 or frame.data:sub(1, 4) ~= SYNC then
      return { sync = false }
    end
    return { sync = true, type = bytes:byte(3), length = bytes:byte(4) }
  end,
}
