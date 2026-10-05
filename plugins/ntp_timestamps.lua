-- ntp_timestamps.lua: a detector for runs of NTP timestamps.
--
-- NTP counts seconds since 1900 in a big-endian 32-bit word, so a 2024
-- timestamp reads as 3.9 billion and the built-in Unix-time detector misses
-- it. This script looks for runs of at least four plausible NTP seconds at
-- a fixed stride, which is what a log of NTP packets or a table of sample
-- times looks like.
--
-- Offsets in `window` are 0-based; findings use window offsets and the host
-- adds `ctx.base` to turn them into document offsets.

local NTP_TO_UNIX = 2208988800
local MIN_SECONDS = 946684800 + NTP_TO_UNIX   -- 2000-01-01
local MAX_SECONDS = 2208988800 + NTP_TO_UNIX  -- 2040-01-01
local MAX_GAP = 366 * 24 * 3600
local MIN_RUN = 4
local STRIDES = { 8, 12, 16, 32 }

local function plausible(seconds)
  return seconds and seconds >= MIN_SECONDS and seconds < MAX_SECONDS
end

-- Format NTP seconds as a UTC date, good enough for a description.
local function describe(ntp_seconds)
  local unix = ntp_seconds - NTP_TO_UNIX
  local days = unix // 86400
  local z = days + 719468
  local era = z // 146097
  local doe = z - era * 146097
  local yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
  local y = yoe + era * 400
  local doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
  local mp = (5 * doy + 2) // 153
  local d = doy - (153 * mp + 2) // 5 + 1
  local m = mp < 10 and mp + 3 or mp - 9
  if m <= 2 then y = y + 1 end
  return string.format("%04d-%02d-%02d", y, m, d)
end

local function scan(window, ctx)
  local findings = {}
  local n = window:len()
  for _, stride in ipairs(STRIDES) do
    for phase = 0, stride - 1 do
      local run_start, run_len, previous = nil, 0, nil
      local offset = phase
      while offset + 4 <= n do
        local value = window:u32be(offset)
        local continues = plausible(value) and previous and value >= previous and value - previous <= MAX_GAP
        if continues then
          run_len = run_len + 1
        else
          if run_len >= MIN_RUN then
            findings[#findings + 1] = {
              id = "ntp-run",
              start = run_start,
              len = (run_len - 1) * stride + 4,
              category = "Timestamp",
              title = "NTP timestamps",
              detail = string.format("%d values every %d bytes, from %s", run_len, stride,
                describe(window:u32be(run_start))),
              confidence = 0.6,
            }
          end
          run_start, run_len = offset, plausible(value) and 1 or 0
        end
        previous = plausible(value) and value or nil
        offset = offset + stride
      end
      if run_len >= MIN_RUN then
        findings[#findings + 1] = {
          id = "ntp-run",
          start = run_start,
          len = (run_len - 1) * stride + 4,
          category = "Timestamp",
          title = "NTP timestamps",
          detail = string.format("%d values every %d bytes, from %s", run_len, stride,
            describe(window:u32be(run_start))),
          confidence = 0.6,
        }
      end
    end
  end
  return findings
end

theviewer.register_detector{
  id = "ntp-timestamps",
  name = "NTP timestamp runs",
  categories = { "Timestamp" },
  scan = scan,
}
