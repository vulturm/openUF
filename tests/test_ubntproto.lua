-- Tests for openuf/ubntproto.lua: UniFi's AP-to-AP neighbour messages, heard
-- and never sent. Addresses are from the documentation range.
-- Run from project root: lua tests/run_tests.lua

local p = dofile("openuf/ubntproto.lua")
local crypto = dofile("openuf/crypto.lua")
p._crypto = crypto

local KEY = "000102030405060708090a0b0c0d0e0f"
local IV = string.rep(string.char(0x5a), 16)
local SENDER = string.char(0, 0, 0x5e, 0, 0x53, 0x10)

local function be32(n) return string.char(0, 0, math.floor(n / 256), n % 256) end
local function bss(last, op, ssid)
	return string.char(0, 0, 0x5e, 0, 0x53, last, op, 0x12) .. ssid
		.. string.rep(string.char(0), 32 - #ssid) .. string.char(#ssid)
end
local function body(channel, kind, entries)
	local b = SENDER .. be32(0) .. be32(channel) .. be32(kind) .. string.char(1, #entries)
		.. table.concat(entries)
	return b .. string.rep(string.char(0), 352 - #b)
end
local function frame(msg_type, plaintext, n)
	local ct = crypto.aes_cbc_encrypt(KEY, IV, plaintext)
	n = n or #ct
	local c = p.crc32(crypto.aes_cbc_decrypt_raw(KEY, IV, ct))
	local crc = string.char(math.floor(c / 16777216), math.floor(c / 65536) % 256,
		math.floor(c / 256) % 256, c % 256)
	return string.char(0x22, 0x33, 0x44, 0x55, 2, 2, math.floor(n / 256), n % 256, 0, msg_type, 0, 3)
		.. IV .. SENDER .. string.char(0, 0) .. crc .. ct
end

return {
	{
		name = "ubntproto: a neighbour message decodes to its sender, channel and BSSes",
		fn = function()
			local m = p.decode(frame(5, body(6, 2, {bss(1, 81, "home"), bss(2, 81, "guest net")})), KEY)
			assert_eq(m.sender, "00:00:5e:00:53:10", "the sender")
			assert_eq(m.kind, 2, "an answer")
			assert_eq(#m.entries, 2, "both BSSes")
			assert_eq(m.entries[1].bssid, "00:00:5e:00:53:01", "BSSID")
			assert_eq(m.entries[2].essid, "guest net", "SSID, by its length")
			assert_eq(m.entries[1].freq, 2437, "channel 6")
			m = p.decode(frame(5, body(124, 1, {bss(3, 121, "home")})), KEY)
			assert_eq(m.entries[1].freq, 5620, "channel 124")
			assert_eq(m.kind, 1, "a request")
		end
	},
	{
		name = "ubntproto: crc32 is zlib's",
		fn = function()
			assert_eq(p.crc32("123456789"), 0xCBF43926, "the standard check value")
			assert_eq(p.crc32(""), 0, "empty")
			assert_eq(p.crc32(string.rep(string.char(0), 4)), 0x2144DF1C, "zeros")
		end
	},
	{
		name = "ubntproto: anything else is ignored",
		fn = function()
			local good = frame(5, body(6, 2, {bss(1, 81, "home")}))
			assert_nil(p.decode(frame(1, body(6, 2, {bss(1, 81, "home")})), KEY), "another message type")
			assert_nil(p.decode("x" .. good:sub(2), KEY), "wrong magic")
			assert_nil(p.decode(good:sub(1, -2), KEY), "truncated")
			assert_nil(p.decode(good, "ffffffffffffffffffffffffffffffff"), "another site's key")
			assert_nil(p.decode(good:sub(1, 36) .. string.rep("x", 4) .. good:sub(41), KEY), "a wrong CRC")
			local last = good:byte(#good)
			assert_nil(p.decode(good:sub(1, -2) .. string.char((last + 1) % 256), KEY), "a corrupt block")
			assert_nil(p.parse_neighbours(body(6, 3, {bss(1, 81, "home")})), "unknown kind")
			assert_nil(p.parse_neighbours(string.rep(string.char(0), 19) .. string.char(200)), "count past the end")
			assert_eq(#p.parse_neighbours(body(1, 2, {bss(1, 131, "six")})).entries, 0, "6 GHz is left out")
			assert_nil(p.freq_of(81, 124), "a class and a channel that do not agree")
		end
	},
	{
		name = "ubntproto: drain reads what waits and never sends",
		fn = function()
			local q = {frame(5, body(6, 2, {bss(1, 81, "home")})), "junk", frame(5, body(11, 1, {bss(2, 81, "home")}))}
			local sent = 0
			p._sock = {receive = function() return table.remove(q, 1) end,
				send = function() sent = sent + 1 end, sendto = function() sent = sent + 1 end,
				close = function() end}
			local seen = {}
			assert_eq(p.drain(KEY, function(m) seen[#seen + 1] = m.channel end), 2, "the two valid ones")
			assert_eq(seen[2], 11, "in order")
			assert_eq(sent, 0, "nothing on the wire")
			p.close()
			assert_nil(p._sock, "closed")
		end
	},
	{
		name = "ubntproto: a joined socket is kept until the address changes",
		fn = function()
			local opened, o = 0, p._socket
			p._socket = function()
				return {udp = function()
					opened = opened + 1
					return {setoption = function() return 1 end, setsockname = function() return 1 end,
						settimeout = function() end, close = function() end}
				end}
			end
			assert_true(p.ensure("192.0.2.2", "239.254.127.63"), "joined")
			assert_true(p.ensure("192.0.2.2", "239.254.127.63"), "still")
			assert_eq(opened, 1, "one socket")
			p.ensure("192.0.2.3", "239.254.127.63")
			assert_eq(opened, 2, "reopened on a new address")
			p.close()
			p._socket = o
		end
	},
}
