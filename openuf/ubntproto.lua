--[[
	Listens to the neighbour messages UniFi APs send each other, and sends none.

	wevent keeps each AP's list of its siblings' channels (/proc/ui_neighbor)
	from `ubnt_protocol`: UDP 48000 on the site's `unifi.mcip`, AES-128-CBC
	under `unifi.key`, both pushed by the controller. An AP that comes up or
	changes channel asks (kind 1) and every sibling answers (kind 2), each with
	its band's BSSes. Read off BZ2.8.8.14 and a capture of two U7s:

	  frame    0  22 33 44 55, 02 02
	           6  ciphertext length (u16 BE), 8 message type (u16 BE)
	          12  IV (16), 28 sender's serial (6), 34 zero (2),
	          36  CRC-32 of the plaintext, padding included (u32 BE)
	          40  ciphertext
	  type 5   0  serial asked or answered (6)
	           6  band (u32), 10 channel (u32 BE), 14 kind (u32 BE)
	          18  not understood, 19 BSS count
	          20  per BSS, 41 bytes: BSSID (6), operating class, one byte not
	              understood, SSID (32, NUL-padded), SSID length

	It tells openUF a sibling's channel the moment it changes, and names a
	sibling on a band this AP cannot sweep (a wireless uplink's radio). The
	other message types are clients' roams and are ignored.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

M.PORT       = 48000
M.HEADER_LEN = 40
M.TYPE_NEIGHBOURS = 5
M.ENTRY_LEN  = 41
M.MAX_FRAMES = 32     -- read per heartbeat
-- Siblings say this only when something changes, so it is remembered longer
-- than a scan's sighting (nrlist.REMEMBER).
M.KEEP       = 86400

M._crypto = nil       -- set by inform.lua
M._socket = function() return require("socket") end
M._sock, M._ip, M._group, M._err = nil, nil, nil, nil

local MAGIC = string.char(0x22, 0x33, 0x44, 0x55, 0x02, 0x02)

local function u16(s, i) return s:byte(i) * 256 + s:byte(i + 1) end
local function u32(s, i) return u16(s, i) * 65536 + u16(s, i + 2) end
local function mac(s, i)
	return string.format("%02x:%02x:%02x:%02x:%02x:%02x", s:byte(i, i + 5))
end

-- The CRC-32 zlib computes (polynomial 0xEDB88320), as an unsigned number.
local crc_table
function M.crc32(s)
	local bit = util.bit()
	if not crc_table then
		crc_table = {}
		for i = 0, 255 do
			local c = i
			for _ = 1, 8 do
				if c % 2 == 1 then c = bit.bxor(bit.rshift(c, 1), 0xEDB88320)
				else c = bit.rshift(c, 1) end
			end
			crc_table[i] = c
		end
	end
	local c = bit.bnot(0)
	for i = 1, #s do
		c = bit.bxor(bit.rshift(c, 8), crc_table[bit.band(bit.bxor(c, s:byte(i)), 0xFF)])
	end
	return bit.bnot(c) % 4294967296
end

-- {type, sender, crc, iv, ciphertext}, or nil for anything not of this shape.
function M.parse_frame(f)
	if type(f) ~= "string" or #f <= M.HEADER_LEN or f:sub(1, 6) ~= MAGIC then return nil end
	local n = u16(f, 7)
	if n == 0 or n % 16 ~= 0 or #f ~= M.HEADER_LEN + n then return nil end
	return {type = u16(f, 9), sender = mac(f, 29), crc = u32(f, 37), iv = f:sub(13, 28),
		ciphertext = f:sub(41)}
end

-- MHz of a 20 MHz channel from its global operating class. nil for 6 GHz, whose
-- classes this message was never seen with.
function M.freq_of(op_class, channel)
	if op_class >= 81 and op_class <= 82 and channel >= 1 and channel <= 14 then
		return channel == 14 and 2484 or 2407 + 5 * channel
	end
	if op_class >= 115 and op_class <= 130 and channel >= 32 and channel <= 177 then
		return 5000 + 5 * channel
	end
	return nil
end

-- {channel, kind, entries = {{bssid, essid, freq}}} from a type 5 plaintext, or
-- nil. A BSS that does not parse is left out.
function M.parse_neighbours(p)
	if type(p) ~= "string" or #p < 20 then return nil end
	local channel, kind, count = u32(p, 11), u32(p, 15), p:byte(20)
	if (kind ~= 1 and kind ~= 2) or count == 0 or 20 + count * M.ENTRY_LEN > #p then return nil end
	local out = {channel = channel, kind = kind, entries = {}}
	for i = 0, count - 1 do
		local at = 21 + i * M.ENTRY_LEN
		local len = p:byte(at + 40)
		local freq = M.freq_of(p:byte(at + 6), channel)
		if freq and len >= 1 and len <= 32 then
			out.entries[#out.entries + 1] = {bssid = mac(p, at), essid = p:sub(at + 8, at + 7 + len),
				channel = channel, freq = freq}
		end
	end
	return out
end

-- A frame's neighbour message with its sender, or nil.
function M.decode(frame, key_hex)
	local f = M.parse_frame(frame)
	if not (f and f.type == M.TYPE_NEIGHBOURS and M._crypto) then return nil end
	local ok, p = pcall(M._crypto.aes_cbc_decrypt_raw, key_hex, f.iv, f.ciphertext)
	-- CBC has no integrity of its own: a corrupt frame, or one under another
	-- key, decrypts to noise that could still look like a BSS list.
	if not (ok and type(p) == "string" and M.crc32(p) == f.crc) then return nil end
	local msg = M.parse_neighbours(p)
	if msg then msg.sender = f.sender end
	return msg
end

function M.close()
	if M._sock then pcall(M._sock.close, M._sock) end
	M._sock, M._ip, M._group = nil, nil, nil
end

-- Joined on ip's interface, reopened when the address or the group changes.
function M.ensure(ip, group)
	if M._sock and M._ip == ip and M._group == group then return true end
	M.close()
	local udp = M._socket().udp()
	if not udp then return false end
	udp:setoption("reuseaddr", true)
	local bound, err = udp:setsockname(group, M.PORT)
	local joined
	if bound then
		joined, err = udp:setoption("ip-add-membership", {multiaddr = group, interface = ip})
	end
	if not (bound and joined) then
		udp:close()
		if M._err ~= tostring(err) then
			M._err = tostring(err)
			io.stderr:write("openuf: ubntproto: cannot listen on " .. group .. ": " .. M._err .. "\n")
		end
		return false
	end
	udp:settimeout(0)
	M._sock, M._ip, M._group, M._err = udp, ip, group, nil
	return true
end

-- Every neighbour message waiting, as on_message(msg).
function M.drain(key_hex, on_message)
	local n = 0
	for _ = 1, M.MAX_FRAMES do
		local frame = M._sock and M._sock:receive()
		if not frame then break end
		local msg = M.decode(frame, key_hex)
		if msg then n = n + 1; on_message(msg) end
	end
	return n
end

return M
