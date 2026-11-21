--[[
	Clients off a BSS before a `wifi reload` restarts it.

	A reload that changes a radio (country, channel, width) or a WLAN restarts
	those BSSes, and hostapd's 802.11r keys live only in its memory: every
	PMK-R0 it held for its clients is gone with the restart. A client that
	then roams by FT to a UniFi AP asks this AP for its key, gets nothing, and
	falls back to a full login. On a hAP ac (2026-11-21) the S10 tried FT
	three times on the U7 after a reload here, then ran into PSK-MISMATCH on
	the U7's private-PSK WLAN and was dropped.

	So before such a reload, each client of a BSS that will restart is sent a
	BSS Transition request (802.11v, disassociation imminent) naming the
	BSS's 802.11k neighbours, and the reload waits up to WAIT seconds for the
	clients to leave. They roam while this AP still holds their keys -- the
	way Cisco and Aruba move clients off an AP before upgrading it. A client
	without 802.11v ignores the request and is dropped by the reload, as
	before.

	Only what the reload restarts is touched: the wireless config before the
	push and just before the reload are compared section by section, and a
	push that changes nothing (most of them) sends nothing. Neighbours that
	restart in the same reload are left out of the candidates.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

M._popen = util.popen
M._exec = os.execute
M._read_file = util.read_file
M._sleep = function(s) os.execute("sleep " .. tonumber(s)) end
M._load_cjson = function()
	local ok, mod = pcall(require, "cjson")
	return ok and mod or nil
end
M._log = function(msg) io.stderr:write("openuf: handover: " .. msg .. "\n") end

-- Seconds the reload waits, at most, for the clients to leave. A dozing
-- phone hears the request at its next DTIM wake-up and an FT roam takes a
-- few tens of ms, so a few seconds cover them; a client that stays is
-- dropped by the reload anyway.
M.WAIT = 4
-- How long the request holds, in beacon intervals (~100 ms each).
M.VALIDITY = 100

local function ubus_json(cmd)
	local cjson = M._load_cjson()
	if not cjson then return nil end
	local out = M._popen(cmd .. " 2>/dev/null")
	if not out or out == "" then return nil end
	local ok, t = pcall(cjson.decode, out)
	return ok and type(t) == "table" and t or nil
end

local function is_ifname(s) return type(s) == "string" and s:match("^[%w%-%._]+$") ~= nil end
local function is_mac(s) return type(s) == "string" and s:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") ~= nil end

-- One string per section of /etc/config/wireless, from a uci cursor's
-- get_all: what a restart depends on, independent of the order pairs() walks.
function M.snapshot(cursor)
	local out = {}
	local all = cursor and cursor.get_all and cursor:get_all("wireless")
	for name, s in pairs(type(all) == "table" and all or {}) do
		local keys = {}
		for k in pairs(s) do
			if k == ".type" or k:sub(1, 1) ~= "." then keys[#keys + 1] = k end
		end
		table.sort(keys)
		local parts = {}
		for _, k in ipairs(keys) do
			local v = s[k]
			if type(v) == "table" then v = table.concat(v, "\1") end
			parts[#parts + 1] = k .. "=" .. tostring(v)
		end
		out[name] = {type = s[".type"], device = s.device, sig = table.concat(parts, "\0")}
	end
	return out
end

-- Whether anything in the wireless config differs (most pushes: nothing).
function M.changed(before, after)
	for name, b in pairs(before or {}) do
		local a = after and after[name]
		if not a or a.sig ~= b.sig then return true end
	end
	for name in pairs(after or {}) do
		if not (before and before[name]) then return true end
	end
	return false
end

-- The live AP netdevs a reload from `before` to `after` restarts, from netifd's
-- `network.wireless status` (taken before the reload). A radio that changed
-- takes all its BSSes; a WLAN that changed (or came or went) its own.
function M.affected(before, after, status)
	local radios, sections = {}, {}
	local seen = {}
	local function mark(name)
		if seen[name] then return end
		seen[name] = true
		local b, a = before[name], after[name]
		if b and a and b.sig == a.sig then return end
		local e = a or b
		if e.type == "wifi-device" then radios[name] = true
		elseif e.type == "wifi-iface" then
			sections[name] = true
			-- A WLAN moved between radios restarts on both.
			if b and a and b.device ~= a.device then
				if b.device then radios[b.device] = true end
				if a.device then radios[a.device] = true end
			end
		end
	end
	for name in pairs(before or {}) do mark(name) end
	for name in pairs(after or {}) do mark(name) end
	local out, have = {}, {}
	for radio, dev in pairs(type(status) == "table" and status or {}) do
		for _, i in ipairs(type(dev) == "table" and type(dev.interfaces) == "table" and dev.interfaces or {}) do
			local mode = type(i) == "table" and type(i.config) == "table" and i.config.mode or "ap"
			if type(i) == "table" and mode == "ap" and is_ifname(i.ifname)
					and (radios[radio] or sections[i.section]) and not have[i.ifname] then
				have[i.ifname] = true
				out[#out + 1] = i.ifname
			end
		end
	end
	table.sort(out)
	return out
end

local function bssid_of(ifname)
	local raw = M._read_file("/sys/class/net/" .. ifname .. "/address")
	local mac = type(raw) == "string" and raw:match("(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
	return mac and mac:lower() or nil
end

-- The BSS's clients, and of those the ones that may answer a BSS Transition
-- request (util.sta_btm: capable, or hostapd too old to say). Only those are
-- waited for: one without 802.11v never leaves, and held every push that
-- touched its WLAN up for the whole WAIT.
local function clients_of(ifname)
	local t = ubus_json("ubus call hostapd." .. ifname .. " get_clients")
	local all, btm = {}, {}
	for mac, e in pairs(t and type(t.clients) == "table" and t.clients or {}) do
		if is_mac(mac) then
			all[#all + 1] = mac:lower()
			if util.sta_btm(e) ~= false then btm[#btm + 1] = mac:lower() end
		end
	end
	table.sort(all)
	table.sort(btm)
	return all, btm
end

-- Ask the clients of `ifnames` to leave, then wait for them. Returns the
-- number of clients asked and the number still there when the wait ended.
function M.run(ifnames)
	if type(ifnames) ~= "table" or #ifnames == 0 then return 0, 0 end
	local restarting = {}
	for _, ifn in ipairs(ifnames) do
		local b = bssid_of(ifn)
		if b then restarting[b] = true end
	end
	local asked, watch = 0, {}
	for _, ifn in ipairs(ifnames) do
		local _, clients = clients_of(ifn)
		if #clients > 0 then
			local nr = ubus_json("ubus call hostapd." .. ifn .. " rrm_nr_list")
			local cands = {}
			for _, e in ipairs(nr and type(nr.list) == "table" and nr.list or {}) do
				local b, hex = type(e) == "table" and e[1], type(e) == "table" and e[3]
				if is_mac(b) and not restarting[b:lower()]
						and type(hex) == "string" and hex:match("^%x+$") then
					cands[#cands + 1] = '"' .. hex .. '"'
				end
			end
			-- Nowhere to send them: the reload drops them as it always did.
			if #cands > 0 then
				for _, mac in ipairs(clients) do
					M._exec(string.format(
						"ubus call hostapd.%s bss_transition_request " ..
						"'{\"addr\":\"%s\",\"disassociation_imminent\":true," ..
						"\"disassociation_timer\":%d,\"abridged\":true,\"validity_period\":%d," ..
						"\"dialog_token\":1,\"neighbors\":[%s]}' >/dev/null 2>&1",
						ifn, mac, M.WAIT * 10, M.VALIDITY, table.concat(cands, ",")))
					asked = asked + 1
				end
				watch[#watch + 1] = ifn
			end
		end
	end
	if asked == 0 then return 0, 0 end
	local left = asked
	for _ = 1, M.WAIT do
		M._sleep(1)
		left = 0
		for _, ifn in ipairs(watch) do left = left + #select(2, clients_of(ifn)) end
		if left == 0 then break end
	end
	M._log(("%d client(s) of %s asked to roam before the reload; %d still here")
		:format(asked, table.concat(watch, " "), left))
	return asked, left
end

return M
