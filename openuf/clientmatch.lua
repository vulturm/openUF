--[[
	Client steering by what the client hears (conf.lua client_steering).

	A client decides for itself when to roam, and many hold on to an AP long
	after another one would serve them better: a phone that joined in the
	hallway and sits at -78 dBm in a room whose own AP it would hear at -55.
	The AP's own reading of a client says how weak it is here, not where it
	would be better off -- only the client knows that. Aruba's ClientMatch and
	Cisco's optimized roaming steer from exactly that knowledge; this is the
	same with what 802.11k and 802.11v give every AP:

	  1. A client's signal here stays under FLOOR for HOLD seconds, it has been
	     associated for MIN_CONNECTED seconds, and it was not steered within
	     COOLDOWN.
	  2. It is asked for a beacon report (rrmscan.request) for its own
	     sub-band -- clients that can make one only (rrm capability bits) and
	     that take BSS Transition requests, at most once per REQUEST_GAP.
	  3. Its answer (rrmscan.harvest's per-station view) names a BSS of this
	     BSS's 802.11k neighbour list -- the site's other APs on the same SSID
	     and this AP's other band -- that the client hears DIFF_DB louder than
	     it hears this one, and above FLOOR.
	  4. It gets a BSS Transition request naming that BSS. Not "disassociation
	     imminent", and nothing follows it: a client that stays, stays. This
	     only tells a client what it could not see for itself.

	A WLAN under the controller's Roaming Assistant is roamassist.lua's, and
	while usteer steers (Band Steering) nothing is steered here at all
	(inform.lua builds the observations): a client is never pushed by two
	steerers that disagree, back and forth between the bands.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

M._popen = util.popen
M._exec = os.execute
M._read_file = util.read_file
M._load_cjson = function()
	local ok, mod = pcall(require, "cjson")
	return ok and mod or nil
end
M._log = function(msg) io.stderr:write("openuf: client steering: " .. msg .. "\n") end

M.FLOOR          = -70    -- dBm: weaker than this here is worth a look
M.DIFF_DB        = 8      -- the other BSS must be heard this much louder
M.HOLD           = 20     -- s under FLOOR before asking
M.MIN_CONNECTED  = 60     -- s associated before acting (a fresh join settles first)
M.COOLDOWN       = 300    -- s between steers of one client
M.REQUEST_GAP    = 120    -- s between beacon requests to one client
M.REPORT_MAX_AGE = 60     -- s a report is trusted for
M.FORGET         = 600    -- s unseen before a client's state is dropped
M.VALIDITY       = 100    -- beacon intervals the request holds

-- [mac] = {below_since, asked_at, acted_at, seen_at}
M._state = {}

local function is_ifname(s) return type(s) == "string" and s:match("^[%w%-%._]+$") ~= nil end
local function is_mac(s) return type(s) == "string" and s:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") ~= nil end

local function ubus_json(cmd)
	local cjson = M._load_cjson()
	if not cjson then return nil end
	local out = M._popen(cmd .. " 2>/dev/null")
	if not out or out == "" then return nil end
	local ok, t = pcall(cjson.decode, out)
	return ok and type(t) == "table" and t or nil
end

local function own_bssid(ifname)
	local raw = M._read_file("/sys/class/net/" .. ifname .. "/address")
	local mac = type(raw) == "string" and raw:match("(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
	return mac and mac:lower() or nil
end

-- The best neighbour for one client, or nil. heard: {[bssid] = {signal,
-- seen_at}} from its report; nr: this BSS's rrm_nr_list entries.
function M.pick(obs, heard, nr, own, now, diff_db, floor)
	diff_db, floor = diff_db or M.DIFF_DB, floor or M.FLOOR
	-- The client's own reading of this BSS, from the same report: the same
	-- receiver as the candidates. Without it there is no steer -- hostapd's
	-- reading is the client's uplink at the AP, and an AP transmits louder
	-- than a phone, so a neighbour as far away as this AP read ~10 dB
	-- "better" against it.
	local mine = own and heard[own]
	if not (mine and now - mine.seen_at <= M.REPORT_MAX_AGE) then return nil end
	local here = mine.signal
	local best, best_sig
	for _, e in ipairs(type(nr) == "table" and nr or {}) do
		local b, hex = type(e) == "table" and e[1], type(e) == "table" and e[3]
		local h = is_mac(b) and heard[b:lower()]
		if h and b:lower() ~= own and type(hex) == "string" and hex:match("^%x+$")
				and now - h.seen_at <= M.REPORT_MAX_AGE
				and h.signal >= floor and h.signal >= here + diff_db
				and (not best_sig or h.signal > best_sig) then
			best, best_sig = {bssid = b:lower(), nr = hex, signal = h.signal, here = here}, h.signal
		end
	end
	return best
end

-- The 802.11 operating class of a channel's 20 MHz sub-band (Annex E,
-- global classes): a beacon request for one class covers only its channels,
-- so a client on 100 asked for 115 (36-48) reports nothing near it. nil for a
-- channel this table does not know: no request then, rather than a wrong one.
function M.op_class(channel, band)
	local ch = tonumber(channel)
	if not ch then return nil end
	if band == "6e" then return (ch >= 1 and ch <= 233) and 131 or nil end
	if ch >= 1 and ch <= 13 then return 81 end
	if ch >= 36 and ch <= 48 then return 115 end
	if ch >= 52 and ch <= 64 then return 118 end
	if ch >= 100 and ch <= 144 then return 121 end
	if ch >= 149 and ch <= 165 then return 125 end
	return nil
end

-- One heartbeat. observations: {ifname, ssid, mac, signal, connected_sec}
-- for every client of a WLAN this module may steer. opts.reports: the
-- per-station view ({[mac] = {[bssid] = {signal, seen_at}}}); opts.request:
-- rrmscan.request; opts.capable(ifname): rrmscan.capable_stations;
-- opts.diff_db; opts.on_steer(mac). Returns the number of BTM requests sent.
function M.tick(observations, now, opts)
	opts = opts or {}
	local reports = opts.reports or {}
	local sent = 0
	local nr_cache, capable_cache, own_cache, btm_cache = {}, {}, {}, {}
	-- util.sta_btm per client of a BSS: a client that says it takes no BSS
	-- Transition request is neither asked for a report nor steered.
	local function btm_of(ifn, mac)
		if btm_cache[ifn] == nil then
			local t = ubus_json("ubus call hostapd." .. ifn .. " get_clients")
			local set = {}
			for m, e in pairs(t and type(t.clients) == "table" and t.clients or {}) do
				if type(m) == "string" then set[m:lower()] = util.sta_btm(e) ~= false end
			end
			btm_cache[ifn] = set
		end
		return btm_cache[ifn][mac] ~= false
	end
	local function nr_of(ifn)
		if nr_cache[ifn] == nil then
			local t = ubus_json("ubus call hostapd." .. ifn .. " rrm_nr_list")
			nr_cache[ifn] = t and type(t.list) == "table" and t.list or false
		end
		return nr_cache[ifn] or nil
	end
	local function capable(ifn, mac)
		if capable_cache[ifn] == nil then
			local set = {}
			local ok, list = pcall(opts.capable or function() return {} end, ifn)
			for _, m in ipairs(ok and type(list) == "table" and list or {}) do set[m:lower()] = true end
			capable_cache[ifn] = set
		end
		return capable_cache[ifn][mac] or false
	end
	for _, o in ipairs(observations or {}) do
		local mac = is_mac(o.mac) and o.mac:lower()
		local signal = tonumber(o.signal)
		if mac and is_ifname(o.ifname) and signal then
			local cs = M._state[mac] or {}
			M._state[mac] = cs
			cs.seen_at = now
			if signal >= M.FLOOR then
				cs.below_since = nil
			else
				cs.below_since = cs.below_since or now
				local ready = now - cs.below_since >= M.HOLD
					and (tonumber(o.connected_sec) or 0) >= M.MIN_CONNECTED
					and (not cs.acted_at or now - cs.acted_at >= M.COOLDOWN)
					and btm_of(o.ifname, mac)
				if ready then
					own_cache[o.ifname] = own_cache[o.ifname] or own_bssid(o.ifname) or false
					local own = own_cache[o.ifname] or nil
					local best = M.pick(o, reports[mac] or {}, nr_of(o.ifname), own, now, opts.diff_db)
					if best then
						if opts.on_steer then pcall(opts.on_steer, mac) end
						M._exec(string.format(
							"ubus call hostapd.%s bss_transition_request " ..
							"'{\"addr\":\"%s\",\"disassociation_imminent\":false,\"abridged\":true," ..
							"\"validity_period\":%d,\"dialog_token\":1,\"neighbors\":[\"%s\"]}' >/dev/null 2>&1",
							o.ifname, mac, M.VALIDITY, best.nr))
						cs.acted_at = now
						sent = sent + 1
						M._log(("%s on %s hears %s at %d dBm, here at %d: asked to move there")
							:format(mac, o.ifname, best.bssid, best.signal, best.here))
					elseif (not cs.asked_at or now - cs.asked_at >= M.REQUEST_GAP)
							and opts.request and o.op_class and capable(o.ifname, mac) then
						cs.asked_at = now
						pcall(opts.request, o.ifname, mac, {op_class = o.op_class})
					end
				end
			end
		end
	end
	for mac, cs in pairs(M._state) do
		if now - (cs.seen_at or 0) > M.FORGET then M._state[mac] = nil end
	end
	return sent
end

return M
