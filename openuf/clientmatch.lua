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
	  2. It is asked for beacon reports (rrmscan.request) on its own channel and
	     on each channel of this BSS's 802.11k neighbour list, one channel per
	     heartbeat -- clients that can make one only (rrm capability bits) and
	     that take BSS Transition requests, at most one round per REQUEST_GAP.
	     A request names one operating class, and a client on 36 asked for
	     its own never measured a parent on 124 or anything on 2.4 GHz.
	  3. Its answers (rrmscan.harvest's per-station view) name a BSS of that
	     list -- the site's other APs on the same SSID and this AP's other
	     band -- that the client hears DIFF_DB louder than it hears this one,
	     and above FLOOR. Never a lower band: 2.4 GHz carries further, so a
	     5 GHz client at -72 nearly always hears it 8 dB louder and would be
	     moved to the slower band for it.
	  4. It gets a BSS Transition request naming that BSS. Not "disassociation
	     imminent", and nothing follows it: a client that stays, stays. This
	     only tells a client what it could not see for itself.

	A client on 2.4 GHz with a good signal is never under FLOOR, and a phone
	that joined there can stay for hours next to a clear 5 GHz cell. So one on
	2.4 GHz is also asked about the higher bands' channels of the list, and a
	BSS it hears at UP_FLOOR or better gets the same request. 5 GHz reads
	weaker than 2.4 from the same spot, so this has no DIFF_DB. A 2.4 GHz-only
	device answers such a request with nothing: its rounds back off, from
	UP_GAP doubling up to UP_GAP_MAX.

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
M.REPORT_MAX_AGE = 120    -- s a report is trusted for: a round of MAX_CHANNELS at a ~20 s heartbeat
M.MAX_CHANNELS   = 5      -- channels measured in one round, the client's own included
M.FORGET         = 600    -- s unseen before a client's state is dropped
M.VALIDITY       = 100    -- beacon intervals the request holds
M.UP_FLOOR       = -65    -- dBm: a higher band heard this well is worth moving to
M.UP_GAP         = 900    -- s between rounds about the higher bands, doubling
M.UP_GAP_MAX     = 21600  -- s: where that doubling stops

-- [mac] = {below_since, asked_at, asking, round, up_at, up_gap, acted_at,
-- seen_at}; asking: the round's channels still to request; round: "weak" or
-- "up", which of the two rounds they belong to.
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

-- Operating class and channel of a neighbour report element: BSSID (6 bytes),
-- BSSID information (4), then one byte each.
local function nr_channel(hex)
	if type(hex) ~= "string" or #hex < 26 or not hex:match("^%x+$") then return nil end
	return tonumber(hex:sub(21, 22), 16), tonumber(hex:sub(23, 24), 16)
end

-- 1 = 2.4 GHz, 2 = 5 GHz, 3 = 6 GHz, by global operating class; nil unknown.
local function band_rank(op)
	if not op then return nil end
	if op >= 81 and op <= 84 then return 1 end
	if op >= 115 and op <= 130 then return 2 end
	if op >= 131 and op <= 137 then return 3 end
	return nil
end

-- The round of beacon requests for one client: its own channel first, then
-- each distinct channel of a neighbour it could be steered to. Empty with no
-- such neighbour: nothing to compare, so no client is sent off-channel.
-- higher_only: the higher bands' channels alone, for pick_up.
function M.channels_to_ask(o, nr, own, higher_only)
	local rank, ch = band_rank(o.op_class), tonumber(o.channel)
	if not (rank and ch) then return {} end
	local out, seen = {{op_class = o.op_class, channel = ch}}, {[o.op_class .. "/" .. ch] = true}
	if higher_only then out = {} end
	local any = false
	for _, e in ipairs(type(nr) == "table" and nr or {}) do
		local b = type(e) == "table" and e[1]
		local op, c = nr_channel(type(e) == "table" and e[3])
		local r = band_rank(op)
		if is_mac(b) and b:lower() ~= own and c and r and (r > rank or (r == rank and not higher_only)) then
			any = true
			local key = op .. "/" .. c
			if not seen[key] and #out < M.MAX_CHANNELS then
				seen[key] = true
				out[#out + 1] = {op_class = op, channel = c}
			end
		end
	end
	return any and out or {}
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
	local rank = band_rank(obs.op_class)
	if not rank then return nil end
	local best, best_sig
	for _, e in ipairs(type(nr) == "table" and nr or {}) do
		local b, hex = type(e) == "table" and e[1], type(e) == "table" and e[3]
		local h = is_mac(b) and heard[b:lower()]
		local there = band_rank((nr_channel(hex)))
		if h and b:lower() ~= own and there and there >= rank
				and now - h.seen_at <= M.REPORT_MAX_AGE
				and h.signal >= floor and h.signal >= here + diff_db
				and (not best_sig or h.signal > best_sig) then
			best, best_sig = {bssid = b:lower(), nr = hex, signal = h.signal, here = here}, h.signal
		end
	end
	return best
end

-- The loudest listed BSS of a higher band that a 2.4 GHz client hears at
-- UP_FLOOR or better, or nil.
function M.pick_up(obs, heard, nr, own, now)
	if band_rank(obs.op_class) ~= 1 then return nil end
	local best, best_sig
	for _, e in ipairs(type(nr) == "table" and nr or {}) do
		local b, hex = type(e) == "table" and e[1], type(e) == "table" and e[3]
		local h = is_mac(b) and heard[b:lower()]
		local there = band_rank((nr_channel(hex)))
		if h and b:lower() ~= own and there and there > 1
				and now - h.seen_at <= M.REPORT_MAX_AGE and h.signal >= M.UP_FLOOR
				and (not best_sig or h.signal > best_sig) then
			best, best_sig = {bssid = b:lower(), nr = hex, signal = h.signal}, h.signal
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
	local function own_of(ifn)
		if own_cache[ifn] == nil then own_cache[ifn] = own_bssid(ifn) or false end
		return own_cache[ifn] or nil
	end
	local function steer(o, mac, cs, best, what)
		if opts.on_steer then pcall(opts.on_steer, mac) end
		M._exec(string.format(
			"ubus call hostapd.%s bss_transition_request " ..
			"'{\"addr\":\"%s\",\"disassociation_imminent\":false,\"abridged\":true," ..
			"\"validity_period\":%d,\"dialog_token\":1,\"neighbors\":[\"%s\"]}' >/dev/null 2>&1",
			o.ifname, mac, M.VALIDITY, best.nr))
		cs.acted_at, cs.asking, cs.round = now, nil, nil
		sent = sent + 1
		M._log(("%s on %s hears %s at %d dBm, %s: asked to move there")
			:format(mac, o.ifname, best.bssid, best.signal, what))
	end
	-- One per heartbeat: a client measures one request at a time, and each
	-- takes it off its channel.
	local function next_request(o, mac, cs)
		if not cs.asking then return end
		pcall(opts.request, o.ifname, mac, table.remove(cs.asking, 1))
		if #cs.asking == 0 then cs.asking = nil end
	end
	for _, o in ipairs(observations or {}) do
		local mac = is_mac(o.mac) and o.mac:lower()
		local signal = tonumber(o.signal)
		if mac and is_ifname(o.ifname) and signal then
			local cs = M._state[mac] or {}
			M._state[mac] = cs
			cs.seen_at = now
			local settled = (tonumber(o.connected_sec) or 0) >= M.MIN_CONNECTED
				and (not cs.acted_at or now - cs.acted_at >= M.COOLDOWN)
			if signal >= M.FLOOR then
				cs.below_since = nil
				if cs.round == "weak" then cs.asking, cs.round = nil, nil end
				-- The time gates first: this runs for every 2.4 GHz client on
				-- every heartbeat, and btm_of is a ubus call.
				local due = not cs.up_at or now - cs.up_at >= (cs.up_gap or M.UP_GAP)
				local answering = cs.up_at and now - cs.up_at <= M.REPORT_MAX_AGE
				if band_rank(o.op_class) == 1 and settled and (cs.asking or due or answering)
						and btm_of(o.ifname, mac) then
					local own = own_of(o.ifname)
					local best = not cs.asking
						and M.pick_up(o, reports[mac] or {}, nr_of(o.ifname), own, now)
					if best then
						steer(o, mac, cs, best, ("here at %d, on 2.4 GHz"):format(signal))
					else
						if not cs.asking and due and opts.request and capable(o.ifname, mac) then
							local round = M.channels_to_ask(o, nr_of(o.ifname), own, true)
							if #round > 0 then
								cs.up_at, cs.asking, cs.round = now, round, "up"
								cs.up_gap = math.min((cs.up_gap or M.UP_GAP / 2) * 2, M.UP_GAP_MAX)
							end
						end
						next_request(o, mac, cs)
					end
				end
			else
				if cs.round == "up" then cs.asking, cs.round = nil, nil end
				cs.below_since = cs.below_since or now
				local ready = now - cs.below_since >= M.HOLD and settled and btm_of(o.ifname, mac)
				if ready then
					local own = own_of(o.ifname)
					-- Not in the middle of a round: the first channel to answer
					-- is not yet the best one.
					local best = not cs.asking
						and M.pick(o, reports[mac] or {}, nr_of(o.ifname), own, now, opts.diff_db)
					if best then
						steer(o, mac, cs, best, ("here at %d"):format(best.here))
					else
						if not cs.asking and (not cs.asked_at or now - cs.asked_at >= M.REQUEST_GAP)
								and opts.request and capable(o.ifname, mac) then
							local round = M.channels_to_ask(o, nr_of(o.ifname), own)
							if #round > 0 then cs.asked_at, cs.asking, cs.round = now, round, "weak" end
						end
						next_request(o, mac, cs)
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
