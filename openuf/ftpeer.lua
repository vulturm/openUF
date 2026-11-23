--[[
	rrb-unifi's ft_peer list, kept from what this AP hears, and kept per SSID.

	hostapd pushes a client's PMK-R1 (pmk_r1_push) only to key holders it
	has an explicit r1kh entry for, never to the wildcard -- and UniFi APs
	configure only the wildcard, so without explicit entries a client that
	roams from here to a UniFi AP has to wait for that AP to pull its key,
	and a pull that finds this AP restarted (its keys gone) is a full login.
	rrb-unifi writes those entries from `rrb-unifi.main.ft_peer`
	("<bssid>,<r0kh-id>"); by hand, nobody keeps that list up to date.

	The site's UniFi APs beacon their element (nrlist.lua's siblings), with
	SSID and BSSID. Every sibling BSS whose SSID is one of this AP's 802.11r
	WLANs is a peer; its R0KH-ID is the BSSID without colons (UniFi's
	nas_identifier). A peer stays KEEP after it was last heard: a scan that
	misses it must not rewrite the list, because a new list is a `wifi
	reload` of every 802.11r WLAN, and that drops their keys. Entries in the
	list that this module never learned (written by hand) are left alone.

	rrb-unifi puts the one list on every WLAN, so AP-guest pushed its
	clients' keys to the eG BSSIDs too. Those cannot use them -- another
	WLAN's key wraps them and another mobility domain binds them -- but they
	have no business getting them either: filter() keeps, per WLAN, only the
	peers heard on that SSID. The store remembers each peer's SSID across a
	reboot, which nrlist's /tmp store does not.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

M.STORE   = "/etc/openuf/ft-peers.json"
M.KEEP    = 7 * 86400   -- s a peer stays after it was last heard
M.REFRESH = 86400       -- s a peer's last-heard time may lag on flash
M.RRB     = "rrb-unifi"
M.ENABLED = "/etc/openuf/plugins.enabled"

M._read_file = util.read_file
M._write_file = util.write_atomic
M._load_cjson = function()
	local ok, mod = pcall(require, "cjson")
	return ok and mod or nil
end

local function nasid(bssid) return (bssid:gsub(":", "")) end

-- Whether rrb-unifi is enabled (plugins.lua's list): without it nothing
-- reads ft_peer.
function M.plugin_enabled()
	for line in (M._read_file(M.ENABLED) or ""):gmatch("[^\n]+") do
		if line:match("^%s*rrb%-unifi%s*$") then return true end
	end
	return false
end

-- {[bssid] = {ssid, at}} from the store; {} when there is none.
function M.load()
	local cjson = M._load_cjson()
	local raw = M._read_file(M.STORE)
	local out = {}
	if not (cjson and raw and raw ~= "") then return out end
	local ok, t = pcall(cjson.decode, raw)
	for b, e in pairs(ok and type(t) == "table" and t or {}) do
		if util.is_mac(b) and type(e) == "table" and type(e.ssid) == "string"
				and tonumber(e.at) then
			out[b:lower()] = {ssid = e.ssid, at = tonumber(e.at)}
		end
	end
	return out
end

function M.save(map)
	local cjson = M._load_cjson()
	if not cjson then return false end
	local ok, js = pcall(cjson.encode, map)
	return ok and M._write_file(M.STORE, js) or false
end

-- The SSIDs of the 802.11r WLANs in /etc/config/wireless.
function M.ft_ssids(cursor)
	local out = {}
	if not (cursor and cursor.foreach) then return out end
	cursor:foreach("wireless", "wifi-iface", function(s)
		if s.ieee80211r == "1" and s.disabled ~= "1" and (s.mode or "ap") == "ap"
				and type(s.ssid) == "string" and s.ssid ~= "" then
			out[s.ssid] = true
		end
	end)
	return out
end

-- The peers from `map` refreshed by `seen` (nrlist._seen) and aged out.
-- Returns the new map, whether it differs from `map` enough to be written
-- (a peer came, went or changed SSID, or its time moved REFRESH), and the
-- peers that went: their entries leave the list, which would otherwise keep
-- them as hand-written ones. The fourth value: a peer came, went or changed
-- SSID, which changes what filter() leaves on a WLAN.
function M.merge(map, seen, ssids, own, now)
	local out, dirty, gone, moved = {}, false, {}, false
	for b, e in pairs(map or {}) do
		if now - e.at <= M.KEEP and not own[b] then
			out[b] = {ssid = e.ssid, at = e.at}
		else
			dirty, gone[b], moved = true, true, true
		end
	end
	for b, e in pairs(seen or {}) do
		b = type(b) == "string" and b:lower()
		if util.is_mac(b) and type(e) == "table" and ssids[e.ssid] and not own[b]
				and tonumber(e.at) and now - e.at <= M.KEEP then
			local cur = out[b]
			if not cur or cur.ssid ~= e.ssid then
				out[b], dirty, gone[b], moved = {ssid = e.ssid, at = e.at}, true, nil, true
			elseif e.at > cur.at then
				if e.at - cur.at >= M.REFRESH then dirty = true end
				cur.at = e.at
			end
		end
	end
	return out, dirty, gone, moved
end

-- The ft_peer list for `map`: one entry per peer, plus every entry of
-- `current` whose BSSID this module does not know (written by hand) and
-- that is not one of the peers `gone`. Sorted.
function M.list_for(map, current, gone)
	local out, have = {}, {}
	for b in pairs(map) do
		out[#out + 1] = b .. "," .. nasid(b)
		have[b] = true
	end
	for _, e in ipairs(current or {}) do
		local b = tostring(e):match("^%s*([^,%s]+)")
		b = b and b:lower()
		if not (b and (have[b] or (gone and gone[b]))) then out[#out + 1] = tostring(e) end
	end
	table.sort(out)
	return out
end

local function as_list(v)
	if type(v) == "table" then return v end
	if type(v) == "string" and v ~= "" then return {v} end
	return {}
end

local function same(a, b)
	if #a ~= #b then return false end
	local s = {}
	for _, v in ipairs(a) do s[v] = (s[v] or 0) + 1 end
	for _, v in ipairs(b) do
		if not s[v] or s[v] == 0 then return false end
		s[v] = s[v] - 1
	end
	return true
end

-- The last map tick() worked from, and what of it is on flash.
M._map = nil
-- The first pass of a process also asks for a rewrite, a deferred one: what
-- the WLANs carry was cut by whatever ran before (an older openUF, a store
-- written by a previous run).
M._first = true

-- One pass: refresh the peers from `seen`, write the store when it moved,
-- and rrb-unifi's ft_peer when the list changed. Returns:
--   changed  the list changed: the WLANs need the new key holders now
--   list     the list
--   pending  the list is the same, but a peer's SSID was learned (or this is
--            the first pass): only filter()'s per-WLAN cut moves, and that
--            can wait for a reload that comes anyway -- every reload drops
--            the 802.11r keys of the clients this AP authenticated, and a
--            phone that authenticated here could then roam back by FT no
--            more (xan-bc: the key was asked for five times, and nobody had
--            it).
function M.tick(cursor, seen, own, now)
	if not M.plugin_enabled() then return false end
	if not (cursor and cursor.get and cursor.set) then return false end
	M._map = M._map or M.load()
	local map, dirty, gone, moved = M.merge(M._map, seen, M.ft_ssids(cursor), own or {}, now)
	M._map = map
	if dirty then M.save(map) end
	local current = as_list(cursor:get(M.RRB, "main", "ft_peer"))
	local want = M.list_for(map, current, gone)
	local first = M._first
	M._first = false
	if same(current, want) then return false, want, moved or first end
	if not cursor:get(M.RRB, "main") then cursor:set(M.RRB, "main", "rrb") end
	if #want > 0 then
		cursor:set(M.RRB, "main", "ft_peer", want)
	else
		cursor:delete(M.RRB, "main", "ft_peer")
	end
	cursor:commit(M.RRB)
	return true, want
end

-- After rrb-unifi wrote a WLAN's r0kh/r1kh: drop the explicit entries of
-- peers heard on another SSID. The wildcards and entries this module does
-- not know stay. `map` defaults to the store.
function M.filter(extra, ssid, map)
	if type(extra) ~= "table" then return 0 end
	map = map or M.load()
	local dropped = 0
	for _, k in ipairs({"r0kh", "r1kh"}) do
		if type(extra[k]) == "table" then
			local keep = {}
			for _, e in ipairs(extra[k]) do
				local b = type(e) == "string" and e:match("^([^,]+)")
				local p = b and map[b:lower()]
				if p and p.ssid ~= ssid then
					dropped = dropped + 1
				else
					keep[#keep + 1] = e
				end
			end
			extra[k] = keep
		end
	end
	return dropped
end

return M
