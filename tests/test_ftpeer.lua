-- Tests for openuf/ftpeer.lua: rrb-unifi's ft_peer list from the sibling
-- BSSes heard, and the per-SSID cut. Run from project root: lua tests/run_tests.lua

local ftpeer = dofile("openuf/ftpeer.lua")

local U7G, U7E = "b2:9c:6c:b8:ab:7f", "a8:9c:6c:b8:ab:7f"
local RMG, FOREIGN = "8e:78:48:06:03:fc", "76:ac:b9:11:22:33"

local function wireless()
	return {
		{ssid = "AP-guest", ieee80211r = "1", mode = "ap"},
		{ssid = "eG", ieee80211r = "1"},
		{ssid = "plain"},
		{ssid = "off", ieee80211r = "1", disabled = "1"},
	}
end

-- A uci cursor over a wireless list and an rrb-unifi main section.
local function cursor(ft_peer)
	local c = {rrb = {main = ft_peer and {ft_peer = ft_peer} or {}}, commits = 0}
	function c:foreach(cfg, typ, fn)
		if cfg == "wireless" and typ == "wifi-iface" then
			for _, s in ipairs(wireless()) do fn(s) end
		end
	end
	function c:get(cfg, sec, opt)
		if cfg ~= "rrb-unifi" then return nil end
		local s = self.rrb[sec]
		if not opt then return s and "rrb" or nil end
		return s and s[opt]
	end
	function c:set(cfg, sec, opt, v)
		if v == nil then self.rrb[sec] = self.rrb[sec] or {} else self.rrb[sec][opt] = v end
	end
	function c:delete(cfg, sec, opt) self.rrb[sec][opt] = nil end
	function c:commit() self.commits = self.commits + 1 end
	return c
end

-- The module's file access, faked: plugins.enabled and the store.
local function with_files(files, fn)
	local o = {ftpeer._read_file, ftpeer._write_file, ftpeer._map, ftpeer._first}
	ftpeer._read_file = function(p) return files[p] end
	ftpeer._write_file = function(p, s) files[p] = s; return true end
	ftpeer._map, ftpeer._first = nil, false
	local ok, err = pcall(fn, files)
	ftpeer._read_file, ftpeer._write_file, ftpeer._map, ftpeer._first = o[1], o[2], o[3], o[4]
	if not ok then error(err, 0) end
end

local NOW = 1000000

return {
	{
		name = "ftpeer: siblings on our 802.11r SSIDs become peers, others and our own do not",
		fn = function()
			with_files({[ftpeer.ENABLED] = "rrb-unifi\n"}, function(files)
				local c = cursor()
				local seen = {
					[U7G] = {ssid = "AP-guest", at = NOW},
					[U7E] = {ssid = "eG", at = NOW},
					[FOREIGN] = {ssid = "KEMIA", at = NOW},
					["aa:aa:aa:aa:aa:01"] = {ssid = "AP-guest", at = NOW},
				}
				local changed, list = ftpeer.tick(c, seen, {["aa:aa:aa:aa:aa:01"] = true}, NOW)
				assert_true(changed, "a new list")
				assert_eq(table.concat(list, " "), U7E .. ",a89c6cb8ab7f " .. U7G .. ",b29c6cb8ab7f",
					"bssid,nasid per peer")
				assert_eq(c.commits, 1, "committed once")
				assert_true(files[ftpeer.STORE] ~= nil, "the SSIDs stored")
				local again = ftpeer.tick(c, seen, {["aa:aa:aa:aa:aa:01"] = true}, NOW + 300)
				assert_false(again, "the same peers write nothing")
				assert_eq(c.commits, 1, "no second commit")
			end)
		end
	},
	{
		name = "ftpeer: a peer missed by a scan stays KEEP, then goes; a hand-written entry stays",
		fn = function()
			with_files({[ftpeer.ENABLED] = "rrb-unifi\n"}, function()
				local c = cursor({"11:22:33:44:55:66,custom"})
				ftpeer.tick(c, {[RMG] = {ssid = "AP-guest", at = NOW}}, {}, NOW)
				assert_eq(#c.rrb.main.ft_peer, 2, "learned one, kept the manual one")
				assert_false(ftpeer.tick(c, {}, {}, NOW + 3 * 86400), "unheard three days: kept")
				assert_true(ftpeer.tick(c, {}, {}, NOW + ftpeer.KEEP + 1), "after KEEP: dropped")
				assert_eq(table.concat(c.rrb.main.ft_peer, " "), "11:22:33:44:55:66,custom",
					"the hand-written entry is not this module's to drop")
			end)
		end
	},
	{
		name = "ftpeer: a hand-written entry heard as a sibling is taken over",
		fn = function()
			with_files({[ftpeer.ENABLED] = "rrb-unifi\n"}, function()
				local c = cursor({U7G .. ",b29c6cb8ab7f"})
				local changed, _, pending = ftpeer.tick(c, {[U7G] = {ssid = "AP-guest", at = NOW}}, {}, NOW)
				assert_false(changed, "the same list: nothing now")
				assert_true(pending, "but the per-SSID cut moved: a deferred rewrite")
				assert_eq(c.commits, 0, "the list itself is not rewritten")
				local ch2, _, p2 = ftpeer.tick(c, {[U7G] = {ssid = "AP-guest", at = NOW + 60}}, {}, NOW + 60)
				assert_false(ch2 or p2, "nothing new: nothing to do")
				assert_false(ftpeer.tick(c, {}, {}, NOW + ftpeer.KEEP - 10), "kept as a learned peer")
				assert_true(ftpeer.tick(c, {}, {}, NOW + 60 + ftpeer.KEEP + 1), "and aged out like one")
			end)
		end
	},
	{
		name = "ftpeer: the store survives a restart, and is not rewritten for every sighting",
		fn = function()
			with_files({[ftpeer.ENABLED] = "rrb-unifi\n"}, function(files)
				ftpeer.tick(cursor(), {[U7G] = {ssid = "AP-guest", at = NOW}}, {}, NOW)
				local first = files[ftpeer.STORE]
				ftpeer.tick(cursor(), {[U7G] = {ssid = "AP-guest", at = NOW + 600}}, {}, NOW + 600)
				assert_eq(files[ftpeer.STORE], first, "a fresher sighting alone writes no flash")
				ftpeer._map = nil
				local m = ftpeer.load()
				assert_eq(m[U7G] and m[U7G].ssid, "AP-guest", "read back")
			end)
		end
	},
	{
		name = "ftpeer: the first pass after a start asks for a deferred rewrite once",
		fn = function()
			with_files({[ftpeer.ENABLED] = "rrb-unifi\n"}, function()
				ftpeer.tick(cursor(), {[U7G] = {ssid = "AP-guest", at = NOW}}, {}, NOW)
				local c = cursor({U7G .. ",b29c6cb8ab7f"})
				ftpeer._map, ftpeer._first = nil, true
				local ch, _, p = ftpeer.tick(c, {}, {}, NOW + 60)
				assert_false(ch, "a restart: nothing now")
				assert_true(p, "but a deferred rewrite")
				local ch2, _, p2 = ftpeer.tick(c, {}, {}, NOW + 120)
				assert_false(ch2 or p2, "then only on a change")
				assert_eq(c.commits, 0, "the list itself untouched")
			end)
		end
	},
	{
		name = "inform: a deferred rewrite waits for a push, or replays in FTPEER_HOUR",
		fn = function()
			local inform = dofile("openuf/inform.lua")
			local res = {}
			local now = os.time({year = 2026, month = 1, day = 10, hour = 13, min = 0})
			inform._time = function() return now end
			inform._nrlist = {_seen = {}}
			inform._ucihelper = {get_vap_table = function() return {} end}
			inform._ftpeer = {tick = function() return false, {}, res.pending end}
			inform._ftpeer_next = 0
			inform._replay_due = false
			local function tick()
				inform._ftpeer_next = 0
				local ok, r = pcall(inform._ftpeer_tick, {}, {})
				assert_true(ok, "no error")
				return r
			end
			res.pending = true
			assert_false(tick(), "13:00: deferred, no replay")
			assert_false(inform._replay_due, "nothing replayed")
			res.pending = nil
			now = os.time({year = 2026, month = 1, day = 11, hour = 4, min = 2})
			assert_true(tick(), "04:02: the deferred rewrite replays")
			assert_true(inform._replay_due, "replay due")
			inform._replay_due = false
			assert_false(tick(), "once")
			-- A push in between carries it: nothing at 04:00.
			now = os.time({year = 2026, month = 1, day = 11, hour = 13, min = 0})
			res.pending = true
			tick()
			res.pending = nil
			inform._ucihelper._ftpeer_applied_at = now + 10
			now = os.time({year = 2026, month = 1, day = 12, hour = 4, min = 2})
			assert_false(tick(), "a push applied the cut meanwhile")
			assert_false(inform._replay_due, "no night reload")
		end
	},
	{
		name = "ftpeer: nothing is written without rrb-unifi enabled",
		fn = function()
			with_files({}, function()
				local c = cursor()
				assert_false(ftpeer.tick(c, {[U7G] = {ssid = "AP-guest", at = NOW}}, {}, NOW), "off")
				assert_eq(c.commits, 0, "untouched")
			end)
		end
	},
	{
		name = "ftpeer: filter keeps a WLAN's own peers, the wildcards and unknown entries",
		fn = function()
			local map = {[U7G] = {ssid = "AP-guest", at = NOW}, [U7E] = {ssid = "eG", at = NOW}}
			local extra = {
				r0kh = {U7G .. ",b29c6cb8ab7f,k", U7E .. ",a89c6cb8ab7f,k",
					"11:22:33:44:55:66,custom,k", "ff:ff:ff:ff:ff:ff,*,k"},
				r1kh = {U7G .. "," .. U7G .. ",k", U7E .. "," .. U7E .. ",k",
					"00:00:00:00:00:00,00:00:00:00:00:00,k"},
			}
			assert_eq(ftpeer.filter(extra, "AP-guest", map), 2, "eG's peer, from both lists")
			assert_eq(#extra.r0kh, 3, "r0kh: own peer, manual, wildcard")
			assert_eq(extra.r0kh[1], U7G .. ",b29c6cb8ab7f,k", "order kept")
			assert_eq(#extra.r1kh, 2, "r1kh: own peer, wildcard")
		end
	},
}
