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
				local changed = ftpeer.tick(c, {[U7G] = {ssid = "AP-guest", at = NOW}}, {}, NOW)
				assert_true(changed, "the same list, but now cut per SSID: rewrite the WLANs")
				assert_eq(c.commits, 0, "the list itself is not rewritten")
				assert_false(ftpeer.tick(c, {[U7G] = {ssid = "AP-guest", at = NOW + 60}}, {}, NOW + 60),
					"nothing new: nothing to do")
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
		name = "ftpeer: the first pass after a start asks for the rewrite once",
		fn = function()
			with_files({[ftpeer.ENABLED] = "rrb-unifi\n"}, function()
				ftpeer.tick(cursor(), {[U7G] = {ssid = "AP-guest", at = NOW}}, {}, NOW)
				local c = cursor({U7G .. ",b29c6cb8ab7f"})
				ftpeer._map, ftpeer._first = nil, true
				assert_true(ftpeer.tick(c, {}, {}, NOW + 60), "a restart: rewrite once")
				assert_false(ftpeer.tick(c, {}, {}, NOW + 120), "then only on a change")
				assert_eq(c.commits, 0, "the list itself untouched")
			end)
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
