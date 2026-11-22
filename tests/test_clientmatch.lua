-- Tests for openuf/clientmatch.lua: a client held on a weak signal steered
-- to the BSS it reports hearing clearly better. Run from project root.

local cm = dofile("openuf/clientmatch.lua")

local OWN = "4e:8f:5a:34:1e:49"
local U7  = "b2:9c:6c:b8:ab:7f"
local ROOMS = "8e:78:48:06:03:fc"
-- As hostapd lists them: BSSID, information, operating class, channel, PHY.
local NR  = {{U7, "AP-guest", "b29c6cb8ab7faf080000510607"}, {ROOMS, "AP-guest", "8e78480603fcaf080000510b07"}}

local function with_ap(fn)
	local o = {cm._popen, cm._exec, cm._read_file, cm._log, cm._state}
	local sent, logged = {}, {}
	local cjson = require("cjson")
	cm._popen = function(cmd)
		if cmd:find("rrm_nr_list", 1, true) then return cjson.encode({list = NR}) end
		return ""
	end
	cm._exec = function(cmd) sent[#sent + 1] = cmd; return 0 end
	cm._read_file = function(p) return p:find("phy1-ap2", 1, true) and (OWN .. "\n") or nil end
	cm._log = function(m) logged[#logged + 1] = m end
	cm._state = {}
	local ok, err = pcall(fn, sent, logged)
	cm._popen, cm._exec, cm._read_file, cm._log, cm._state = o[1], o[2], o[3], o[4], o[5]
	if not ok then error(err, 0) end
end

local function obs(signal, conn)
	return {{ifname = "phy1-ap2", ssid = "AP-guest", mac = "a8:db:03:35:45:cc",
		signal = signal, connected_sec = conn or 600, op_class = 81, channel = 1}}
end

return {
	{
		name = "clientmatch: pick takes the loudest listed neighbour DIFF_DB above this BSS, by the client's own ears",
		fn = function()
			local now = 1000
			local heard = {[U7] = {signal = -55, seen_at = now}, [OWN] = {signal = -72, seen_at = now},
				["8e:78:48:06:03:fc"] = {signal = -60, seen_at = now}}
			local best = cm.pick({signal = -60, op_class = 81}, heard, NR, OWN, now)
			assert_eq(best and best.bssid, U7, "the U7, loudest")
			assert_eq(best.here, -72, "compared with what the client hears here, not hostapd's -60")
			heard[OWN] = nil
			assert_nil(cm.pick({signal = -90, op_class = 81}, heard, NR, OWN, now), "no reading of this BSS in the report: no steer")
			heard = {[U7] = {signal = -55, seen_at = now - cm.REPORT_MAX_AGE - 1}, [OWN] = {signal = -80, seen_at = now}}
			assert_nil(cm.pick({signal = -80, op_class = 81}, heard, NR, OWN, now), "a stale report is not used")
			heard = {["00:00:5e:00:53:99"] = {signal = -40, seen_at = now}, [OWN] = {signal = -80, seen_at = now}}
			assert_nil(cm.pick({signal = -80, op_class = 81}, heard, NR, OWN, now), "a BSS outside the neighbour list is never named")
			heard = {[U7] = {signal = -74, seen_at = now}, [OWN] = {signal = -85, seen_at = now}}
			assert_nil(cm.pick({signal = -85, op_class = 81}, heard, NR, OWN, now), "a candidate under FLOOR is no better place")
		end
	},
	{
		name = "clientmatch: a weak client is held, asked for a report, steered once, then left alone for COOLDOWN",
		fn = function()
			with_ap(function(sent, logged)
				local asked = {}
				local reports = {}
				local opts = {
					reports = reports,
					request = function(ifn, mac, o)
						asked[#asked + 1] = ifn .. " " .. mac .. " " .. o.op_class .. "/" .. o.channel
					end,
					capable = function() return {"a8:db:03:35:45:cc"} end,
				}
				local t = 1000
				assert_eq(cm.tick(obs(-78), t, opts), 0, "first sight: held")
				assert_eq(#asked, 0, "not asked yet")
				t = t + cm.HOLD
				cm.tick(obs(-78), t, opts)
				assert_eq(asked[1], "phy1-ap2 a8:db:03:35:45:cc 81/1", "its own channel first")
				cm.tick(obs(-78), t + 5, opts)
				assert_eq(asked[2], "phy1-ap2 a8:db:03:35:45:cc 81/6", "then one neighbour channel a heartbeat")
				reports["a8:db:03:35:45:cc"] = {[U7] = {signal = -55, seen_at = t + 6},
					[OWN] = {signal = -77, seen_at = t + 6}}
				assert_eq(cm.tick(obs(-78), t + 7, opts), 0, "no steer before the round has ended")
				assert_eq(asked[3], "phy1-ap2 a8:db:03:35:45:cc 81/11", "the last channel")
				assert_eq(#asked, 3, "one request each")
				assert_eq(cm.tick(obs(-78), t + 10, opts), 1, "the answer names the U7: steered")
				assert_contains(sent[1], "bss_transition_request", "a BTM request")
				assert_contains(sent[1], '"disassociation_imminent":false', "a request, not a kick")
				assert_contains(sent[1], "b29c6cb8ab7faf080000510607", "naming the U7")
				assert_contains(logged[1] or "", "asked to move", "and logged")
				assert_eq(cm.tick(obs(-78), t + 20, opts), 0, "COOLDOWN holds")
				-- After COOLDOWN the old report is stale: a fresh one is asked
				-- for, never a steer on five-minute-old ears.
				assert_eq(cm.tick(obs(-78), t + 10 + cm.COOLDOWN, opts), 0, "no steer on a stale report")
				assert_eq(#asked, 4, "a new round is asked for instead")
			end)
		end
	},
	{
		name = "clientmatch: strong, freshly joined or report-less clients are not touched",
		fn = function()
			with_ap(function(sent)
				local asked = 0
				local opts = {reports = {}, request = function() asked = asked + 1 end,
					capable = function() return {} end}
				cm.tick(obs(-60), 1000, opts); cm.tick(obs(-60), 1000 + cm.HOLD, opts)
				assert_eq(asked + #sent, 0, "above FLOOR: nothing")
				cm.tick(obs(-80, 10), 2000, opts); cm.tick(obs(-80, 10 + cm.HOLD), 2000 + cm.HOLD, opts)
				assert_eq(asked + #sent, 0, "a fresh join settles first")
				cm.tick(obs(-80), 3000, opts); cm.tick(obs(-80), 3000 + cm.HOLD, opts)
				assert_eq(asked, 0, "a client that cannot make a report is never asked")
				assert_eq(#sent, 0, "and never steered blind")
			end)
		end
	},
	{
		name = "clientmatch: the round covers every sub-band a client could go to, and never a lower band",
		fn = function()
			local S5, R5 = "a8:9c:6c:b8:ab:80", "84:78:48:06:03:fd"
			local list = {{S5, "x", "a89c6cb8ab80af180000797c09"},   -- 121/124
				{R5, "x", "8478480603fdaf180000732409"},             -- 115/36
				{U7, "x", "b29c6cb8ab7faf080000510607"}}             -- 81/6
			local function keys(o, nr)
				local t = {}
				for _, c in ipairs(cm.channels_to_ask(o, nr, OWN)) do t[#t + 1] = c.op_class .. "/" .. c.channel end
				return table.concat(t, " ")
			end
			assert_eq(keys({op_class = 81, channel = 11}, list), "81/11 121/124 115/36 81/6", "2.4 GHz: every band")
			assert_eq(keys({op_class = 115, channel = 36}, list), "115/36 121/124", "5 GHz: the other sub-band, no 2.4")
			assert_eq(keys({op_class = 115, channel = 36}, {list[3]}), "", "only a lower band listed: nobody is asked")
			assert_eq(keys({op_class = 81, channel = "auto"}, list), "", "no channel: no request")
			local many = {}
			for i = 1, 8 do many[i] = {("00:00:5e:00:53:%02x"):format(i), "x",
				("00005e0053%02xaf080000"):format(i) .. "79" .. ("%02x"):format(96 + 4 * i) .. "09"} end
			assert_eq(#cm.channels_to_ask({op_class = 81, channel = 1}, many, OWN), cm.MAX_CHANNELS, "capped")
			local now = 1000
			local heard = {[OWN] = {signal = -72, seen_at = now}, [U7] = {signal = -50, seen_at = now},
				[S5] = {signal = -62, seen_at = now}}
			assert_eq(cm.pick({op_class = 115}, heard, list, OWN, now).bssid, S5, "5 GHz: the 5 GHz AP, not the louder 2.4")
			heard[S5] = nil
			assert_nil(cm.pick({op_class = 115}, heard, list, OWN, now), "2.4 GHz alone is no target from 5 GHz")
			heard[S5] = {signal = -62, seen_at = now}
			assert_eq(cm.pick({op_class = 81}, heard, list, OWN, now).bssid, U7, "from 2.4 GHz the loudest wins")
			heard[U7] = nil
			assert_eq(cm.pick({op_class = 81}, heard, list, OWN, now).bssid, S5, "and 5 GHz is a target")
		end
	},
	{
		name = "clientmatch: a good 2.4 GHz client is asked about 5 GHz and moved up at UP_FLOOR",
		fn = function()
			local S5 = "a8:9c:6c:b8:ab:80"
			local saved = NR
			NR = {{S5, "AP-guest", "a89c6cb8ab80af180000797c09"}, {U7, "AP-guest", "b29c6cb8ab7faf080000510607"}}
			local ok, err = pcall(with_ap, function(sent, logged)
				local asked, reports = {}, {}
				local opts = {reports = reports, capable = function() return {"a8:db:03:35:45:cc"} end,
					request = function(_, _, o) asked[#asked + 1] = o.op_class .. "/" .. o.channel end}
				local M = "a8:db:03:35:45:cc"
				assert_eq(cm.tick(obs(-55, 10), 1000, opts), 0, "a fresh join settles first")
				assert_eq(#asked, 0, "not asked")
				cm.tick(obs(-55), 1100, opts)
				assert_eq(table.concat(asked, " "), "121/124", "only the higher band's channel")
				reports[M] = {[S5] = {signal = -66, seen_at = 1105}}
				assert_eq(cm.tick(obs(-55), 1110, opts), 0, "-66 is under UP_FLOOR")
				assert_eq(#asked, 1, "and no new round before UP_GAP")
				reports[M] = {[S5] = {signal = -64, seen_at = 1115}}
				assert_eq(cm.tick(obs(-55), 1120, opts), 1, "-64: moved up, with no DIFF_DB")
				assert_contains(sent[1], "a89c6cb8ab80af180000797c09", "naming the 5 GHz BSS")
				assert_contains(sent[1], '"disassociation_imminent":false', "a request, not a kick")
				assert_contains(logged[1], "on 2.4 GHz", "and logged")
				assert_eq(cm.tick(obs(-55), 1130, opts), 0, "COOLDOWN holds")
			end)
			NR = saved
			if not ok then error(err, 0) end
		end
	},
	{
		name = "clientmatch: a 2.4 GHz-only device is asked ever more rarely, a 5 GHz client not at all",
		fn = function()
			local S5 = "a8:9c:6c:b8:ab:80"
			local saved = NR
			NR = {{S5, "AP-guest", "a89c6cb8ab80af180000797c09"}}
			local ok, err = pcall(with_ap, function(sent)
				local asked = 0
				local opts = {reports = {}, capable = function() return {"a8:db:03:35:45:cc"} end,
					request = function() asked = asked + 1 end}
				local t = 1000
				cm.tick(obs(-55), t, opts)
				assert_eq(asked, 1, "first round")
				cm.tick(obs(-55), t + cm.UP_GAP - 1, opts)
				assert_eq(asked, 1, "not before UP_GAP")
				t = t + cm.UP_GAP
				cm.tick(obs(-55), t, opts)
				assert_eq(asked, 2, "second round")
				cm.tick(obs(-55), t + cm.UP_GAP, opts)
				assert_eq(asked, 2, "the gap has doubled")
				cm.tick(obs(-55), t + 2 * cm.UP_GAP, opts)
				assert_eq(asked, 3, "third round")
				assert_eq(cm._state["a8:db:03:35:45:cc"].up_gap, 4 * cm.UP_GAP, "doubling")
				assert_eq(#sent, 0, "nothing heard, nothing sent")
				cm._state, asked = {}, 0
				local five = obs(-55); five[1].op_class, five[1].channel = 115, 36
				cm.tick(five, 5000, opts)
				assert_eq(asked, 0, "a client already on 5 GHz gets no such round")
				local list = {{U7, "x", "b29c6cb8ab7faf080000510607"}}
				assert_nil(cm.pick_up({op_class = 115}, {[U7] = {signal = -40, seen_at = 1}}, list, OWN, 1), "never down")
			end)
			NR = saved
			if not ok then error(err, 0) end
		end
	},
}
