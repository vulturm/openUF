-- Tests for openuf/clientmatch.lua: a client held on a weak signal steered
-- to the BSS it reports hearing clearly better. Run from project root.

local cm = dofile("openuf/clientmatch.lua")

local OWN = "4e:8f:5a:34:1e:49"
local U7  = "b2:9c:6c:b8:ab:7f"
local NR  = {{U7, "AP-guest", "b29c6cb8ab7faf"}, {"8e:78:48:06:03:fc", "AP-guest", "8e7848af"}}

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
		signal = signal, connected_sec = conn or 600, op_class = 81}}
end

return {
	{
		name = "clientmatch: pick takes the loudest listed neighbour DIFF_DB above this BSS, by the client's own ears",
		fn = function()
			local now = 1000
			local heard = {[U7] = {signal = -55, seen_at = now}, [OWN] = {signal = -72, seen_at = now},
				["8e:78:48:06:03:fc"] = {signal = -60, seen_at = now}}
			local best = cm.pick({signal = -60}, heard, NR, OWN, now)
			assert_eq(best and best.bssid, U7, "the U7, loudest")
			assert_eq(best.here, -72, "compared with what the client hears here, not hostapd's -60")
			heard[OWN] = nil
			assert_nil(cm.pick({signal = -90}, heard, NR, OWN, now), "no reading of this BSS in the report: no steer")
			heard = {[U7] = {signal = -55, seen_at = now - cm.REPORT_MAX_AGE - 1}, [OWN] = {signal = -80, seen_at = now}}
			assert_nil(cm.pick({signal = -80}, heard, NR, OWN, now), "a stale report is not used")
			heard = {["00:00:5e:00:53:99"] = {signal = -40, seen_at = now}, [OWN] = {signal = -80, seen_at = now}}
			assert_nil(cm.pick({signal = -80}, heard, NR, OWN, now), "a BSS outside the neighbour list is never named")
			heard = {[U7] = {signal = -74, seen_at = now}, [OWN] = {signal = -85, seen_at = now}}
			assert_nil(cm.pick({signal = -85}, heard, NR, OWN, now), "a candidate under FLOOR is no better place")
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
					request = function(ifn, mac, o) asked[#asked + 1] = ifn .. " " .. mac .. " " .. o.op_class end,
					capable = function() return {"a8:db:03:35:45:cc"} end,
				}
				local t = 1000
				assert_eq(cm.tick(obs(-78), t, opts), 0, "first sight: held")
				assert_eq(#asked, 0, "not asked yet")
				t = t + cm.HOLD
				cm.tick(obs(-78), t, opts)
				assert_eq(asked[1], "phy1-ap2 a8:db:03:35:45:cc 81", "asked for a 2.4 GHz report")
				cm.tick(obs(-78), t + 5, opts)
				assert_eq(#asked, 1, "not again within REQUEST_GAP")
				reports["a8:db:03:35:45:cc"] = {[U7] = {signal = -55, seen_at = t + 6},
					[OWN] = {signal = -77, seen_at = t + 6}}
				assert_eq(cm.tick(obs(-78), t + 10, opts), 1, "the answer names the U7: steered")
				assert_contains(sent[1], "bss_transition_request", "a BTM request")
				assert_contains(sent[1], '"disassociation_imminent":false', "a request, not a kick")
				assert_contains(sent[1], "b29c6cb8ab7faf", "naming the U7")
				assert_contains(logged[1] or "", "asked to move", "and logged")
				assert_eq(cm.tick(obs(-78), t + 20, opts), 0, "COOLDOWN holds")
				-- After COOLDOWN the old report is stale: a fresh one is asked
				-- for, never a steer on five-minute-old ears.
				assert_eq(cm.tick(obs(-78), t + 10 + cm.COOLDOWN, opts), 0, "no steer on a stale report")
				assert_eq(#asked, 2, "a new report is asked for instead")
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
}
