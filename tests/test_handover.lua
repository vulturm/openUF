-- Tests for openuf/handover.lua: clients asked to roam before a reload
-- restarts their BSS. Run from project root: lua tests/run_tests.lua

local handover = dofile("openuf/handover.lua")

local function cursor_of(all) return {get_all = function(_, cfg) return cfg == "wireless" and all or nil end} end

local function base()
	return {
		radio0 = {[".type"] = "wifi-device", channel = "124", country = "US", htmode = "VHT80"},
		radio1 = {[".type"] = "wifi-device", channel = "1", country = "US"},
		guest5 = {[".type"] = "wifi-iface", device = "radio0", ssid = "AP-guest", r0kh = {"a", "b"}},
		guest2 = {[".type"] = "wifi-iface", device = "radio1", ssid = "AP-guest"},
		main2  = {[".type"] = "wifi-iface", device = "radio1", ssid = "eG", [".index"] = 3},
	}
end

local STATUS = {
	radio0 = {interfaces = {
		{section = "guest5", ifname = "phy0-ap0", config = {mode = "ap"}},
		{section = "uplink", ifname = "phy0-sta0", config = {mode = "sta"}},
	}},
	radio1 = {interfaces = {
		{section = "guest2", ifname = "phy1-ap0", config = {mode = "ap"}},
		{section = "main2", ifname = "phy1-ap1", config = {mode = "ap"}},
	}},
}

-- hostapd's ubus, faked: clients per BSS (shrinking as they leave), its
-- neighbour list, and every BTM request sent.
local function with_hostapd(clients, nrs, fn)
	local o = {handover._popen, handover._exec, handover._sleep, handover._read_file, handover._log}
	local sent, slept, logged = {}, 0, {}
	local cjson = require("cjson")
	handover._popen = function(cmd)
		local ifn, verb = cmd:match("hostapd%.([%w%-%._]+) (%S+)")
		if verb == "get_clients" then
			local t = {}
			for _, m in ipairs(clients[ifn] or {}) do t[m] = {} end
			return cjson.encode({clients = next(t) and t or setmetatable({}, cjson.empty_table_mt)})
		elseif verb == "rrm_nr_list" then
			return cjson.encode({list = nrs[ifn] or {}})
		end
		return ""
	end
	handover._exec = function(cmd) sent[#sent + 1] = cmd; return 0 end
	handover._sleep = function() slept = slept + 1; for k in pairs(clients) do clients[k] = {} end end
	handover._read_file = function(p)
		return ({["/sys/class/net/phy0-ap0/address"] = "48:8f:5a:34:1e:48\n",
			["/sys/class/net/phy1-ap0/address"] = "4e:8f:5a:34:1e:49\n",
			["/sys/class/net/phy1-ap1/address"] = "48:8f:5a:34:1e:49\n"})[p]
	end
	handover._log = function(m) logged[#logged + 1] = m end
	local ok, err = pcall(fn, sent, function() return slept end, logged)
	handover._popen, handover._exec, handover._sleep, handover._read_file, handover._log = o[1], o[2], o[3], o[4], o[5]
	if not ok then error(err, 0) end
end

return {
	{
		name = "handover: an unchanged config restarts nothing, whatever order the sections come in",
		fn = function()
			local b = handover.snapshot(cursor_of(base()))
			local a = handover.snapshot(cursor_of(base()))
			assert_eq(#handover.affected(b, a, STATUS), 0, "a push that changes nothing")
			assert_false(handover.changed(b, a), "and says so without asking netifd")
			local w = base(); w.radio1.channel = "6"
			assert_true(handover.changed(b, handover.snapshot(cursor_of(w))), "a change is one")
		end
	},
	{
		name = "handover: a radio change takes every AP of that radio, a WLAN change its own, stations never",
		fn = function()
			local b = handover.snapshot(cursor_of(base()))
			local w = base(); w.radio0.country = "HK"
			local got = handover.affected(b, handover.snapshot(cursor_of(w)), STATUS)
			assert_eq(table.concat(got, ","), "phy0-ap0", "the radio's AP, not its station")
			w = base(); w.main2.ssid = "eG2"
			got = handover.affected(b, handover.snapshot(cursor_of(w)), STATUS)
			assert_eq(table.concat(got, ","), "phy1-ap1", "only the WLAN that changed")
			w = base(); w.guest5.r0kh = {"a", "b", "c"}
			got = handover.affected(b, handover.snapshot(cursor_of(w)), STATUS)
			assert_eq(table.concat(got, ","), "phy0-ap0", "a list option counts")
			w = base(); w.main2 = nil
			got = handover.affected(b, handover.snapshot(cursor_of(w)), STATUS)
			assert_eq(table.concat(got, ","), "phy1-ap1", "a WLAN that goes")
			w = base(); w.main2.device = "radio0"
			got = handover.affected(b, handover.snapshot(cursor_of(w)), STATUS)
			assert_eq(table.concat(got, ","), "phy0-ap0,phy1-ap0,phy1-ap1", "moved: both radios")
		end
	},
	{
		name = "handover: clients are asked to leave for neighbours that are not restarting, then waited for",
		fn = function()
			local clients = {["phy1-ap0"] = {"a8:db:03:35:45:cc"}, ["phy1-ap1"] = {"2c:be:eb:53:09:a1"}}
			local nrs = {
				["phy1-ap0"] = {{"b2:9c:6c:b8:ab:7f", "AP-guest", "b29c6cb8ab7faf"},
					{"48:8f:5a:34:1e:48", "AP-guest", "488f5a341e48af"}},
				["phy1-ap1"] = {{"4e:8f:5a:34:1e:49", "eG", "4e8f5a341e49af"}},
			}
			with_hostapd(clients, nrs, function(sent, slept, logged)
				local asked, left = handover.run({"phy1-ap0", "phy1-ap1"})
				assert_eq(asked, 1, "one client had somewhere to go")
				assert_eq(left, 0, "and left")
				assert_eq(#sent, 1, "one request")
				assert_contains(sent[1], "hostapd.phy1-ap0 bss_transition_request", "on its own BSS")
				assert_contains(sent[1], "a8:db:03:35:45:cc", "to that client")
				assert_contains(sent[1], "\"disassociation_imminent\":true", "imminent")
				assert_contains(sent[1], "b29c6cb8ab7faf", "the U7 offered")
				assert_contains(sent[1], "488f5a341e48af", "this AP's other radio offered (it stays up)")
				assert_eq(slept(), 1, "the wait ends when they are gone")
				assert_contains(logged[1] or "", "1 client(s)", "and is said once")
			end)
		end
	},
	{
		name = "handover: no clients, or no neighbour to send them to, means no request and no wait",
		fn = function()
			with_hostapd({}, {}, function(sent, slept)
				assert_eq(select(1, handover.run({"phy1-ap0"})), 0, "nobody there")
				assert_eq(#sent, 0, "nothing sent")
				assert_eq(slept(), 0, "no wait")
			end)
			with_hostapd({["phy1-ap0"] = {"a8:db:03:35:45:cc"}}, {["phy1-ap0"] = {}}, function(sent, slept)
				handover.run({"phy1-ap0"})
				assert_eq(#sent, 0, "no neighbour: nothing to ask for")
				assert_eq(slept(), 0, "and no wait")
			end)
			assert_eq(select(1, handover.run({})), 0, "an empty list")
		end
	},
	{
		name = "handover: a client that ignores the request is waited for WAIT seconds at most",
		fn = function()
			local clients = {["phy1-ap0"] = {"a8:db:03:35:45:cc"}}
			local nrs = {["phy1-ap0"] = {{"b2:9c:6c:b8:ab:7f", "AP-guest", "b29c6cb8ab7faf"}}}
			with_hostapd(clients, nrs, function(_, slept)
				handover._sleep = function() end   -- it never leaves
				local n = 0
				handover._sleep = function() n = n + 1 end
				local asked, left = handover.run({"phy1-ap0"})
				assert_eq(asked, 1, "asked")
				assert_eq(left, 1, "still here")
				assert_eq(n, handover.WAIT, "WAIT one-second looks, then the reload goes ahead")
			end)
		end
	},
}
