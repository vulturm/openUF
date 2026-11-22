-- Tests for openuf/backhaul.lua: the mesh backhaul plan, the wired-first
-- uplink policy and the wireless `uplink` report. No device access: every seam
-- is replaced.

local backhaul = dofile("openuf/backhaul.lua")

local MESH = {status = true, version = 3, essid = "vwire-5f3369181f7fbab5",
	psk = "0123456789abcdef0123456789abcdef", serial1 = "78:bb:c1:fe:3f:c9",
	connectivity = {status = true, uplink_eth = "eth0", uplink_wds = "ath4", uplink_bridge = "br0"}}
local ENTRIES = {
	{role = "downlink", radio = "radio1", ssid = "vwire-5f3369181f7fbab5",
		psk = "0123456789abcdef0123456789abcdef", devname = "vwire3", hidden = true},
	{role = "uplink", radio = "radio1", ssid = "vport-ac10076fc670", devname = "ath4", hidden = true},
}

-- A fake ucihelper: the two functions tick()/uplink_report() call.
local function fake_ufuci(sections, ifname, dl_sections)
	local f = {calls = {}}
	function f.backhaul_uplink_sections() return sections end
	function f.backhaul_downlink_sections() return dl_sections or {} end
	function f.ifname_for_section(name) return ifname end
	function f.backhaul_set_uplink_enabled(enabled)
		f.calls[#f.calls + 1] = enabled
		for _, s in ipairs(sections) do s.disabled = not enabled end
		return true
	end
	return f
end

local function fake_sysinfo(port)
	return {
		lan_bridge = function() return "br-lan" end,
		uplink_bridge_port = function() return port end,
	}
end

-- A Deco M4R v1-shaped swconfig board: one CPU trunk (eth0, its LAN as
-- eth0.1 in br-lan), two sockets on physical switch ports 3 and 5.
local SWCFG = {
	net  = {lan_cpueth = "eth0", lan_vlanid = 1,
		ports = {{idx = 1, swport = "lan1"}, {idx = 2, swport = "lan2"}}},
	vlan = {device = "switch0", cpu_lan = 0, cpu_wan = 0, ports = {lan1 = 3, lan2 = 5}},
}

-- sysinfo for a swconfig board. sw.gw is the physical port the ARL has the
-- gateway on (nil: not learnt), sw.up the switch's per-port link, sw.fdb_port
-- the LAN bridge port the gateway is learnt behind.
local function fake_swsysinfo(sw)
	return {
		lan_bridge = function() return nil end,   -- the trunk is in no bridge itself
		bridge_of = function(ifname) if ifname == "eth0.1" then return "br-lan" end end,
		switch_status = function(dev)
			sw.status_calls = (sw.status_calls or 0) + 1
			local ports = {}
			for n, up in pairs(sw.up) do ports[n] = {up = up} end
			return {ports = ports, arl = {gw = sw.gw}}
		end,
		uplink_phys_port = function(arl) return arl.gw end,
		uplink_bridge_port = function()
			sw.fdb_calls = (sw.fdb_calls or 0) + 1
			return sw.fdb_port
		end,
	}
end

-- Seams for the swconfig tests: sysfs reads from `files`, `ls` from `dirs`,
-- every write and command recorded.
local function with_sw_seams(files, dirs, fn)
	local o = {backhaul._read_file, backhaul._popen, backhaul._log, backhaul._write_file, backhaul._exec}
	local rec = {writes = {}, cmds = {}, logs = {}}
	backhaul._read_file = function(path) return files[path] end
	backhaul._popen = function(cmd)
		local dir = cmd:match("^ls (%S+)$")
		return dir and dirs[dir] or ""
	end
	backhaul._log = function(msg) rec.logs[#rec.logs + 1] = msg end
	backhaul._write_file = function(path, v) rec.writes[#rec.writes + 1] = path .. "=" .. v; return true end
	backhaul._exec = function(cmd) rec.cmds[#rec.cmds + 1] = cmd; return 0 end
	backhaul._down_ticks = 0
	backhaul._dirty = false
	backhaul._arl_heal = 0
	local ok, err = pcall(fn, rec)
	backhaul._read_file, backhaul._popen, backhaul._log, backhaul._write_file, backhaul._exec =
		o[1], o[2], o[3], o[4], o[5]
	if not ok then error(err, 0) end
end

local function count(list, pattern)
	local n = 0
	for _, v in ipairs(list) do if v:find(pattern) then n = n + 1 end end
	return n
end

local function with_seams(carrier_by_port, popen_out, fn)
	local orig_read, orig_popen, orig_log = backhaul._read_file, backhaul._popen, backhaul._log
	backhaul._read_file = function(path)
		local port, what = path:match("^/sys/class/net/([^/]+)/(%w+)$")
		if port and (what == "carrier" or what == "operstate") then
			local c = carrier_by_port[port]
			if c == nil then return nil end
			if what == "operstate" then return c and "up\n" or "lowerlayerdown\n" end
			return c and "1\n" or "0\n"
		end
		local stat = path:match("/statistics/([a-z_]+)$")
		if stat then return ({tx_bytes = "1000", rx_bytes = "2000", tx_packets = "10", rx_packets = "20"})[stat] end
		return nil
	end
	backhaul._popen = function() return popen_out or "" end
	backhaul._log = function() end
	backhaul._down_ticks = 0
	backhaul._dirty = false
	local ok, err = pcall(fn)
	backhaul._read_file, backhaul._popen, backhaul._log = orig_read, orig_popen, orig_log
	if not ok then error(err, 0) end
end

return {
	{
		name = "backhaul: plan() turns the captured entries into a downlink AP and a disabled uplink station",
		fn = function()
			local plan = backhaul.plan(MESH, ENTRIES, {}, {backhaul_mode = ""})
			assert_true(plan ~= nil, "a plan")
			assert_eq(plan.downlink.radio, "radio1", "downlink radio")
			assert_eq(plan.downlink.ssid, MESH.essid, "downlink ssid is the mesh essid")
			assert_eq(plan.downlink.key, MESH.psk, "downlink key is the site PSK")
			assert_eq(plan.uplink.radio, "radio1", "uplink radio")
			assert_eq(plan.uplink.ssid, MESH.essid, "the station joins the mesh essid, not its own vport name")
			assert_eq(plan.uplink.key, MESH.psk, "same PSK")
			assert_false(plan.uplink.enabled, "wired by default: the station is written disabled")
			assert_nil(plan.uplink.bssid, "no BSSID pin from the push")
			assert_eq(plan.uplink.vport, "vport-ac10076fc670", "the station's own name is kept for reporting")
			assert_eq(plan.uplink.devname, "ath4", "the controller's devname for the station")
			assert_eq(plan.downlink.devname, "vwire3", "and for the downlink")
		end
	},
	{
		name = "backhaul: plan() keeps the station enabled while the device is already on its wireless uplink",
		fn = function()
			local plan = backhaul.plan(MESH, ENTRIES, {}, {backhaul_mode = "wireless"})
			assert_true(plan.uplink.enabled, "stays enabled across a push")
		end
	},
	{
		name = "backhaul: plan() is nil without an enabled mesh block, a usable PSK, or any entry",
		fn = function()
			assert_nil(backhaul.plan(nil, ENTRIES), "no mesh block")
			local off = {status = false, essid = MESH.essid, psk = MESH.psk}
			assert_nil(backhaul.plan(off, ENTRIES), "mesh.status=disabled")
			local short = {status = true, essid = MESH.essid, psk = "short"}
			assert_nil(backhaul.plan(short, ENTRIES), "a PSK under 8 chars is not WPA2")
			assert_nil(backhaul.plan(MESH, {}), "no entries")
			local only_dl = backhaul.plan(MESH, {ENTRIES[1]})
			assert_true(only_dl.downlink ~= nil and only_dl.uplink == nil, "a parent-only push")
		end
	},
	{
		name = "backhaul: decide() is wired-first with hysteresis on loss and none on return",
		fn = function()
			local mode, ticks = backhaul.decide(true, "wired", 0)
			assert_eq(mode, "wired", "carrier: wired")
			mode, ticks = backhaul.decide(false, "wired", 0)
			assert_eq(mode, "wired", "one tick without carrier: still wired")
			assert_eq(ticks, 1, "counted")
			mode, ticks = backhaul.decide(false, "wired", 1)
			assert_eq(mode, "wireless", "second tick: wireless")
			mode, ticks = backhaul.decide(true, "wireless", 5)
			assert_eq(mode, "wired", "carrier back: wired at once")
			assert_eq(ticks, 0, "counter reset")
			mode, ticks = backhaul.decide(nil, "wireless", 3)
			assert_eq(mode, "wireless", "unknown carrier: hold")
			assert_eq(ticks, 0, "and do not accumulate")
			mode = backhaul.decide(nil, nil, nil)
			assert_eq(mode, "wired", "nothing known: wired")
		end
	},
	{
		name = "backhaul: tick() learns the wired socket, enables the station after two carrier-less ticks and disables it when the wire is back",
		fn = function()
			local carrier = {wan = true}
			with_seams(carrier, "", function()
				local st = {backhaul_mode = "", backhaul_wired_port = ""}
				local secs = {{name = "openuf_bh_ul_radio1", radio = "radio1", ssid = MESH.essid, disabled = true}}
				local uf = fake_ufuci(secs, "phy1-sta0")
				local saves = 0
				local state_mod = {save = function() saves = saves + 1 end}
				assert_eq(backhaul.tick(st, {}, uf, fake_sysinfo("wan"), state_mod), "wired", "wired with carrier")
				assert_eq(st.backhaul_wired_port, "wan", "remembered the socket the gateway is behind")
				assert_eq(saves, 1, "persisted once")
				-- the cable goes: the gateway is no longer behind any port, carrier 0
				carrier.wan = false
				local si = fake_sysinfo(nil)
				assert_eq(backhaul.tick(st, {}, uf, si, state_mod), "wired", "first tick: patience")
				assert_eq(#uf.calls, 0, "station untouched")
				assert_eq(backhaul.tick(st, {}, uf, si, state_mod), "wireless", "second tick: wireless")
				assert_eq(uf.calls[1], true, "station enabled")
				assert_eq(st.backhaul_mode, "wireless", "mode persisted")
				-- the gateway is now behind the station netdev: that must not be taken as a wired socket
				assert_eq(backhaul.tick(st, {}, uf, fake_sysinfo("phy1-sta0"), state_mod), "wireless", "stays wireless")
				assert_eq(st.backhaul_wired_port, "wan", "the station is not a wired socket")
				-- cable back
				carrier.wan = true
				assert_eq(backhaul.tick(st, {}, uf, fake_sysinfo("wan"), state_mod), "wired", "wired again at once")
				assert_eq(uf.calls[#uf.calls], false, "station disabled")
			end)
		end
	},
	{
		name = "backhaul: tick() is a no-op on a device with no uplink station section",
		fn = function()
			with_seams({wan = false}, "", function()
				local st = {backhaul_mode = ""}
				assert_nil(backhaul.tick(st, {}, fake_ufuci({}, nil), fake_sysinfo("wan"), nil), "nothing to do")
				assert_true(st.backhaul_mode == "", "state untouched")
			end)
		end
	},
	{
		name = "backhaul: uplink_report() describes the hop only while wireless and associated",
		fn = function()
			local link = "Connected to 78:bb:c1:fe:3f:cb (on phy1-sta0)\n\tSSID: vwire-5f3369181f7fbab5\n"
				.. "\tfreq: 5500\n\tRX: 1000 bytes (10 packets)\n\tTX: 2000 bytes (20 packets)\n"
				.. "\tsignal: -47 dBm\n\trx bitrate: 866.7 MBit/s\n\ttx bitrate: 780.0 MBit/s\n"
			with_seams({}, link, function()
				local secs = {{name = "openuf_bh_ul_radio1", radio = "radio1", ssid = MESH.essid, disabled = false}}
				local uf = fake_ufuci(secs, "phy1-sta0")
				local st = {backhaul_mode = "wireless", backhaul_parent = "78:bb:c1:fe:3f:c9"}
				local up = backhaul.uplink_report(st, {}, uf)
				assert_eq(up.type, "wireless", "type")
				assert_eq(up.name, "phy1-sta0", "netdev name when the section has no controller devname")
				secs[1].devname = "ath4"
				assert_eq(backhaul.uplink_report(st, {}, uf).name, "ath4", "the controller's devname when known")
				secs[1].devname = nil
				assert_eq(up.bssid, "78:bb:c1:fe:3f:cb", "the BSS it joined")
				assert_eq(up.uplink_mac, "78:bb:c1:fe:3f:c9", "the parent the controller named")
				assert_eq(up.channel, 100, "freq 5500 -> channel 100")
				assert_eq(up.radio, "na", "5 GHz")
				assert_eq(up.signal, -47, "signal")
				assert_eq(up.tx_rate, 780000, "kbps")
				assert_eq(up.tx_bytes, 1000, "counters from sysfs")
				assert_eq(up.essid, MESH.essid, "essid")
				assert_nil(backhaul.uplink_report({backhaul_mode = "wired"}, {}, uf), "wired: nothing")
				-- no priority-1 parent from the controller: resolve it from the sibling element
				local si = {scan_table = function() return {
					{bssid = "aa:bb:cc:dd:ee:ff", is_unifi = false},
					{bssid = "78:BB:C1:FE:3F:CB", is_unifi = true, serialno = "78:bb:c1:fe:3f:c9"},
				} end}
				local up2 = backhaul.uplink_report({backhaul_mode = "wireless", backhaul_parent = ""}, {}, uf, si)
				assert_eq(up2.uplink_mac, "78:bb:c1:fe:3f:c9", "parent from the scan table's serialno")
				local up3 = backhaul.uplink_report({backhaul_mode = "wireless", backhaul_parent = ""}, {}, uf,
					{scan_table = function() return {} end})
				assert_nil(up3.uplink_mac, "unknown parent stays absent, never guessed")
			end)
			with_seams({}, "Not connected.\n", function()
				local secs = {{name = "openuf_bh_ul_radio1", radio = "radio1", ssid = MESH.essid, disabled = false}}
				assert_nil(backhaul.uplink_report({backhaul_mode = "wireless"}, {}, fake_ufuci(secs, "phy1-sta0")),
					"not associated: nothing")
			end)
		end
	},
	{
		name = "backhaul: parent_for_bssid() names the sibling behind the BSS joined, from the RAW scan entry, before the push's parent",
		fn = function()
			-- sysinfo.scan_table's entries carry the sibling element as peer_mac;
			-- is_unifi/serialno exist only on the payload's scan_radio_table.
			local si = {scan_table = function() return {
				{bssid = "aa:bb:cc:dd:ee:ff"},
				{bssid = "7A:BB:C1:FE:3F:CB", peer_mac = "78:BB:C1:FE:3F:C9"},
			} end}
			assert_eq(backhaul.parent_for_bssid({backhaul_parent = ""}, "7a:bb:c1:fe:3f:cb", "phy1-sta0", si),
				"78:bb:c1:fe:3f:c9", "the raw entry's peer_mac, case-insensitively on both sides")
			assert_eq(backhaul.parent_for_bssid({backhaul_parent = "11:22:33:44:55:66"}, "7a:bb:c1:fe:3f:cb", "phy1-sta0", si),
				"78:bb:c1:fe:3f:c9", "the BSS actually joined beats the parent the last push named")
			-- Payload-shaped entries still work (is_unifi + serialno).
			local si2 = {scan_table = function() return {
				{bssid = "7a:bb:c1:fe:3f:cb", is_unifi = true, serialno = "78:bb:c1:fe:3f:c9"},
			} end}
			assert_eq(backhaul.parent_for_bssid({}, "7a:bb:c1:fe:3f:cb", "phy1-sta0", si2), "78:bb:c1:fe:3f:c9", "decoded shape too")
			-- The push's parent is the fallback, never the first word.
			assert_eq(backhaul.parent_for_bssid({backhaul_parent = "11:22:33:44:55:66"}, "aa:bb:cc:dd:ee:ff", "phy1-sta0", si),
				"11:22:33:44:55:66", "a BSS with no sibling element: the push's parent")
			assert_eq(backhaul.parent_for_bssid({backhaul_parent = "11:22:33:44:55:66"}, "7a:bb:c1:fe:3f:cb", nil, si),
				"11:22:33:44:55:66", "no interface to scan from: the push's parent")
			assert_nil(backhaul.parent_for_bssid({backhaul_parent = ""}, "aa:bb:cc:dd:ee:ff", "phy1-sta0", si), "neither: unknown, never a guess")
			assert_nil(backhaul.parent_for_bssid({backhaul_parent = ""}, "7a:bb:c1:fe:3f:cb", nil, si), "no interface and no push: unknown")
		end
	},
	{
		name = "backhaul: child_serialno() names the one sibling AP learnt behind a downlink station's netdev",
		fn = function()
			local scans = {{name = "radio1", scan_table = {
				{bssid = "aa:bb:cc:dd:ee:01", is_unifi = false},
				{bssid = "ac:10:07:6f:c6:71", is_unifi = true, serialno = "AC:10:07:6F:C6:70"},
				{bssid = "11:22:33:44:55:66", is_unifi = true, serialno = "11:22:33:44:55:60"},
			}}}
			local fdb = {["ac:10:07:6f:c6:70"] = "phy1-ap1.sta1", ["20:f1:b2:c5:c6:de"] = "phy1-ap1.sta1",
				["aa:10:07:6f:c6:72"] = "phy1-ap1.sta1", ["66:76:5b:ed:8c:a2"] = "phy1-ap0"}
			local si = {lan_bridge = function() return "br-lan" end, bridge_fdb_ports = function() return fdb end}
			assert_eq(backhaul.child_serialno("phy1-ap1.sta1", scans, {}, si), "ac:10:07:6f:c6:70",
				"the sibling whose identity MAC sits behind the station's netdev, lower-cased")
			assert_nil(backhaul.child_serialno("phy1-ap0", scans, {}, si), "a user VAP netdev: no sibling behind it")
			assert_nil(backhaul.child_serialno("phy1-ap1.sta1", {}, {}, si), "no siblings known: nothing")
			fdb["11:22:33:44:55:60"] = "phy1-ap1.sta1"
			assert_nil(backhaul.child_serialno("phy1-ap1.sta1", scans, {}, si), "two siblings behind one netdev (multi-hop): refuse to guess")
		end
	},
	{
		name = "backhaul: lan_bridge() follows a swconfig trunk to the bridge its LAN sub-device sits in",
		fn = function()
			local si = fake_swsysinfo({up = {}})
			assert_eq(backhaul.lan_bridge(SWCFG, si), "br-lan", "eth0 has no master; eth0.1 does")
			local cfg = {net = {lan_cpueth = "eth0", lan_vlanid = 2}}
			assert_nil(backhaul.lan_bridge(cfg, si), "the LAN's VLAN id decides which sub-device")
			local dsa = {lan_bridge = function(i) return i == "br-lan" and "br-lan" or nil end}
			assert_eq(backhaul.lan_bridge({net = {lan_cpueth = "br-lan"}}, dsa), "br-lan", "DSA: the bridge itself")
			assert_nil(backhaul.lan_bridge({net = {}}, dsa), "nothing named: nothing")
		end
	},
	{
		name = "backhaul: tick() on swconfig follows the socket's switch link, not the CPU trunk's always-up carrier",
		fn = function()
			local files = {}
			local dirs = {
				["/sys/class/net"] = "br-lan\nbr-openuf20\neth0\neth0.1\neth0.20\nbr-lan.20\nphy0-ap0\nphy0-sta0\n",
				["/sys/class/net/br-lan/brif"] = "eth0.1\nphy0-ap0\nphy0-sta0\n",
				["/sys/class/net/br-openuf20/brif"] = "eth0.20\nbr-lan.20\nphy0-ap1\n",
			}
			with_sw_seams(files, dirs, function(rec)
				local sw = {gw = 3, up = {[0] = true, [3] = true, [5] = false}, fdb_port = "eth0.1"}
				local si = fake_swsysinfo(sw)
				local st = {backhaul_mode = ""}
				local secs = {{name = "openuf_bh_ul_radio0", radio = "radio0", ssid = MESH.essid, disabled = true}}
				local uf = fake_ufuci(secs, "phy0-sta0")
				assert_eq(backhaul.tick(st, SWCFG, uf, si, nil), "wired", "socket 3 has link")
				assert_eq(st.backhaul_wired_phys, 3, "remembered the switch port the ARL has the gateway on")
				assert_nil(st.backhaul_wired_port, "not the CPU trunk's sub-device")
				assert_eq(sw.fdb_calls or 0, 0, "no bridge FDB dump: this board has no socket of its own outside the switch")
				-- The cable goes. The driver flushes the port's ARL entries; eth0.1 stays up.
				sw.gw, sw.up[3] = nil, false
				assert_eq(backhaul.tick(st, SWCFG, uf, si, nil), "wired", "first tick: patience")
				assert_eq(#uf.calls, 0, "station untouched")
				assert_eq(backhaul.tick(st, SWCFG, uf, si, nil), "wireless", "second tick: wireless")
				assert_eq(uf.calls[1], true, "station enabled")
				assert_eq(st.backhaul_wired_phys, 3, "the socket is still remembered")
				-- The switch forgot the gateway by itself; the bridges did not:
				-- every wired port of br-lan and of the VLAN bridge is flushed,
				-- no wireless one.
				assert_eq(count(rec.writes, "^/sys/class/net/eth0%.1/brport/flush=1$"), 1, "eth0.1 flushed")
				assert_eq(count(rec.writes, "^/sys/class/net/eth0%.20/brport/flush=1$"), 1, "eth0.20 flushed")
				assert_eq(count(rec.writes, "^/sys/class/net/br%-lan%.20/brport/flush=1$"), 1, "br-lan.20 flushed")
				assert_eq(count(rec.writes, "phy0%-"), 0, "wireless ports keep theirs")
				-- On the air the ARL has the gateway on the CPU port (flooded in
				-- from br-lan): not a socket, nothing changes.
				sw.gw = 0
				assert_eq(backhaul.tick(st, SWCFG, uf, si, nil), "wireless", "stays wireless")
				assert_eq(st.backhaul_wired_phys, 3, "the CPU port is never taken for the socket")
				assert_eq(count(rec.cmds, "flush_arl_table"), 0, "no ARL flush while wireless")
				-- Cable back in socket 3, the station still up: the ARL still says
				-- CPU port. Wired at once, and that stale entry is flushed.
				sw.up[3] = true
				assert_eq(backhaul.tick(st, SWCFG, uf, si, nil), "wired", "wired again at once")
				assert_eq(uf.calls[#uf.calls], false, "station disabled")
				assert_eq(count(rec.cmds, "^swconfig dev switch0 set flush_arl_table"), 1,
					"the switch's address table flushed: the gateway sat on the CPU port")
				backhaul.tick(st, SWCFG, uf, si, nil)
				assert_eq(count(rec.cmds, "flush_arl_table"), 2, "and again while it still does")
				sw.gw = 3
				backhaul.tick(st, SWCFG, uf, si, nil)
				assert_eq(count(rec.cmds, "flush_arl_table"), 2, "not once the gateway is behind the socket")
				-- Past the window a CPU-port entry is left alone: a board with two
				-- CPU ports lists the gateway there legitimately.
				sw.gw = 0
				for _ = 1, 4 do backhaul.tick(st, SWCFG, uf, si, nil) end
				assert_eq(count(rec.cmds, "flush_arl_table"), 2, "only in the heartbeats right after the switch")
				sw.gw = 3
				-- A cable moved to the other socket is followed, as on DSA.
				sw.gw, sw.up[5] = 5, true
				backhaul.tick(st, SWCFG, uf, si, nil)
				assert_eq(st.backhaul_wired_phys, 5, "socket 5 now")
			end)
		end
	},
	{
		name = "backhaul: tick() on swconfig holds when the switch cannot be read",
		fn = function()
			with_sw_seams({}, {}, function()
				local si = fake_swsysinfo({up = {}})   -- no ports: swconfig missing
				local st = {backhaul_mode = "wired", backhaul_wired_phys = 3}
				local secs = {{name = "openuf_bh_ul_radio0", radio = "radio0", ssid = MESH.essid, disabled = true}}
				local uf = fake_ufuci(secs, "phy0-sta0")
				for _ = 1, 4 do backhaul.tick(st, SWCFG, uf, si, nil) end
				assert_eq(st.backhaul_mode, "wired", "unknown link is not a lost link")
				assert_eq(#uf.calls, 0, "station untouched")
			end)
		end
	},
	{
		name = "backhaul: tick() on swconfig asks the bridge only about a socket that is a netdev of its own",
		fn = function()
			-- TL-WDR3500 shape: four switch sockets and a WAN PHY outside the switch.
			local cfg = {
				net  = {lan_cpueth = "eth0", ports = {{idx = 1, swport = "lan1"}, {idx = 5, ifname = "eth1"}}},
				vlan = {device = "switch0", cpu_lan = 0, cpu_wan = 0, ports = {lan1 = 1}},
			}
			local files = {["/sys/class/net/eth1/operstate"] = "up\n"}
			with_sw_seams(files, {}, function()
				local sw = {gw = 0, up = {[0] = true, [1] = false}, fdb_port = "eth1"}
				local si = fake_swsysinfo(sw)
				local st = {backhaul_mode = ""}
				local secs = {{name = "openuf_bh_ul_radio0", radio = "radio0", ssid = MESH.essid, disabled = true}}
				local uf = fake_ufuci(secs, "phy0-sta0")
				assert_eq(backhaul.tick(st, cfg, uf, si, nil), "wired", "eth1 has carrier")
				assert_eq(st.backhaul_wired_port, "eth1", "the own-PHY socket, from the bridge")
				assert_nil(st.backhaul_wired_phys, "no switch port")
				-- The CPU trunk's sub-device is never a socket.
				local st2 = {backhaul_mode = ""}
				sw.fdb_port = "eth0.1"
				backhaul.tick(st2, cfg, uf, si, nil)
				assert_nil(st2.backhaul_wired_port, "eth0.1 refused")
				-- Gateway behind switch socket 1 now: the switch wins, the netdev is forgotten.
				sw.gw, sw.up[1] = 1, true
				backhaul.tick(st, cfg, uf, si, nil)
				assert_eq(st.backhaul_wired_phys, 1, "switch socket")
				assert_nil(st.backhaul_wired_port, "one remembered uplink at a time")
			end)
		end
	},
	{
		name = "backhaul: child_serialno() finds a swconfig parent's LAN bridge through the trunk's sub-device",
		fn = function()
			local scans = {{name = "radio0", scan_table = {
				{bssid = "ac:10:07:6f:c6:71", is_unifi = true, serialno = "ac:10:07:6f:c6:70"},
			}}}
			local si = fake_swsysinfo({up = {}})
			si.bridge_fdb_ports = function(br)
				assert_eq(br, "br-lan", "asked of the LAN bridge")
				return {["ac:10:07:6f:c6:70"] = "phy0-ap1.sta1"}
			end
			assert_eq(backhaul.child_serialno("phy0-ap1.sta1", scans, SWCFG, si), "ac:10:07:6f:c6:70",
				"the child behind the WDS netdev")
		end
	},
	{
		name = "backhaul: follow_parent_channel() pins the station's radio to the parent's channel once it holds",
		fn = function()
			local o_popen, o_log = backhaul._popen, backhaul._log
			local link = "Connected to 00:00:5e:00:53:80 (on phy0-sta0)\n\tfreq: 5620.0\n"
			backhaul._popen = function(cmd)
				assert_eq(cmd, "iw dev phy0-sta0 link", "asks the station")
				return link
			end
			backhaul._log = function() end
			backhaul._chan_seen, backhaul._chan_ticks, backhaul._dirty = nil, 0, false
			local uci = {radio0 = "153"}
			local sets = {}
			local uf = {
				radio_channel = function(r) return uci[r] end,
				set_radio_channel = function(r, c) sets[#sets + 1] = r .. "=" .. c; uci[r] = tostring(c); return true end,
			}
			local st = {backhaul_mode = "wireless"}
			local first = backhaul.follow_parent_channel(st, uf, "phy0-sta0", "radio0")
			local second = backhaul.follow_parent_channel(st, uf, "phy0-sta0", "radio0")
			local third = backhaul.follow_parent_channel(st, uf, "phy0-sta0", "radio0")
			link = "Not connected.\n"
			local gone = backhaul.follow_parent_channel(st, uf, "phy0-sta0", "radio0")
			backhaul._popen, backhaul._log = o_popen, o_log
			assert_nil(first, "one sighting is not enough")
			assert_eq(second, 124, "moved on the second")
			assert_nil(third, "already there")
			assert_nil(gone, "no link, no move")
			assert_eq(#sets, 1, "one reload")
			assert_eq(sets[1], "radio0=124", "the parent's channel")
			assert_eq(st.backhaul_parent_channel, 124, "remembered for pushes")
		end
	},
	{
		name = "backhaul: phy_aps() lists a phy's AP interfaces and which beacon, leaving out AP/VLANs and other phys",
		fn = function()
			-- `iw dev` on a stalled hAP ac: neither AP has an ssid line.
			local stalled = table.concat({
				"phy#1",
				"\tInterface phy1-ap0", "\t\tssid other", "\t\ttype AP",
				"phy#0",
				"\tInterface phy0-ap1-21", "\t\ttype AP/VLAN",
				"\tInterface phy0-ap1", "\t\ttype AP", "\t\ttxpower 27.00 dBm",
				"\tInterface phy0-sta0", "\t\tssid vwire-x", "\t\ttype managed",
				"\t\tchannel 124 (5620 MHz), width: 80 MHz, center1: 5610 MHz",
				"\tInterface phy0-ap0", "\t\ttype AP", "\t\ttxpower 27.00 dBm",
			}, "\n")
			local aps = backhaul.phy_aps(stalled, "phy0")
			assert_eq(#aps, 2, "two APs on phy0, the AP/VLAN and the station left out")
			assert_eq(aps[1].ifname, "phy0-ap1", "first AP")
			assert_eq(aps[2].ifname, "phy0-ap0", "second AP")
			assert_true(not aps[1].beaconing and not aps[2].beaconing, "neither beacons")
			local up = stalled:gsub("\tInterface phy0%-ap0\n", "\tInterface phy0-ap0\n\t\tssid eG\n")
			assert_true(backhaul.phy_aps(up, "phy0")[2].beaconing, "an ssid line is a started AP")
			assert_eq(#backhaul.phy_aps(stalled, "phy7"), 0, "an unknown phy has none")
		end
	},
	{
		name = "backhaul: channel_dfs() reads the radar flag and DFS state of one channel",
		fn = function()
			local ch = table.concat({
				"Band 2:",
				"\t* 5600 MHz [120] ", "\t  Radar detection", "\t  DFS state: available (for 9 sec)",
				"\t* 5620 MHz [124] ", "\t  Maximum TX power: 27.0 dBm", "\t  Radar detection",
				"\t  Channel widths: 20MHz HT40- HT40+ VHT80", "\t  DFS state: usable (for 36212 sec)",
				"\t* 5745 MHz [149] ", "\t  Maximum TX power: 30.0 dBm",
			}, "\n")
			local d = backhaul.channel_dfs(ch, 5620)
			assert_true(d.radar, "124 is a radar channel")
			assert_eq(d.state, "usable", "never cleared")
			assert_eq(backhaul.channel_dfs(ch, 5600).state, "available", "the neighbour's own state, not 124's")
			local c = backhaul.channel_dfs(ch, 5745)
			assert_true(not c.radar and c.state == nil, "149 is no DFS channel")
			assert_nil(backhaul.channel_dfs(ch, 5180), "an unlisted channel is unknown")
		end
	},
	{
		name = "backhaul: check_ap_stall() names the DFS cause once, after STALL_TICKS, and clears when the APs beacon",
		fn = function()
			local o_popen, o_read, o_log = backhaul._popen, backhaul._read_file, backhaul._log
			-- ap: "stalled" (no channel, no ssid), "cac" (channel, no ssid), "up" (both)
			local logs, ap = {}, "stalled"
			local link = "Connected to 00:00:5e:00:53:80 (on phy0-sta0)\n\tfreq: 5620.0\n"
			backhaul._popen = function(cmd)
				if cmd == "iw dev phy0-sta0 link" then return link end
				if cmd == "iw dev" then
					return "phy#0\n\tInterface phy0-ap0\n"
						.. (ap == "up" and "\t\tssid eG\n" or "") .. "\t\ttype AP\n"
						.. (ap ~= "stalled" and "\t\tchannel 124 (5620 MHz), width: 80 MHz\n" or "")
				end
				if cmd == "iw phy phy0 channels" then
					return "\t* 5620 MHz [124] \n\t  Radar detection\n\t  DFS state: usable (for 3 sec)\n"
				end
				error("unexpected command " .. cmd)
			end
			backhaul._read_file = function(path)
				assert_eq(path, "/sys/class/net/phy0-sta0/phy80211/name", "the station's phy")
				return "phy0\n"
			end
			backhaul._log = function(m) logs[#logs + 1] = m end
			backhaul._stall_ticks, backhaul.ap_stall = 0, nil
			local r1 = backhaul.check_ap_stall("phy0-sta0", "radio0")
			local r2 = backhaul.check_ap_stall("phy0-sta0", "radio0")
			local r3 = backhaul.check_ap_stall("phy0-sta0", "radio0")
			local r4 = backhaul.check_ap_stall("phy0-sta0", "radio0")
			assert_nil(r1, "one silent heartbeat is a reload, not a stall")
			assert_nil(r2, "two neither")
			assert_eq(r3 and r3.reason, "dfs", "the third names DFS")
			assert_eq(r3.channel, 124, "on the parent's channel")
			assert_eq(r3.dfs_state, "usable", "and why")
			assert_eq(r3.phy, "phy0", "with the phy")
			assert_eq(r3.ifname, "phy0-ap0", "and the AP hostapd answers on")
			assert_eq(r4, r3, "still stalled")
			assert_eq(#logs, 1, "said once, not every heartbeat")
			assert_true(logs[1]:find("DFS channel 124", 1, true) ~= nil, "the log names the cause")
			ap = "up"
			assert_nil(backhaul.check_ap_stall("phy0-sta0", "radio0"), "beaconing again")
			assert_nil(backhaul.ap_stall, "cleared")
			assert_true(logs[2]:find("on the air again", 1, true) ~= nil, "and said so")
			-- A CAC in progress holds a channel but has no ssid yet (hostapd's ubus
			-- object is gone meanwhile -- the false stall the first build raised).
			ap = "cac"
			for _ = 1, 5 do assert_nil(backhaul.check_ap_stall("phy0-sta0", "radio0"), "CAC running") end
			-- No link: nothing to judge.
			ap, link = "stalled", "Not connected.\n"
			for _ = 1, 5 do assert_nil(backhaul.check_ap_stall("phy0-sta0", "radio0"), "station down") end
			backhaul._popen, backhaul._read_file, backhaul._log = o_popen, o_read, o_log
			backhaul._stall_ticks, backhaul.ap_stall = 0, nil
		end
	},
	{
		name = "backhaul: check_ap_stall() says unknown, not DFS, on a channel that needs no CAC",
		fn = function()
			local o_popen, o_read, o_log = backhaul._popen, backhaul._read_file, backhaul._log
			local logs = {}
			backhaul._popen = function(cmd)
				if cmd == "iw dev phy0-sta0 link" then return "Connected to 00:00:5e:00:53:80\n\tfreq: 5745.0\n" end
				if cmd == "iw dev" then return "phy#0\n\tInterface phy0-ap0\n\t\ttype AP\n" end
				if cmd == "iw phy phy0 channels" then return "\t* 5745 MHz [149] \n\t  Maximum TX power: 30.0 dBm\n" end
				error("unexpected command " .. cmd)
			end
			backhaul._read_file = function() return "phy0" end
			backhaul._log = function(m) logs[#logs + 1] = m end
			backhaul._stall_ticks, backhaul.ap_stall = 0, nil
			local r
			for _ = 1, backhaul.STALL_TICKS do r = backhaul.check_ap_stall("phy0-sta0", "radio0") end
			backhaul._popen, backhaul._read_file, backhaul._log = o_popen, o_read, o_log
			backhaul._stall_ticks, backhaul.ap_stall = 0, nil
			assert_eq(r and r.reason, "unknown", "no radar flag: the cause is not guessed")
			assert_true(logs[1]:find("DFS", 1, true) == nil, "and the log does not blame DFS")
		end
	},
	{
		name = "backhaul: dfs_cac_recover off (the default) never restarts hostapd on a DFS stall",
		fn = function()
			local o_exec, o_log = backhaul._exec, backhaul._log
			local execs = {}
			backhaul._exec = function(c) execs[#execs + 1] = c; return 0 end
			backhaul._log = function() end
			local st = {backhaul_mode = "wireless"}
			local stall = {radio = "radio0", channel = 124, reason = "dfs", phy = "phy0", ifname = "phy0-ap0"}
			assert_false(backhaul.cac_start(st, nil, nil, stall), "no config: off")
			assert_false(backhaul.cac_start(st, {config = {}}, nil, stall), "absent: off")
			assert_false(backhaul.cac_start(st, {config = {dfs_cac_recover = false}}, nil, stall), "false: off")
			backhaul._exec, backhaul._log = o_exec, o_log
			assert_eq(#execs, 0, "hostapd was never touched")
			assert_nil(st.backhaul_cac, "no job")
		end
	},
	{
		name = "backhaul: dfs_cac_recover restarts hostapd in place (the uplink untouched) and closes the job once an AP beacons",
		fn = function()
			local o = {backhaul._popen, backhaul._log, backhaul._exec, backhaul._now}
			local now, beacon, execs, logs = 1000, false, {}, {}
			backhaul._now = function() return now end
			backhaul._exec = function(cmd) execs[#execs + 1] = cmd; return 0 end
			backhaul._log = function(m) logs[#logs + 1] = m end
			backhaul._popen = function(cmd)
				if cmd == "iw dev" then
					return "phy#0\n\tInterface phy0-ap0\n" .. (beacon and "\t\tssid eG\n" or "") .. "\t\ttype AP\n"
				end
				error("unexpected " .. cmd)
			end
			local uf = fake_ufuci({{name = "openuf_bh_ul_radio0", radio = "radio0", disabled = false}}, "phy0-sta0")
			uf.radio_channel = function() return "124" end
			local st = {backhaul_mode = "wireless"}
			local cfg = {config = {dfs_cac_recover = true}}
			local stall = {radio = "radio0", channel = 124, reason = "dfs", phy = "phy0", ifname = "phy0-ap0"}
			local unknown = {radio = "radio0", channel = 124, reason = "unknown", phy = "phy0", ifname = "phy0-ap0"}
			assert_false(backhaul.cac_start(st, cfg, uf, unknown), "an unproven cause is never acted on")
			assert_false(backhaul.cac_start(st, cfg, uf, {radio = "radio0", channel = 124, reason = "dfs",
				phy = "phy0", ifname = "x; reboot"}), "an interface name cannot reach the shell")
			assert_true(backhaul.cac_start(st, cfg, uf, stall), "started")
			assert_eq(#execs, 1, "one command")
			assert_eq(execs[1], "hostapd_cli -i phy0-ap0 disable >/dev/null 2>&1; sleep 1; "
				.. "hostapd_cli -i phy0-ap0 enable >/dev/null 2>&1", "disable + enable: hostapd's ordinary start")
			assert_eq(#uf.calls, 0, "the uplink station was not touched")
			assert_eq(st.backhaul_cac.phy, "phy0", "the job remembers the phy")
			assert_eq(backhaul.ap_stall.reason, "cac", "status says a CAC is running")
			now = 1030
			assert_true(backhaul.cac_step(st), "CAC still running")
			now, beacon = 1062, true
			assert_false(backhaul.cac_step(st), "done")
			assert_nil(st.backhaul_cac, "job closed")
			assert_eq(st.backhaul_cac_rejoined, 1062, "dated, to judge whether it holds")
			assert_true(logs[#logs]:find("cleared in 62 s", 1, true) ~= nil, "and said how long it took")
			assert_nil(backhaul.ap_stall, "no stall reported any more")
			assert_eq(#uf.calls, 0, "still nothing done to the station")
			backhaul._popen, backhaul._log, backhaul._exec, backhaul._now = o[1], o[2], o[3], o[4]
		end
	},
	{
		name = "backhaul: a CAC job fails after CAC_MAX and backs off when the clearing does not hold",
		fn = function()
			local o = {backhaul._popen, backhaul._log, backhaul._exec, backhaul._now}
			local now = 5000
			backhaul._now = function() return now end
			backhaul._exec = function() return 0 end
			backhaul._log = function() end
			backhaul._popen = function() return "phy#0\n\tInterface phy0-ap0\n\t\ttype AP\n" end
			local uf = {radio_channel = function() return "124" end}
			local st = {backhaul_mode = "wireless"}
			local cfg = {config = {dfs_cac_recover = true}}
			local stall = {radio = "radio0", channel = 124, reason = "dfs", phy = "phy0", ifname = "phy0-ap0"}
			assert_true(backhaul.cac_start(st, cfg, uf, stall), "started")
			now = 5000 + backhaul.CAC_MAX + 1
			assert_false(backhaul.cac_step(st), "given up")
			assert_eq(st.backhaul_cac_fails, 1, "a failure counted")
			now = 5000 + backhaul.RETRY_BASE + 1
			assert_false(backhaul.cac_start(st, cfg, uf, stall), "one failure doubles the wait")
			now = 5000 + backhaul.cac_backoff(1) + 1
			assert_true(backhaul.cac_start(st, cfg, uf, stall), "retried after the backoff")
			backhaul._popen = function() return "phy#0\n\tInterface phy0-ap0\n\t\tssid eG\n\t\ttype AP\n" end
			now = now + 70
			assert_false(backhaul.cac_step(st), "cleared")
			assert_eq(st.backhaul_cac_fails, 1, "a clearing is not yet a failure")
			now = now + 60
			assert_false(backhaul.cac_start(st, cfg, uf, stall), "the stall came back within HOLD: wait")
			assert_eq(st.backhaul_cac_fails, 2, "and that counts as a failure")
			assert_eq(backhaul.cac_backoff(20), backhaul.RETRY_MAX, "the wait is capped")
			uf.radio_channel = function() return "100" end
			now = now + backhaul.RETRY_MAX
			assert_false(backhaul.cac_start(st, cfg, uf, stall),
				"UCI not on the parent's channel yet: a CAC would clear the wrong one")
			backhaul._popen, backhaul._log, backhaul._exec, backhaul._now = o[1], o[2], o[3], o[4]
		end
	},
	{
		name = "backhaul: an open CAC job is judged by tick() after a restart, and closed when the uplink went wired",
		fn = function()
			local o = {backhaul._popen, backhaul._log, backhaul._exec, backhaul._now}
			backhaul._now = function() return 100 end
			backhaul._exec = function() return 0 end
			backhaul._log = function() end
			backhaul._popen = function(cmd)
				if cmd == "iw dev" then return "phy#0\n\tInterface phy0-ap0\n\t\tssid eG\n\t\ttype AP\n" end
				return ""
			end
			local uf = fake_ufuci({{name = "openuf_bh_ul_radio0", radio = "radio0", disabled = false}}, "phy0-sta0")
			local st = {backhaul_mode = "wireless",
				backhaul_cac = {since = 40, radio = "radio0", channel = 124, phy = "phy0"}}
			backhaul.tick(st, {}, uf, {}, nil)
			assert_nil(st.backhaul_cac, "the job a previous daemon started was closed on the first tick")
			assert_eq(st.backhaul_cac_rejoined, 100, "as a success")
			local st2 = {backhaul_mode = "wired",
				backhaul_cac = {since = 40, radio = "radio0", channel = 124, phy = "phy0"}}
			assert_false(backhaul.cac_step(st2), "closed")
			assert_nil(st2.backhaul_cac, "the job is gone")
			assert_eq(#uf.calls, 0, "no station switched by either")
			backhaul._popen, backhaul._log, backhaul._exec, backhaul._now = o[1], o[2], o[3], o[4]
		end
	},
	{
		name = "backhaul: pin_parent_channel() overrides the pushed channel on the uplink radio only while wireless",
		fn = function()
			local uf = fake_ufuci({{name = "openuf_bh_ul_radio0", radio = "radio0", disabled = false}}, "phy0-sta0")
			local rt = {{name = "radio0", channel = 153}, {name = "radio1", channel = 6}}
			assert_nil(backhaul.pin_parent_channel(rt, {backhaul_mode = "wired", backhaul_parent_channel = 124}, uf),
				"wired: the controller's channel stands")
			assert_eq(rt[1].channel, 153, "untouched while wired")
			assert_eq(backhaul.pin_parent_channel(rt, {backhaul_mode = "wireless", backhaul_parent_channel = 124}, uf),
				"radio0", "pinned")
			assert_eq(rt[1].channel, 124, "the parent's channel")
			assert_eq(rt[2].channel, 6, "the other radio keeps its own")
			assert_nil(backhaul.pin_parent_channel(rt, {backhaul_mode = "wireless"}, uf),
				"no parent channel learnt yet")
		end
	},
	{
		name = "backhaul: pin_parent_channel() narrows the pushed width to what the parent's channel has",
		fn = function()
			local uf = fake_ufuci({{name = "openuf_bh_ul_radio0", radio = "radio0", disabled = false}}, "phy0-sta0")
			uf.cap_htmode = dofile("openuf/ucihelper.lua").cap_htmode
			local o_log = backhaul._log
			local logged = {}
			backhaul._log = function(m) logged[#logged + 1] = m end
			local rt = {{name = "radio0", channel = 36, htmode = "VHT80"}}
			backhaul.pin_parent_channel(rt, {backhaul_mode = "wireless", backhaul_parent_channel = 165}, uf)
			assert_eq(rt[1].htmode, "VHT20", "165 has no 80 MHz block")
			assert_contains(logged[1] or "", "VHT80", "and says so")
			rt = {{name = "radio0", channel = 36, htmode = "VHT80"}}
			backhaul.pin_parent_channel(rt, {backhaul_mode = "wireless", backhaul_parent_channel = 124}, uf)
			assert_eq(rt[1].htmode, "VHT80", "124 sits in 116-128: kept")
			rt = {{name = "radio0", channel = 36, htmode = "HE160"}}
			backhaul.pin_parent_channel(rt, {backhaul_mode = "wireless", backhaul_parent_channel = 149}, uf)
			assert_eq(rt[1].htmode, "HE80", "149 has 80, not 160")
			backhaul._log = o_log
			assert_eq(backhaul.max_width_5g(40), 160, "36-64")
			assert_eq(backhaul.max_width_5g(144), 80, "132-144")
			assert_eq(backhaul.max_width_5g(161), 80, "149-161")
			assert_eq(backhaul.max_width_5g(165), 20, "165 alone")
			assert_nil(backhaul.max_width_5g(6), "2.4 GHz: not judged")
		end
	},
	{
		name = "backhaul: a failed CAC leaves no stale stall behind, and a clearing that held resets the backoff",
		fn = function()
			local o = {backhaul._popen, backhaul._log, backhaul._exec, backhaul._now}
			local now = 9000
			backhaul._now = function() return now end
			backhaul._exec = function() return 0 end
			backhaul._log = function() end
			backhaul._popen = function() return "phy#0\n\tInterface phy0-ap0\n\t\ttype AP\n" end
			local uf = {radio_channel = function() return "124" end}
			local st = {backhaul_mode = "wireless", backhaul_cac_fails = 3}
			local cfg = {config = {dfs_cac_recover = true}}
			local stall = {radio = "radio0", channel = 124, reason = "dfs", phy = "phy0", ifname = "phy0-ap0"}
			-- A clearing that held past HOLD: the earlier failures are forgotten.
			st.backhaul_cac_rejoined = now - backhaul.HOLD - 1
			assert_true(backhaul.cac_start(st, cfg, uf, stall), "started without the inflated backoff")
			assert_eq(st.backhaul_cac_fails, 0, "the failures before a held clearing reset")
			now = now + backhaul.CAC_MAX + 1
			assert_false(backhaul.cac_step(st), "failed")
			assert_nil(backhaul.ap_stall, "no {reason = cac} left behind")
			assert_eq(backhaul._stall_ticks, 0, "the stall is diagnosed afresh")
			backhaul._popen, backhaul._log, backhaul._exec, backhaul._now = o[1], o[2], o[3], o[4]
		end
	},
	{
		name = "backhaul: follow_parent_channel() does not pin a 6 GHz parent's frequency as a 5 GHz channel",
		fn = function()
			local o_popen, o_log = backhaul._popen, backhaul._log
			backhaul._popen = function() return "Connected to 00:00:5e:00:53:80 (on phy0-sta0)\n\tfreq: 5975.0\n" end
			backhaul._log = function() end
			backhaul._chan_seen, backhaul._chan_ticks = nil, 0
			local sets = 0
			local uf = {radio_channel = function() return "36" end,
				set_radio_channel = function() sets = sets + 1 end}
			for _ = 1, 3 do backhaul.follow_parent_channel({}, uf, "phy0-sta0", "radio0") end
			backhaul._popen, backhaul._log = o_popen, o_log
			assert_eq(sets, 0, "no channel 195 written")
		end
	},
	{
		name = "backhaul: follow_preferred_parent() roams to the named parent's downlink, once per ROAM_EVERY",
		fn = function()
			local o_popen, o_exec, o_log = backhaul._popen, backhaul._exec, backhaul._log
			local cmds = {}
			backhaul._popen = function() return "Connected to 8e:78:48:06:03:fd (on phy0-sta0)\n" end
			backhaul._exec = function(c) cmds[#cmds + 1] = c; return 0 end
			backhaul._log = function() end
			backhaul._roam_at = nil
			local ssid = "vwire-edac2772347aef1a"
			local scan = {
				{bssid = "8e:78:48:06:03:fd", essid = ssid, signal = -64, age = 0, peer_mac = "84:78:48:06:03:f9"},
				-- the parent's client WLAN: same device, not the downlink
				{bssid = "a8:9c:6c:b8:ab:80", essid = "corp", signal = -50, age = 0, peer_mac = "a8:9c:6c:b8:ab:7e"},
				-- its hidden downlink
				{bssid = "b2:9c:6c:b8:ab:80", signal = -55, age = 0, peer_mac = "a8:9c:6c:b8:ab:7e", freq = 5180},
			}
			local si = {scan_table = function() return scan end}
			local st = {backhaul_parent = "A8:9C:6C:B8:AB:7E"}
			assert_eq(backhaul.follow_preferred_parent(st, "phy0-sta0", ssid, si, 1000),
				"b2:9c:6c:b8:ab:80", "roams to the hidden downlink, not the client WLAN")
			assert_eq(cmds[1], "iw dev phy0-sta0 scan freq 5180 ssid 'vwire-edac2772347aef1a' >/dev/null 2>&1",
				"first a probe naming the hidden downlink's SSID, on its channel")
			assert_true(cmds[2]:find("wpa_supplicant.phy0-sta0 control", 1, true) ~= nil
				and cmds[2]:find("ROAM b2:9c:6c:b8:ab:80", 1, true) ~= nil, "then ubus ROAM")
			assert_nil(backhaul.follow_preferred_parent(st, "phy0-sta0", ssid, si, 1000 + 60),
				"not again within ROAM_EVERY")
			assert_eq(#cmds, 2, "one probe, one roam")
			-- Already on it: nothing.
			backhaul._roam_at = nil
			backhaul._popen = function() return "Connected to b2:9c:6c:b8:ab:80 (on phy0-sta0)\n" end
			assert_nil(backhaul.follow_preferred_parent(st, "phy0-sta0", ssid, si, 5000), "on the parent")
			-- Too weak, stale, or no parent named: nothing.
			backhaul._popen = function() return "Connected to 8e:78:48:06:03:fd (on phy0-sta0)\n" end
			scan[3].signal = -80
			assert_nil(backhaul.follow_preferred_parent(st, "phy0-sta0", ssid, si, 9000), "too weak")
			scan[3].signal, scan[3].age = -55, 600
			assert_nil(backhaul.follow_preferred_parent(st, "phy0-sta0", ssid, si, 9000), "stale entry")
			scan[3].age = 0
			assert_nil(backhaul.follow_preferred_parent({backhaul_parent = ""}, "phy0-sta0", ssid, si, 9000),
				"Auto in the controller")
			-- Not joined: left to wpa_supplicant.
			backhaul._popen = function() return "Not connected.\n" end
			assert_nil(backhaul.follow_preferred_parent(st, "phy0-sta0", ssid, si, 9000), "not joined")
			assert_eq(#cmds, 2, "still one probe and one roam")
			backhaul._popen, backhaul._exec, backhaul._log = o_popen, o_exec, o_log
			backhaul._roam_at = nil
		end
	},
	{
		name = "backhaul: follow_preferred_parent() takes conf.lua's preferred_parent, and auto moves only to a clearly better, near downlink",
		fn = function()
			local o_popen, o_exec, o_log = backhaul._popen, backhaul._exec, backhaul._log
			local cmds = {}
			backhaul._popen = function() return "Connected to 8e:78:48:06:03:fd (on phy0-sta0)\n" end
			backhaul._exec = function(c) cmds[#cmds + 1] = c; return 0 end
			backhaul._log = function() end
			local ssid = "vwire-edac2772347aef1a"
			local function dl(bssid, peer, sig, hop)
				return {bssid = bssid, essid = nil, signal = sig, age = 0, peer_mac = peer,
					mesh_downlink = hop ~= nil or nil, mesh_hop = hop}
			end
			local scan = {
				dl("8e:78:48:06:03:fd", "84:78:48:06:03:f9", -71, 0),   -- on it: wired U7
				dl("b2:9c:6c:b8:ab:80", "a8:9c:6c:b8:ab:7e", -55, 1),   -- meshed U7, 16 dB louder
			}
			local si = {scan_table = function() return scan end}
			-- Named locally, over the controller's choice.
			backhaul._roam_at = nil
			local cfg = {config = {preferred_parent = "a8:9c:6c:b8:ab:7e"}}
			assert_eq(backhaul.follow_preferred_parent({backhaul_parent = "84:78:48:06:03:f9"},
				"phy0-sta0", ssid, si, 1000, cfg), "b2:9c:6c:b8:ab:80", "conf.lua wins over the controller")
			-- Auto: 16 dB louder, one hop further -> move.
			backhaul._roam_at = nil
			assert_eq(backhaul.follow_preferred_parent({}, "phy0-sta0", ssid, si, 2000, {config = {}}),
				"b2:9c:6c:b8:ab:80", "auto: clearly better and one hop out")
			-- Auto: only 6 dB louder, minus 3 for the hop -> stay.
			backhaul._roam_at = nil
			scan[2].signal = -65
			assert_nil(backhaul.follow_preferred_parent({}, "phy0-sta0", ssid, si, 3000, {config = {}}),
				"auto: under the margin")
			-- The case it was written for: -64 on the wired AP, -56 one hop out
			-- (scores -64 and -59) -> move; and from there, not back.
			backhaul._roam_at = nil
			scan[1].signal, scan[2].signal = -64, -56
			assert_eq(backhaul.follow_preferred_parent({}, "phy0-sta0", ssid, si, 3500, {config = {}}),
				"b2:9c:6c:b8:ab:80", "auto: 8 dB louder one hop out is the better parent")
			backhaul._roam_at = nil
			backhaul._popen = function() return "Connected to b2:9c:6c:b8:ab:80 (on phy0-sta0)\n" end
			assert_nil(backhaul.follow_preferred_parent({}, "phy0-sta0", ssid, si, 3600, {config = {}}),
				"auto: and no swap back")
			backhaul._popen = function() return "Connected to 8e:78:48:06:03:fd (on phy0-sta0)\n" end
			scan[1].signal = -71
			-- Auto: louder, but two hops further (a child of ours) -> stay.
			backhaul._roam_at = nil
			scan[2].signal, scan[2].mesh_hop = -50, 2
			assert_nil(backhaul.follow_preferred_parent({}, "phy0-sta0", ssid, si, 4000, {config = {}}),
				"auto: never two hops further")
			-- Auto: no hop count (openUF's own downlink) -> not a candidate.
			backhaul._roam_at = nil
			scan[2].mesh_hop, scan[2].mesh_downlink = nil, nil
			assert_nil(backhaul.follow_preferred_parent({}, "phy0-sta0", ssid, si, 5000, {config = {}}),
				"auto: a downlink without a hop count")
			-- Auto off.
			backhaul._roam_at = nil
			scan[2].mesh_hop, scan[2].mesh_downlink = 1, true
			assert_nil(backhaul.follow_preferred_parent({}, "phy0-sta0", ssid, si, 6000,
				{config = {mesh_parent_auto = false}}), "mesh_parent_auto = false")
			assert_eq(#cmds, 6, "three roams in all, each after its probe")
			backhaul._popen, backhaul._exec, backhaul._log = o_popen, o_exec, o_log
			backhaul._roam_at = nil
		end
	},
}
