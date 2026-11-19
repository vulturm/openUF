--[[
	MikroTik hAP ac (RB962UiGS-5HacT2HnT) hardware profile.

	Sources, each re-checkable (OpenWrt 25.12, ath79/mikrotik):
	  • target/linux/ath79/dts/qca9558_mikrotik_routerboard-962uigs-5hact2hnt.dts
	    and qca9558_mikrotik_routerboard-96x.dtsi   eth0 = RGMII to the switch,
	    eth1 = SGMII to the SFP cage, one LED (green:user)
	  • .../mikrotik/base-files/etc/board.d/02_network   switch layout, and the
	    MAC: read from RouterBoot's hard_config, put on the UCI devices only
	  • target/linux/ath79/image/mikrotik.mk   ath10k-ct + qca988x firmware for
	    5 GHz; no DEVICE_ALT*_VARIANT, so one board, one compatible string
	Measured on one unit (OpenWrt 25.12.0), deployed as a mesh
	child with no cable: switch0 = AR8337, 7 ports, CPU on 0; radio0 = 5 GHz
	(ath10k, phy0), radio1 = 2.4 GHz (ath9k, phy1); /sys/class/leds holds
	green:user plus the two phy throughput triggers and nothing else.

	⚠️ THE ETHERNET MACS ARE RANDOM ON EVERY BOOT. RouterBoot keeps the MAC in
	hard_config, which the DTS cannot point ag71xx at, so dmesg says "invalid
	MAC address, using random address" for eth0 and eth1 alike. board.d puts
	the real one (hard_config's mac_base, the label MAC) on eth0.1 and eth0.2
	only. The kernel exposes hard_config as /sys/firmware/mikrotik/hard_config,
	so this map names its mac_base as the identity (identity_mac_file below):
	both daemons report the label MAC whatever eth0 holds this boot, with no
	UCI pin. br-lan carries the same MAC (it follows eth0.1), so the identity,
	the DHCP server's view and lldpd's chassis ID agree. Checked on the unit:
	mac_base, eth0.1 and br-lan held one MAC while eth0 and eth1 held random
	ones (addr_assign_type 1).

	⚠️ The order of ether2..ether5 on switch ports 2..5 is not stated anywhere
	in the source (board.d gives them no label numbers, and 01_leds has no
	entry for this board). See dev.conf.vlan below.

	Presented to the controller as a U6-InWall, the validated identity. The
	hardware is WiFi 5; `rf_config`'s hardware clamp keeps the radios at what
	`iw phy` advertises. "uhdiw" (UAP-IW-HD: WiFi 5, five sockets, like this
	board) would be the closer identity, but no controller has adopted it yet.
]]--

local dev = {}
dev.conf = {}

-- The DTS compatible string; setup.sh matches it against /tmp/sysinfo/board_name.
-- Keep it on ONE line -- setup.sh's map_boards() parses it with sed.
dev.openwrt_boards = {"mikrotik,routerboard-962uigs-5hact2hnt"}

-- OpenWrt network layout.
--
-- ONE switch netdev. board.d 02_network:
--   ucidef_add_switch "switch0" "0@eth0" "2:lan" "3:lan" "4:lan" "5:lan" "1:wan"
-- No `u` on the CPU port, so it is TAGGED: the LAN reaches the SoC as eth0.1
-- (bridged into br-lan) and the WAN as eth0.2, both over the eth0 trunk --
-- the Archer A7 v5's shape.
--
-- lan_cpueth is the TRUNK, eth0. The generic map's eth1 is the SFP cage on
-- this board, outside the switch and outside br-lan: with it every inform
-- reported ip 0.0.0.0, the identity was eth1's random MAC, and a pushed VLAN
-- 20 became eth1.20, a bridge whose only uplink was an empty SFP cage. With
-- eth0 a pushed VLAN 20 is eth0.20 beside eth0.1, announce.get_ip follows
-- eth0 -> eth0.1 -> br-lan to the address, and a tagged SSID crosses a mesh
-- hop through meshvlan's br-lan.<vid> (which needs dev.conf.vlan below).
dev.conf.net = {
	lan_name	= "lan",
	lan_cpueth	= "eth0",
	-- The identity: RouterBoot's label MAC, which no netdev here is born with
	-- (see the header). announce.get_identity reads it before anything else;
	-- an unreadable or malformed file falls back to the netdev rules.
	identity_mac_file = "/sys/firmware/mikrotik/hard_config/mac_base",
	lan_vlanid	= 1,
	-- The WAN VLAN's sub-device on the same trunk; gone once setup.sh's AP
	-- conversion folds the WAN socket into VLAN 1.
	wan_cpueth	= "eth0.2",
	-- One entry per RJ45 socket, named as MikroTik prints them on the case.
	-- The SFP cage is eth1, a netdev of its own outside br-lan, and not
	-- listed: nothing bridges it on an AP, and a port the controller can
	-- configure but openUF cannot attach would be worse than none. The uplink
	-- socket is detected from the switch's ARL table at runtime, never
	-- declared. `idx` is the UniFi port_idx the controller keys per-port
	-- settings on: pinned to a socket, never renumbered once adopted.
	ports = {
		{idx = 1, swport = "ether1"},
		{idx = 2, swport = "ether2"},
		{idx = 3, swport = "ether3"},
		{idx = 4, swport = "ether4"},
		{idx = 5, swport = "ether5"},
	},
}

-- No Locate / LED toggle. The board has one controllable LED, green:user,
-- and the DTS aliases led-boot, led-failsafe and led-upgrade all to it, so
-- procd owns it through boot, failsafe and sysupgrade. ath10k-phy0 and
-- ath9k-phy1 are the radios' throughput triggers. Set this to "green:user"
-- to have Locate anyway and accept sharing the LED with procd (led-running is
-- not aliased, so it is left alone once the board has booted).
dev.conf.led = nil

-- Switch layout (AR8337 via swconfig).
--
-- ether1 (Internet, PoE in) is physical 1: board.d's "1:wan", and the label
-- the case prints next to it. ether2..ether5 are the set {2,3,4,5} for
-- certain ("2:lan" .. "5:lan"); that they run in order is assumed. The DTS
-- names ether5's PoE-out GPIO "port5-poe", which is consistent with it but
-- is not proof.
-- ⚠️ Settle it on a unit: `swconfig dev switch0 show | grep link` while
-- moving a cable between sockets. A reversal mislabels the controller's
-- Ports view and lands per-port settings on the wrong socket; the uplink is
-- unaffected (it comes from the ARL table). If it proves reversed, change
-- this table and the hAP ac test in tests/test_modelmap.lua together.
-- Port 0 is the CPU, tagged, serving both VLANs: cpu_lan == cpu_wan. Port 6
-- (link up at 10baseT on the measured unit) is the switch's second CPU-side
-- port, unused by OpenWrt here, and never a socket.
dev.conf.vlan = {
	device	= "switch0",
	cpu_lan	= 0,
	cpu_wan	= 0,
	ports	= {
		ether1	= 1,
		ether2	= 2,
		ether3	= 3,
		ether4	= 4,
		ether5	= 5,
	}
}

-- UniFi configuration
dev.openuf = {}

dev.openuf.uap = {
	-- U6-InWall, the validated identity -- see the header for uhdiw.
	ufmodel		= "u6iw",
	hwassign	= {"radio0", "radio1"},	-- radio0 = 5 GHz (ath10k), radio1 = 2.4 GHz (ath9k): measured
}

return dev
