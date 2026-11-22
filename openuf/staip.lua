--[[
	The IPv4 address of each wireless client, learned from its ARP.

	A UniFi AP reports `ip` for every station. openUF had only /proc/net/arp,
	the AP's own L3 view, and a client on a tagged SSID sits on a VLAN this AP
	holds no address on, so that cache never names it: the controller showed
	such a client with no IP at all.

	A bridge-family nft set records (source MAC . sender IP) from the ARP
	frames that enter on a client VAP. Every other frame costs one comparison
	on the EtherType, which is why the rule starts there and why it does not
	learn from IP traffic: that would be a set write per packet on a 720 MHz
	MIPS. A client ARPs for its gateway often enough. One that has not yet is
	reported with no address, never a guessed one.

	The table is read once a minute, and rebuilt only when it is gone: a
	rebuild would forget every address.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

M._exec = os.execute
M._popen = util.popen

M.NFT_TABLE   = "bridge openuf_staip"
M.SCRIPT_PATH = "/tmp/openuf-staip.nft"
M.SET_SIZE    = 512
M.TIMEOUT     = "10m"
M.READ_EVERY  = 60

M._ips, M._ifs, M._next, M._warned = {}, {}, 0, false

local function exec_ok(rv) return rv == 0 or rv == true end

function M.nft_script()
	return table.concat({
		"table " .. M.NFT_TABLE .. " {",
		"  set ifs {",
		"    type ifname",
		"    size 64",
		"  }",
		"  set sta_ips {",
		"    type ether_addr . ipv4_addr",
		"    size " .. M.SET_SIZE,
		"    flags dynamic,timeout",
		"    timeout " .. M.TIMEOUT,
		"  }",
		"  chain learn {",
		"    type filter hook prerouting priority filter + 10; policy accept;",
		"    ether type arp iifname @ifs arp saddr ip != 0.0.0.0 update @sta_ips { ether saddr . arp saddr ip }",
		"  }",
		"}",
		"",
	}, "\n")
end

-- "9m58s980ms" -> 598.98. `ms` is matched whole, so it cannot read as minutes.
local function secs(t)
	local n = 0
	for v, unit in tostring(t):gmatch("(%d+)(%a+)") do
		local mult = (unit == "ms" and 0.001) or (unit == "s" and 1) or (unit == "m" and 60)
			or (unit == "h" and 3600) or (unit == "d" and 86400) or 0
		n = n + tonumber(v) * mult
	end
	return n
end

-- {[mac] = ip} from `nft list set`. A client that has held two addresses
-- inside the timeout resolves to the one it used last, and on a tie to the
-- lower, so the report cannot flip between heartbeats. Link-local addresses
-- are what a client holds when DHCP failed: not an address to report.
function M.parse(text)
	local out, age = {}, {}
	local pat = "(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s*%.%s*(%d+%.%d+%.%d+%.%d+)([^,\n}]*)"
	for mac, ip, rest in tostring(text or ""):gmatch(pat) do
		if not ip:match("^169%.254%.") then
			mac = mac:lower()
			local left = secs(rest:match("expires%s+(%S+)") or "")
			if age[mac] == nil or left > age[mac] or (left == age[mac] and ip < out[mac]) then
				out[mac], age[mac] = ip, left
			end
		end
	end
	return out
end

local function install()
	local f = io.open(M.SCRIPT_PATH, "w")
	if not f then return false end
	f:write(M.nft_script())
	f:close()
	local ok = exec_ok(M._exec("nft -f " .. M.SCRIPT_PATH .. " 2>/dev/null"))
	os.remove(M.SCRIPT_PATH)
	if not ok and not M._warned then
		M._warned = true
		io.stderr:write("openuf: staip: could not install nft table " .. M.NFT_TABLE
			.. " -- clients on a tagged SSID will have no IP\n")
	end
	return ok
end

-- Once a minute. devs: {[netdev] = true}, the client VAPs of the last payload.
function M.tick(now, devs)
	if type(devs) ~= "table" or next(devs) == nil or now < M._next then return false end
	M._next = now + M.READ_EVERY
	local text = M._popen("nft list set " .. M.NFT_TABLE .. " sta_ips 2>/dev/null") or ""
	if text == "" then
		M._ips, M._ifs = {}, {}
		if not install() then return false end
	else
		M._ips = M.parse(text)
	end
	local add = {}
	for dev in pairs(devs) do
		if not M._ifs[dev] and util.valid_ifname(dev) then add[#add + 1] = dev end
	end
	if #add > 0 then
		table.sort(add)
		local ok = exec_ok(M._exec("nft 'add element " .. M.NFT_TABLE .. ' ifs { "'
			.. table.concat(add, '", "') .. "\" }' >/dev/null 2>&1"))
		if ok then
			for _, dev in ipairs(add) do M._ifs[dev] = true end
		end
	end
	return true
end

function M.ip(mac)
	return type(mac) == "string" and M._ips[mac:lower()] or nil
end

function M.teardown()
	M._exec("nft delete table " .. M.NFT_TABLE .. " >/dev/null 2>&1")
	M._ips, M._ifs, M._next = {}, {}, 0
end

return M
