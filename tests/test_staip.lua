-- Tests for openuf/staip.lua: wireless client addresses from their ARP.
-- Run from project root: lua tests/run_tests.lua

local staip = dofile("openuf/staip.lua")

local A, B = "2c:be:eb:53:09:a1", "9a:b2:61:5a:cd:e5"

local function with_nft(listing, fn)
	local o = {staip._exec, staip._popen}
	local ran = {}
	staip._exec = function(c) ran[#ran + 1] = c; return 0 end
	staip._popen = function() return listing end
	staip._ips, staip._ifs, staip._next, staip._warned = {}, {}, 0, false
	local ok, err = pcall(fn, ran)
	staip._exec, staip._popen = o[1], o[2]
	staip._ips, staip._ifs, staip._next = {}, {}, 0
	if not ok then error(err, 0) end
end

return {
	{
		name = "staip: the rule tests the EtherType first and writes only from a VAP's ARP",
		fn = function()
			local s = staip.nft_script()
			assert_contains(s, "ether type arp iifname @ifs arp saddr ip != 0.0.0.0 update @sta_ips", "the one rule")
			assert_contains(s, "{ ether saddr . arp saddr ip }", "keyed on the frame's own source")
			assert_contains(s, "policy accept", "it never drops")
			assert_contains(s, "size " .. staip.SET_SIZE, "a bounded set")
		end
	},
	{
		name = "staip: parse keeps the address used last, skips link-local",
		fn = function()
			local t = staip.parse("elements = { " .. A .. " . 192.168.20.19 timeout 10m expires 9m58s980ms,\n"
				.. "\t" .. A .. " . 192.168.20.7 timeout 10m expires 2m1s,\n"
				.. "\t" .. B:upper() .. " . 169.254.3.4 timeout 10m expires 9m }")
			assert_eq(t[A], "192.168.20.19", "the freshest of two")
			assert_nil(t[B], "a link-local address is not reported")
			t = staip.parse(A .. " . 10.0.0.9 expires 5m, " .. A .. " . 10.0.0.10 expires 5m")
			assert_eq(t[A], "10.0.0.10", "a tie takes the lower, as a string, the same every time")
			assert_eq(next(staip.parse("")), nil, "nothing listed")
		end
	},
	{
		name = "staip: tick installs once, adds each VAP once, reads once a minute",
		fn = function()
			with_nft("", function(ran)
				assert_false(staip.tick(100, {}), "no VAP: nothing")
				assert_eq(#ran, 0, "and no command")
				staip.tick(100, {["phy1-ap0"] = true, ["phy1-ap2-20"] = true})
				assert_contains(ran[1], "nft -f", "installed")
				assert_contains(ran[2], '"phy1-ap0", "phy1-ap2-20"', "both VAPs")
				assert_false(staip.tick(100 + staip.READ_EVERY - 1, {["phy1-ap0"] = true}), "not within the minute")
				assert_eq(#ran, 2, "no new command")
			end)
			with_nft("elements = { " .. A .. " . 192.168.20.19 expires 9m }", function(ran)
				staip._ifs = {["phy1-ap0"] = true}
				staip.tick(100, {["phy1-ap0"] = true, ["bad;name"] = true})
				assert_eq(#ran, 0, "table there, VAP known, a bad name never reaches the shell")
				assert_eq(staip.ip(A:upper()), "192.168.20.19", "looked up by MAC in any case")
				assert_nil(staip.ip(B), "unknown client: nil")
			end)
		end
	},
}
