--[[


]]--

local uap = {}


-- general config
uap = {
	platform		= "BZ2",
	-- System id: Ubiquiti's public device database (static.ui.com/fingerprint/
	-- ui/public.json). Beaconed in UniFi's sibling element
	-- (sysinfo.ubnt_ie_hex) so genuine UniFi APs do not list this AP as a rogue.
	sysid			= "e542",
	fw				= {
		pre			= "BZ.ar7240.v",
		ver 		= "3.7.x",			-- format M.m.bbbb
		buildtime	= "160101.0000", 	-- format YYMMDD.HHMM
		factoryver 	= "2.3.6"
	},
	bootver 		= "",
}

-- special flags



return uap
