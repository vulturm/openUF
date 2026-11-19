--[[


]]--

local uap = {}


-- general config
uap = {
	platform		= "U7LR",
	-- System id: Ubiquiti's public device database (static.ui.com/fingerprint/
	-- ui/public.json). Beaconed in UniFi's sibling element
	-- (sysinfo.ubnt_ie_hex) so genuine UniFi APs do not list this AP as a rogue.
	sysid			= "e527",
	fw				= {
		pre			= "BZ.qca956x.v",
		ver			= "3.7.x",
		buildtime	= "160101.0000",
		factoryver  = "3.4.1"
	},
	bootver			= "",
}

-- special flags



return uap
