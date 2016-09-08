FOR %%I IN (1,2,3,4,5,6,7,8) DO (
	netsh interface ipv4 add address name="Ethernet" 10.53.0.%%I 255.255.255.0
	netsh interface ipv6 add address interface="Ethernet" fd92:7065:b8e:ffff::%%I/64
)
	