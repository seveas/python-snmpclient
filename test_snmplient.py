import snmpclient

router = '10.42.1.1'
authdata = {'community': 'public', 'version': snmpclient.V2C}

client = snmpclient.SnmpClient(router, [authdata])
print client.alive
print client.get('SNMPv2-MIB::sysName.0')
print client.gettable('UDP-MIB::udpLocalAddress')
print client.matchtables('IF-MIB::ifIndex', ('IF-MIB::ifDescr', 'IF-MIB::ifPhysAddress', 'IF-MIB::ifOperStatus'))
