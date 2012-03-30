# Wrapper around pysnmp for easy access to snmp-based information
# (c)2008-2010 Dennis Kaarsemaker
#
# Latest version can be found on http://github.com/seveas/python-snmpclient
# 
# This script is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 3, as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import pysnmp.entity.rfc3413.oneliner.cmdgen as cmdgen
from pysnmp.smi import builder, view
from pysnmp.smi.error import SmiError

__all__ = ['V1', 'V2', 'V2C', 'add_mib_path', 'load_mibs',
           'nodeinfo', 'nodename', 'nodeid', 'SnmpClient']

# Snmp version constants
V1 = 0
V2 = V2C = 1

# The internal mib builder
__mibBuilder = builder.MibBuilder()
__mibViewController = view.MibViewController(__mibBuilder)

def add_mib_path(*path):
    """Add a directory to the MIB search path"""
    __mibBuilder.setMibPath(*(__mibBuilder.getMibPath() + path))

def load_mibs(*modules):
    """Load one or more mibs"""
    for m in modules:
        try:
            __mibBuilder.loadModules(m)
        except SmiError, e:
            if 'already exported' in str(e):
                continue
            raise

# Load basic mibs that come with pysnmp
load_mibs('SNMPv2-MIB','IF-MIB','IP-MIB','HOST-RESOURCES-MIB','FIBRE-CHANNEL-FE-MIB')

def nodeinfo(oid):
    """Translate dotted-decimal oid to a tuple with symbolic info"""
    if isinstance(oid, basestring):
        oid = tuple([int(x) for x in oid.split('.') if x])
    return (__mibViewController.getNodeLocation(oid), 
            __mibViewController.getNodeName(oid))

def nodename(oid):
    """Translate dotted-decimal oid or oid tuple to symbolic name"""
    oid = __mibViewController.getNodeLocation(oid)
    name = '::'.join(oid[:-1])
    noid = '.'.join([str(x) for x in oid[-1]])
    if noid:
        name += '.' + noid
    return name
        
def nodeid(oid):
    """Translate named oid to dotted-decimal format"""
    ids = oid.split('.')
    symbols = ids[0].split('::')
    ids = tuple([int(x) for x in ids[1:]])
    mibnode, = __mibBuilder.importSymbols(*symbols)
    oid = mibnode.getName() + ids
    return oid

class SnmpClient(object):
    """Easy access to an snmp deamon on a host"""

    def __init__(self, host, communities):
        """Set up the client and detect the community to use"""
        self.host = host
        self.alive = False

        # Which community to use
        noid = nodeid('SNMPv2-MIB::sysName.0')
        for community in communities:
            auth = cmdgen.CommunityData(community.get('name','snmpclient'), 
                                        community.get('community', 'public'), 
                                        community.get('version', V2C))
            port = community.get('port', 161)
            (errorIndication, errorStatus, errorIndex, varBinds) = \
                cmdgen.CommandGenerator().getCmd(auth, cmdgen.UdpTransportTarget((self.host, port)), noid)
            if errorIndication == 'requestTimedOut':
                continue
            else:
                self.alive = True
                self.auth = auth
                self.port = port
                break

    def get(self, oid):
        """Get a specific node in the tree"""
        noid = nodeid(oid)
        (errorIndication, errorStatus, errorIndex, varBinds) = \
            cmdgen.CommandGenerator().getCmd(self.auth, cmdgen.UdpTransportTarget((self.host, self.port)), noid)
        if errorIndication:
            raise RuntimeError("SNMPget of %s on %s failed" % (oid, self.host))
        return varBinds[0][1]

    def gettable(self, oid):
        """Get a complete subtable"""
        noid = nodeid(oid)
        (errorIndication, errorStatus, errorIndex, varBinds) = \
            cmdgen.CommandGenerator().nextCmd(self.auth, cmdgen.UdpTransportTarget((self.host, self.port)), noid)
        if errorIndication:
            raise RuntimeError("SNMPget of %s on %s failed" % (oid, self.host))
        return [x[0] for x in varBinds]

    def matchtables(self, index, tables):
        """Match a list of tables using either a specific index table or the
           common tail of the OIDs in the tables"""
        oid_to_index = {}
        result = {}
        indexlen = 1
        if index:
            #  Use the index if available
            for oid, index in self.gettable(index):
                oid_to_index[oid[-indexlen:]] = index
                result[index] = []
        else:
            # Generate an index from the first table
            baselen = len(nodeid(tables[0]))
            for oid, value in self.gettable(tables[0]):
                indexlen = len(oid) - baselen
                oid_to_index[oid[-indexlen:]] = oid[-indexlen:]
                result[oid[-indexlen:]] = [value]
            tables = tables[1:]
        # Fetch the tables and match indices
        for table in tables:
            for oid, value in self.gettable(table):
                index = oid_to_index[oid[-indexlen:]]
                result[index].append(value)
        return result
