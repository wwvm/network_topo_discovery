#!/bin/env python

import re
import sys
import yaml
from pysnmp.hlapi import *
from ipaddress import ip_address

SYS_NAME = '1.3.6.1.2.1.1.5.0'
VENDOR = '1.3.6.1.2.1.1.2.0'

LLDP_REM_NAME = '1.0.8802.1.1.2.1.4.1.1.9'
LLDP_REM_PORT = '1.0.8802.1.1.2.1.4.1.1.7'
LLDP_REM_ADDR = '1.0.8802.1.1.2.1.4.2.1.4'
LLDP_LOC_PORT = '1.0.8802.1.1.2.1.3.7.1.3'

CDP_REM_NAME = '1.3.6.1.4.1.9.9.23.1.2.1.1.6'
CDP_REM_PORT = '1.3.6.1.4.1.9.9.23.1.2.1.1.7'
CDP_REM_ADDR = '1.3.6.1.4.1.9.9.23.1.2.1.1.20'
CDP_LOC_PORT = '1.3.6.1.2.1.31.1.1.1.1'


HW_LLDP_ENABLED = '1.3.6.1.4.1.2011.5.25.134.1.1.1'

def walk(addr, oid):
    suffix = len(oid.split('.'))
    res = {}
    
    for ei, es, e, vbs in snmp(addr, oid, nextCmd):
       if ei:
          print(ei)
          return None

       elif es:
          print(f'es.prettyPrint() at {ei and vbs[int(ei)-1][0] or "?"}')
          return None

       for o, value in vbs:
          vas = value.asOctets()
          try:
             vas = vas.decode()
          except:
             vas = str(ip_address(vas))
          if vas:
             res[o[suffix:].prettyPrint()] = vas

    return res


def snmp(addr, oid, cmd):
    return cmd(SnmpEngine(), CommunityData(conf['community']), UdpTransportTarget((addr, 161)),
             ContextData(), ObjectType(ObjectIdentity(oid)), lexicographicMode=False)


def get(addr, oid):
    for ei, es, e, vbs in snmp(addr, oid, getCmd):
        # TODO error check
        for o, vb in vbs:
            vas = vb.asOctets()
            try:
               vas = vas.decode()
            except:
               vas = str(ip_address(vas))
            return vas


def getVendor(addr):
    for ei, es, e, vbs in snmp(addr, VENDOR, getCmd): 
        # TODO error check
        for oid, vb in vbs:
            return vb[6]


def getNext(addr, oid):
    res = snmp(addr, oid, nextCmd)

    length = len(oid.split('.')) + 6

    for ei, es, e, vbs in res:
        # TODO error check
        if len(vbs[0][0]) == length:
            return vbs[0][0][-4:].prettyPrint()
        # TODO check?
        print(vbs)
    # not found
    return None
    

def lldp(addr, name):
    rem_name = walk(addr, LLDP_REM_NAME)

    for index, val in rem_name.items():
        if val == name:
           print('Inter-connection, ignore!')
           continue
        rem_intf = get(addr, f'{LLDP_REM_PORT}.{index}')
        loc_intf = get(addr, f'{LLDP_LOC_PORT}.{index.split(".")[-2]}')
        rem_addr = getNext(addr, f'{LLDP_REM_ADDR}.{index}')

        print(addr, name, loc_intf, rem_addr, val, rem_intf) 


def cdp(addr, name):
    rem_name = walk(addr, CDP_REM_NAME)

    for index, nm in rem_name.items(): 
        # TODO internal connection, mgmt0 connection
        rem_port = get(addr, f'{CDP_REM_PORT}.{index}')
        rem_addr = get(addr, f'{CDP_REM_ADDR}.{index}')
        loc_port = get(addr, f'{CDP_LOC_PORT}.{index.split(".")[-2]}')

        ss = re.match(r'([^\(\)]+)\(?(.*)\)?', nm)
        #if ss: print(ss.groups())
        print(addr, name, loc_port, rem_addr, ss.group(1), rem_port)


def main():
    global conf
    with open('conf.yaml') as fi:
        conf = yaml.safe_load(fi)

    # TODO skip inter connection
    name = get(sys.argv[1], SYS_NAME)
    vendor = getVendor(sys.argv[1])
    func_name = conf['handler'][vendor]
    func = globals()[func_name]
    func(sys.argv[1], name)
    #cdp(sys.argv[1])    
    #lldp(sys.argv[1], name)    


if __name__ == '__main__':
    main()
