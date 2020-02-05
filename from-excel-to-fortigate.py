import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import pandas as pd
import numpy as np

def func_addrgrp(x):
    return pd.Series(dict(name=x['name'].min(),
                          member=[{'name': str(w)} for w in x['member']]))

def func_policy(x):
    return pd.Series(dict(name=x['name'].min(),
                          srcintf=[{'name': str(p)} for p in x['srcintf'] if p is not np.NaN],
                          dstintf=[{'name': str(q)} for q in x['dstintf'] if q is not np.NaN],
                          srcaddr=[{'name': str(r)} for r in x['srcaddr'] if r is not np.NaN],
                          dstaddr=[{'name': str(s)} for s in x['dstaddr'] if s is not np.NaN],
                          action=x['action'].min(),
                          service=[{'name': str(t)} for t in x['service'] if t is not np.NaN],
                          schedule=x['schedule'].min(),
                          nat=x['nat'].min(),
                          ippool=x['ippool'].min(),
                          poolname=[{'name': str(u)} for u in x['poolname'] if u is not np.NaN]))

## If there're free cells or multiple column-cells in single entry...
## policies_file = policies_file.fillna(method='ffill', axis=0)
## policies_file = policies_file.groupby('NO.').apply(f)

## Reading Excel Configuration
config_file = pd.ExcelFile('configs.xlsx')

interfaces_file = pd.read_excel(config_file,'Interfaces')
routes_file = pd.read_excel(config_file,'Routes')
addr_file = pd.read_excel(config_file,'Addresses')

addrgrp_file = pd.read_excel(config_file,'Addrgrps')
addrgrp_file = addrgrp_file.fillna(method='ffill', axis=0)
addrgrp_file = addrgrp_file.groupby('name').apply(func_addrgrp)

iprange_file = pd.read_excel(config_file,'IPranges')

service_file = pd.read_excel(config_file,'Services')

firewallgrp_file = pd.read_excel(config_file,'Firewallgrps')

ippool_file = pd.read_excel(config_file,'Ippools')

vip_file = pd.read_excel(config_file,'Vips')
vip_file['mappedip'] = vip_file['mappedip'].apply(lambda x: [{'range':str(x)}])

policy_file = pd.read_excel(config_file,'Policies')
policy_col = ['name','nat','action','schedule']
policy_file.loc[:,policy_col]=policy_file.loc[:,policy_col].ffill()
policy_file = policy_file.groupby('name').apply(func_policy)

trafficshaper_file = pd.read_excel(config_file,'Trafficshapers')
trafficshapingpolicy_file = pd.read_excel(config_file,'Trafficshapingpolicies')

## Connect to Fortigate and get CSRFTOKEN
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
s = requests.Session()
bodyhash = {'username': 'admin', 'secretkey': 'FortiGate001'}
r = s.post('https://10.10.10.10/logincheck', data=bodyhash, verify=False)
for cookie in s.cookies:
    try:
        if cookie.name == 'ccsrftoken':
            csrftoken = cookie.value[1:-1]
            print('csrftoken found:',csrftoken)
            s.headers.update({'X-CSRFTOKEN': csrftoken})
    except:
        print('csrftoken not found')

## Rule-of-Thumb for REST APIs
## To get what's there --> GET
## To put something completely new --> POST
## To update something which is already there --> PUT
## To delete something --> DELETE

## Interfaces that are already there...
req = s.get('https://172.25.102.199/api/v2/cmdb/system/interface')
forti_interfaces = [x['name'] for x in req.json()['results']]

for x in interfaces_file.to_dict(orient='records'):
    req = s.put('https://172.25.102.199/api/v2/cmdb/system/interface/'+x['name'],data=str(x))

## Routes...
for x in routes_file.to_dict(orient='records'):
    req = s.post('https://172.25.102.199/api/v2/cmdb/router/static',data=str(x))

## Address Objects...
for x in addr_file.to_dict(orient='records'):
    req = s.post('https://172.25.102.199/api/v2/cmdb/firewall/address',data=str(x))
    ## print(x['name'],'creation',req.json()['status'])

## IP Ranges...
for x in iprange_file.to_dict(orient='records'):
    req = s.post('https://172.25.102.199/api/v2/cmdb/firewall/address',data=str(x))

## Address Groups...
for x in addrgrp_file.to_dict(orient='records'):
    req = s.post('https://172.25.102.199/api/v2/cmdb/firewall/addrgrp',data=str(x))

## Services...
for x in service_file.to_dict(orient='records'):
    req = s.post('https://172.25.102.199/api/v2/cmdb/firewall.service/custom',data=str(x))

## Firewall Groups...
for x in firewallgrp_file.to_dict(orient='records'):
    req = s.post('https://172.25.102.199/api/v2/cmdb/firewall.service/group',data=str(x))

## IP Pools...
for x in ippool_file.to_dict(orient='records'):
    req = s.post('https://172.25.102.199/api/v2/cmdb/firewall/ippool',data=str(x))

## VIPs...
for x in vip_file.to_dict(orient='records'):
    req = s.post('https://172.25.102.199/api/v2/cmdb/firewall/vip',data=str(x))

## Policies...
for x in policy_file.to_dict(orient='records'):
    req = s.post('https://172.25.102.199/api/v2/cmdb/firewall/policy',data=str(x))
