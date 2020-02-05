import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import pandas as pd
import numpy as np

## Setting up static parameters
FORTIGATE = '172.17.1.3'
PORT = '443'
USERNAME = 'mitsupport'
PASSWORD = 'M1t_F0rt!'
## DATA_NEEDED = input('Enter details you need:')

BASE_URL = '/api/v2/cmdb'

## Connect to Fortigate and get CSRFTOKEN
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
s = requests.Session()
bodyhash = {'username': USERNAME, 'secretkey': PASSWORD}
r = s.post('https://'+FORTIGATE+":"+PORT+'/logincheck', data=bodyhash, verify=False)
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

## getting Interface data...
req = s.get('https://'+FORTIGATE+":"+PORT+'/api/v2/cmdb/system/interface')
REST_interfaces = pd.DataFrame(req.json()['results'])

## getting Route Data...
req = s.get('https://'+FORTIGATE+":"+PORT+'/api/v2/cmdb/router/static')
REST_routes = pd.DataFrame(req.json()['results'])

## getting Addresses Data...
req = s.get('https://'+FORTIGATE+":"+PORT+'/api/v2/cmdb/firewall/address')
REST_addresses = pd.DataFrame(req.json()['results'])

## getting Address Groups Data...
req = s.get('https://'+FORTIGATE+":"+PORT+'/api/v2/cmdb/firewall/addrgrp')
REST_addrgrps = pd.DataFrame(req.json()['results'])

## getting Services Data...
req = s.get('https://'+FORTIGATE+":"+PORT+'/api/v2/cmdb/firewall.service/custom')
REST_services = pd.DataFrame(req.json()['results'])

## getting Service Groups Data...
req = s.get('https://'+FORTIGATE+":"+PORT+'/api/v2/cmdb/firewall.service/group')
REST_servicegrps = pd.DataFrame(req.json()['results'])

## getting Policies Data...
req = s.get('https://'+FORTIGATE+":"+PORT+'/api/v2/cmdb/firewall/policy')
REST_policies = pd.DataFrame(req.json()['results'])

with pd.ExcelWriter('configs_rev.xlsx') as writer:
    REST_interfaces.to_excel(writer, sheet_name='Interfaces')
    REST_routes.to_excel(writer, sheet_name='Routes')
    REST_addresses.to_excel(writer, sheet_name='Addresses')
    REST_addrgrps.to_excel(writer, sheet_name='Addrgrps')
    REST_services.to_excel(writer, sheet_name='Services')
    REST_servicegrps.to_excel(writer, sheet_name='Servicegrps')
    REST_policies.to_excel(writer, sheet_name='Policies')
