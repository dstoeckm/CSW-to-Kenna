# encoding = utf-8

import sys
import json
from tetpyclient import RestClient
import urllib3
import pandas as pd
from netaddr import *
urllib3.disable_warnings()

def collect_info():
    API_ENDPOINT="https://tet-pov-rtp1.cpoc.co"
    restclient = RestClient(API_ENDPOINT, credentials_file='credentials.json', verify=False)

    # Grab sensors, and put UUID's in a list
    resp = restclient.get('/sensors')

    #Turn Response into python list
    r_status=resp.status_code
    if r_status !=200:
        resp.raise_for_status()
    sensor_resp = resp.json()
    uuid_list=[]
    #CREATE A LIST OF UUID'S THAT WE CAN ITERATE OVER FOR INFORMATION
    for sensor in sensor_resp["results"]:
        uuid_list.append(sensor["uuid"])
    final_result = []
    # ITERATE over UUID's and grab workload profiles
    for uuid in uuid_list:
        resp = restclient.get('/workload/'+ uuid + '/vulnerabilities')
        r_status=resp.status_code
        if r_status !=200:
            continue
        else:
            parsed_resp = resp.json()
            #FORMATTING ALL OF THE DATA...because our API SUCKS
            for package in parsed_resp:
                element = {}
                #PICKING OUT THE CVE ID AND URL
                element['cve_id'] = package['cve_id']
                try:
                    element['cve_url'] = package['cve_url']
                except KeyError:
                    element['cve_url'] = "n/a"
                appnum = 0
                #GRABBING THE AFFECTED PACKAGES PER CVE...COULD BE MULTIPLE PER CVE/WORKLOAD
                for app in package['package_infos']:
                    element['app' + str(appnum) + 'name'] = app['name']
                    element['app' + str(appnum) + 'version'] = app['version']
                    appnum = appnum + 1
                element['uuid'] = uuid
                # GATHER INFORMATION FROM THE WORKLOAD LIKE HOSTNAME, OS VERSION, AND THE PRIVATE IP4 ADDRESS
                workloadresp = restclient.get('/workload/'+ uuid)
                s_status=workloadresp.status_code
                if s_status !=200:
                    continue
                else:
                    worker_resp = workloadresp.json()
                    element['host_name'] = worker_resp['host_name']
                    element['os_display_label'] = worker_resp['os_display_label']
                    for int in worker_resp['interfaces']:
                        if IPAddress(int['ip']).is_private() and int['family_type'] == "IPV4":
                            element['ip_address'] = int['ip']
                # ADD DICTIONARY TO LIST ITEM
                final_result.append(element)

        # USE PANDAS FUNCTIONS TO CREATE CSV FILE THAT KENNA CAN USE ON IMPORT
        pdObj = pd.read_json(json.dumps(final_result)).to_csv('csw_to_kenna.csv', index=False)

#BOILERPLATE
if __name__ == "__main__":
    collect_info()