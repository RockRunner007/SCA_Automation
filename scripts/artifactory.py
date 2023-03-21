import sys
import requests
import os
import logging
import base64
import time
import json
from datetime import date

def configure_logging():
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

def encode_creds():
    creds = os.environ['xray_user'] + ':' + os.environ['xray_pwd']
    return base64.b64encode(creds.encode("ascii")).decode("ascii")

def get_token(url):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': "Basic %s" % encode_creds()
    }
    params = {
        'username':os.environ['xray_user']
    }
    
    resp = requests.post(f'{url}/api/security/token', params=params, headers=headers, verify=True)
    if resp.status_code == 200:
        return resp.json()['access_token']
    else:
        logging.error(f"Failed to get token.  Status Code: {resp.status_code}")
        exit(1)

def get_violations(token, xrayurl, watch, severity):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': "Basic %s" % encode_creds()
    }
    
    violations_list = []
    total_violations = 0
    block_size = 50
    page = 1
    get_next_page = True
    
    while get_next_page == True:
        data = {
            "filters": {
                "name_contains": "",
                "watch_name": watch,            
                "min_severity": severity,
                "created_from": f"{date(date.today().year-2,1,1)}T01:01:01+01:00"
                },
            "pagination": {
                "limit": block_size,
                "offset": page
                }
        }

        resp = requests.post(f'{xrayurl}/api/v1/violations', headers=headers, data=json.dumps(data), verify=True)
     
        if resp.status_code == 200:
            with open('osa.json', 'w', encoding="utf-8") as f: json.dump(resp.json(), f, ensure_ascii=False)
            logging.info("Successfully retrieved violations")
            total_violations = resp.json()['total_violations']

            for violation in resp.json()['violations']:
                violations_list.append(violation['violation_details_url'])
            
            if block_size * page >= total_violations:
                get_next_page = False
            
            page += 1
        else:
            logging.error(f"Failed to get violations.  Status Code: {resp.status_code}")            
    return violations_list

def get_violations_details(token, url):
    headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'Authorization': "Basic %s" % encode_creds()
    }
    
    resp = requests.get(url, headers=headers, verify=True)
    if resp.status_code == 200:
        violation_details = resp.json()
        package_details = violation_details['infected_components'][0].split(':')

        package_manager = package_details[0]
        package_name = package_details[1][2:]
        package_version = package_details[2]
        
        infected_string = ""
        if 'infected_versions' in violation_details:
            for infection in violation_details['infected_versions']:
                infected_string += infection + " || "

        fixstring = ""
        if 'fix_versions' in violation_details:
            for fix in violation_details['fix_versions']:
                fixstring += fix + " || "

        # Not every violation is uniform
        v_type = str(violation_details['type']) if 'type' in violation_details else ""
        v_summary = str(violation_details['summary']) if 'summary' in violation_details else ""
        v_description = str(violation_details['description']) if 'description' in violation_details else ""
        v_severity = str(violation_details['severity']) if 'severity' in violation_details else ""

        licenseurl = f"https://tldrlegal.com/license/{v_summary}"
        licenseurl = licenseurl.replace("Version ", "V").replace(" ", "-")
        if (licenseurl == 'https://tldrlegal.com/license/Mozilla-Public-License-2.0-(MPL-2.0)'): licenseurl = 'https://tldrlegal.com/license/Mozilla-Public-License-2.0-(MPL-2)'
        if (licenseurl == 'https://tldrlegal.com/license/GNU-General-Public-License-version-3'): licenseurl = 'https://tldrlegal.com/license/gnu-lesser-general-public-license-v3-(lgpl-3)'

        if package_manager == 'nuget': 
            packagelocation = f"https://www.nuget.org/packages/{package_name}"
        elif package_manager == 'npm':
            packagelocation = f"https://www.npmjs.com/package/{package_name}"
        elif package_manager == 'go':
            packagelocation = f"https://{package_name}"
        else:
            packagelocation = "N/A"

        violation_dict = {
            "manager": package_manager,
            "package": package_name,
            "version": package_version,
            "type": v_type,
            "summary": v_summary,
            "description": v_description,
            "severity": v_severity,
            "infected_versions": infected_string[:-4],
            "fixed_versions": fixstring[:-4],
            "licenseurl": licenseurl,
            "packagelocation" : packagelocation
        }
        
        return violation_dict
    else:
        logging.error(f"Failed to get violations.  Status Code: {resp.status_code}")     

def write_results(results):
    open('License.json', 'a', encoding="utf-8").write("[")
    open('Security.json', 'a', encoding="utf-8").write("[")

    liccount = 0
    seccount = 0
    for result in results:
        if result['type'] == 'License':            
            if liccount > 0: open('License.json', 'a', encoding="utf-8").write(', ')
            with open('License.json', 'a', encoding="utf-8") as f: json.dump(result, f, ensure_ascii=False)
            liccount +=1
        if result['type'] == 'Security':
            if seccount > 0: open('Security.json', 'a', encoding="utf-8").write(', ')
            with open('Security.json', 'a', encoding="utf-8") as f: json.dump(result, f, ensure_ascii=False)
            seccount +=1
    open('License.json', 'a', encoding="utf-8").write("]")
    open('Security.json', 'a', encoding="utf-8").write("]")    

def main():
    configure_logging()
    xrayurl = os.environ['XRAY']
    artifactoryurl = os.environ['ARTIFACTORY']

    token = get_token(artifactoryurl)
    violations = get_violations(token, xrayurl, os.environ['WATCH'], os.environ['SEVERITY'])
    
    violations_list = []
    for violation in violations:
        violations_list.append(get_violations_details(token, violation))
    write_results(violations_list)

if __name__ == "__main__":
    main()