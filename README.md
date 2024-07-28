import requests
import time
import json
 
file1 = open('domains.txt', 'r')
Lines = file1.readlines()
count = 0
 
for line in Lines:
    count += 1
    url = "https://www.virustotal.com/api/v3/ip_addresses/" + line.strip()
    headers = {
        "accept": "application/json",
        "x-apikey": "INSERT-Virus-Total-API-KEY-HERE"
    }
 
    response = requests.get(url, headers=headers)
    response_to_dict = response.json()
    IP_stats = response_to_dict["data"]["attributes"]["last_analysis_stats"]
    IP_country = response_to_dict["data"]["attributes"]["country"]
    malicious_count = IP_stats.get("malicious", 0)
    if malicious_count > 0 or IP_country == "RU":
        print(f"\033[43m\033[31m\033[1m{line.strip()}\033[0m - {IP_stats}, originating from {IP_country}\033[0m\033[0m")
    else:
        print(f"\033[31m\033[32m{line.strip()} - clean IP\033[0m\033[0m")
   
    print("\n")
