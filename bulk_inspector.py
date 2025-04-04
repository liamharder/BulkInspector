import json
import sys
import requests
import base64

services = { #List of API-accessible services we can query
    "VirusTotal": ""
}

#Retrieve API keys from JSON file
#First, create the file if it doesn't exist to prevent errors
k = open("APIkeys.json", "a")
k.close()

#Now read the file contents
keyfile = open("APIkeys.json", "r")
contents = keyfile.read()
if (len(contents) == 0): #If the file is empty
    print("ERROR: API key file empty. Populating APIkeys.json...")
    keyfile.close()
    
    #Create a JSON template containing a list of services needing API keys
    jsonTemplate = json.dumps(services)
    
    #Write the template to file so the user can fill in their API keys
    keyfile = open("APIkeys.json", "w")
    keyfile.write(jsonTemplate)
    keyfile.close()
    
    #Exit the program
    sys.exit("Exiting program. Please edit APIkeys.json so that it contains all necessary API keys.")

else:
    #Read the JSON data and convert to Python dictionary
    APIkeys = json.loads(contents)
    print("API keys loaded from file.")
    keyfile.close()
    
    #Count keys present/missing
    keysnum = 0
    keyspresent = 0
    keysmissing = 0
    #Check to make sure each key is present and not blank
    for key in APIkeys:
        keysnum += 1
        if (APIkeys[key] == ""): #If the key is blank/no API key was provided
            print("ERROR: No API key provided for service ["+key+"]. Please add an API key to APIkeys.json. Continuing to check other API keys...")
            keysmissing+= 1
        else:
            print("Key present for service ["+key+"].")
            keyspresent+= 1
    print(f"{keysnum} service(s), {keyspresent} have keys, {keysmissing} missing keys.")
    if (keyspresent > 0): #If there are API keys we can use 
        print("Continuing to data processing...")
    else: #If there are no usable API keys
        print("ERROR: No API keys provided.")
        sys.exit("Exiting program. Please edit APIkeys.json so that it contains all necessary API keys.")
        
#By now we have a dictionary of API keys we can use to process data

#Given a list of urls, scan each one with VirusTotal
def urlscan_VirusTotal(urls):
    results = {}
    for url in urls:
        print("Scanning '" + url+"':")
        #VirusTotal wants a url ID, not the url itself, thankfully it gives us the code to generate the ID
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        #It also gives us the code for making the API request
        APIurl = "https://www.virustotal.com/api/v3/urls/" + url_id

        headers = {
            "accept": "application/json",
            "x-apikey": APIkeys["VirusTotal"]
        }

        response = requests.get(APIurl, headers=headers)
        results[url] = response.json()
        code = results[url]["data"]["attributes"]["last_http_response_code"]
        if (code == 200):
            print("HTTP response: "+str(code)+" OK")
        else:
            print("HTTP response: "+str(code))
    return results
    
    
test = urlscan_VirusTotal({"yahoo.com"})
for key in test: 
    print("VirusTotal security analysis for url " + key)
    print(str(test[key]["data"]["attributes"]["last_analysis_stats"]["malicious"]) + " scanners marked this url as malicious.")
    print(str(test[key]["data"]["attributes"]["last_analysis_stats"]["suspicious"]) + " scanners marked this url as suspicious.")
    print(str(test[key]["data"]["attributes"]["last_analysis_stats"]["harmless"]) + " scanners marked this url as harmless.")
    print(str(test[key]["data"]["attributes"]["last_analysis_stats"]["undetected"]) + " scanners did not detect this url.")
    print(str(test[key]["data"]["attributes"]["last_analysis_stats"]["timeout"]) + " scanners timed out attempting to scan this url.")