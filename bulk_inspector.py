import json
import sys
import requests

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
            APIkeys.pop(key) #Remove this service from the list of usable services
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