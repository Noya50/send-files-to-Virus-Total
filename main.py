import os
import json
import random
from random import randint
import shutil
import requests
import time
import logging

# --------------------------- user config ---------------------------

# can be found in the personal virustotal account
API_KEY = "3d893c13b4813357bc4bb86f657570a5a06dcd71e0a790f17c5484a31e1c8b00"
#path to the local folder that contains all the files to scan (the folder can contain subfolders).
HASHES_TO_CHECK = r"C:\Users\lapto\Desktop\noya\send-files-to-Virus-Total\hashesToCheck.txt"

# --------------------------- user config ---------------------------

logger = logging.getLogger(__name__)
logging.basicConfig(filename='logger2.log', level=logging.INFO, format='%(asctime)s = %(message)s' , datefmt='%Y-%m-%d %H-%M:%S')

VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/files/"
VIRUS_TOTAL_ANALYSES_URL = "https://www.virustotal.com/api/v3/analyses/"
HEADERS = {
  "accept": "application/json",
  "x-apikey": API_KEY,
}

def listHashes(hashFile):
    openedFile = open(hashFile, "r")    
    hashes = openedFile.readlines()
    
    return hashes


def sendToVirusTotal(hash):
    logger.info(f"{hash} Get analysis from ViruseTotal...")
    try:
        headers = {
            # "accept": "application/json",
            'x-apikey': API_KEY
            }
        url = f"{VIRUS_TOTAL_URL}{hash}"
        print(url)
        response = requests.get(url, headers=headers) 
        print(f"recieved request {response.text}")
        logger.info("sleeping...")
        time.sleep(16)
        analysisResult = ((json.loads(response.content))["data"]["attributes"]["last_analysis_stats"])
        logger.info("done: got analysis")
    
    except Exception as error:
        logger.error(f"Unable to scan the file. error: {str(error)}")
        return "error"

    return analysisResult


def validateAnalysis(analysisDetails):
    logger.info(f"{analysisDetails}")
    if (analysisDetails["malicious"] == 0 and analysisDetails["suspicious"] == 0 and analysisDetails["undetected"] == 0 and analysisDetails["harmless"] == 0 
    and analysisDetails["timeout"] == 0 and analysisDetails["confirmed-timeout"] == 0 and analysisDetails["failure"] == 0
    and analysisDetails["type-unsupported"] == 0): 
        return False
    else:  
        return True
    

def getsAnalysisResults(analysisId):
    url = VIRUS_TOTAL_ANALYSES_URL + analysisId
    headers = HEADERS
    analysisValid = False
    logger.info("interprets the analysis...")
    
    try:
        print(f"url: {url}")
        fullAnalysis = requests.get(url, headers=headers)
        print(fullAnalysis.content)
        analysisDetails = (json.loads(fullAnalysis.content))["data"]["attributes"]["stats"]
        if validateAnalysis(analysisDetails):
            analysisValid = True
        
        if analysisValid:
            logger.info("The analysis was found valid and was interpreted.", )
            return ((json.loads(fullAnalysis.content))["data"]["attributes"]["stats"])
        else:
            logger.info("Analysis found invalid and can't be interpreted. Moving on to the next files...")
            return "error"
    except:
        logger.info("An error occurred while interpreting the analysis. Moving on to the next files...")
        return "error"


def printSummery(cleanFiles, corruptedFiles, unhandledFiles):
    print("found ", len(cleanFiles), "clean file/s, ", len(corruptedFiles), " corrupt file/s, and ", len(unhandledFiles), " unhandled file/s.")
    
    if len(corruptedFiles) != 0 :
        logger.info("the corrupted files are: ")
        
        for file in corruptedFiles:
            logger.info(f"hash: {file['hash']}")
            logger.info(f"Results: {file['analysisResults']}")
    
    if len(unhandledFiles) != 0:
        printUnhandledFiles = input("Would you like to print the paths of all the  unhandled files? \nType 'y' for yes or any other character for no: ")
    
        if printUnhandledFiles == "y":
            logger.info(f"\nUnhandled files are: {unhandledFiles}")
    
    if len(cleanFiles) != 0:
        printAllClean = input("Would you like to print the details of all the clean files? \nType 'y' for yes or any other character for no: ")
        
        if printAllClean == "y":
            logger.info("Clean files are: ")
            for file in cleanFiles:
                logger.info(f"hash: {file['hash']}")
                logger.info(f"Results: {file['analysisResults']}")
                
def moveFiles(cleanFiles, corruptedFiles, unhaldedFiles):
    try:
        for file in cleanFiles:
            with open('./cleanFiles.txt', 'a') as allCleans:
                allCleans.write(f"{file}\n")
                # toScan = open('./hashesToCheck.txt', 'a')
        
        # if cleanFiles:
        #     with open("./hashesToCheck.txt", 'r') as hashesToCheck:
        #         file_content = hashesToCheck.read()
                
        #         for hash in cleanFiles:
        #             file_content.replace(hash['hash'], "")
                
        #         with open("./hashesToCheck.txt", 'wb') as file:
        #             file.write(file_content)
        
        for file in corruptedFiles:
            with open('./corruptedFiles.txt', 'a') as allCorrupted:
                allCorrupted.write(f"{file}\n")
            
        # if corruptedFiles:
        #     with open("./hashesToCheck.txt", 'r') as toScanFile:
        #         file_content = toScanFile.read()
                
        #         for hash in corruptedFiles:
        #             print(hash['hash'])
        #             file_content.replace(hash['hash'], "")
                    
        #     with open("./hashesToCheck.txt", 'wb') as file:
        #         file.write(file_content)
        for file in unhaldedFiles:
            with open('./unhaldedFiles.txt', 'a') as unhalded:
                unhalded.write(f"{file}")        

    except Exception as error:
        logger.info(f"faild to move the hash '{file}' to the cleanFiles/corruptedFiles file. error: {error}")

def main():
    hashList = listHashes(HASHES_TO_CHECK)
    results = []
    unhandledFiles = []
    
    logger.info(f"{len(hashList)} files to check.")
  
    for hash in hashList:
        analysisResults = sendToVirusTotal(hash)
        if analysisResults == "error":
            unhandledFiles.append(hash)
        else:
            logger.info(f"send analysis to validation. analysis results: {analysisResults}")
            if validateAnalysis(analysisResults):
                results.append({
                    "hash" : hash,
                    "analysisResults" :  analysisResults
                })
            else:
                unhandledFiles.append(hash)

    clean = []
    corrupted = []
    
    for result in results:
        if result["analysisResults"]["malicious"] != 0 or result["analysisResults"]["suspicious"] != 0 :
            corrupted.append(result)
        else:
            clean.append(result)
    
    print(f"clean: {clean}, corrupted: {corrupted}")        
    printSummery(cleanFiles = clean, corruptedFiles = corrupted, unhandledFiles = unhandledFiles)
    moveFiles(clean, corrupted, unhandledFiles)

def delete_empty_dirs():
    directory = HASHES_TO_CHECK
    for dirpath, dirnames, filenames in os.walk(directory, topdown=False):
        for dirname in dirnames:
            dir_to_check = os.path.join(dirpath, dirname)
            try:
                os.rmdir(dir_to_check)
            except OSError as e:
                logger.info(f"Could not delete directory: {dir_to_check}. Reason: {e}")


main()
# delete_empty_dirs()
