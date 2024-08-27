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
DIR_TO_CHECK = "C:/Users/lapto/Desktop/noya/virusTotalScanner2/toScan"
DIR_TO_CHECK_NAME = "toScan"
CLEAN_FILES_DIR = "C:/Users/lapto/Desktop/noya/virusTotalScanner2/cleanFiles"

# --------------------------- user config ---------------------------

logger = logging.getLogger(__name__)
logging.basicConfig(filename='logger2.log', level=logging.INFO, format='%(asctime)s = %(message)s' , datefmt='%Y-%m-%d %H-%M:%S')

VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/files/"
VIRUS_TOTAL_ANALYSES_URL = "https://www.virustotal.com/api/v3/analyses/"
HEADERS = {
  "accept": "application/json",
  "x-apikey": API_KEY,
}

def listAllFilesOfDir(dirPath):    
    allPaths = []

    for root, _, files in os.walk(dirPath):
        for filename in files:
            filePath = (os.path.join(root, filename))
            allPaths.append(filePath)
    
    return allPaths


def sendToVirusTotal(path):
    logger.info(f"{path} Get analysis from ViruseTotal...")
    try:
        files = { "file": (path, open(path, "rb"), "application/json") }
        headers = {
            "accept": "application/json",
            "x-apikey": HEADERS["x-apikey"],
            }
        print("sent request")
        response = requests.post(VIRUS_TOTAL_URL, files=files, headers=headers) 
        print(f"recieved request {response}")
        logger.info("sleeping...")
        time.sleep(16)
        analysisId = ((json.loads(response.content))["data"]["id"])
        logger.info("done: got analysis")
    
    except Exception as error:
        logger.error(f"Unable to scan the file. error: {error.__reduce_ex__}")
        return "error"

    return analysisId


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
    triesCount = 0
    logger.info("interprets the analysis...")
    
    try:
        fullAnalysis = requests.get(url, headers=headers)
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
            logger.info(f"path: {file['path']}")
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
                logger.info(f"path: {file['path']}")
                logger.info(f"Results: {file['analysisResults']}")
                
def moveCleanFiles(cleanFiles):
    for file in cleanFiles:
        try:
            destenationPath = (CLEAN_FILES_DIR)
            shutil.move(file['path'], destenationPath)
        except Exception as error:
            randomNumber = random.randint(1, 1000)
            newDestanationPath = f"{destenationPath}" + f"({randomNumber})/"
            shutil.move(file['path'], newDestanationPath)

def main():
    pathsToCheck = listAllFilesOfDir(dirPath = DIR_TO_CHECK)
    results = []
    unhandledFiles = []
    
    logger.info(f"{len(pathsToCheck)} files to check.")
  
    for path in pathsToCheck:
        analysisId = sendToVirusTotal(path = path)
        if analysisId == "error":
            unhandledFiles.append(path)
        else:
            logger.info(f"send analysis to validation and interaption. analysis id: {analysisId}")
            analysisResults = getsAnalysisResults(analysisId)
            print(analysisResults)
            if analysisResults == "error":
                unhandledFiles.append(path)
            else:
                results.append({
                    "path" : path,
                    "analysisResults" :  analysisResults
                })

    clean = []
    corrupted = []
    
    for result in results:
        if result["analysisResults"]["malicious"] != 0 or result["analysisResults"]["suspicious"] != 0 :
            corrupted.append(result)
        else:
            clean.append(result)
    
    printSummery(cleanFiles = clean, corruptedFiles = corrupted, unhandledFiles = unhandledFiles)
    moveCleanFiles(clean)

def delete_empty_dirs():
    directory = DIR_TO_CHECK
    for dirpath, dirnames, filenames in os.walk(directory, topdown=False):
        for dirname in dirnames:
            dir_to_check = os.path.join(dirpath, dirname)
            try:
                os.rmdir(dir_to_check)
            except OSError as e:
                logger.info(f"Could not delete directory: {dir_to_check}. Reason: {e}")


main()
# delete_empty_dirs()
