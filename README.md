# MAUPS

Malware Analysis Using Python Script v1.1

# Description

This is a portable script written in python used for "Static Analysis" of malwares. Focus on malware PE Headers, Strings, Image Type, MD5 Hash, VirusTotal Analysis. You can skip VirusTotal API Key if dont want to upload your sample on VirusTotal. Supported wherever python is installed (Tested on Linux, Windows). MAUPS will generate three output files in the same folder as the script: Strings.txt for the extracted strings, PE Analysis.txt for PE headers and VT Scan.txt for the how many AV (Name of AV eg Sophos, symantec. etc) is able to detect with the name of detected malware, will contain VirusTotal output. 

# Pre-Requesites (Only for Windows OS)

Install the following libraries: requests, pefile and pywin32.

pip install -r requirements.txt

# Usage

python maups.py

# Example




           M   M   AAAA   U   U   PPPP    SSSSS
           M M M   A  A   U   U   P   P   S
           M M M   AaaA   U   U   PPPP    SSSSS
           M   M   A  A   U   U   P           S
           M   M . A  A .  UUU  . P     . SSSSS v 1.1


        +++++++++++++++++++++++++++++++++++++++++++++++++
        + Copyright :- Shilpesh Trivedi                 +
        + Title :- Malware Analysis Using Python Script +
        +++++++++++++++++++++++++++++++++++++++++++++++++


 +++++++++++++++++++++++++++++++++++++++++++++++++
 
    Copyright :- Shilpesh Trivedi             
    Title :- Malware Analysis Using Python Script  
 
 +++++++++++++++++++++++++++++++++++++++++++++++++

 [*] Enter file name which you want to scan :- Path_to_the_malware

 [*] Enter Virus Total API Key :- VirusTotal_API_key
