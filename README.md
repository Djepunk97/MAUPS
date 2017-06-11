# MAUPS

Malware Analysis Using Python Script

# Description

This is a portable script written in python used for "Static Analysis" of malwares. Focus on malware PE Headers, Strings, Image Type, MD5 Hash, VirusTotal Analysis. You can skip VirusTotal API Key if dont want to upload your sample on VirusTotal. Supported wherever python is installed (Tested on Linux, Windows). MAUPS will generate three output files in the same folder as the script: Strings.txt for the extracted strings, PE Analysis.txt for PE headers and output.txt will contain VirusTotal output. 

# Pre-Requesites (Only for Windows OS)

Install the following libraries: requests, pefile and pywin32.

pip install -r requirements.txt

# Usage

python maups.py

# Example

 +++++++++++++++++++++++++++++++++++++++++++++++++
 
    Copyright :- Shilpesh Trivedi             
    Title :- Title :- Malware Analysis Using Python Script  
 
 +++++++++++++++++++++++++++++++++++++++++++++++++

 [*] Enter file name which you want to scan :- Path_to_the_malware

 [*] Enter Virus Total API Key :- VirusTotal_API_key
