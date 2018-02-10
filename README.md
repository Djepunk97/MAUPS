# MAUPS

Malware Analysis Using Python Script v1.1

# Description

This is a portable script written in python used for "Static Analysis" of malwares. Focus on malware PE Headers, Strings, Image Type, MD5 Hash, VirusTotal Analysis. You can skip VirusTotal API Key if dont want to upload your sample on VirusTotal. Supported wherever python is installed (Tested on Linux, Windows). MAUPS will generate three output files in the same folder as the script: Strings.txt for the extracted strings, PE Analysis.txt for PE headers and VT Scan.txt.  

# What is New

You have to enter yor Virus Total API Key inside program at line number 51.

           key="" # <= Here Enter Your VT API Key between double quotes


Now MAUPS v1.1 is able to do static malware in very deep way, the two more features is added.

           1] Header Members
           
                      a] IMAGE_DOS_HEADER
                      b] IMAGE_NT_HEADERS
                      
           2] Optional Headers
           
Now it is able to perform full VT Analysis and store the output as VT Scan.csv which contain how many AV (Name of AV eg Sophos, symantec. etc) are able to detected malware with the respectively malware name. 

Eg:

![alt text](https://github.com/ShilpeshTrivedi/MAUPS/blob/master/VT%20Scan.png)

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
        + Auther :- Shilpesh Trivedi                    +
        + Title :- Malware Analysis Using Python Script +
        +++++++++++++++++++++++++++++++++++++++++++++++++

 [*] Enter file name which you want to scan :- Path_to_the_malware
