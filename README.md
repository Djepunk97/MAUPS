# MAUPS

Malware Analysis Using Python Script v1.1

# Description

This is a portable script written in python used for "Static Analysis" of malwares. Focus on malware PE Headers, Strings, Image Type, MD5 Hash, VirusTotal Analysis. You can skip VirusTotal API Key if dont want to upload your sample on VirusTotal. Supported wherever python is installed (Tested on Linux, Windows). MAUPS will generate three output files in the same folder as the script: Strings.txt for the extracted strings, PE Analysis.txt for PE headers and VT Scan.txt.  

# What is New

Now MAUPS v1.1 is able to do static malware in very deep way, the two more features is added.

           1] Header Members
           
                      a] IMAGE_DOS_HEADER
                      b] IMAGE_NT_HEADERS
                      
           2] Optional Headers
Now it is able to perform full VT Analysis and store the output as VT Scan.csv for the howmany AV (Name of AV eg Sophos, symantec. etc) is able to detect with the name of detected malware, will contain VirusTotal output. 

Eg:

AV Name	           Detection	AV Version	           Malware Name	           AV Updated Date
MicroWorld-eScan	TRUE	version:14.0.297.0	Trojan.GenericKD.30318425	20180209
CAT-QuickHeal	TRUE	version:14.00	Trojan.Multi	           20180208
Cylance	           TRUE	version:2.3.1.101	Unsafe	                      20180209
AegisLab	           TRUE	version:4.2	Troj.Dropper.W32.Injector!c	20180208
K7GW	           TRUE	version:10.39.26155	Trojan ( 005263591 )	           20180208
K7AntiVirus	TRUE	version:10.39.26155	Trojan ( 005263591 )	           20180208

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

 [*] Enter file name which you want to scan :- Path_to_the_malware

 [*] Enter Virus Total API Key :- VirusTotal_API_key
