import requests
import re
import hashlib
import io
import pefile
import struct

print '\n'
print ' +++++++++++++++++++++++++++++++++++++++++++++++++'
print ' + Copyright :- Shilpesh Trivedi                 +'
print ' + Title :- Portable Malware Analysisy Tool      +'
print ' +++++++++++++++++++++++++++++++++++++++++++++++++'


try:
##### Asking For File#####
    f=raw_input("\n\n [*] Enter file name which you want to scan :- ")
    
    print '\n'
    try:
        fp= open(f)
        fp.close()
        key=raw_input('\n [*] Enter Virus Total API Key :- ')
    except IOError:
        print "\n [-] There is a no file like '", f ,"'"
        exit()
        
    print'\n\n'

    
## Image Type Anlaysis
    print ('----------------.')
    print (' [*] Image Base |')
    print ('----------------`')
    print '\n'
    IMAGE_FILE_MACHINE_I386=332
    IMAGE_FILE_MACHINE_IA64=512
    IMAGE_FILE_MACHINE_AMD64=34404
    
    fl=open(f, "rb")

    s=fl.read(2)
    if s!="MZ":
        print " Not an EXE file"
    else:
        fl.seek(60)
        s=fl.read(4)
        header_offset=struct.unpack("<L", s)[0]
        fl.seek(header_offset+4)
        s=fl.read(2)
        machine=struct.unpack("<H", s)[0]

        if machine==IMAGE_FILE_MACHINE_I386:
            print " IA-32 (32-bit x86)"
            fp=open('PE Analysis.txt','a')
            fp.write("Image Type = IA-32 (32-bit x86)")
            fp.write('\n\n')
            fp.close()
        elif machine==IMAGE_FILE_MACHINE_IA64:
            print " IA-64 (Itanium)"
            fp=open('PE Analysis.txt','a')
            fp.write("Image Type = IA-64 (Itanium)")
            fp.write('\n\n')
            fp.close()
        elif machine==IMAGE_FILE_MACHINE_AMD64:
            print " AMD64 (64-bit x86)"
            fp=open('PE Analysis.txt','a')
            fp.write("Image Type = AMD64 (64-bit x86)")
            fp.write('\n\n')
            fp.close()
        else:
            print " Unknown architecture"

    fl.close()

## PE File Analysis"   
    try:
        print ("\n\n-----------------.")
        print ' [*] PE Analysis |'
        print '-----------------`'
        pe=pefile.PE(f)
        print '\n ImageBase = ' + hex(pe.OPTIONAL_HEADER.ImageBase)
        print '\n AddressOfEntryPoint = ' + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        print '\n NumberOfRvaAndSizes = ' + hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes )
        print '\n NumberOfSections = ' + hex(pe.FILE_HEADER.NumberOfSections)

        fp=open('PE Analysis.txt','a')
        
        fp.write('ImageBase = ' + hex(pe.OPTIONAL_HEADER.ImageBase))
        fp.write('\n\nAddress Of EntryPoint = ' + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        fp.write('\n\nNumber Of RvaAndSizes = ' + hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes ))
        fp.write('\n\nNumber Of Sections = ' + hex(pe.FILE_HEADER.NumberOfSections))
        fp.write('\n')
        fp.write('\n')

        ## List Import Sections"
        print '\n [*] Listing Sections...\n'
        fp.write('\n')
        fp.write('\n')
        fp.write('[*] Listing Sections \n\n')
        for section in pe.sections:
            print(' ' + section.Name.decode('utf-8'))
            print("\tVirtual Address: " + hex(section.VirtualAddress))
            print("\tVirtual Size: " + hex(section.Misc_VirtualSize))
            print("\tRaw Size: " + hex(section.SizeOfRawData))
            fp.write('\n ' + section.Name.decode('utf-8'))
            fp.write("\n\n\tVirtual Address: " + hex(section.VirtualAddress))
            fp.write("\n\n\tVirtual Size: " + hex(section.Misc_VirtualSize))
            fp.write("\n\n\tRaw Size: " + hex(section.SizeOfRawData))

            print '\n'

        ## List Import DLL"
        fp.write('\n')
        fp.write('\n')
        fp.write('\n')
        fp.write('\n[*] Listing imported DLLs...')
        fp.write('\n')
        print ' [*] Listing imported DLLs...\n'
        for lst in pe.DIRECTORY_ENTRY_IMPORT:
            print ('\n '+lst.dll.decode('utf-8'))
            fp.write('\n'+lst.dll.decode('utf-8'))
            for s in lst.imports:
                print ("\t - %s at 0x%08x" % (unicode(s.name).decode('utf-8'), s.address))
                fp.write('\n\n' + "\t - %s at 0x%08x" % (unicode(s.name).decode('utf-8'), s.address)+ '\n',)
        print '\n\n ***********************'
        print ' * See PE Analysis.txt *'
        print ' ***********************'
        
    except:
        print '\n [-] ' + f + ' DOS Header magic not found.'

    
#### Strings Analysis Extracting Atrings From File ####
    print ' \n\n\n\n----------------------.'    
    print ' [*] Strings Analysis |'
    print '----------------------`'
    srt=open(f,"rb")
    data=srt.read()
    unicode_str = re.compile( u'[\u0020-\u007e]{3,}',re.UNICODE )
    myList = unicode_str.findall(data)
    fp=open('strings.txt','a')

    for p in myList:
        fp.write(p + '\n')
    fp.close()
    
    print '\n\n *******************'
    print ' * See Strings.txt *'
    print ' *******************'
    #### Count Hash Value###
    print '\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'
    with io.open(f, mode="rb") as fd:
        content = fd.read()
        md5=hashlib.md5(content).hexdigest()

    print ' [*] MD5 Hash Value Of Your File Is :- ', md5
    print '++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'


    #####Virus Total Analysis#####
    
    #####Asking For Key#####
    print '\n\n\n\n--------------------------.'
    print ' [*] Virus Total Analysis |'
    print '--------------------------`'

    #####Main Program Function#####
    def main():
        VT_Request(key, md5.rstrip())
    
    ####Upload Hash On Virus Total####
    def VT_Request(key, hash):
    
        if len(key) == 64:
            try:
                params = {'apikey': key, 'resource': hash}
                url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                json_response = url.json()
                #print json_response
                    
                response = int(json_response.get('response_code'))
                if response == 0:
                    print ('[-] ' + f + ' [' + hash + '] is not in Virus Total')
                    file = open('output.txt','a')
                    file.write('[-] ' + f + ' [' + hash + '] is not in Virus Total')
                    file.write('\n')
                    file.close()
                elif response == 1:
                    positives = int(json_response.get('positives'))
                    if positives == 0:
                        print ('[-] ' + f + ' [' + hash + '] is not malicious')
                        file = open('output.txt','a')
                        file.write('[-] ' + f + ' [' + hash + '] is not malicious')
                        file.write('\n')
                        file.close()
                    else:

                        sha1 = json_response.get('sha1')
                        positives= int(json_response.get('positives'))
                        total= int(json_response.get('total'))
                        sha256=json_response.get('sha256')
                        scans=str(json_response.get('scans'))
                
                        print '\n [*] Malware Hit Count ' + str(positives) +'/'+str(total)
                        print '\n [*] Sha1 Value = ' + sha1
                        print '\n [*] Sha256 Value = ' + sha256
                        #print '\n Scans = ' + str(scans)
                        
                        print '\n [*] ' + f +' ['+hash+']' + ' is malicious'
                        file = open('output.txt','a')
                        file.write('[*] ' + f + ' [' + hash + '] is malicious. Hit Count:' + str(positives))
                        file.write('\n')
                        file.close()
                else:
                    print hash + ' [-] could not be searched. Please try again later.'
                print '\n\n ******************'
                print ' * See Output.txt *'
                print ' ******************'
            except Exception, e:
                print '\n [-] Oops!!, Somthing Wrong Check Your Internet Connection'
        else:
            print " [-] There is something Wrong With Your API Key."
            exit()
    
    if __name__ == '__main__':
    	main()
    
except:
    print '\n\n [-] Oops!, Program Halted'
