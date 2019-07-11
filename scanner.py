#! /usr/bin/python

import nmap
import sys

try:
    scanner = nmap.PortScanner()
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(0)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(0)


print "=======================================STARTING NMAP_SCANNER=========================================="
print "                                       Nmap Version: ", scanner.nmap_version()
print "======================================================================================================"

ip = raw_input("Enter the ip address you want to scan: ")

print "Checking the state of.........",ip

try:
    scanner.scan(ip, '1 -1000', '-sT')
    print "........................................."
    print "\tThe host is ", scanner[ip].state()
except:
    print "Down"
    sys.exit(0)


type = raw_input("""\n####################////// Which type of scan do you want to run? //////###########################
                1. sT == ^TCP Connect Scan^
                2. sS == ^SYN Scan or half-open scan^
                3. sA == ^ACK SCan^
                4. sX == ^Xmas Tree Scan^
                5. sN == ^Null Scan^\n""")



if type == "sT":
    scanner.scan(ip, '1-1000', '-v -sT')
    for host in scanner.all_hosts():
            print ('######################################################')
                print ('Host : %s (%s)' % (host, scanner[host].hostname())) 
                print ('State : %s' % scanner[host].state())
                print ('######################################################')
                for proto in scanner[host].all_protocols():
                        print ('\n======================RESULT========================')
                        print ('Protocol : %s' % proto)

                        lport = scanner[host][proto].keys()
                        lport.sort()
                        for port in lport:
                                print ('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
                        print ('=====================================================')

elif type == "sS":
    scanner.scan(ip, '1-1000', '-v -sS')
        for host in scanner.all_hosts():
        print ('######################################################')
                print ('Host : %s (%s)' % (host, scanner[host].hostname())) 
                print ('State : %s' % scanner[host].state())
        print ('######################################################')
                for proto in scanner[host].all_protocols():
                        print ('\n======================RESULT========================')
                        print ('Protocol : %s' % proto)

                        lport = scanner[host][proto].keys()
                        lport.sort()
                        for port in lport:
                                print ('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
            print ('=====================================================')

elif type == "sA":
    scanner.scan(ip, '1-1000', '-v -sA')
    for host in scanner.all_hosts():
                print ('######################################################')
                print ('Host : %s (%s)' % (host, scanner[host].hostname())) 
                print ('State : %s' % scanner[host].state())
                print ('######################################################')
                for proto in scanner[host].all_protocols():
                        print ('\n======================RESULT========================')
                        print ('Protocol : %s' % proto)

                        lport = scanner[host][proto].keys()
                        lport.sort()
                        for port in lport:
                                print ('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
                        print ('=====================================================')

elif type == "sX":
    scanner.scan(ip, '1-1000', '-v -sX')
        for host in scanner.all_hosts():
                print ('######################################################')
                print ('Host : %s (%s)' % (host, scanner[host].hostname())) 
                print ('State : %s' % scanner[host].state())
                print ('######################################################')
                for proto in scanner[host].all_protocols():
                        print ('\n======================RESULT========================')
                        print ('Protocol : %s' % proto)

                        lport = scanner[host][proto].keys()
                        lport.sort()
                        for port in lport:
                                print ('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
                        print ('=====================================================')

elif type == "sN":
    scanner.scan(ip, '1-1000', '-v -sN')
        for host in scanner.all_hosts():
                print ('######################################################')
                print ('Host : %s (%s)' % (host, scanner[host].hostname())) 
                print ('State : %s' % scanner[host].state())
                print ('######################################################')
                for proto in scanner[host].all_protocols():
                        print ('\n======================RESULT========================')
                        print ('Protocol : %s' % proto)

                        lport = scanner[host][proto].keys()
                        lport.sort()
                        for port in lport:
                                print ('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
                        print ('=====================================================')

else:
    print("Enter the valid option.")
