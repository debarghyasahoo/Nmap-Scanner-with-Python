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


print "=======================================NETWORK_SCANNER BY LOSSIFER=========================================="
print "                                          Nmap Version:" ,scanner.nmap_version()
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
                1. ^TCP Connect Scan^
                2. ^SYN Scan or half-open scan^
                3. ^ACK SCan^
                4. ^Xmas Tree Scan^
                5. ^Null Scan^
		6. ^UDP Scan^
		7. ^Comprehensive All Ports Scan^\n""")


if type == "1":
	scanner.scan(ip, '1-1024', '-v -sT -sV -Pn')
	for host in scanner.all_hosts():
        	print ('######################################################')
        	print ('Host : %s (%s)' %(host, scanner[host].hostname())) 
        	print ('State : %s' % scanner[host].state())
        	print ('######################################################')
        	for proto in scanner[host].all_protocols():
         		print ('\n======================RESULT========================')
                	print ('Protocol : %s' % proto)

                	lport = scanner[host][proto].keys()
                	lport.sort()
                	for port in lport:
          	        	print ('Port : %s\tState : %s\tName: %s\tVersion: %s\tReason: %s\tConf: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name'], scanner[host][proto][port]['version'], scanner[host][proto][port]['reason'],scanner[host][proto][port]['conf']))
			print ('=====================================================')

elif type == "2":
	scanner.scan(ip, '1-1024', '-v -sS -sV -Pn')
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
          	        	print ('Port : %s\tState : %s\tName: %sVersion: %s\tReason: %s\tConf: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name'],scanner[host][proto][port]['version'], scanner[host][proto][port]['reason'],scanner[host][proto][port]['conf']))
            		print ('=====================================================')

elif type == "3":
	scanner.scan(ip, '1-1024', '-v -sA -sV -Pn')
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
          	        	print ('Port : %s\tState : %s\tName: %s\tVersion: %s\tReason: %s\tConf: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name'],scanner[host][proto][port]['version'], scanner[host][proto][port]['reason'],scanner[host][proto][port]['conf']))
                        print ('=====================================================')

elif type == "4":
	scanner.scan(ip, '1-1024', '-v -sX -sV -Pn')
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
          	        	print ('Port : %s\tState : %s\tName: %s\tVersion: %s\tReason: %s\tConf: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name'],scanner[host][proto][port]['version'], scanner[host][proto][port]['reason'],scanner[host][proto][port]['conf']))
                        print ('=====================================================')

elif type == "5":
	scanner.scan(ip, '1-1024', '-v -sN -sV -Pn')
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
          	        	print ('Port : %s\tState : %s\tName: %s\tVersion: %s\tReason: %s\tConf: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name'],scanner[host][proto][port]['version'], scanner[host][proto][port]['reason'],scanner[host][proto][port]['conf']))
                        print ('=====================================================')

elif type == "6":
        scanner.scan(ip, '1-1024', '-v -sU -Pn')
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
          	        	print ('Port : %s\tState : %s\tName: %s\tReason: %s\tConf: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name'], scanner[host][proto][port]['reason'],scanner[host][proto][port]['conf']))
                        print ('=====================================================')

elif type == "7":
        scanner.scan(ip, '1-65535', '-v -sS -sV -O -sC -A -Pn')
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
          	        	print ('Port : %s\tState : %s\tName: %s\tVersion: %s\tProduct: %s\tExtrainfo: %s\tReason: %s\tConf: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name'],scanner[host][proto][port]['version'], scanner[host][proto][port]['product'], scanner[host][proto][port]['extrainfo'], scanner[host][proto][port]['reason'],scanner[host][proto][port]['conf']))

else:
    print("Enter the valid option.")
