#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

# Global Variables
scans = ("null","fin","xmas","pass","nikto","smb")
detected = list()
packetCount = 0
threatCount = 0
nullCount = 0
nullPorts = list()
finCount = 0
finPorts = list()
xmasCount = 0
xmasPorts = list()
passCount = 0
passPairs = list()
niktoCount = 0
niktoPorts = list()
smbCount = 0
userStrings = list()

def packetcallback(packet):
    # Vars for keeping counts between callbacks
    global packetCount
    global threatCount
    global nullCount
    global nullPorts
    global finCount
    global finPorts
    global xmasCount
    global xmasPorts
    global passCount
    global passPairs
    global niktoCount
    global niktoPorts
    global smbCount

    # Vars for parsing plaintext passwords from packets
    global userStrings
    passString = str()
    pair = str()

    # Increment to keep running total of packets scanned
    packetCount += 1
    try:
        # For each type of supported scan, perform a check
        for scan in scans:
            # Null scan check
            if scan == "null":
                if packet[TCP].flags == "":
                    nullCount += 1
                    nullPorts.append(packet[TCP].dport)
                    # Alert only once unless verbose x3
                    if not "null" in detected:
                        # Add to list of detected threat types
                        detected.append("null")
                        threatCount += 1
                        alert(threatCount,"Null scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
                    elif args.v > 2:
                        threatCount += 1
                        alert(threatCount,"Null scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
            # FIN scan check
            elif scan == "fin":
                if packet[TCP].flags == "F":
                    finCount += 1
                    finPorts.append(packet[TCP].dport)
                    if not "fin" in detected:
                        detected.append("fin")
                        threatCount += 1
                        alert(threatCount,"FIN scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
                    elif args.v > 2:
                        threatCount += 1
                        alert(threatCount,"FIN scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
            # Xmas scan check
            elif scan == "xmas":
                if packet[TCP].flags == "FPU":
                    xmasCount += 1
                    xmasPorts.append(packet[TCP].dport)
                    if not "xmas" in detected:
                        detected.append("xmas")
                        threatCount += 1
                        alert(threatCount,"Xmas scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
                    elif args.v > 2:
                        threatCount += 1
                        alert(threatCount,"Xmas scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
            # Parse out common plaintext password types
            elif scan == "pass":
                # HTTP Authorization Basic
                if packet[TCP].dport == 80:
                    if "Authorization: Basic " in str(packet):
                        passString = str(packet)[(str(packet).find("Authorization: Basic ") + len("Authorization: Basic ")):-9]
                        passString = base64.b64decode(passString).decode('utf-8')
                        pair = ("username:"+passString[0:passString.find(":")] +
                                ", password:"+passString[passString.find(":")+1:])
                        if not pair in passPairs:
                            passPairs.append(pair)
                            threatCount += 1
                            passCount += 1
                            alert(threatCount,"Usernames and passwords sent in the clear",
                                    packet[IP].src,"HTTP",pair)
                        if not "pass" in detected:
                            detected.append("pass")
                # IMAP
                elif packet[TCP].dport == 143:
                    if "LOGIN " in str(packet):
                        passString = str(packet)[str(packet).find("LOGIN ")+len("LOGIN "):-6]
                        pair = ("username:"+passString[0:passString.find(" \"")] +
                                ", password:"+passString[passString.find(" \"")+2:])
                        if not pair in passPairs:
                            passPairs.append(pair)
                            threatCount += 1
                            passCount += 1
                            alert(threatCount,"Usernames and passwords sent in the clear",
                                    packet[IP].src,"IMAP",pair)
                        if not "pass" in detected:
                            detected.append("pass")
                # FTP
                elif packet[TCP].dport == 21:
                    if "USER" in str(packet):
                        userStrings.append(str(packet[TCP].load.decode('utf-8'))[5:-2])
                    elif "PASS" in str(packet):
                        pair = ("username:"+userStrings.pop(0)+", password:"+
                                        str(packet[TCP].load.decode('utf-8'))[5:-2])
                        if not pair in passPairs:
                            passPairs.append(pair)
                            threatCount += 1
                            passCount += 1
                        alert(threatCount,"Usernames and passwords sent in the clear",
                                packet[IP].src,"FTP",pair)
                        if not "pass" in detected:
                            detected.append("pass")
            # Nikto scan check
            elif scan == "nikto":
                if packet[TCP].dport == 80 and "Nikto" in str(packet):
                    niktoCount += 1
                    niktoPorts.append(packet[TCP].sport)
                    if not "nikto" in detected:
                        detected.append("nikto")
                        threatCount += 1
                        alert(threatCount,"Nikto scan",packet[IP].src,
                                "HTTP",packet[TCP].load.decode('utf-8'))
                    elif args.v > 2:
                        threatCount += 1
                        alert(threatCount,"Nikto scan",packet[IP].src,
                                "HTTP",packet[TCP].load.decode('utf-8'))
            # SMB scan check
            elif scan == "smb":
                 if packet[TCP].dport == 445 and "R" in packet[TCP].flags:
                     smbCount += 1
                     if not "smb" in detected:
                         detected.append("smb")
                         threatCount += 1
                         alert(threatCount,"SMB scan",packet[IP].src,
                                "SMB2","no payload on RST")
                     elif args.v > 2:
                         threatCount += 1
                         alert(threatCount,"SMB scan",packet[IP].src,
                                "SMB2","no payload on RST")

    except Exception as e:
        # Print exceptions if we're being super verbose
        if args.v > 3:
            print(e)
        pass

# Standardize the alert format for more concise code
def alert(threatCount,inc,source,proto,pay):
    outstring = str.format("ALERT {incident_number}: {inc} is detected from {source} ({proto}) ({pay})!",
                            incident_number=threatCount,inc=inc,source=source,proto=proto,pay=pay)
    print(outstring)

# Scanning portion of program
def scan():
    if args.pcapfile:
        print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
        try:
            sniff(offline=args.pcapfile, prn=packetcallback)
        except:
            print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
    else:
        print("Sniffing on %(interface)s... " % {"interface" : args.interface})
        try:
            sniff(iface=args.interface, prn=packetcallback)
        except:
            print("Sorry, can\'t read network traffic. Are you root?")

# Summarize scans and output based on verbosity
def afterparty():
    global packetCount
    global threatCount
    global nullCount
    global nullPorts
    global finCount
    global finPorts
    global xmasCount
    global xmasPorts
    global passCount
    global passPairs
    global niktoCount
    global niktoPorts

    if len(detected) > 0:
        if args.v :
            print("----------------------")
            print("Scan Summary")
            print("----------------------")
            for scan in detected:
                if scan == "null":
                    print("Null Scan")
                    print("------------------")
                    nullPorts = list(set(nullPorts))
                    print("# Null Packets:\t\t",nullCount,"\n# Ports Scanned:\t",len(nullPorts))
                    if args.v > 1:
                        nullPorts.sort()
                        print("Scanned Ports:\n",nullPorts)
                    print("----------------------")
                elif scan == "fin":
                    print("FIN Scan")
                    print("------------------")
                    finPorts = list(set(finPorts))
                    print("# FIN Packets:\t\t",finCount,"\n# Ports Scanned:\t",len(finPorts))
                    if args.v > 1:
                        finPorts.sort()
                        print("Scanned Ports:\n",finPorts)
                    print("----------------------")
                elif scan == "xmas":
                    print("Xmas Scan")
                    print("------------------")
                    xmasPorts = list(set(xmasPorts))
                    print("# Xmas Packets:\t\t",xmasCount,"\n# Ports Scanned:\t",len(xmasPorts))
                    if args.v > 1:
                        xmasPorts.sort()
                        print("Scanned Ports:\n",xmasPorts)
                    print("----------------------")
                elif scan == "pass":
                    print("Plaintext Auth Pairs")
                    print("------------------")
                    print("# Auth Pairs:\t",passCount)
                    for pair in passPairs: print(pair)
                    print("----------------------")
                elif scan == "nikto":
                    print("Nikto Scan")
                    print("------------------")
                    niktoPorts = list(set(niktoPorts))
                    print("# Nikto Packets:\t",niktoCount,"\n# Ports Scanned:\t",len(niktoPorts))
                    if args.v > 1:
                        niktoPorts.sort()
                        print("Scanned Port Numbers:\n",niktoPorts)
                    print("----------------------")
                elif scan == "smb":
                    print("SMB scan")
                    print("------------------")
                    print("# Failed SMB connections:\t",smbCount)
        else:
            print("For more detailed output try using the -v argument!")
    else:
        print("No Threats Detected!")

# void main() {
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
parser.add_argument('-v', action='count', default=0, help='Verbose mode; stacks up to -vvvv')
args = parser.parse_args()
scan()
afterparty()
# }
