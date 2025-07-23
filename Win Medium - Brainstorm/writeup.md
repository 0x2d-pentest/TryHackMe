# TryHackMe - Win Medium - Brainstorm

📅 Дата: 2025-07-23  
🧠 Сложность: Medium  
💻 IP-адрес: 10.10.206.118  

---

## Sugar

```bash
nmap_ctf() {
  local ip=$1
  sudo nmap -sS -p- -Pn --max-parallelism 100 --min-rate 1000 -v -oN nmap-sS.txt $ip && nmap -sT -Pn -sV -T4 -A -v -p "$(grep -oP \"^[0-9]+(?=/tcp\s+open)\" nmap-sS.txt | sort -n | paste -sd \",\")" -oN nmap-sV.txt $ip
}
```


## 🔍 Сканирование

```bash
export ip=10.10.206.118 && nmap_ctf $ip
```

### nmap

```bash
PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2025-07-23T12:49:18+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=brainstorm
| Issuer: commonName=brainstorm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-07-22T12:27:55
| Not valid after:  2026-01-21T12:27:55
| MD5:   e48d:29db:a794:ae6b:e58a:83f4:9e02:7a84
|_SHA-1: 5382:63ad:2a30:2735:c33b:1e13:a599:f9f8:5ce5:9fcb
| rdp-ntlm-info: 
|   Target_Name: BRAINSTORM
|   NetBIOS_Domain_Name: BRAINSTORM
|   NetBIOS_Computer_Name: BRAINSTORM
|   DNS_Domain_Name: brainstorm
|   DNS_Computer_Name: brainstorm
|   Product_Version: 6.1.7601
|_  System_Time: 2025-07-23T12:48:48+00:00
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.94SVN%I=7%D=7/23%Time=6880D981%P=x86_64-pc-linux-gnu%r
SF:(NULL,52,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20en
SF:ter\x20your\x20username\x20\(max\x2020\x20characters\):\x20")%r(GetRequ
SF:est,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20ente
SF:r\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20
SF:message:\x20")%r(HTTPOptions,63,"Welcome\x20to\x20Brainstorm\x20chat\x2
SF:0\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20charac
SF:ters\):\x20Write\x20a\x20message:\x20")%r(FourOhFourRequest,63,"Welcome
SF:\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20us
SF:ername\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%
SF:r(JavaRMI,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x
SF:20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x2
SF:0a\x20message:\x20")%r(GenericLines,63,"Welcome\x20to\x20Brainstorm\x20
SF:chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x2
SF:0characters\):\x20Write\x20a\x20message:\x20")%r(RTSPRequest,63,"Welcom
SF:e\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20u
SF:sername\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")
SF:%r(RPCCheck,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease
SF:\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\
SF:x20a\x20message:\x20")%r(DNSVersionBindReqTCP,63,"Welcome\x20to\x20Brai
SF:nstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(ma
SF:x\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(DNSStatusReq
SF:uestTCP,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20
SF:enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a
SF:\x20message:\x20")%r(Help,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(
SF:beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20character
SF:s\):\x20Write\x20a\x20message:\x20")%r(SSLSessionReq,63,"Welcome\x20to\
SF:x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\
SF:x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(Termi
SF:nalServerCookie,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPl
SF:ease\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Wr
SF:ite\x20a\x20message:\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Phone|8.1 (88%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1:r1
Aggressive OS guesses: Microsoft Windows Server 2008 R2 SP1 (88%), Microsoft Windows Server 2008 (87%), Microsoft Windows Server 2008 R2 (87%), Microsoft Windows Server 2008 R2 or Windows 8 (87%), Microsoft Windows 7 SP1 (87%), Microsoft Windows 8.1 Update 1 (87%), Microsoft Windows Phone 7.5 or 8.0 (87%), Microsoft Windows Embedded Standard 7 (86%), Microsoft Windows 8.1 R1 (85%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.016 days (since Wed Jul 23 08:25:43 2025)
TCP Sequence Prediction: Difficulty=265 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 0s

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   216.12 ms 10.21.0.1
2   ... 30
```

---

## 🕵️ Enumeration

На порту 9999 висит какой-то чат, видимо его и будем эксплуатировать
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub]
└─$ nc 10.10.206.118 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): max
Write a message: Hi


Wed Jul 23 05:48:01 2025
max said: Hi


Write a message:  ^C
```

### ftp
`ftp` позволяет анонимное соединение.
Подключаюсь и скачиваю файлы к себе, похоже, что это файлы того самого чата, что висит на 9999
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ ftp 10.10.206.118
Connected to 10.10.206.118.
220 Microsoft FTP Service
Name (10.10.206.118:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-29-19  08:36PM       <DIR>          chatserver
226 Transfer complete.
ftp> cd chatserver
250 CWD command successful.
ftp> ls
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-29-19  10:26PM                43747 chatserver.exe
08-29-19  10:27PM                30761 essfunc.dll
226 Transfer complete.
ftp> binary
200 Type set to I.
ftp> mget *.*
mget chatserver.exe [anpqy?]? y
200 EPRT command successful.
125 Data connection already open; Transfer starting.
100% |*********************************************************************| 43747       38.80 KiB/s    00:00 ETA
226 Transfer complete.
43747 bytes received in 00:01 (38.79 KiB/s)
mget essfunc.dll [anpqy?]? y
200 EPRT command successful.
125 Data connection already open; Transfer starting.
100% |*********************************************************************| 30761       34.74 KiB/s    00:00 ETA
226 Transfer complete.
30761 bytes received in 00:00 (34.74 KiB/s)
ftp> exit
221 Goodbye.
```

Информация по файлам
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ file essfunc.dll 
essfunc.dll: PE32 executable for MS Windows 4.00 (DLL), Intel i386 (stripped to external PDB), 9 sections
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ file chatserver.exe
chatserver.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 (stripped to external PDB), 7 sections
```

### radare2
chatserver.exe
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ rabin2 -I chatserver.exe
arch     x86
baddr    0x400000
binsz    43747
bintype  pe
bits     32
canary   true
injprot  false
retguard false
class    PE32
cmp.csum 0x0000b072
compiled Mon Sep 11 19:08:08 1972
crypto   false
endian   little
havecode true
hdr.csum 0x0000b072
laddr    0x0
lang     c
linenum  true
lsyms    false
machine  i386
nx       false
os       windows
overlay  true
cc       cdecl
pic      false
relocs   true
signed   false
sanitize false
static   false
stripped true
subsys   Windows CUI
va       true
```

essfunc.dll
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ rabin2 -I essfunc.dll   
arch     x86
baddr    0x62500000
binsz    30761
bintype  pe
bits     32
canary   true
injprot  false
retguard false
class    PE32
cmp.csum 0x00011053
compiled Thu Jan  1 13:12:16 1970
crypto   false
endian   little
havecode true
hdr.csum 0x00011053
laddr    0x0
lang     c
linenum  true
lsyms    false
machine  i386
nx       false
os       windows
overlay  true
cc       cdecl
pic      false
relocs   false
signed   false
sanitize false
static   false
stripped true
subsys   Windows CUI
va       true
```

Резюме по файлам:
- `arch     x86`
- `nx       false`
  - стек и куча исполняемые
- `canary   true`
  - убью при перезаписи EIP
- `stripped true`
  - вряд ли стоит смотреть в ghidra, код будет непонятным

При этом есть различия в `ASLR (Address Space Layout Randomization)`
- `chatserver.exe`
  - `pic      false` — код не является позиционно-независимым (Position Independent Code).
  - `relocs   true`  — присутствуют записи перемещения (relocation records).
Для исполняемого файла (exe) это означает, что ASLR может быть поддержан, если операционная система включает эту функцию.  
Исполняемые файлы могут быть загружены по случайному адресу, даже если они не являются PIC, при наличии записей перемещения.

Из этого следует, что, возможно, инструкцию `call esp/jmp esp` для вызова кода из стека, нужно искать в `DLL`, где адреса точно постоянны.

Запускаю `chatserver.exe` на Windows машине с `immunity debugger`
Создаю рабочую директорию `!mona config -set workingfolder c:\mona\%p`
<img width="1918" height="1016" alt="image" src="https://github.com/user-attachments/assets/c67671c4-bbcb-4fc6-ad44-81a2af470664" />

Далее создаю шаблон с помощью `pwntool`
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ actv
                                                                                                                  
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ pwn template ./chatserver.exe --quiet --host 192.168.56.124 --port 9999 > x.py 
[*] Automatically detecting challenge binaries...
```


![nmap scan](screenshots/nmap_scan.png)



## 📂 Получение доступа



## ⚙️ Привилегии



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


