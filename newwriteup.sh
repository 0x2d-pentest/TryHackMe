#!/bin/bash

# Проверка первого аргумента (название машины)
if [ -z "$1" ]; then
  echo "❌ Укажи название машины:"
  echo "Пример: ./newwriteup.sh Relevant 192.168.56.101"
  exit 1
fi

# Проверка второго аргумента (IP-адрес)
if [ -z "$2" ]; then
  echo "❌ Укажи IP-адрес машины:"
  echo "Пример: ./newwriteup.sh Relevant 192.168.56.101"
  exit 1
fi

# Валидация IP-адреса (IPv4)
if ! [[ "$2" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "❌ Неверный формат IP-адреса!"
  exit 1
fi

# Проверка диапазонов октетов (0–255)
IFS='.' read -r o1 o2 o3 o4 <<< "$2"
for octet in $o1 $o2 $o3 $o4; do
  if ((octet < 0 || octet > 255)); then
    echo "❌ Неверный IP-адрес: октеты должны быть от 0 до 255."
    exit 1
  fi
done

MACHINENAME=$1
IP=$2
DATE=$(date +"%Y-%m-%d")

# Создание структуры каталогов
mkdir -p "$MACHINENAME"/{scans,exploits,screenshots}
cd "$MACHINENAME" || exit

# Создание шаблона writeup.md
cat << EOF > writeup.md
# TryHackMe - $MACHINENAME

📅 Дата: $DATE  
🧠 Сложность:  
💻 IP-адрес: $IP  

---

## Sugar

\`\`\`bash
nmap_ctf() {
  local ip=\$1
  sudo nmap -sS -p- -Pn --max-parallelism 100 --min-rate 1000 -v -oN nmap-sS.txt \$ip && nmap -sT -Pn -sV -T4 -A -v -p "\$(grep -oP \"^[0-9]+(?=/tcp\\s+open)\" nmap-sS.txt | sort -n | paste -sd \",\")" -oN nmap-sV.txt \$ip
}
\`\`\`


## 🔍 Сканирование

\`\`\`bash
export ip=$IP && nmap_ctf \$ip
\`\`\`

### nmap

![nmap scan](screenshots/nmap_scan.png)

---

## 🕵️ Enumeration



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


EOF

# Git действия
cd .. || exit
git add "$MACHINENAME"
git commit -m "📝 Добавлен writeup по машине $MACHINENAME"
git push origin HEAD

echo "✅ Writeup для '$MACHINENAME' создан и отправлен в GitHub!"
