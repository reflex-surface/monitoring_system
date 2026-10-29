#!/usr/bin/env python3
import re
import time
import sqlite3
import os

LOG_FILE = "/var/log/remote/worker-audit.log"
DB_PATH = "/opt/monitor.db"
INCIDENT_DIR = "/opt/incidents"
os.makedirs(INCIDENT_DIR, exist_ok=True)

# =====================================================
# ПОДКЛЮЧЕНИЕ К БАЗЕ
# =====================================================
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

# =====================================================
# ТАБЛИЦА СОБЫТИЙ
# =====================================================
c.execute("""
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    hostname TEXT,
    user TEXT,
    event_type TEXT,
    severity TEXT,
    source_ip TEXT,
    terminal TEXT,
    raw_message TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
)
""")

# =====================================================
# ТАБЛИЦА АЛЕРТОВ
# =====================================================
c.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT,
    severity TEXT,
    username TEXT,
    source_ip TEXT,
    attempts INTEGER,
    status TEXT DEFAULT 'ACTIVE',
    created_at TEXT DEFAULT (datetime('now','localtime'))
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    alert_type TEXT,
    source_ip TEXT,

    action_taken TEXT,

    created_at TEXT DEFAULT (datetime('now','localtime'))
)
""")

conn.commit()
print("[*] База данных подключена:", DB_PATH)

# =====================================================
# REGEX
# =====================================================
acct_pattern = re.compile(r'acct="([^"]+)"')
addr_pattern = re.compile(r'addr=([^\s]+)')
host_pattern = re.compile(r'^(\S+)')

# =====================================================
# ДЕДУПЛИКАЦИЯ ПО ВРЕМЕНИ И IP
# =====================================================
# Храним последние события: ключ = (user, ip), значение = timestamp
recent_events = {}

def is_duplicate(user, ip):
    """
    Проверяем, не является ли текущее событие "фантомным хвостом"
    предыдущего. Если от того же IP и с тем же пользователем (или "?")
    уже было событие в последние 3 секунды — считаем дубликатом.
    """
    global recent_events
    now = time.time()
    
    # Очищаем старые записи (старше 3 секунд)
    recent_events = {k: t for k, t in recent_events.items() if now - t < 3.0}
    
    key = (user, ip)
    if key in recent_events:
        return True
    
    # Дополнительная проверка: если от того же IP недавно было событие
    # с реальным именем, а сейчас приходит "?" — это фантомный хвост SSH
    if user == "?":
        for (u, i), t in recent_events.items():
            if i == ip and u != "?":
                return True
    
    recent_events[key] = now
    return False

# =====================================================
# СОЗДАНИЕ ALERT
# =====================================================
def create_alert_ssh(username, ip, attempts):
    c.execute("""
        SELECT id FROM alerts
        WHERE alert_type='SSH_BRUTE_FORCE'
        AND source_ip=?
        AND status='ACTIVE'
    """, (ip,))
    existing = c.fetchone()
    if existing:
        return
    
    c.execute("""
        INSERT INTO alerts (alert_type, severity, username, source_ip, attempts)
        VALUES ('SSH_BRUTE_FORCE', 'CRITICAL', ?, ?, ?)
    """, (username, ip, attempts))
    conn.commit()

    execute_response(
        "SSH_BRUTE_FORCE",
        username,
        ip,
        attempts
    )   
    print("==============================")
    print("[CRITICAL ALERT]")
    print("Тип: SSH_BRUTE_FORCE")
    print("IP:", ip)
    print("Пользователь:", username)
    print("Попыток:", attempts)
    print("==============================")

def create_alert_auth(username, ip, attempts):
    c.execute("""
        SELECT id FROM alerts
        WHERE alert_type='AUTH_BRUTE_FORCE'
        AND source_ip=?
        AND status='ACTIVE'
    """, (ip,))
    existing = c.fetchone()
    if existing:
        return
    
    c.execute("""
        INSERT INTO alerts (alert_type, severity, username, source_ip, attempts)
        VALUES ('AUTH_BRUTE_FORCE', 'CRITICAL', ?, ?, ?)
    """, (username, ip, attempts))
    conn.commit()

    execute_response(
        "AUTH_BRUTE_FORCE",
        username,
        ip,
        attempts
    )

    print("==============================")
    print("[CRITICAL ALERT]")
    print("Тип: AUTH_BRUTE_FORCE")
    print("IP:", ip)
    print("Пользователь:", username)
    print("Попыток:", attempts)
    print("==============================")


def execute_response(alert_type, username, ip, attempts):

    # ===== создаем карточку инцидента =====

    incident_file = (
        f"{INCIDENT_DIR}/"
        f"{alert_type}_{int(time.time())}.txt"
    )

    with open(incident_file, "w") as f:

        f.write(
            f"""ИНЦИДЕНТ БЕЗОПАСНОСТИ
            Тип: {alert_type}
            Пользователь: {username}
            IP-адрес: {ip}
            Количество попыток: {attempts}
            Время: {time.strftime('%Y-%m-%d %H:%M:%S')}
            Мера реагирования:
            Инцидент зарегистрирован.
            Администратор уведомлен.
            Источник помечен как подозрительный.
            """
        )

    # ===== системный журнал =====

    with open("/var/log/security_response.log", "a") as f:

        f.write(
            f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
            f"{alert_type} "
            f"{ip} "
            f"incident_created\n"
        )

    # ===== таблица responses =====

    action = (
        "Инцидент зарегистрирован, "
        "создана карточка инцидента, "
        "администратор уведомлен"
    )

    c.execute("""
        INSERT INTO responses
        (
            alert_type,
            source_ip,
            action_taken
        )
        VALUES (?, ?, ?)
        """, (
            alert_type,
            ip,
            action
        )
    )

    conn.commit()

    print("\n[RESPONSE]")
    print(action)


# =====================================================
# ПРОВЕРКА BRUTEFORCE
# =====================================================
def check_bruteforce_ssh(username, ip):
    c.execute("""
        SELECT COUNT(*) FROM events
        WHERE event_type='SSH_FAILED'
        AND source_ip=?
        AND created_at >= datetime('now','-2 minutes')
    """, (ip,))
    count = c.fetchone()[0]
    if count >= 3:
        create_alert_ssh(username, ip, count)

def check_bruteforce_auth(username, ip):
    c.execute("""
        SELECT COUNT(*) FROM events
        WHERE event_type='AUTH_FAILED'
        AND source_ip=?
        AND created_at >= datetime('now','-2 minutes')
    """, (ip,))
    count = c.fetchone()[0]
    if count >= 3:
        create_alert_auth(username, ip, count)

# =====================================================
# РАЗБОР СОБЫТИЙ
# =====================================================
def parse_event(line):
    if "res=failed" not in line:
        return None
    
    user_match = acct_pattern.search(line)
    ip_match = addr_pattern.search(line)
    host_match = host_pattern.search(line)
    
    user = user_match.group(1) if user_match else "unknown"
    ip = ip_match.group(1) if ip_match else "unknown"
    hostname = host_match.group(1) if host_match else "unknown"
    
    # SSH события
    if (
        "sshd" in line.lower()
        or "terminal=sshd" in line.lower()
        or 'exe="/usr/sbin/sshd"' in line.lower()
    ):
        return {
            "event_type": "SSH_FAILED",
            "severity": "HIGH",
            "user": user,
            "source_ip": ip,
            "hostname": hostname,
            "terminal": "sshd",
            "raw": line.strip()
        }
    
    # Прочие ошибки входа (включая GUI)
    return {
        "event_type": "AUTH_FAILED",
        "severity": "MEDIUM",
        "user": user,
        "source_ip": ip,
        "hostname": hostname,
        "terminal": "local",
        "raw": line.strip()
    }

# =====================================================
# МОНИТОРИНГ ЛОГА
# =====================================================
print("[*] Мониторинг запущен")
with open(LOG_FILE, "r") as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue
        
        event = parse_event(line)
        if not event:
            continue
        
        # Умная дедупликация: отсекаем только "фантомные хвосты"
        if is_duplicate(event["user"], event["source_ip"]):
            continue
        
        print("====================")
        print("[ALERT]", event["event_type"])
        print("Пользователь:", event["user"])
        print("IP:", event["source_ip"])
        print("====================")
        
        c.execute("""
            INSERT INTO events 
            (timestamp, hostname, user, event_type, severity, source_ip, terminal, raw_message)
            VALUES (datetime('now','localtime'), ?, ?, ?, ?, ?, ?, ?)
        """, (
            event["hostname"],
            event["user"],
            event["event_type"],
            event["severity"],
            event["source_ip"],
            event["terminal"],
            event["raw"]
        ))
        conn.commit()
        
        # Корреляция SSH brute force
        if event["event_type"] == "SSH_FAILED":
            check_bruteforce_ssh(event["user"], event["source_ip"])
            
        if event["event_type"] == "AUTH_FAILED":
            check_bruteforce_auth(event["user"], event["source_ip"])
