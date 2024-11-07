import sys
import psutil
import os
import re
import requests
import time
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# Константы
CACHE_FILE = '/tmp/ipcache'
CACHE_EXPIRATION = timedelta(hours=96)

# Запуск таймера для подсчета времени выполнения
start_time = time.time()

# Чтение данных из stdin
data = sys.stdin.read()

# Установка границы для фильтрации по дате (два дня назад)
date_limit = datetime.now() - timedelta(days=2)
recent_limit = datetime.now() - timedelta(hours=2)

def get_xray_uptime():
    # Find the xray process and calculate the time since it started
    for process in psutil.process_iter(['name', 'create_time']):
        if process.info['name'] == 'xray':
            start_time = datetime.fromtimestamp(process.info['create_time'])
            uptime = datetime.now() - start_time
            hours = uptime.seconds // 3600
            minutes = (uptime.seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    return "Xray process not running."

def get_load_average():
    # Get the load averages for the past 1, 5, and 15 minutes
    load_avg = os.getloadavg()
    return {
        "1_min": round(load_avg[0], 2),
        "5_min": round(load_avg[1], 2),
        "15_min": round(load_avg[2], 2)
    }

def get_memory_utilization():
    # Get memory usage details
    memory_info = psutil.virtual_memory()
    memory_utilization = memory_info.percent
    return memory_utilization

def get_network_connections():
    # Get all network connections
    connections = psutil.net_connections()
    
    # Count established and non-established (SYN_SENT or SYN_RECV) connections
    established_count = sum(1 for conn in connections if conn.status == psutil.CONN_ESTABLISHED)
    non_established_count = sum(1 for conn in connections if conn.status in (psutil.CONN_SYN_SENT, psutil.CONN_SYN_RECV))
    
    return {
        "established": established_count,
        "non_established": non_established_count
    }

# Словарь для хранения IP-адресов и их временных меток
ip_time_dict = defaultdict(list)
total_lines_processed = 0
load_avg = get_load_average()
memory_utilization = get_memory_utilization()
network_connections = get_network_connections()
xray_uptime = get_xray_uptime()

# Фильтрация строк по дате, извлечение IP-адресов и их временных меток
for line in data.strip().split('\n'):
    match = re.search(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', line)
    if match:
        timestamp = match.group(1)
        log_date = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        if log_date >= date_limit:
            total_lines_processed += 1
            ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b(?=\:\d+\s+ESTABLISHED)', line)
            if ip_match:
                ip = ip_match.group()
                ip_time_dict[ip].append(log_date)

# Проверка на отсутствие данных для анализа
if not ip_time_dict:
    print("Нет данных для анализа в пределах последних двух суток.")
    sys.exit(0)


# Функция для объединения временных меток по 10-минутным интервалам и отметки последних двух часов
def group_timestamps(timestamps):
    timestamps.sort()
    grouped = []
    start = timestamps[0]
    end = start
    latest_timestamp = timestamps[-1]

    for current in timestamps[1:]:
        if (current - end).total_seconds() <= 600:
            end = current
        else:
            grouped.append((start, end))
            start = current
            end = current
    grouped.append((start, end))

    formatted_intervals = []
    for start, end in grouped:
        start_fmt = start.strftime('%m/%d %H:%M')
        end_fmt = end.strftime('%H:%M')
        interval_str = f"{start_fmt}" if start == end else f"{start_fmt} — {end_fmt}"

        # Проверка, содержит ли интервал временные метки за последние два часа
        if end >= recent_limit:
            interval_str = f'<span class="recent">{interval_str}</span>'

        formatted_intervals.append(interval_str)

    return "<br>".join(formatted_intervals), latest_timestamp

# Загрузка кеша из файла
def load_cache():
    try:
        with open(CACHE_FILE, 'r') as f:
            cache_data = json.load(f)
            return {ip: (data, datetime.fromisoformat(timestamp)) for ip, (data, timestamp) in cache_data.items()}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# Сохранение кеша в файл
def save_cache(cache):
    serializable_cache = {}
    for ip, (data, timestamp) in cache.items():
        # Проверяем, чтобы все объекты datetime были преобразованы в строку ISO
        if isinstance(timestamp, datetime):
            timestamp = timestamp.isoformat()

       # Также проверяем, что latest_timestamp в data тоже в строке
        if isinstance(data["latest_timestamp"], datetime):
            data["latest_timestamp"] = data["latest_timestamp"].isoformat()

        try:
            timestamp = data["latest_timestamp"]
        except:
            pass

        serializable_cache[ip] = (data, timestamp)

    with open(CACHE_FILE, 'w') as f:
        json.dump(serializable_cache, f)

# Функция для получения информации о местоположении и провайдере с кешированием
def get_ip_info(ip, cache):
    current_time = datetime.now()

    # Проверка кеша: если данные есть и не истекли, возвращаем их
    if ip in cache:
        cached_data, timestamp = cache[ip]
        if current_time - timestamp < CACHE_EXPIRATION:
            intervals, latest_timestamp = group_timestamps(ip_time_dict[ip])
            cached_data["count"] = len(ip_time_dict[ip])
            cached_data["intervals"] = intervals
            cached_data["latest_timestamp"] = latest_timestamp
            cache[ip] = (cached_data, latest_timestamp)
            save_cache(cache)
            return cached_data

    # Запрос к сервису ipwhois.app, если данных нет в кеше или они устарели
    try:
        response = requests.get(f'https://ipwhois.app/json/{ip}')
        response.raise_for_status()
        info = response.json()
        country_code = info.get("country_code", "").lower()
        flag_url = f"https://flagcdn.com/16x12/{country_code}.png" if country_code else ""
        intervals, latest_timestamp = group_timestamps(ip_time_dict[ip])

        # Формируем данные для возврата
        ip_data = {
            "ip": ip,
            "city": info.get("city", "N/A"),
            "country": info.get("country", "N/A"),
            "flag_url": flag_url,
            "provider": info.get("isp", "N/A"),
            "count": len(ip_time_dict[ip]),
            "intervals": intervals,
            "latest_timestamp": latest_timestamp
        }

        # Обновляем кеш и сохраняем его в файл
        cache[ip] = (ip_data, latest_timestamp)
        save_cache(cache)
        return ip_data

    except requests.RequestException as e:
        print(f"Ошибка при получении данных для IP {ip}: {e}")
        return None

# Загрузка и инициализация кеша
cache = load_cache()


ip_info_list = [get_ip_info(ip, cache) for ip in ip_time_dict if ip_time_dict[ip]]
ip_info_list = [info for info in ip_info_list if info is not None]
if not ip_info_list:
    print("Не удалось получить информацию для IP-адресов.")
    sys.exit(0)

# Сортируем по убыванию количества вхождений и свежести последнего временного штампа
ip_info_list.sort(key=lambda x: (x["count"], x["latest_timestamp"]), reverse=True)

# Завершение таймера
end_time = time.time()
elapsed_time = end_time - start_time

# Формируем текущее время в GMT+3
current_time = datetime.now(timezone(timedelta(hours=3))).strftime('%Y-%m-%d %H:%M:%S')

# Создаем HTML-страницу с таблицей
html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IP Address Analysis</title>
<style>
    body {{
        font-family: Arial, sans-serif;
        margin: 0;
        padding: 0;
        background-color: #f4f7fa;
        color: #333;
    }}
    .container {{
        max-width: 1200px;
        margin: 20px auto;
        padding: 20px;
        background-color: #fff;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        border-radius: 8px;
    }}
    h2 {{
        text-align: center;
        color: #4CAF50;
        font-size: 24px;
        margin-bottom: 10px;
    }}
    .summary {{
        text-align: center;
        font-size: 14px;
        color: #555;
        margin-bottom: 20px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 10px;
    }}
    th, td {{
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #ddd;
    }}
    th {{
        background-color: #4CAF50;
        color: white;
    }}
    tr:nth-child(even) {{
        background-color: #f9f9f9;
    }}
    tr:hover {{
        background-color: #f1f1f1;
    }}
    .recent {{
        font-weight: bold;
        color: darkred;
    }}
    img {{
        vertical-align: middle;
        margin-right: 8px;
    }}
</style>
</head>
<body>
<div class="container">
<h2>IP Address Analysis (Last 2 Days)</h2>
<p>{current_time} LA: <b>{load_avg['1_min']}</b> {load_avg['5_min']} {load_avg['15_min']} RAM: <b>{memory_utilization}%</b> xray uptime: <b>{xray_uptime}</b> connections: <b>{network_connections['established']}</b> waiting: {network_connections['non_established']} generated in {elapsed_time:.2f} seconds</p>
<table>
    <tr>
        <th>IP Address</th>
        <th>Count</th>
        <th>City</th>
        <th>Country</th>
        <th>Provider</th>
        <th>Timestamps</th>
    </tr>
"""

# Заполняем таблицу данными IP-адресов
for info in ip_info_list:
    if info['count'] > 4:
        html_content += f"""
        <tr>
            <td>{info['ip']}</td>
            <td>{info['count']}</td>
            <td>{info['city']}</td>
            <td><img src="{info['flag_url']}" alt="{info['country']}" /> {info['country']}</td>
            <td>{info['provider']}</td>
            <td>{info['intervals']}</td>
        </tr>
        """

# Завершаем HTML-контент
html_content += """
</table>
</div>
</body>
</html>
"""

# Выводим HTML-контент
print(html_content)

# Сохранение кеша перед завершением работы программы
#save_cache(cache)