import re
from collections import Counter

def parse_failed_logins(log_file_path, threshold=3):
    failed_ips = []
    pattern = re.compile(r'Failed login attempt.*from\s+([\d\.]+)')

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    failed_ips.append(match.group(1))
    except FileNotFoundError:
        print(f"Error: El archivo {log_file_path} no existe.")
        return {}

    ip_counts = Counter(failed_ips)
    return {ip: count for ip, count in ip_counts.items() if count >= threshold}

if __name__ == "__main__":
    log_path = "logs/auth_simulated.log"
    print(f"Analizando logs en: {log_path}...\n")
    alerts = parse_failed_logins(log_path)

    if alerts:
        print("[!] ALERTA: Posible ataque de fuerza bruta detectado:")
        for ip, count in alerts.items():
            print(f" -> IP: {ip} con {count} intentos fallidos.")
    else:
        print("[+] No se detectó actividad sospechosa.")