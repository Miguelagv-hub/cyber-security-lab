import re
from collections import Counter
import argparse

def parse_failed_logins(log_file_path, threshold=3):
    """Analiza un archivo de logs en busca de intentos fallidos de inicio de sesión."""
    failed_ips = []
    pattern = re.compile(r'Failed login attempt.*from\s+([\d\.]+)')
    
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    failed_ips.append(match.group(1))
    except FileNotFoundError:
        print(f"[!] Error: El archivo '{log_file_path}' no existe.")
        return {}

    ip_counts = Counter(failed_ips)
    return {ip: count for ip, count in ip_counts.items() if count >= threshold}

if __name__ == "__main__":
    # Configuración de argumentos de la terminal (CLI)
    parser = argparse.ArgumentParser(description="Analizador de logs de autenticación para detección de fuerza bruta.")
    parser.add_argument("--log", type=str, default="logs/auth_simulated.log", help="Ruta del archivo de log a analizar")
    parser.add_argument("--threshold", type=int, default=3, help="Número mínimo de intentos fallidos para activar la alerta")
    
    args = parser.parse_args()

    print(f"[*] Analizando logs en: {args.log} (Umbral: {args.threshold} intentos)...\n")
    alerts = parse_failed_logins(args.log, threshold=args.threshold)
    
    if alerts:
        print("[!] ¡ALERTA DE SEGURIDAD! Posible ataque de fuerza bruta detectado:")
        for ip, count in alerts.items().sort(key=lambda x: x[1], reverse=True) if hasattr(alerts.items(), 'sort') else alerts.items():
            print(f" -> IP sospechosa: {ip} | Intentos fallidos: {count}")
    else:
        print("[+] No se detectó actividad sospechosa que supere el umbral.")