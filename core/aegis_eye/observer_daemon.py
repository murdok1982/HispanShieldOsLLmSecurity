"""
AegisEye: Continuous Observer Daemon
Scrapea constantemente la situaciÃ³n de memoria, cpu, logs crÃ­ticos nativos de Linux y estado del trÃ¡fico.
Crea un 'Memory Snapshot' que el Orchestrator de HispanShield OS LLmSecurity consume para proveer Ground Truth al LLM.
"""
import psutil
import json
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [AegisEye] - %(message)s')

def capture_system_snapshot():
    # 1. Uso bÃ¡sico CPU y RAM
    mem = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=1)
    
    # 2. Conexiones vivas (top 5 para bajo overhead)
    connections = psutil.net_connections(kind='inet')
    active_conns = [f"{c.laddr.ip}:{c.laddr.port} -> {c.raddr.ip if c.raddr else 'NONE'} ({c.status})" 
                    for c in connections if c.status == 'ESTABLISHED'][:5]
    
    # Este snapshot se escribirÃ­a en un Tmpfs (memoria RAM) o socket 
    # para que el Orchestrator lo lea en < 1ms
    snapshot = {
        "timestamp": time.time(),
        "memory_used_mb": mem.used / (1024 * 1024),
        "memory_percent": mem.percent,
        "cpu_load_percent": cpu,
        "active_network_flows": active_conns,
        "health_status": "NORMAL" if cpu < 85 else "HIGH_LOAD"
    }
    
    return snapshot

def observer_loop():
    logging.info("Iniciando AegisEye. Monitoreo pasivo del ring0 / user-space activo.")
    while True:
        try:
            snapshot = capture_system_snapshot()
            # En un entorno real usamos archivos IPC o named pipes
            with open("/opt/HispanShield OS LLmSecurity/core/data/aegis_eye.json", "w") as f:
                json.dump(snapshot, f)
            time.sleep(2)
        except Exception as e:
            logging.error(f"Falla de captura: {e}")
            time.sleep(5)

if __name__ == "__main__":
    observer_loop()
