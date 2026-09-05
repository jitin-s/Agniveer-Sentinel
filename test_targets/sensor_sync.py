import sys
import subprocess
import re

def ping_sensor(sensor_ip):
    print(f"[SURVEILLANCE SYNC] Connecting to Border Sensor node at: {sensor_ip}")
    
    # SECURE FIX: Input validation + safe argument-separated process execution without shell
    is_valid_ip = re.match(r"^[a-zA-Z0-9.-]+$", sensor_ip)
    if not is_valid_ip or ";" in sensor_ip or "&" in sensor_ip or "|" in sensor_ip:
        print("[SURVEILLANCE SYNC] [GUARD ALERT] Malicious command characters detected in sensor IP. Aborting.")
        return
        
    cmd = ["ping", "-n", "1", sensor_ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        exit_code = proc.returncode
    except Exception:
        exit_code = 1
    
    if exit_code == 0:
        print("[SURVEILLANCE SYNC] Status check: ONLINE")
    else:
        print("[SURVEILLANCE SYNC] Status check: OFFLINE")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sensor_sync.py <sensor_ip_or_address>")
        sys.exit(1)
        
    sensor_input = sys.argv[1]
    ping_sensor(sensor_input)