import sys
import os

def ping_sensor(sensor_ip):
    print(f"[SURVEILLANCE SYNC] Connecting to Border Sensor node at: {sensor_ip}")
    
    # Vulnerability: Shell command execution via string concatenation of user input.
    # Allows command injection (e.g. passing "127.0.0.1; whoami" or "127.0.0.1 & echo VULNERABLE").
    cmd = f"ping -n 1 {sensor_ip}"
    
    # Executing the command directly in shell
    exit_code = os.system(cmd)
    
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