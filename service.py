import time
import subprocess
import sys

INTERVAL_SECONDS = 15 * 60

if __name__ == "__main__":
    while True:
        print("=== IOC updater pass start ===")
        try:
            subprocess.run([sys.executable, "run_once.py"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] run_once failed: {e}")
        print("=== IOC updater pass end ===")
        time.sleep(INTERVAL_SECONDS)
