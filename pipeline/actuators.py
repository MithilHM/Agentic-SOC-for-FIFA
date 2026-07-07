import os
import json
import time
import uuid
import logging
import redis
import requests

logger = logging.getLogger(__name__)

r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

def _log_action(action_type: str, target: str, incident_id: str, status: str, message: str, requires_approval: bool = False):
    action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
    action_data = {
        "action_id": action_id,
        "action_type": action_type,
        "target": target,
        "incident_id": incident_id,
        "status": status,  # "pending_approval", "executed", "rejected"
        "message": message,
        "timestamp": time.time(),
        "requires_approval": requires_approval
    }
    
    # Store action data
    r.set(f"action:{action_id}", json.dumps(action_data))
    # Keep track of recent actions in a list (e.g. max 1000)
    r.lpush("soc:actions", action_id)
    r.ltrim("soc:actions", 0, 999)
    
    # Publish for live dashboard updates
    r.publish("actions.live", action_id)
    
    return action_data

def block_ip(ip_address: str, incident_id: str) -> dict:
    """Simulate blocking an IP address."""
    msg = f"Blocked IP {ip_address} on edge firewall."
    logger.info(msg)
    return _log_action("block_ip", ip_address, incident_id, "executed", msg)

def isolate_device(device_id: str, incident_id: str) -> dict:
    """Simulate isolating a device via EDR."""
    msg = f"Isolated device {device_id} from network."
    logger.info(msg)
    return _log_action("isolate_device", device_id, incident_id, "executed", msg)

def suspend_user(user_id: str, incident_id: str) -> dict:
    """Simulate suspending a user account."""
    msg = f"Suspended user account {user_id}."
    logger.info(msg)
    return _log_action("suspend_user", user_id, incident_id, "executed", msg)

def reset_credentials(user_id: str, incident_id: str) -> dict:
    """Simulate resetting a user's credentials."""
    msg = f"Triggered password reset for {user_id}."
    logger.info(msg)
    return _log_action("reset_credentials", user_id, incident_id, "executed", msg)

def request_human_approval(action_type: str, target: str, incident_id: str, reason: str) -> dict:
    """Request human approval for a critical action."""
    msg = f"Approval required to {action_type} on {target}: {reason}"
    logger.info(msg)
    return _log_action(action_type, target, incident_id, "pending_approval", msg, requires_approval=True)

def _execute_action_on_sandbox(action_type: str, target: str):
    if action_type == "block_ip":
        try:
            sandbox_url = f"http://sandbox:8000/admin/block?target_ip={target}"
            resp = requests.post(sandbox_url, timeout=5)
            logger.info(f"Sandbox block API response: {resp.status_code}")
        except Exception as e:
            logger.error(f"Failed to reach sandbox for action {action_type}: {e}")

def approve_action(action_id: str) -> dict:
    """Mark a pending action as executed."""
    raw = r.get(f"action:{action_id}")
    if not raw:
        return {"status": "error", "message": "Action not found"}
    action = json.loads(raw)
    if action["status"] != "pending_approval":
        return {"status": "error", "message": "Action not pending approval"}
    
    action["status"] = "executed"
    action["message"] = f"Approved: {action['message']} (Enforced on Sandbox)"
    r.set(f"action:{action_id}", json.dumps(action))
    r.publish("actions.live", action_id)
    
    _execute_action_on_sandbox(action["action_type"], action["target"])
    
    return action

def reject_action(action_id: str) -> dict:
    """Mark a pending action as rejected."""
    raw = r.get(f"action:{action_id}")
    if not raw:
        return {"status": "error", "message": "Action not found"}
    action = json.loads(raw)
    if action["status"] != "pending_approval":
        return {"status": "error", "message": "Action not pending approval"}
    
    action["status"] = "rejected"
    action["message"] = f"Rejected: {action['message']}"
    r.set(f"action:{action_id}", json.dumps(action))
    r.publish("actions.live", action_id)
    return action
