"""
NeuroShield API Server
FastAPI server handling:
  - WebSocket real-time broadcast (`/ws`)
  - Telemetry Ingestion (`/api/v1/telemetry`)
  - Threat History & Metrics (`/api/v1/alerts`, `/api/v1/stats`)
  - Realistic Attack Injection Endpoints (`/api/v1/simulate/*`)
"""

import asyncio
from datetime import datetime, timezone
import json
import random
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ai_pipeline import neuroshield_pipeline

app = FastAPI(
    title="NeuroShield AI Core API",
    version="2.0.0",
    description="Dual-Core Explainable AI Framework for IIoT Attack Detection & Correlation",
)

# Enable CORS for Next.js and external frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── REAL-TIME WEBSOCKET CONNECTION MANAGER ─────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        serialized = json.dumps(message)
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(serialized)
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead)

manager = ConnectionManager()

# In-memory storage of recent alert buffer (last 100 alerts)
ALERT_BUFFER: List[Dict[str, Any]] = []

def record_alert(alert: Dict[str, Any]):
    global ALERT_BUFFER
    ALERT_BUFFER.insert(0, alert)
    if len(ALERT_BUFFER) > 100:
        ALERT_BUFFER = ALERT_BUFFER[:100]


# ─── API MODELS ─────────────────────────────────────────────────────────────
class TelemetryPayload(BaseModel):
    device_id: str = "PLC_001"
    user: Optional[str] = "operator_1"
    protocol: Optional[str] = "Modbus TCP"
    packet_rate: Optional[float] = None
    byte_entropy: Optional[float] = None
    inter_arrival_ms: Optional[float] = None
    command_frequency: Optional[float] = None
    flag_variance: Optional[float] = None
    attack_type: Optional[str] = None
    technique_id: Optional[str] = None
    is_malicious_simulation: Optional[bool] = False


# ─── CORE ENDPOINTS ─────────────────────────────────────────────────────────
@app.get("/")
def read_root():
    return {
        "framework": "NeuroShield Dual-Core Explainable AI",
        "status": "Operational",
        "engines": ["Engine A (CNN-LSTM)", "Engine B (GNN Correlation)", "XAI Attribution"],
        "active_clients": len(manager.active_connections),
        "total_alerts_logged": len(ALERT_BUFFER),
    }

@app.get("/api/v1/alerts")
def get_recent_alerts(limit: int = 25):
    """Returns recent alerts processed by the Dual-Core pipeline."""
    return {
        "status": "success",
        "count": min(len(ALERT_BUFFER), limit),
        "alerts": ALERT_BUFFER[:limit],
    }

@app.get("/api/v1/stats")
def get_dashboard_stats():
    """Calculates live statistical metrics for SOC dashboard."""
    critical_count = sum(1 for a in ALERT_BUFFER if a.get("severity") == "Critical")
    high_count = sum(1 for a in ALERT_BUFFER if a.get("severity") == "High")
    medium_count = sum(1 for a in ALERT_BUFFER if a.get("severity") == "Medium")
    low_count = sum(1 for a in ALERT_BUFFER if a.get("severity") == "Low")

    devices_status = [
        {"id": "SCADA_01", "name": "SCADA Master Server", "type": "SCADA", "status": "online", "risk": "Critical" if critical_count > 3 else "Low"},
        {"id": "PLC_001", "name": "Robotics PLC Controller", "type": "PLC", "status": "online", "risk": "High" if high_count > 2 else "Low"},
        {"id": "PLC_002", "name": "Assembly Line PLC", "type": "PLC", "status": "online", "risk": "Low"},
        {"id": "HMI_01", "name": "Control Room HMI", "type": "HMI", "status": "online", "risk": "Medium"},
        {"id": "Robotic_Arm_A", "name": "Manufacturing Robotic Arm", "type": "Robot", "status": "online", "risk": "Low"},
        {"id": "Gateway_Edge", "name": "IT-OT Security Gateway", "type": "Gateway", "status": "online", "risk": "Low"},
    ]

    return {
        "status": "success",
        "stats": {
            "total_alerts": len(ALERT_BUFFER),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "active_devices": len(devices_status),
            "mean_trust_score": round(sum(a.get("trust_score", 95) for a in ALERT_BUFFER) / max(1, len(ALERT_BUFFER)), 1) if ALERT_BUFFER else 95.0,
        },
        "devices": devices_status,
        "mitre_active_tactics": list(set(a.get("mitre_tactic", "Discovery") for a in ALERT_BUFFER[:10])),
    }

@app.post("/api/v1/telemetry")
async def ingest_telemetry(payload: TelemetryPayload):
    """Direct ingestion endpoint for live IIoT sensors or PCAP parsers."""
    result = neuroshield_pipeline.process_telemetry(payload.dict())
    if result.get("is_anomaly") or result.get("severity") != "Low":
        record_alert(result)
        await manager.broadcast(result)
    return {"status": "success", "processed_result": result}


# ─── ATTACK INJECTION & SIMULATION ENDPOINTS ────────────────────────────────
@app.post("/api/v1/simulate/modbus_injection")
async def simulate_modbus_injection():
    """Simulates rogue Modbus TCP function code injection targeting PLC_001."""
    telemetry = {
        "device_id": "PLC_001",
        "user": "external_adversary",
        "protocol": "Modbus TCP",
        "command_frequency": random.uniform(35.0, 75.0),
        "byte_entropy": 7.4,
        "attack_type": "modbus_injection",
        "technique_id": "T0855",
        "is_malicious_simulation": True,
    }
    result = neuroshield_pipeline.process_telemetry(telemetry)
    record_alert(result)
    await manager.broadcast(result)
    return {"status": "attack_injected", "attack": "Modbus Unauthorized Command Injection (T0855)", "alert": result}

@app.post("/api/v1/simulate/ddos_scada")
async def simulate_ddos_scada():
    """Simulates high-frequency distributed denial of service targeting SCADA_01."""
    telemetry = {
        "device_id": "SCADA_01",
        "user": "botnet_cluster",
        "protocol": "TCP SYN Flood",
        "packet_rate": random.uniform(950.0, 1600.0),
        "inter_arrival_ms": 0.25,
        "flag_variance": 0.95,
        "attack_type": "ddos_flood",
        "technique_id": "T1498",
        "is_malicious_simulation": True,
    }
    result = neuroshield_pipeline.process_telemetry(telemetry)
    record_alert(result)
    await manager.broadcast(result)
    return {"status": "attack_injected", "attack": "SCADA Master Network DoS (T1498)", "alert": result}

@app.post("/api/v1/simulate/lateral_movement")
async def simulate_lateral_movement():
    """Simulates credential abuse and lateral movement from HMI_01 to Robotic_Arm_A."""
    telemetry = {
        "device_id": "HMI_01",
        "user": "compromised_operator",
        "protocol": "Remote Shell / VNC",
        "command_frequency": 18.0,
        "byte_entropy": 6.8,
        "attack_type": "recon_scan",
        "technique_id": "T1021",
        "is_malicious_simulation": True,
    }
    result = neuroshield_pipeline.process_telemetry(telemetry)
    record_alert(result)
    await manager.broadcast(result)
    return {"status": "attack_injected", "attack": "Lateral Movement via Remote Services (T1021)", "alert": result}


# ─── REAL-TIME WEBSOCKET STREAM ─────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial recent state to client immediately upon connection
        if ALERT_BUFFER:
            for alert in ALERT_BUFFER[:5]:
                await websocket.send_text(json.dumps(alert))
        while True:
            # Listen for client heartbeat/trigger messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong", "time": datetime.now(timezone.utc).isoformat()}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ─── BACKGROUND INDUSTRIAL TELEMETRY STREAM ─────────────────────────────────
async def continuous_industrial_stream():
    """Generates continuous realistic plant telemetry with periodic anomalies."""
    devices = ["PLC_001", "PLC_002", "SCADA_01", "HMI_01", "Robotic_Arm_A", "Gateway_Edge"]
    users = ["op_wright", "maint_tech", "sys_daemon", "eng_admin"]

    while True:
        await asyncio.sleep(random.uniform(2.5, 4.5))
        # 30% chance of background stochastic anomaly for live monitoring realism
        is_attack = random.random() < 0.30
        device = random.choice(devices)

        data = {
            "device_id": device,
            "user": random.choice(users),
            "protocol": "Modbus TCP" if "PLC" in device else ("OPC-UA" if "SCADA" in device else "EtherNet/IP"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_malicious_simulation": is_attack,
        }
        if is_attack:
            data["attack_type"] = random.choice(["modbus_injection", "ddos_flood", "recon_scan"])

        result = neuroshield_pipeline.process_telemetry(data)
        if result.get("is_anomaly"):
            record_alert(result)
            await manager.broadcast(result)


@app.on_event("startup")
async def on_startup():
    # Pre-seed 6 initial realistic alerts so dashboard has rich initial data
    devices = ["SCADA_01", "PLC_001", "HMI_01", "Robotic_Arm_A"]
    for d in devices:
        seed_data = {
            "device_id": d,
            "user": "sec_auditor",
            "protocol": "Modbus TCP",
            "is_malicious_simulation": True,
            "attack_type": random.choice(["modbus_injection", "ddos_flood", "recon_scan"]),
        }
        res = neuroshield_pipeline.process_telemetry(seed_data)
        record_alert(res)

    # Launch background continuous stream
    asyncio.create_task(continuous_industrial_stream())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
