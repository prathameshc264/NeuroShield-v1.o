// NeuroShield AI Pipeline Simulation
// This module simulates the dual-engine AI pipeline (CNN-LSTM + GNN)
// with MITRE ATT&CK mapping, explainability, and trust validation.

import { Alert, DashboardStats, DeviceInfo, MitreStage, ThreatDataPoint } from "./types";

// ─── MITRE ATT&CK Techniques ───────────────────────────────────────────────
const MITRE_TECHNIQUES = [
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
  { id: "T1059", name: "Command & Scripting Interpreter", tactic: "Execution" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "Execution" },
  { id: "T1548", name: "Abuse Elevation Control", tactic: "Privilege Escalation" },
  { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion" },
  { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access" },
  { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
  { id: "T1560", name: "Archive Collected Data", tactic: "Collection" },
  { id: "T1041", name: "Exfiltration Over C2", tactic: "Exfiltration" },
  { id: "T1498", name: "Network Denial of Service", tactic: "Impact" },
  { id: "T1489", name: "Service Stop", tactic: "Impact" },
  { id: "T0855", name: "Unauthorized Command Message", tactic: "ICS Impair" },
  { id: "T0831", name: "Manipulation of Control", tactic: "ICS Impair" },
];

const MITRE_CHAIN: Record<string, { next: string; prob: number }> = {
  "Initial Access": { next: "Execution", prob: 82 },
  "Execution": { next: "Privilege Escalation", prob: 76 },
  "Privilege Escalation": { next: "Defense Evasion", prob: 71 },
  "Defense Evasion": { next: "Credential Access", prob: 68 },
  "Credential Access": { next: "Lateral Movement", prob: 88 },
  "Discovery": { next: "Lateral Movement", prob: 79 },
  "Lateral Movement": { next: "Collection", prob: 73 },
  "Collection": { next: "Exfiltration", prob: 85 },
  "Exfiltration": { next: "Impact", prob: 92 },
  "Impact": { next: "ICS Impair", prob: 60 },
  "ICS Impair": { next: "Impact", prob: 50 },
};

// ─── IIoT Devices ──────────────────────────────────────────────────────────
const DEVICES: DeviceInfo[] = [
  { id: "PLC-001", name: "Primary PLC Controller", type: "PLC", status: "online", risk_level: "Low", last_seen: "", alert_count: 0 },
  { id: "PLC-002", name: "Backup PLC Controller", type: "PLC", status: "online", risk_level: "Low", last_seen: "", alert_count: 0 },
  { id: "SCADA-01", name: "SCADA Master Server", type: "SCADA", status: "online", risk_level: "Low", last_seen: "", alert_count: 0 },
  { id: "HMI-01", name: "Operator HMI Panel", type: "HMI", status: "online", risk_level: "Low", last_seen: "", alert_count: 0 },
  { id: "RTU-01", name: "Remote Terminal Unit A", type: "RTU", status: "online", risk_level: "Low", last_seen: "", alert_count: 0 },
  { id: "GW-X1", name: "Edge Gateway X1", type: "Gateway", status: "online", risk_level: "Low", last_seen: "", alert_count: 0 },
  { id: "ROBO-A", name: "Robotic Arm Assembly", type: "Robot", status: "online", risk_level: "Low", last_seen: "", alert_count: 0 },
  { id: "SENSOR-T1", name: "Temperature Sensor Array", type: "Sensor", status: "online", risk_level: "Low", last_seen: "", alert_count: 0 },
];

const ASSET_CRITICALITY: Record<string, number> = {
  "SCADA": 5, "PLC": 4, "RTU": 4, "HMI": 3, "Robot": 3, "Gateway": 2, "Sensor": 1,
};

const USERS = ["operator_1", "admin", "maintenance", "system", "eng_supervisor", "unknown", "root"];

const FEATURE_SETS: Record<string, { feature: string; weight: number }[]> = {
  "CNN-LSTM": [
    { feature: "packet_length_mean", weight: 0 },
    { feature: "flow_duration", weight: 0 },
    { feature: "fwd_pkt_rate", weight: 0 },
    { feature: "bwd_pkt_rate", weight: 0 },
    { feature: "syn_flag_count", weight: 0 },
    { feature: "payload_entropy", weight: 0 },
  ],
  "GNN": [
    { feature: "node_degree_centrality", weight: 0 },
    { feature: "api_call_frequency", weight: 0 },
    { feature: "process_spawn_depth", weight: 0 },
    { feature: "comm_graph_anomaly", weight: 0 },
    { feature: "privilege_escalation_score", weight: 0 },
  ],
};

// ─── Seeded Random (deterministic per time window) ──────────────────────
function seededRandom(seed: number): () => number {
  let s = seed;
  return () => {
    s = (s * 16807 + 0) % 2147483647;
    return (s - 1) / 2147483646;
  };
}

// ─── Alert Generator ────────────────────────────────────────────────────
export function generateAlerts(count: number, offsetSeed: number = 0): Alert[] {
  const now = Date.now();
  const rand = seededRandom(now + offsetSeed);
  const alerts: Alert[] = [];

  for (let i = 0; i < count; i++) {
    const device = DEVICES[Math.floor(rand() * DEVICES.length)];
    const technique = MITRE_TECHNIQUES[Math.floor(rand() * MITRE_TECHNIQUES.length)];
    const engine: "CNN-LSTM" | "GNN" | "Ensemble" = rand() > 0.6 ? "Ensemble" : rand() > 0.5 ? "GNN" : "CNN-LSTM";
    const featureKey = engine === "Ensemble" ? (rand() > 0.5 ? "CNN-LSTM" : "GNN") : engine;

    const criticality = ASSET_CRITICALITY[device.type] || 1;
    const rawConf = 0.55 + rand() * 0.44;
    const combinedScore = rawConf * (criticality / 5);

    let severity: Alert["severity"];
    if (combinedScore > 0.8) severity = "Critical";
    else if (combinedScore > 0.6) severity = "High";
    else if (combinedScore > 0.4) severity = "Medium";
    else severity = "Low";

    const chainEntry = MITRE_CHAIN[technique.tactic];
    const trustScore = Math.round(75 + rand() * 24);

    const features = FEATURE_SETS[featureKey].map(f => ({
      feature: f.feature,
      weight: Math.round((0.3 + rand() * 0.7) * 100) / 100,
    })).sort((a, b) => b.weight - a.weight);

    alerts.push({
      id: `NS-${now}-${i}-${Math.floor(rand() * 9999)}`,
      timestamp: new Date(now - Math.floor(rand() * 30000)).toISOString(),
      device_id: device.id,
      device_type: device.type,
      user: USERS[Math.floor(rand() * USERS.length)],
      is_anomaly: true,
      severity,
      trust_score: trustScore,
      mitre_stage: `${technique.id} - ${technique.name}`,
      mitre_tactic: technique.tactic,
      next_stage_pred: chainEntry ? chainEntry.next : "Impact",
      next_stage_probability: chainEntry ? chainEntry.prob + Math.floor(rand() * 10 - 5) : 50,
      explanation: {
        feature_importance: features,
        method: engine === "Ensemble" ? "SHAP + LIME (Ensemble)" : engine === "CNN-LSTM" ? "SHAP (DeepExplainer)" : "GNNExplainer + LIME",
        summary: generateExplanationSummary(technique, device, features[0]),
      },
      engine_source: engine,
      raw_confidence: Math.round(rawConf * 100) / 100,
    });
  }

  return alerts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

function generateExplanationSummary(
  technique: { id: string; name: string; tactic: string },
  device: DeviceInfo,
  topFeature: { feature: string; weight: number }
): string {
  const summaries = [
    `Anomalous ${topFeature.feature} (weight: ${topFeature.weight}) detected on ${device.name} suggests ${technique.tactic} activity consistent with ${technique.id}.`,
    `Device ${device.id} exhibited behavior patterns matching ${technique.name}. Primary indicator: ${topFeature.feature} deviated ${Math.round(topFeature.weight * 100)}% from baseline.`,
    `The ${device.type} asset "${device.name}" triggered ${technique.id} detection. Feature ${topFeature.feature} was the strongest contributor to the classification.`,
  ];
  return summaries[Math.floor(Math.random() * summaries.length)];
}

// ─── Stats Generator ────────────────────────────────────────────────────
export function generateStats(): DashboardStats {
  const rand = seededRandom(Math.floor(Date.now() / 60000)); // changes every minute
  return {
    total_events_24h: 145000 + Math.floor(rand() * 20000),
    total_alerts: 47 + Math.floor(rand() * 30),
    critical_count: 3 + Math.floor(rand() * 5),
    high_count: 8 + Math.floor(rand() * 8),
    medium_count: 15 + Math.floor(rand() * 12),
    low_count: 20 + Math.floor(rand() * 15),
    devices_monitored: DEVICES.length,
    avg_trust_score: 82 + Math.floor(rand() * 12),
    detection_rate: 96.2 + rand() * 3,
    false_positive_rate: 1.2 + rand() * 2.5,
  };
}

// ─── Threat Timeline Generator ──────────────────────────────────────────
export function generateThreatTimeline(points: number = 24): ThreatDataPoint[] {
  const rand = seededRandom(Math.floor(Date.now() / 30000));
  const data: ThreatDataPoint[] = [];
  const now = new Date();

  for (let i = points - 1; i >= 0; i--) {
    const t = new Date(now.getTime() - i * 3600000);
    const critical = Math.floor(rand() * 4);
    const high = Math.floor(rand() * 8);
    const medium = Math.floor(rand() * 12);
    const low = Math.floor(rand() * 15);
    data.push({
      time: t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      critical, high, medium, low,
      total: critical + high + medium + low,
    });
  }
  return data;
}

// ─── MITRE Attack Chain ─────────────────────────────────────────────────
export function generateMitreChain(alerts: Alert[]): MitreStage[] {
  const tactics = [
    "Initial Access", "Execution", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Exfiltration", "Impact", "ICS Impair",
  ];

  const tacticCounts: Record<string, number> = {};
  alerts.forEach(a => {
    tacticCounts[a.mitre_tactic] = (tacticCounts[a.mitre_tactic] || 0) + 1;
  });

  return tactics.map((tactic, i) => ({
    id: `stage-${i}`,
    name: tactic,
    tactic,
    count: tacticCounts[tactic] || 0,
    active: (tacticCounts[tactic] || 0) > 0,
  }));
}

// ─── Device Status ──────────────────────────────────────────────────────
export function generateDeviceStatus(alerts: Alert[]): DeviceInfo[] {
  const deviceAlerts: Record<string, { count: number; maxSeverity: string }> = {};
  alerts.forEach(a => {
    if (!deviceAlerts[a.device_id]) deviceAlerts[a.device_id] = { count: 0, maxSeverity: "Low" };
    deviceAlerts[a.device_id].count++;
    const sevOrder = ["Low", "Medium", "High", "Critical"];
    if (sevOrder.indexOf(a.severity) > sevOrder.indexOf(deviceAlerts[a.device_id].maxSeverity)) {
      deviceAlerts[a.device_id].maxSeverity = a.severity;
    }
  });

  return DEVICES.map(d => ({
    ...d,
    last_seen: new Date().toISOString(),
    alert_count: deviceAlerts[d.id]?.count || 0,
    status: deviceAlerts[d.id]?.maxSeverity === "Critical" ? "compromised" as const : "online" as const,
    risk_level: (deviceAlerts[d.id]?.maxSeverity as DeviceInfo["risk_level"]) || "Low",
  }));
}
