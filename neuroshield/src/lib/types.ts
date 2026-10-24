// NeuroShield Type Definitions

export interface Alert {
  id: string;
  timestamp: string;
  device_id: string;
  device_type: string;
  user: string;
  is_anomaly: boolean;
  severity: "Critical" | "High" | "Medium" | "Low";
  trust_score: number;
  mitre_stage: string;
  mitre_tactic: string;
  next_stage_pred: string;
  next_stage_probability: number;
  explanation: {
    feature_importance: { feature: string; weight: number }[];
    method: string;
    summary: string;
  };
  engine_source: "CNN-LSTM" | "GNN" | "Ensemble";
  raw_confidence: number;
}

export interface DashboardStats {
  total_events_24h: number;
  total_alerts: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  devices_monitored: number;
  avg_trust_score: number;
  detection_rate: number;
  false_positive_rate: number;
}

export interface ThreatDataPoint {
  time: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface MitreStage {
  id: string;
  name: string;
  tactic: string;
  count: number;
  active: boolean;
}

export interface DeviceInfo {
  id: string;
  name: string;
  type: string;
  status: "online" | "compromised" | "offline";
  risk_level: "Critical" | "High" | "Medium" | "Low";
  last_seen: string;
  alert_count: number;
}
