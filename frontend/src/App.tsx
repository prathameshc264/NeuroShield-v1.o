import React, { useEffect, useState, useRef } from 'react';
import { Activity, ShieldAlert, Cpu, Network, Zap, Crosshair, ArrowRight } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface Alert {
  timestamp: string;
  device_id: string;
  user: string;
  is_anomaly: boolean;
  severity: string;
  trust_score: number;
  mitre_stage: string;
  next_stage_pred: string;
  explanation: any;
}

const severityColors = {
  Critical: 'text-neuro-critical bg-neuro-critical/10 border-neuro-critical',
  High: 'text-neuro-high bg-neuro-high/10 border-neuro-high',
  Medium: 'text-neuro-medium bg-neuro-medium/10 border-neuro-medium',
  Low: 'text-neuro-low bg-neuro-low/10 border-neuro-low',
};

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connectionStatus, setConnectionStatus] = useState('Connecting...');
  
  // Data for chart
  const [chartData, setChartData] = useState<{time: string, risk: number}[]>([]);

  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8000/ws');
    
    ws.onopen = () => {
      setConnectionStatus('Connected to AI Core');
    };
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data) as Alert;
      if (data.is_anomaly) {
        setAlerts(prev => [data, ...prev].slice(0, 15)); // Keep last 15 alerts
        
        setChartData(prev => {
          const newData = [...prev, {
            time: new Date().toLocaleTimeString(),
            risk: data.severity === 'Critical' ? 100 : data.severity === 'High' ? 75 : data.severity === 'Medium' ? 50 : 25
          }];
          return newData.slice(-20); // Keep last 20 data points
        });
      }
    };
    
    ws.onclose = () => {
      setConnectionStatus('Disconnected. Reconnecting...');
    };

    return () => ws.close();
  }, []);

  return (
    <div className="min-h-screen bg-neuro-dark text-slate-200 p-6 flex flex-col font-sans">
      
      {/* Header */}
      <header className="flex justify-between items-center mb-8 pb-4 border-b border-slate-700/50">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-8 h-8 text-neuro-accent animate-pulse" />
          <h1 className="text-2xl font-bold tracking-wider text-white">
            NeuroShield <span className="text-neuro-accent">SOC</span>
          </h1>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-4 py-2 rounded-full bg-slate-800/50 border border-slate-700">
            <Activity className="w-4 h-4 text-emerald-400" />
            <span className="text-sm font-medium">{connectionStatus}</span>
          </div>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1">
        
        {/* Main Feed */}
        <div className="lg:col-span-2 flex flex-col gap-6">
          
          {/* Chart Widget */}
          <div className="glass-panel p-5 h-64 flex flex-col">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Network className="w-5 h-5 text-neuro-accent" />
              Real-Time Threat Velocity
            </h2>
            <div className="flex-1 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
                  <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} />
                  <YAxis stroke="#94a3b8" fontSize={12} domain={[0, 100]} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569' }}
                    itemStyle={{ color: '#38bdf8' }}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="risk" 
                    stroke="#ef4444" 
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 8, fill: '#ef4444' }}
                    isAnimationActive={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Active Alerts Table */}
          <div className="glass-panel p-5 flex-1 flex flex-col overflow-hidden">
             <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Zap className="w-5 h-5 text-neuro-accent" />
              Live IT-OT Attack Chain Detections
            </h2>
            <div className="overflow-y-auto pr-2">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-700 text-sm text-slate-400 uppercase tracking-wider">
                    <th className="pb-3 font-medium">Time</th>
                    <th className="pb-3 font-medium">Asset</th>
                    <th className="pb-3 font-medium">Severity</th>
                    <th className="pb-3 font-medium">MITRE Stage</th>
                    <th className="pb-3 font-medium">Trust Score</th>
                  </tr>
                </thead>
                <tbody className="text-sm">
                  {alerts.map((alert, i) => (
                    <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 text-slate-400">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-3 font-medium flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-slate-500" />
                        {alert.device_id}
                      </td>
                      <td className="py-3">
                        <span className={`px-2 py-1 rounded text-xs font-semibold border ${severityColors[alert.severity as keyof typeof severityColors] || severityColors.Low}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 text-slate-300">
                        {alert.mitre_stage}
                      </td>
                      <td className="py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-2 bg-slate-700 rounded-full overflow-hidden">
                            <div 
                              className="h-full bg-neuro-accent" 
                              style={{ width: `${alert.trust_score}%` }} 
                            />
                          </div>
                          <span className="text-xs text-slate-400">{alert.trust_score}%</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {alerts.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-500">
                        Monitoring IT-OT telemetry... No anomalies detected.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Predictive Threat Analysis */}
        <div className="glass-panel p-5 flex flex-col h-full">
          <h2 className="text-lg font-semibold mb-6 flex items-center gap-2 border-b border-slate-700 pb-4">
            <Crosshair className="w-5 h-5 text-neuro-critical" />
            Predictive Threat Analysis
          </h2>
          
          {alerts.length > 0 ? (
            <div className="flex flex-col gap-6">
              <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
                <h3 className="text-sm text-slate-400 mb-1 uppercase tracking-wider font-semibold">Correlated Incident</h3>
                <p className="text-white font-medium text-lg mb-2">Cross-Domain Lateral Movement</p>
                <div className="flex flex-col gap-3 mt-4">
                  <div className="flex items-start gap-3">
                    <div className="w-6 h-6 rounded-full bg-slate-700 flex items-center justify-center text-xs shrink-0 mt-0.5">1</div>
                    <div>
                      <p className="text-sm text-slate-300">{alerts[0].mitre_stage}</p>
                      <p className="text-xs text-slate-500">Current observed behavior</p>
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-600 ml-1" />
                  <div className="flex items-start gap-3">
                    <div className="w-6 h-6 rounded-full bg-neuro-accent/20 border border-neuro-accent text-neuro-accent flex items-center justify-center text-xs shrink-0 mt-0.5">2</div>
                    <div>
                      <p className="text-sm font-semibold text-neuro-accent">{alerts[0].next_stage_pred}</p>
                      <p className="text-xs text-slate-400">Predicted Next Stage</p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700 flex-1">
                <h3 className="text-sm text-slate-400 mb-3 uppercase tracking-wider font-semibold">Explainability Engine</h3>
                <div className="space-y-4">
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Most Influential Features (SHAP)</p>
                    {alerts[0].explanation?.feature_importance?.map((f: any, idx: number) => (
                      <div key={idx} className="flex justify-between items-center mb-1">
                        <span className="text-sm font-mono text-slate-300">{f.feature}</span>
                        <div className="flex items-center gap-2 w-1/2">
                          <div className="h-1.5 flex-1 bg-slate-700 rounded-full overflow-hidden">
                            <div className="h-full bg-emerald-500" style={{ width: `${f.weight * 100}%` }} />
                          </div>
                          <span className="text-xs text-slate-400">{(f.weight * 100).toFixed(0)}%</span>
                        </div>
                      </div>
                    ))}
                    {!alerts[0].explanation?.feature_importance && (
                      <p className="text-sm text-slate-400 italic">No feature importance data available.</p>
                    )}
                  </div>
                  
                  <div className="mt-4 pt-4 border-t border-slate-700">
                    <p className="text-xs text-slate-500 mb-1">Trust Validator</p>
                    <div className="flex justify-between items-center bg-slate-900/50 p-2 rounded">
                      <span className="text-sm text-slate-300">Perturbation Score</span>
                      <span className={`text-sm font-bold ${alerts[0].trust_score > 80 ? 'text-emerald-400' : 'text-amber-400'}`}>
                        {alerts[0].trust_score}% Reliable
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
             <div className="flex flex-col items-center justify-center flex-1 text-center opacity-50">
               <Crosshair className="w-12 h-12 mb-3 text-slate-600" />
               <p className="text-slate-400 text-sm">Awaiting anomalies to generate<br/>predictive threat chains.</p>
             </div>
          )}
        </div>
      </div>
    </div>
  );
}
