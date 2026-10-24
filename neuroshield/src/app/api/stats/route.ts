// GET /api/stats — Returns aggregated dashboard statistics
import { NextResponse } from "next/server";
import { generateStats, generateThreatTimeline, generateAlerts, generateMitreChain, generateDeviceStatus } from "../../../lib/pipeline";

export async function GET() {
  const stats = generateStats();
  const timeline = generateThreatTimeline(24);
  const recentAlerts = generateAlerts(20, 42);
  const mitreChain = generateMitreChain(recentAlerts);
  const devices = generateDeviceStatus(recentAlerts);

  return NextResponse.json({
    status: "success",
    stats,
    timeline,
    mitre_chain: mitreChain,
    devices,
  });
}
