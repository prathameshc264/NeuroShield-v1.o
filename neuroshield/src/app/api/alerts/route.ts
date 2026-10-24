// GET /api/alerts — Returns simulated real-time alerts from the AI pipeline
import { NextResponse } from "next/server";
import { generateAlerts } from "../../../lib/pipeline";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const count = Math.min(parseInt(searchParams.get("count") || "5"), 20);
  const seed = parseInt(searchParams.get("seed") || "0");

  const alerts = generateAlerts(count, seed);

  return NextResponse.json({
    status: "success",
    engine: "NeuroShield Dual-Core v1.0",
    generated_at: new Date().toISOString(),
    alerts,
  });
}
