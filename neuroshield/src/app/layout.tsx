import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NeuroShield SOC | AI-Powered IIoT Intrusion Detection",
  description: "Real-time Security Operations Center dashboard for NeuroShield — an AI-driven Intrusion Detection System for Industrial IoT using CNN-LSTM, GNN, and MITRE ATT&CK mapping.",
  keywords: ["NeuroShield", "SOC", "IDS", "IIoT", "SCADA", "MITRE ATT&CK", "AI Security"],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <div className="scan-line" />
        {children}
      </body>
    </html>
  );
}
