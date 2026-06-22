import { useState } from "react";
import type { EnrichmentFinding } from "../context/ScannerContext";

interface EnrichmentPanelProps {
  findings: EnrichmentFinding[];
}

const SEVERITY_COLORS: Record<string, { bg: string; border: string; text: string; label: string }> = {
  critical: { bg: "#2a0d0d", border: "#ff2222", text: "#ff4444", label: "CRITICAL" },
  high: { bg: "#2a1a0d", border: "#ff6622", text: "#ff8844", label: "HIGH" },
  medium: { bg: "#2a2a0d", border: "#aaaa22", text: "#cccc44", label: "MEDIUM" },
  low: { bg: "#0d1a2a", border: "#2266aa", text: "#4488cc", label: "LOW" },
  info: { bg: "#0d0d0d", border: "#333", text: "#888", label: "INFO" },
};

const PROVIDER_ICONS: Record<string, string> = {
  hibp: "🔓",
  dehashed: "🗝️",
  hunter: "📧",
  shodan: "🌐",
  virustotal: "🛡️",
};

function SeverityBadge({ severity }: { severity: string }) {
  const s = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;
  return (
    <span
      style={{
        background: s.bg,
        border: `1px solid ${s.border}`,
        color: s.text,
        padding: "1px 6px",
        fontSize: "0.6rem",
        fontWeight: "bold",
        fontFamily: "monospace",
        borderRadius: "2px",
        letterSpacing: "0.05em",
      }}
    >
      {s.label}
    </span>
  );
}

function ProviderIcon({ provider }: { provider: string }) {
  return (
    <span style={{ marginRight: "0.35rem", fontSize: "0.75rem" }}>
      {PROVIDER_ICONS[provider] || "📡"}
    </span>
  );
}

export function EnrichmentPanel({ findings }: EnrichmentPanelProps) {
  const [expandedIndex, setExpandedIndex] = useState<Record<number, boolean>>({});

  const toggleExpand = (idx: number) => {
    setExpandedIndex((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const groupedBySeverity: Record<string, EnrichmentFinding[]> = {};
  const order = ["critical", "high", "medium", "low", "info"];
  for (const f of findings) {
    const sev = f.severity || "info";
    if (!groupedBySeverity[sev]) groupedBySeverity[sev] = [];
    groupedBySeverity[sev].push(f);
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* Summary bar */}
      <div
        style={{
          background: "#141414",
          border: "1px solid #333",
          padding: "0.75rem 1rem",
          fontFamily: "monospace",
          fontSize: "0.8rem",
          display: "flex",
          gap: "1.5rem",
        }}
      >
        <span style={{ color: "#aaa" }}>ENRICHMENT FINDINGS</span>
        {order.map((sev) => {
          const count = (groupedBySeverity[sev] || []).length;
          if (!count) return null;
          const s = SEVERITY_COLORS[sev];
          return (
            <span key={sev} style={{ color: s.text }}>
              {s.label}: {count}
            </span>
          );
        })}
      </div>

      {/* Findings by severity */}
      {order.map((sev) => {
        const items = groupedBySeverity[sev];
        if (!items || items.length === 0) return null;
        const s = SEVERITY_COLORS[sev];

        return (
          <div key={sev}>
            <h3
              style={{
                color: s.text,
                fontFamily: "monospace",
                fontSize: "0.7rem",
                letterSpacing: "0.1em",
                margin: "0 0 0.75rem 0",
                padding: "0 0 0.25rem 0",
                borderBottom: `1px solid ${s.border}40`,
              }}
            >
              {s.label} — {items.length} finding{items.length !== 1 ? "s" : ""}
            </h3>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              {items.map((finding, idx) => {
                const globalIdx = findings.indexOf(finding);
                const isExpanded = !!expandedIndex[globalIdx];
                const detailEntries = finding.details
                  ? Object.entries(finding.details).filter(
                      ([_, v]) => v !== null && v !== undefined && !(typeof v === "object" && Object.keys(v).length === 0)
                    )
                  : [];

                return (
                  <div
                    key={`${finding.provider}-${finding.target_value}-${idx}`}
                    style={{
                      background: s.bg,
                      border: `1px solid ${s.border}30`,
                      borderRadius: "3px",
                      overflow: "hidden",
                    }}
                  >
                    <div
                      onClick={() => toggleExpand(globalIdx)}
                      style={{
                        display: "flex",
                        alignItems: "flex-start",
                        gap: "0.75rem",
                        padding: "0.6rem 0.75rem",
                        cursor: "pointer",
                        fontFamily: "monospace",
                        fontSize: "0.78rem",
                      }}
                    >
                      <div style={{ flexShrink: 0, paddingTop: "1px" }}>
                        <SeverityBadge severity={sev} />
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ color: "#ccc", marginBottom: "0.15rem" }}>
                          <ProviderIcon provider={finding.provider} />
                          <strong style={{ color: "#fff" }}>
                            {finding.provider.toUpperCase()}
                          </strong>
                          <span style={{ color: "#666", margin: "0 0.5rem" }}>→</span>
                          <span style={{ color: s.text }}>
                            {finding.target_type}: {finding.target_value}
                          </span>
                        </div>
                        <div style={{ color: "#aaa", lineHeight: "1.4", wordBreak: "break-word" }}>
                          {finding.summary}
                        </div>
                      </div>
                      <div style={{ flexShrink: 0, color: "#555", fontSize: "0.7rem" }}>
                        {isExpanded ? "[–]" : "[+]"}
                      </div>
                    </div>

                    {isExpanded && detailEntries.length > 0 && (
                      <div
                        style={{
                          padding: "0.5rem 0.75rem 0.75rem 0.75rem",
                          borderTop: `1px solid ${s.border}20`,
                          fontFamily: "monospace",
                          fontSize: "0.7rem",
                        }}
                      >
                        <div
                          style={{
                            color: s.text,
                            marginBottom: "0.35rem",
                            fontWeight: "bold",
                          }}
                        >
                          RAW TELEMETRY:
                        </div>
                        <div
                          style={{
                            background: "#0a0a0a",
                            padding: "0.4rem 0.6rem",
                            borderRadius: "2px",
                            color: "#888",
                            overflowX: "auto",
                          }}
                        >
                          <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                            {JSON.stringify(finding.details, null, 2)}
                          </pre>
                        </div>
                        {finding.source_url && (
                          <div style={{ marginTop: "0.35rem" }}>
                            <a
                              href={finding.source_url}
                              target="_blank"
                              rel="noreferrer"
                              style={{ color: s.text, textDecoration: "none", fontSize: "0.7rem" }}
                            >
                              {finding.source_url} ↗
                            </a>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
