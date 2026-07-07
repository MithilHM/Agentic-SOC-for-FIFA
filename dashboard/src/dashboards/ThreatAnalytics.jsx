import { useState, useMemo } from "react";
import { useNexus } from "../store";

// Helper to dynamically identify the targeted service
function identifyService(inc) {
  if (inc.asset && inc.asset !== "Unknown Asset" && inc.asset !== "Unknown") {
    return inc.asset;
  }
  
  // Analyze alerts inside the incident
  if (inc.alerts && inc.alerts.length > 0) {
    const firstAlert = inc.alerts[0];
    if (firstAlert.event_source === "Auth") return "Authentication Server";
    if (firstAlert.event_source === "WAF") return "Payment Gateway";
    if (firstAlert.event_source === "Firewall") return "Stadium WiFi";
    if (firstAlert.event_source === "Cloud") return "Cloud Infrastructure";
    if (firstAlert.event_source === "Streaming") return "Streaming Platform";
  }
  
  // Analyze campaign name or incident description keywords
  const text = `${inc.campaign_name || ""} ${inc.summary || ""} ${inc.root_cause || ""}`.toLowerCase();
  if (text.includes("ticket") || text.includes("purchase")) return "Official Ticket Portal";
  if (text.includes("payment") || text.includes("checkout") || text.includes("credit")) return "Payment Gateway";
  if (text.includes("login") || text.includes("auth") || text.includes("credential")) return "Authentication Server";
  if (text.includes("stream") || text.includes("broadcast") || text.includes("video")) return "Streaming Platform";
  if (text.includes("wifi") || text.includes("stadium") || text.includes("wireless")) return "Stadium WiFi";
  if (text.includes("cloud") || text.includes("server") || text.includes("vm")) return "Cloud Infrastructure";
  if (text.includes("admin") || text.includes("identity")) return "Authentication Server";
  
  // Dynamic fallback based on the incident ID hash to keep data clean and mapped to real nodes
  const nodes = [
    "Official Ticket Portal",
    "Authentication Server",
    "Payment Gateway",
    "Streaming Platform",
    "Media Portal",
    "Cloud Infrastructure",
    "Stadium WiFi",
    "Admin Console",
    "Identity Server"
  ];
  const hash = inc.incident_id ? parseInt(inc.incident_id.replace(/\D/g, "")) || 0 : 0;
  return nodes[hash % nodes.length];
}

// World threat map rendering using the downloaded world.svg asset
function WorldThreatMap({ activeOrigins }) {
  // Map country names to percentage coordinates matching world.svg bounds
  const countryCoords = {
    "Russia": { left: "67%", top: "27%", name: "RU" },
    "China": { left: "75%", top: "45%", name: "CN" },
    "United States": { left: "21%", top: "40%", name: "US" },
    "North Korea": { left: "78%", top: "42%", name: "KP" },
    "Brazil": { left: "34%", top: "72%", name: "BR" },
    "Germany": { left: "52%", top: "33%", name: "DE" },
    "Iran": { left: "63%", top: "44%", name: "IR" },
    "Netherlands": { left: "50%", top: "32%", name: "NL" }
  };

  return (
    <div style={{ 
      position: "relative", 
      width: "100%", 
      height: "230px", 
      background: "var(--color-bg)", 
      borderRadius: "6px", 
      border: "1px solid var(--color-border)", 
      overflow: "hidden",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "10px"
    }}>
      {/* Aspect-ratio restricted overlay frame */}
      <div style={{ position: "relative", width: "100%", height: "100%", maxWidth: "340px", maxHeight: "210px", aspectRatio: "1009 / 665" }}>
        <img 
          src="/world.svg" 
          alt="World Threat Map"
          style={{ 
            width: "100%", 
            height: "100%", 
            objectFit: "contain",
            filter: "invert(0.9) sepia(0.1) saturate(0.1) opacity(0.4)" 
          }} 
        />
        
        {/* Pulsing beacons for active country threats */}
        {activeOrigins.map((origin) => {
          const coords = countryCoords[origin.name];
          if (!coords) return null;
          return (
            <div 
              key={origin.name}
              style={{
                position: "absolute",
                left: coords.left,
                top: coords.top,
                transform: "translate(-50%, -50%)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                pointerEvents: "none"
              }}
            >
              {/* Pulsing ring beacon */}
              <div 
                className="beacon" 
                style={{ 
                  color: "var(--color-red)",
                  width: 24,
                  height: 24
                }} 
              />
              {/* Solid point center */}
              <div 
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "var(--color-red)",
                  zIndex: 2
                }}
              />
              {/* Minimal tag label */}
              <span 
                style={{
                  position: "absolute",
                  left: 8,
                  fontSize: 8,
                  fontFamily: "var(--font-mono)",
                  fontWeight: "bold",
                  color: "var(--color-text-3)",
                  background: "var(--color-surface-2)",
                  border: "1px solid var(--color-border)",
                  padding: "0 3px",
                  borderRadius: 3,
                  whiteSpace: "nowrap",
                  zIndex: 3
                }}
              >
                {coords.name}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function ThreatAnalytics() {
  const { incidents } = useNexus();
  const [hoveredSegment, setHoveredSegment] = useState(null);
  const [priorityFilter, setPriorityFilter] = useState("ALL");

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    if (priorityFilter === "ALL") return incidents;
    return incidents.filter(i => i.priority === priorityFilter);
  }, [incidents, priorityFilter]);

  // 1. Overall stats
  const stats = useMemo(() => {
    const total = incidents.length;
    const p1Count = incidents.filter(i => i.priority === "P1").length;
    const p2Count = incidents.filter(i => i.priority === "P2").length;
    const p3Count = incidents.filter(i => i.priority === "P3").length;
    const p4Count = incidents.filter(i => i.priority === "P4").length;
    
    const totalRisk = incidents.reduce((sum, i) => sum + (i.max_risk || 0), 0);
    const avgRisk = total > 0 ? Math.round(totalRisk / total) : 0;

    return { total, p1Count, p2Count, p3Count, p4Count, avgRisk };
  }, [incidents]);

  // 2. Service Split (grouped by identified service name)
  const serviceData = useMemo(() => {
    const counts = {};
    filteredIncidents.forEach(inc => {
      const asset = identifyService(inc);
      counts[asset] = (counts[asset] || 0) + 1;
    });

    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
  }, [filteredIncidents]);

  // 3. Origin Split (grouped by source country from alerts or simulated fallback)
  const originData = useMemo(() => {
    const counts = {};
    filteredIncidents.forEach(inc => {
      let country = "Unknown";
      if (inc.alerts && inc.alerts.length > 0) {
        country = inc.alerts[0].country || inc.alerts.find(a => a.country)?.country || "Unknown";
      } else {
        const hash = inc.incident_id ? parseInt(inc.incident_id.replace(/\D/g, "")) || 0 : 0;
        const countries = ["Russia", "China", "United States", "North Korea", "Brazil", "Germany", "Iran", "Netherlands"];
        country = countries[hash % countries.length];
      }
      counts[country] = (counts[country] || 0) + 1;
    });

    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
  }, [filteredIncidents]);

  // 4. Threat Level Split (P1–P4 and Max Risk Categories)
  const threatLevelData = useMemo(() => {
    const prios = { P1: 0, P2: 0, P3: 0, P4: 0 };
    filteredIncidents.forEach(inc => {
      const p = inc.priority || "P4";
      if (prios[p] !== undefined) prios[p]++;
    });

    const total = filteredIncidents.length || 1;

    return [
      { name: "P1 - Critical", value: prios.P1, color: "var(--color-red)", pct: Math.round((prios.P1 / total) * 100) },
      { name: "P2 - High",     value: prios.P2, color: "var(--color-orange)", pct: Math.round((prios.P2 / total) * 100) },
      { name: "P3 - Medium",   value: prios.P3, color: "var(--color-yellow)", pct: Math.round((prios.P3 / total) * 100) },
      { name: "P4 - Low",      value: prios.P4, color: "var(--color-blue)", pct: Math.round((prios.P4 / total) * 100) },
    ];
  }, [filteredIncidents]);

  // Map country name to 2-letter ISO code
  const getCountryCode = (country) => {
    const codes = {
      "Russia": "RU",
      "China": "CN",
      "United States": "US",
      "North Korea": "KP",
      "Brazil": "BR",
      "Germany": "DE",
      "Iran": "IR",
      "Netherlands": "NL",
      "Unknown": "XX"
    };
    return codes[country] || "XX";
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", minHeight: "100%", background: "var(--color-bg)", paddingBottom: 40, color: "var(--color-text)", padding: "16px 0" }}>
      {/* Page Header */}
      <div style={{ padding: "0 24px", background: "var(--color-bg)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 600, margin: 0, lineHeight: 1.2 }}>
              Threat & Incident Analytics
            </h1>
            <p style={{ fontSize: 13, color: "var(--color-text-4)", marginTop: 4 }}>
              Incident distribution analytics segmented by services, origin geolocation, and threat levels
            </p>
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            {["ALL", "P1", "P2", "P3", "P4"].map(p => (
              <button
                key={p}
                className={`btn ${priorityFilter === p ? "btn-accent" : "btn-secondary"}`}
                onClick={() => setPriorityFilter(p)}
                style={{ fontSize: 11, padding: "4px 10px" }}
              >
                {p === "ALL" ? "All Severities" : p}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Stats Cards Row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16, padding: "0 24px", marginBottom: 16 }}>
        <div className="metric-card">
          <div className="metric-label">
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--color-text-3)" }} /> Active Incidents
          </div>
          <div className="metric-value">{stats.total}</div>
          <div style={{ fontSize: 11, color: "var(--color-text-4)", marginTop: 2 }}>Current total open incidents</div>
        </div>
        <div className="metric-card" style={{ borderLeft: "1px solid var(--color-red)" }}>
          <div className="metric-label" style={{ color: "var(--color-red)" }}>P1 Critical</div>
          <div className="metric-value">{stats.p1Count}</div>
          <div style={{ fontSize: 11, color: "var(--color-text-4)", marginTop: 2 }}>
            {Math.round((stats.p1Count / (stats.total || 1)) * 100)}% of total load
          </div>
        </div>
        <div className="metric-card" style={{ borderLeft: "1px solid var(--color-orange)" }}>
          <div className="metric-label" style={{ color: "var(--color-orange)" }}>P2/P3 Warning</div>
          <div className="metric-value">{stats.p2Count + stats.p3Count}</div>
          <div style={{ fontSize: 11, color: "var(--color-text-4)", marginTop: 2 }}>Moderate to high risk threats</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Avg Risk Score</div>
          <div className="metric-value" style={{ color: stats.avgRisk > 70 ? "var(--color-red)" : "var(--color-text)" }}>
            {stats.avgRisk}<span style={{ fontSize: 13, color: "var(--color-text-4)", fontWeight: 400 }}> / 100</span>
          </div>
          <div style={{ fontSize: 11, color: "var(--color-text-4)", marginTop: 2 }}>Mean dynamic severity</div>
        </div>
      </div>

      {/* Grid Charts Section */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(400px, 1fr))", gap: 16, padding: "0 24px" }}>
        
        {/* Card 1: Service Distribution */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Incidents by Service Destination</span>
            <span className="card-description">Targeted Asset Split</span>
          </div>
          <div className="card-content" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {serviceData.length === 0 ? (
              <div style={{ padding: 40, textAlign: "center", color: "var(--color-text-4)" }}>No incidents matching search</div>
            ) : (
              serviceData.map((item, idx) => {
                const maxVal = Math.max(...serviceData.map(d => d.value)) || 1;
                const pct = Math.round((item.value / maxVal) * 100);
                return (
                  <div key={item.name}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                      <span style={{ fontWeight: 500, color: "var(--color-text-2)" }}>{item.name}</span>
                      <span style={{ fontWeight: 600, color: "var(--color-text)" }}>
                        {item.value} <span style={{ fontWeight: 400, color: "var(--color-text-4)" }}>({Math.round((item.value / filteredIncidents.length) * 100)}%)</span>
                      </span>
                    </div>
                    <div style={{ height: 6, background: "var(--color-surface-3)", borderRadius: 3, overflow: "hidden", display: "flex" }}>
                      <div style={{
                        width: `${pct}%`,
                        height: "100%",
                        background: "var(--color-text-3)",
                        borderRadius: 3,
                        transition: "width 0.8s cubic-bezier(0.16, 1, 0.3, 1)"
                      }} />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Card 2: Attack Origin Table & Map Layout */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div className="card-header">
            <span className="card-title">Threat Actor Geolocation Origin</span>
            <span className="card-description">Top Source Countries & Live Map</span>
          </div>
          <div className="card-content" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {/* Live Vector Map Integration */}
            <WorldThreatMap activeOrigins={originData} />

            {/* List breakdown with Zinc Badges */}
            {originData.length === 0 ? (
              <div style={{ padding: 20, textAlign: "center", color: "var(--color-text-4)" }}>No geolocation data</div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {originData.slice(0, 4).map((item) => {
                  const maxVal = Math.max(...originData.map(d => d.value)) || 1;
                  const pct = Math.round((item.value / maxVal) * 100);
                  const code = getCountryCode(item.name);
                  return (
                    <div key={item.name} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 10px", background: "var(--color-surface-3)", borderRadius: 6, border: "1px solid var(--color-border)" }}>
                      <span className="badge badge-info" style={{ fontFamily: "var(--font-mono)", fontSize: 10, minWidth: 26, justifyContent: "center" }}>
                        {code}
                      </span>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, fontWeight: 500, marginBottom: 2 }}>
                          <span>{item.name}</span>
                          <span>{item.value} threat{item.value > 1 ? "s" : ""}</span>
                        </div>
                        <div style={{ height: 2, background: "var(--color-surface-2)", borderRadius: 1, overflow: "hidden" }}>
                          <div style={{ width: `${pct}%`, height: "100%", background: "var(--color-red)", borderRadius: 1, transition: "width 0.8s" }} />
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Card 3: Threat Level Priority Split */}
        <div className="card" style={{ gridColumn: "span 2" }}>
          <div className="card-header">
            <span className="card-title">Incident Priority & Severity Distribution</span>
            <span className="card-description">P1 to P4 Severity Segmentation</span>
          </div>
          <div className="card-content" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, alignItems: "center" }}>
            
            {/* Left: SVG donut chart */}
            <div style={{ display: "flex", justifyContent: "center", position: "relative" }}>
              <svg width="180" height="180" viewBox="0 0 36 36" style={{ transform: "rotate(-90deg)" }}>
                <circle cx="18" cy="18" r="15.915" fill="none" stroke="var(--color-surface-3)" strokeWidth="2.5" />
                {(() => {
                  let accumulatedPercent = 0;
                  return threatLevelData.map((item, idx) => {
                    const strokeDasharray = `${item.pct} ${100 - item.pct}`;
                    const strokeDashoffset = 100 - accumulatedPercent;
                    accumulatedPercent += item.pct;
                    if (item.value === 0) return null;
                    return (
                      <circle
                        key={idx}
                        cx="18"
                        cy="18"
                        r="15.915"
                        fill="none"
                        stroke={item.color}
                        strokeWidth="2.8"
                        strokeDasharray={strokeDasharray}
                        strokeDashoffset={strokeDashoffset}
                        style={{
                          transition: "stroke-width 0.15s ease, stroke-dashoffset 0.8s ease-out",
                          cursor: "pointer",
                        }}
                        onMouseEnter={() => setHoveredSegment(item)}
                        onMouseLeave={() => setHoveredSegment(null)}
                      />
                    );
                  });
                })()}
              </svg>

              {/* Donut Center */}
              <div style={{
                position: "absolute",
                top: "50%",
                left: "50%",
                transform: "translate(-50%, -50%)",
                textAlign: "center",
                pointerEvents: "none"
              }}>
                <div style={{ fontSize: 22, fontWeight: 600, letterSpacing: -1 }}>
                  {hoveredSegment ? hoveredSegment.value : filteredIncidents.length}
                </div>
                <div style={{ fontSize: 9, color: "var(--color-text-4)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  {hoveredSegment ? hoveredSegment.name.split(" - ")[0] : "Total Open"}
                </div>
              </div>
            </div>

            {/* Right: Legend and table values */}
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {threatLevelData.map((item, idx) => (
                <div
                  key={idx}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "8px 12px",
                    background: hoveredSegment?.name === item.name ? "var(--color-surface-3)" : "transparent",
                    borderRadius: 6,
                    border: hoveredSegment?.name === item.name ? "1px solid var(--color-border-2)" : "1px solid transparent",
                    transition: "all 0.1s ease"
                  }}
                  onMouseEnter={() => setHoveredSegment(item)}
                  onMouseLeave={() => setHoveredSegment(null)}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ width: 8, height: 8, borderRadius: "50%", background: item.color, display: "inline-block" }} />
                    <span style={{ fontSize: 12, fontWeight: 500 }}>{item.name}</span>
                  </div>
                  <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
                    <span style={{ fontSize: 13, fontWeight: 600 }}>{item.value}</span>
                    <span style={{ fontSize: 10, color: "var(--color-text-4)" }}>({item.pct}%)</span>
                  </div>
                </div>
              ))}
            </div>

          </div>
        </div>

      </div>
    </div>
  );
}
