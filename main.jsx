import React, { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity, AlertTriangle, ArrowUpRight, BarChart3, Bell, CheckCircle2,
  ChevronDown, Clipboard, Clock3, Cloud, Code2, Copy, Database, FileText,
  Fingerprint, Globe2, Hash, History, Info, Layers3, LockKeyhole, Menu,
  Network, Play, Plus, Radar, RefreshCw, Search, Server, Shield,
  ShieldAlert, ShieldCheck, Sparkles, Terminal, Upload, UserRound, X, Zap
} from "lucide-react";
import "./styles.css";

const demo = {
  "185.220.101.42": {
    type: "IPv4", risk: 87, verdict: "High investigation priority",
    location: "Netherlands", country: "NL", asn: "AS9009", org: "M247 Europe SRL",
    reverse: "185-220-101-42.host.example.net", isp: "M247", usage: "Data Center / Hosting",
    firstSeen: "2026-08-14", lastSeen: "2026-09-20", reports: 347, abuse: 92,
    vt: { malicious: 17, suspicious: 4, harmless: 61, undetected: 12, total: 94 },
    tags: ["tor-exit", "hosting", "scanner"], openPorts: ["22", "80", "443", "8080"],
    dns: ["185.220.101.42.in-addr.arpa"], related: ["185.220.101.41", "185.220.101.43"],
    observations: [
      "Multiple external reputation sources indicate elevated risk.",
      "Abuse reports are recent and associated with hosting infrastructure.",
      "The IP should be correlated against proxy, DNS, firewall and EDR telemetry."
    ]
  },
  "example.com": {
    type: "Domain", risk: 12, verdict: "Low investigation priority",
    location: "United States", country: "US", asn: "AS15133", org: "Example Network",
    reverse: "example.com", isp: "Example CDN", usage: "Content / CDN",
    firstSeen: "1995-08-01", lastSeen: "2026-09-20", reports: 0, abuse: 0,
    vt: { malicious: 0, suspicious: 0, harmless: 72, undetected: 22, total: 94 },
    tags: ["benign", "web"], openPorts: ["80", "443"],
    dns: ["93.184.216.34"], related: ["www.example.com"],
    observations: ["No elevated reputation signal in the demo dataset.", "Use live enrichment before closing an alert."]
  }
};

const seedHistory = [
  { ioc: "185.220.101.42", type: "IPv4", risk: 87, time: "2 min ago" },
  { ioc: "example.com", type: "Domain", risk: 12, time: "Yesterday" },
  { ioc: "44d88612fea8a8f36de82e1278abb02f", type: "MD5", risk: 96, time: "Sep 19" }
];

function detectType(v) {
  const s = v.trim();
  if (/^https?:\/\//i.test(s)) return "URL";
  if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(s)) return "IPv4";
  if (/^[a-f0-9]{64}$/i.test(s)) return "SHA-256";
  if (/^[a-f0-9]{40}$/i.test(s)) return "SHA-1";
  if (/^[a-f0-9]{32}$/i.test(s)) return "MD5";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return "Email";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s)) return "Domain";
  return "Unknown";
}

function demoResult(value) {
  const key = value.trim();
  if (demo[key]) return { ...demo[key], ioc: key, mode: "demo" };
  const type = detectType(key);
  const malicious = type === "MD5" || type === "SHA-256" ? 9 : type === "URL" ? 4 : 0;
  const risk = type === "Unknown" ? 0 : type === "URL" ? 61 : malicious ? 72 : 18;
  return {
    ioc: key, type, risk,
    verdict: risk >= 80 ? "Critical investigation priority" : risk >= 50 ? "High investigation priority" : risk >= 20 ? "Medium investigation priority" : "Low investigation priority",
    location: "—", country: "—", asn: "—", org: "—", reverse: "—", isp: "—", usage: "—",
    firstSeen: "—", lastSeen: "Just now", reports: 0, abuse: 0,
    vt: { malicious, suspicious: risk > 50 ? 3 : 0, harmless: Math.max(0, 94 - malicious - (risk > 50 ? 3 : 0)), undetected: 0, total: 94 },
    tags: type === "URL" ? ["web", "requires-enrichment"] : [type.toLowerCase()],
    openPorts: [], dns: [], related: [],
    observations: [
      "Demo-mode result generated locally.",
      "Connect provider API keys to replace simulated reputation data with live enrichment.",
      "Correlate the IOC with your SIEM and endpoint telemetry before making a containment decision."
    ],
    mode: "demo"
  };
}

function scoreLabel(score) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 30) return "Medium";
  return "Low";
}

function App() {
  const [active, setActive] = useState("Overview");
  const [input, setInput] = useState("185.220.101.42");
  const [result, setResult] = useState(demoResult("185.220.101.42"));
  const [history, setHistory] = useState(seedHistory);
  const [loading, setLoading] = useState(false);
  const [bulk, setBulk] = useState(["185.220.101.42", "example.com"]);
  const [notes, setNotes] = useState("Correlate against DNS, proxy, firewall and EDR telemetry before escalation.");
  const [live, setLive] = useState(false);
  const [copied, setCopied] = useState(false);

  const analyze = async () => {
    if (!input.trim()) return;
    setLoading(true);
    setCopied(false);
    let next = demoResult(input);
    if (live) {
      try {
        const r = await fetch("/api/analyze", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ioc: input.trim()}) });
        if (r.ok) {
          const data = await r.json();
          next = mergeLive(next, data);
        }
      } catch {}
    }
    setTimeout(() => {
      setResult(next);
      setHistory(h => [{ ioc: next.ioc, type: next.type, risk: next.risk, time: "Just now" }, ...h.filter(x => x.ioc !== next.ioc)].slice(0, 10));
      setLoading(false);
      setActive("Overview");
    }, live ? 50 : 350);
  };

  const mergeLive = (base, data) => {
    const vt = data.virustotal || {};
    const abuse = data.abuseipdb || {};
    const malicious = vt.malicious ?? base.vt.malicious;
    const suspicious = vt.suspicious ?? base.vt.suspicious;
    const risk = Math.min(100, Math.round(
      (abuse.confidence != null ? abuse.confidence * 0.65 : 0) +
      (vt.malicious != null && vt.lastAnalysisStats ? Math.min(35, vt.malicious / Math.max(1, (vt.malicious+vt.suspicious+vt.harmless+vt.undetected)) * 100) : base.risk * 0.35)
    ));
    return {
      ...base, mode: "live", risk: risk || base.risk,
      vt: {...base.vt, malicious, suspicious, harmless: vt.harmless ?? base.vt.harmless, undetected: vt.undetected ?? base.vt.undetected, total: (malicious+suspicious+(vt.harmless??base.vt.harmless)+(vt.undetected??base.vt.undetected))},
      abuse: abuse.confidence ?? base.abuse,
      reports: abuse.reports ?? base.reports,
      country: abuse.countryCode || vt.country || base.country,
      isp: abuse.isp || base.isp,
      usage: abuse.usageType || base.usage,
      asn: vt.asn ? `AS${vt.asn}` : base.asn,
      org: vt.asOwner || abuse.isp || base.org,
      observations: [
        ...(abuse.confidence != null ? [`AbuseIPDB confidence is ${abuse.confidence}% with ${abuse.reports ?? 0} reports.`] : []),
        ...(vt.malicious != null ? [`VirusTotal recorded ${vt.malicious} malicious and ${vt.suspicious ?? 0} suspicious detections.`] : []),
        "Live provider data is enrichment evidence; validate against your organization's telemetry and procedures."
      ]
    };
  };

  const addBulk = () => {
    const lines = input.split(/\n|,/).map(s=>s.trim()).filter(Boolean);
    setBulk(prev => Array.from(new Set([...prev, ...lines])));
  };

  const copyValue = async (text) => {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(()=>setCopied(false), 1200); } catch {}
  };

  const exportReport = () => {
    const payload = { generatedAt: new Date().toISOString(), investigation: result, analystNotes: notes, history };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {type:"application/json"});
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `ioc-investigation-${result.ioc.replace(/[^a-z0-9]/gi,"-")}.json`; a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Shield size={17}/></div>
          <div><strong>SENTINEL</strong><span>IOC ANALYZER</span></div>
        </div>
        <div className="side-label">WORKSPACE</div>
        {[
          ["Overview", Radar], ["Investigate", Search], ["IOC Queue", Layers3], ["History", History], ["Reports", FileText]
        ].map(([name, Icon]) => (
          <button key={name} className={`nav-item ${active===name ? "active":""}`} onClick={()=>setActive(name)}>
            <Icon size={17}/><span>{name}</span>{name==="IOC Queue" && <em>{bulk.length}</em>}
          </button>
        ))}
        <div className="side-spacer"/>
        <div className="side-card">
          <div className="mini-orbit"><span/><span/><span/></div>
          <div><b>Enrichment</b><p>{live ? "Live provider mode" : "Demo mode"}</p></div>
          <button onClick={()=>setLive(!live)} title="Toggle live mode"><RefreshCw size={15}/></button>
        </div>
        <div className="profile"><div className="avatar">AK</div><div><b>Analyst</b><span>L1 SOC workspace</span></div><ChevronDown size={15}/></div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="mobile-brand"><Shield size={18}/> SENTINEL</div>
          <div className="crumb"><span>Workspace</span><i>/</i><b>{active}</b></div>
          <div className="top-actions"><span className={`mode-pill ${live ? "live":""}`}><span className="dot"/> {live ? "LIVE" : "DEMO"}</span><Bell size={18}/><div className="top-avatar">AK</div></div>
        </header>

        <section className="content">
          <div className="hero">
            <div>
              <div className="eyebrow"><span className="eyebrow-dot"/> SECURITY OPERATIONS / IOC WORKBENCH</div>
              <h1>Investigate once.<br/><span>See everything.</span></h1>
              <p>Enrich IPs, domains, URLs and hashes in one focused analyst workspace.</p>
            </div>
            <div className="hero-art">
              <div className="halo h1"/><div className="halo h2"/><div className="shield-art"><Shield size={52}/><div className="scan-line"/></div>
              <div className="floating-tag t1"><Activity size={13}/> multi-source</div>
              <div className="floating-tag t2"><LockKeyhole size={13}/> secure keys</div>
            </div>
          </div>

          <section className="search-panel">
            <div className="search-head"><div><span className="panel-kicker">NEW INVESTIGATION</span><h2>Analyze an indicator</h2></div><span className="hotkey">⌘ K</span></div>
            <div className="input-row">
              <div className="ioc-input"><Search size={19}/><input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&analyze()} placeholder="Paste IP, domain, URL or file hash…" /></div>
              <button className="analyze-btn" onClick={analyze} disabled={loading}><span>{loading ? "Analyzing…" : "Analyze IOC"}</span><ArrowUpRight size={17}/></button>
            </div>
            <div className="quick-row">
              <span>Try a sample:</span>
              {["185.220.101.42","example.com","44d88612fea8a8f36de82e1278abb02f"].map(x=><button key={x} onClick={()=>{setInput(x);setResult(demoResult(x));}}>{x.length>24?x.slice(0,16)+"…":x}</button>)}
              <span className="type-hint"><Fingerprint size={13}/> Auto-detect: <b>{detectType(input)}</b></span>
            </div>
          </section>

          {active === "Overview" && <Overview result={result} notes={notes} setNotes={setNotes} exportReport={exportReport} copyValue={copyValue} copied={copied} setInput={setInput} setResult={setResult}/>}
          {active === "Investigate" && <Investigate result={result} copyValue={copyValue} copied={copied}/>}
          {active === "IOC Queue" && <Queue bulk={bulk} setBulk={setBulk} addBulk={addBulk} setInput={setInput} setResult={setResult}/>}
          {active === "History" && <HistoryView history={history} setInput={setInput} setResult={setResult}/>}
          {active === "Reports" && <Reports result={result} exportReport={exportReport}/>}
        </section>
      </main>
    </div>
  );
}

function Overview({result, notes, setNotes, exportReport, copyValue, copied, setInput, setResult}) {
  const vtTotal = result.vt?.total || 94;
  const vtBad = (result.vt?.malicious||0)+(result.vt?.suspicious||0);
  const score = result.risk || 0;
  const label = scoreLabel(score);
  return <div className="dashboard">
    <div className="section-title"><div><span className="panel-kicker">INVESTIGATION OVERVIEW</span><h2>Signal, context, evidence.</h2></div><div className="title-actions"><button className="ghost-btn" onClick={exportReport}><FileText size={15}/> Export JSON</button><button className="primary-mini" onClick={()=>setResult(result)}><RefreshCw size={15}/> Refresh</button></div></div>

    <div className="metric-grid">
      <Metric icon={ShieldAlert} label="Priority" value={label} sub={`${score}/100 investigation score`} tone={score>=60?"warn":"good"}/>
      <Metric icon={Radar} label="IOC type" value={result.type} sub="Automatically detected" />
      <Metric icon={Globe2} label="Reputation" value={`${vtBad}/${vtTotal}`} sub="VT malicious + suspicious" tone={vtBad>0?"warn":"good"}/>
      <Metric icon={Clock3} label="Last observed" value={result.lastSeen} sub="Enrichment context"/>
    </div>

    <div className="main-grid">
      <div className="card signal-card">
        <div className="card-head"><div><span className="panel-kicker">REPUTATION SIGNAL</span><h3>{result.ioc}</h3></div><button className="icon-btn" onClick={()=>copyValue(result.ioc)} title="Copy IOC">{copied?<CheckCircle2 size={17}/>:<Copy size={17}/>}</button></div>
        <div className="signal-body">
          <div className={`risk-ring ${score>=60?"danger":score>=30?"medium":"safe"}`} style={{"--p":`${score*3.6}deg`}}><div><b>{score}</b><span>/ 100</span></div></div>
          <div className="signal-copy"><div className="status-line"><span className={`status-dot ${score>=60?"red":score>=30?"amber":"green"}`}/><b>{result.verdict}</b></div><p>{result.observations?.[0]}</p><div className="chips">{(result.tags||[]).map(t=><span key={t}>{t}</span>)}</div></div>
        </div>
        <div className="evidence-list">{(result.observations||[]).map((x,i)=><div className="evidence" key={i}><span>{String(i+1).padStart(2,"0")}</span><p>{x}</p><CheckCircle2 size={15}/></div>)}</div>
      </div>

      <div className="card provider-card">
        <div className="card-head"><div><span className="panel-kicker">SOURCE MATRIX</span><h3>Enrichment providers</h3></div><span className="tiny-live">{result.mode==="live"?"LIVE":"DEMO"}</span></div>
        <Provider name="VirusTotal" icon={Shield} value={`${result.vt?.malicious||0} malicious`} detail={`${result.vt?.suspicious||0} suspicious / ${vtTotal} analyzed`} state={result.mode==="live"?"connected":"simulated"}/>
        <Provider name="AbuseIPDB" icon={AlertTriangle} value={`${result.abuse||0}% confidence`} detail={`${result.reports||0} abuse reports`} state={result.type.includes("IP") && result.mode==="live"?"connected":"available"}/>
        <Provider name="WHOIS / RDAP" icon={Globe2} value={result.org || "—"} detail={`${result.asn || "ASN unavailable"} · ${result.country || "—"}`} state="available"/>
        <Provider name="DNS / Network" icon={Network} value={result.reverse || "No reverse DNS"} detail={`${result.usage || "Network context"} · ${result.isp || "—"}`} state="available"/>
      </div>
    </div>

    <div className="three-grid">
      <InfoCard title="Network identity" kicker="WHOIS / RDAP" icon={Server} rows={[
        ["Organization", result.org],["ASN",result.asn],["Country",result.country],["ISP",result.isp],["Usage",result.usage],["Reverse DNS",result.reverse]
      ]}/>
      <InfoCard title="DNS & infrastructure" kicker="RESOLUTION" icon={Network} rows={[
        ["A / PTR", (result.dns||[])[0] || "—"],["Related", (result.related||[]).join(", ") || "—"],["Open ports", (result.openPorts||[]).join(" · ") || "—"],["First seen",result.firstSeen],["Last seen",result.lastSeen]
      ]}/>
      <div className="card notes-card">
        <div className="card-head"><div><span className="panel-kicker">ANALYST NOTES</span><h3>Investigation context</h3></div><Sparkles size={16}/></div>
        <textarea value={notes} onChange={e=>setNotes(e.target.value)} />
        <div className="note-footer"><span><LockKeyhole size={12}/> Local workspace</span><button className="ghost-btn small" onClick={exportReport}>Save to report</button></div>
      </div>
    </div>

    <div className="card query-card">
      <div className="card-head"><div><span className="panel-kicker">SIEM HANDOFF</span><h3>Search this IOC in your telemetry</h3></div><span className="code-pill"><Terminal size={13}/> analyst-ready</span></div>
      <div className="query-tabs"><button className="selected">Splunk SPL</button><button>KQL</button><button>Sigma</button></div>
      <pre>{`index=* (src_ip="${result.ioc}" OR dest_ip="${result.ioc}" OR query="${result.ioc}")
| stats count by host, source, sourcetype
| sort -count`}</pre>
    </div>
  </div>;
}

function Metric({icon:Icon,label,value,sub,tone=""}) {
  return <div className="metric"><div className={`metric-icon ${tone}`}><Icon size={17}/></div><div><span>{label}</span><b>{value}</b><small>{sub}</small></div></div>
}
function Provider({name,icon:Icon,value,detail,state}) {
  return <div className="provider"><div className="provider-icon"><Icon size={16}/></div><div className="provider-copy"><b>{name}</b><span>{value}</span><small>{detail}</small></div><span className={`provider-state ${state}`}>{state}</span></div>
}
function InfoCard({title,kicker,icon:Icon,rows}) {
  return <div className="card info-card"><div className="card-head"><div><span className="panel-kicker">{kicker}</span><h3>{title}</h3></div><Icon size={16}/></div><div className="rows">{rows.map(([k,v])=><div className="row" key={k}><span>{k}</span><b>{v}</b></div>)}</div></div>
}
function Investigate({result,copyValue,copied}) {
  return <div className="dashboard"><div className="section-title"><div><span className="panel-kicker">DEEP INVESTIGATION</span><h2>Evidence by layer.</h2></div></div><div className="three-grid wide">
    <InfoCard title="Reputation" kicker="THREAT INTELLIGENCE" icon={ShieldAlert} rows={[["IOC",result.ioc],["Type",result.type],["VT malicious",result.vt?.malicious],["VT suspicious",result.vt?.suspicious],["Abuse confidence",`${result.abuse||0}%`],["Abuse reports",result.reports||0]]}/>
    <InfoCard title="Infrastructure" kicker="NETWORK CONTEXT" icon={Network} rows={[["ASN",result.asn],["Organization",result.org],["Country",result.country],["ISP",result.isp],["Usage",result.usage],["Reverse DNS",result.reverse]]}/>
    <InfoCard title="Artifacts" kicker="OBSERVABLES" icon={Fingerprint} rows={[["Tags",(result.tags||[]).join(", ")||"—"],["Ports",(result.openPorts||[]).join(", ")||"—"],["Related",(result.related||[]).join(", ")||"—"],["DNS",(result.dns||[]).join(", ")||"—"],["Last seen",result.lastSeen]]}/>
  </div><div className="card timeline"><div className="card-head"><div><span className="panel-kicker">INVESTIGATION TIMELINE</span><h3>Analyst activity</h3></div></div>{["IOC submitted","IOC type detected","Threat-intelligence enrichment requested","Evidence consolidated","SIEM correlation recommended"].map((x,i)=><div className="timeline-row" key={x}><span className="timeline-num">{String(i+1).padStart(2,"0")}</span><div><b>{x}</b><small>{i===0?"Just now":"Analysis stage"}</small></div><CheckCircle2 size={15}/></div>)}</div></div>
}
function Queue({bulk,setBulk,addBulk,setInput,setResult}) {
  return <div className="dashboard"><div className="section-title"><div><span className="panel-kicker">IOC QUEUE</span><h2>Batch investigation.</h2></div><button className="primary-mini" onClick={addBulk}><Plus size={15}/> Add from input</button></div><div className="card queue-card"><div className="bulk-drop"><Upload size={24}/><b>Drop a TXT or CSV here</b><span>or paste IOCs into the main analyzer and add them to the queue</span></div><div className="queue-list">{bulk.map((x,i)=><div className="queue-row" key={x}><div className="queue-num">{String(i+1).padStart(2,"0")}</div><div><b>{x}</b><span>{detectType(x)}</span></div><div className={`queue-risk ${demoResult(x).risk>=60?"high":""}`}>{demoResult(x).risk}/100</div><button className="icon-btn" onClick={()=>{setInput(x);setResult(demoResult(x));}}><ArrowUpRight size={16}/></button><button className="icon-btn" onClick={()=>setBulk(bulk.filter(y=>y!==x))}><X size={16}/></button></div>)}</div></div></div>
}
function HistoryView({history,setInput,setResult}) {
  return <div className="dashboard"><div className="section-title"><div><span className="panel-kicker">INVESTIGATION HISTORY</span><h2>Recent analyst activity.</h2></div></div><div className="card history-card"><div className="history-head"><span>IOC</span><span>TYPE</span><span>RISK</span><span>WHEN</span><span/></div>{history.map(x=><button className="history-row" key={x.ioc+x.time} onClick={()=>{setInput(x.ioc);setResult(demoResult(x.ioc))}}><b>{x.ioc}</b><span>{x.type}</span><span className={`score ${x.risk>=60?"bad":""}`}>{x.risk}</span><span>{x.time}</span><ArrowUpRight size={15}/></button>)}</div></div>
}
function Reports({result,exportReport}) {
  return <div className="dashboard"><div className="section-title"><div><span className="panel-kicker">REPORTING</span><h2>Analyst-ready output.</h2></div><button className="primary-mini" onClick={exportReport}><FileText size={15}/> Export JSON</button></div><div className="card report-preview"><div className="report-brand"><div className="brand-mark"><Shield size={17}/></div><div><b>SENTINEL</b><span>IOC INVESTIGATION REPORT</span></div></div><div className="report-title"><span>INVESTIGATION PRIORITY</span><b>{scoreLabel(result.risk)}</b><h3>{result.ioc}</h3><p>{result.type} · Generated {new Date().toLocaleString()}</p></div><div className="report-grid"><div><span>VT signal</span><b>{result.vt?.malicious||0} malicious</b></div><div><span>Abuse confidence</span><b>{result.abuse||0}%</b></div><div><span>Reports</span><b>{result.reports||0}</b></div><div><span>Organization</span><b>{result.org||"—"}</b></div></div><div className="report-copy">{(result.observations||[]).map(x=><p key={x}>• {x}</p>)}</div></div></div>
}

createRoot(document.getElementById("root")).render(<App />);
