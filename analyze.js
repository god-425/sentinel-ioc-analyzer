function detectIOC(input) {
  const value = String(input || "").trim();
  const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
  const ipv6 = /^[0-9a-f:]{2,39}$/i;
  const sha256 = /^[a-f0-9]{64}$/i;
  const sha1 = /^[a-f0-9]{40}$/i;
  const md5 = /^[a-f0-9]{32}$/i;
  const email = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  try {
    const u = new URL(value);
    if (u.protocol === "http:" || u.protocol === "https:") return { type: "URL", value };
  } catch {}
  if (ipv4.test(value)) return { type: "IPv4", value };
  if (ipv6.test(value) && value.includes(":")) return { type: "IPv6", value };
  if (sha256.test(value)) return { type: "SHA-256", value };
  if (sha1.test(value)) return { type: "SHA-1", value };
  if (md5.test(value)) return { type: "MD5", value };
  if (email.test(value)) return { type: "Email", value };
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return { type: "Domain", value };
  return { type: "Unknown", value };
}

async function vtLookup(ioc) {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return { enabled: false, reason: "VIRUSTOTAL_API_KEY not configured" };

  let path = "";
  if (ioc.type === "IPv4" || ioc.type === "IPv6") path = `ip_addresses/${encodeURIComponent(ioc.value)}`;
  else if (ioc.type === "Domain") path = `domains/${encodeURIComponent(ioc.value)}`;
  else if (ioc.type === "URL") {
    const id = Buffer.from(ioc.value).toString("base64").replace(/=+$/,"").replace(/\+/g,"-").replace(/\//g,"_");
    path = `urls/${id}`;
  } else if (["MD5","SHA-1","SHA-256"].includes(ioc.type)) path = `files/${encodeURIComponent(ioc.value)}`;
  else return { enabled: true, supported: false };

  const r = await fetch(`https://www.virustotal.com/api/v3/${path}`, {
    headers: { "x-apikey": key }
  });
  if (!r.ok) return { enabled: true, error: `VirusTotal returned ${r.status}` };
  const j = await r.json();
  const a = j?.data?.attributes || {};
  const stats = a.last_analysis_stats || {};
  return {
    enabled: true,
    reputation: a.reputation ?? null,
    lastAnalysisStats: stats,
    harmless: stats.harmless || 0,
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    undetected: stats.undetected || 0,
    tags: a.tags || [],
    lastAnalysisDate: a.last_analysis_date || null,
    country: a.country || null,
    asn: a.asn || null,
    asOwner: a.as_owner || null
  };
}

async function abuseLookup(ioc) {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key || !["IPv4","IPv6"].includes(ioc.type)) {
    return { enabled: !!key, supported: ["IPv4","IPv6"].includes(ioc.type), reason: key ? "IOC type not supported by AbuseIPDB" : "ABUSEIPDB_API_KEY not configured" };
  }
  const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc.value)}&maxAgeInDays=90`, {
    headers: { "Key": key, "Accept": "application/json" }
  });
  if (!r.ok) return { enabled: true, error: `AbuseIPDB returned ${r.status}` };
  const d = (await r.json())?.data || {};
  return {
    enabled: true,
    confidence: d.abuseConfidenceScore ?? null,
    reports: d.totalReports ?? 0,
    lastReportedAt: d.lastReportedAt ?? null,
    countryCode: d.countryCode ?? null,
    isp: d.isp ?? null,
    domain: d.domain ?? null,
    usageType: d.usageType ?? null,
    isTor: !!d.isTor
  };
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  try {
    const ioc = detectIOC(req.body?.ioc);
    if (!ioc.value) return res.status(400).json({ error: "IOC is required" });
    const [virustotal, abuseipdb] = await Promise.all([
      vtLookup(ioc).catch(e => ({ enabled: true, error: e.message })),
      abuseLookup(ioc).catch(e => ({ enabled: true, error: e.message }))
    ]);
    return res.status(200).json({ ioc, virustotal, abuseipdb, mode: "live" });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Analysis failed" });
  }
}