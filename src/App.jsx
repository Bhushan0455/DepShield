import { useState, useEffect, useRef } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { Copy, CountUp, GaugeArc, Chip, Bar } from "./components/UI";
import { DEPS, PIPE, SEV } from "./components/Data";
import Graph from "./components/Graph";
import Panel from "./components/Panel";
import {
  Shield, CheckCircle2, ChevronRight, Activity, Zap, Info, LayoutDashboard,
  Network, AlertTriangle, Workflow, Moon, Sun, ArrowRight, Github, PackageOpen, Download
} from "lucide-react";

gsap.registerPlugin(ScrollTrigger);

export default function App() {
  const [phase, setPhase] = useState("input"); // input | pipeline | main
  const [tab, setTab] = useState("dashboard");
  const [inputTab, setInputTab] = useState("url"); // url | file
  const [step, setStep] = useState(-1);
  const [done, setDone] = useState([]);
  const [url, setUrl] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState("");
  const [sel, setSel] = useState(null);
  const [filt, setFilt] = useState("All");
  const [sCol, setSCol] = useState("score");
  const [sDir, setSDir] = useState("desc");

  // Custom Cursor Logic
  useEffect(() => {
    const cursor = document.createElement("div");
    cursor.id = "custom-cursor";
    document.body.appendChild(cursor);

    const moveCursor = (e) => {
      cursor.style.left = e.clientX + 'px';
      cursor.style.top = e.clientY + 'px';
    };

    const handleHover = (e) => {
      const target = e.target.closest('button, a, input, [role="button"], tr');
      if (target) cursor.classList.add('hover');
      else cursor.classList.remove('hover');
    };

    window.addEventListener('mousemove', moveCursor);
    window.addEventListener('mouseover', handleHover);

    return () => {
      window.removeEventListener('mousemove', moveCursor);
      window.removeEventListener('mouseover', handleHover);
      if (document.getElementById("custom-cursor")) {
        document.body.removeChild(cursor);
      }
    };
  }, []);

  const TABS = [
    { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard size={14} /> },
    { id: "graph", label: "Dependency Graph", icon: <Network size={14} /> },
    { id: "vulns", label: "Vulnerabilities", icon: <AlertTriangle size={14} /> },
    { id: "fixes", label: "Fix Plan", icon: <Workflow size={14} /> },
  ];

  const API = "http://localhost:5000";

  const runPipeline = async (backendPromise) => {
    setPhase("pipeline"); setStep(-1); setDone([]);
    for (let i = 0; i < PIPE.length - 1; i++) {
      await new Promise(r => setTimeout(r, 120)); setStep(i);
      await new Promise(r => setTimeout(r, 600));
      setDone(p => [...p, i]);
    }
    setStep(PIPE.length - 1);
    await Promise.all([
      new Promise(r => setTimeout(r, 800)),
      backendPromise
    ]);
    setDone(p => [...p, PIPE.length - 1]);
    await new Promise(r => setTimeout(r, 400));
  };

  const startURLScan = async () => {
    if (!url.trim()) return;
    setScanError("");
    const fetchPromise = fetch(`${API}/api/scan`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repoUrl: url }),
    }).then(r => r.json()).catch(err => ({ error: err.message }));

    await runPipeline(fetchPromise);
    const result = await fetchPromise;

    if (result.error) { setScanError(result.error); setPhase("input"); return; }
    if (Array.isArray(result)) { setScanResult(result); setPhase("main"); setTab("dashboard"); }
    else { setScanError("Unexpected response from server."); setPhase("input"); }
  };

  const startFileScan = async (file) => {
    const reader = new FileReader();
    reader.onload = async (e) => {
      let content;
      try { content = JSON.parse(e.target.result); } catch { setScanError("Invalid JSON file"); return; }
      setScanError("");

      const fetchPromise = fetch(`${API}/api/scan-file`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: file.name, content }),
      }).then(r => r.json()).catch(err => ({ error: err.message }));

      await runPipeline(fetchPromise);
      const result = await fetchPromise;

      if (result.error) { setScanError(result.error); setPhase("input"); return; }
      if (Array.isArray(result)) { setScanResult(result); setPhase("main"); setTab("dashboard"); }
      else { setScanError("Unexpected response from server."); setPhase("input"); }
    };
    reader.readAsText(file);
  };

  const activeDeps = scanResult || DEPS;
  const crit = activeDeps.filter(d => d.sev === "CRITICAL").length;
  const high = activeDeps.filter(d => d.sev === "HIGH").length;
  const med = activeDeps.filter(d => d.sev === "MEDIUM").length;
  const low = activeDeps.filter(d => d.sev === "LOW").length;
  const upg = activeDeps.filter(d => d.version !== d.fixv && d.sev !== "SAFE").length;
  const aband = activeDeps.filter(d => d.maint === "Abandoned").length;

  const penalty = (crit * 20 + high * 10 + med * 4 + low * 1);
  const risk = Math.max(0, 100 - penalty);
  const grade = risk >= 90 ? "A" : risk >= 75 ? "B" : risk >= 55 ? "C" : risk >= 35 ? "D" : "F";
  const gc = risk >= 75 ? "#2dd4bf" : risk >= 55 ? "#f59e0b" : risk >= 35 ? "#f97316" : "#ef4444";

  const rows = [...activeDeps]
    .filter(d => filt === "All" || d.sev === filt)
    .sort((a, b) => { let av = a[sCol], bv = b[sCol]; if (typeof av === "string") { av = av.toLowerCase(); bv = bv.toLowerCase(); } return sDir === "asc" ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1); });

  const doSort = c => { if (sCol === c) setSDir(d => d === "asc" ? "desc" : "asc"); else { setSCol(c); setSDir("desc"); } };
  const fixes = activeDeps.filter(d => d.sev !== "SAFE" && d.fix).sort((a, b) => b.score - a.score);

  // GSAP Animations
  const mainRef = useRef(null);
  useEffect(() => {
    if (!mainRef.current) return;
    const ctx = gsap.context(() => {
      // Stagger elements with class 'gsap-stagger'
      gsap.fromTo(".gsap-stagger",
        { y: 30, opacity: 0 },
        { y: 0, opacity: 1, duration: 0.8, stagger: 0.1, ease: "power3.out" }
      );
    }, mainRef);
    return () => ctx.revert();
  }, [phase, tab]);

  const Stat = ({ label, val, color, sub }) => (
    <div className="glass-panel rounded-3xl p-6 relative overflow-hidden group hover:-translate-y-1 transition-all duration-300">
      <div className="absolute top-0 right-0 w-32 h-32 bg-[radial-gradient(ellipse_at_top_right,var(--tw-gradient-stops))] from-white/5 to-transparent blur-xl pointer-events-none opacity-50 group-hover:opacity-100 transition-opacity" />
      <div className="flex justify-between items-start">
        <div>
          <p className="text-[11px] font-bold uppercase tracking-widest text-ghost/40 mb-3 font-mono">{label}</p>
          <div className="font-head text-4xl font-bold leading-none mb-2" style={{ color, textShadow: `0 0 20px color-mix(in srgb, ${color} 30%, transparent)` }}>
            {phase === "main" ? <CountUp n={val} /> : val}
          </div>
          {sub && <p className="text-xs text-ghost/50 font-mono tracking-wide mt-3">{sub}</p>}
        </div>
        <div className="w-1.5 h-12 rounded-full opacity-80 mt-1 shadow-[0_0_12px_currentColor]" style={{ backgroundColor: color, color }} />
      </div>
    </div>
  );

  const goHome = () => {
    setPhase("input");
    setScanResult(null);
    setScanError("");
    setTab("dashboard");
    setSel(null);
    setUrl("");
  };

  return (
    <>
      <div className="noise-overlay" />

      {/* ── NAV "The Floating Island" ── */}
      <header className="fixed top-6 left-1/2 -translate-x-1/2 z-50 w-[95%] max-w-7xl glass-panel rounded-full px-6 py-3 flex items-center justify-between shadow-[0_10px_40px_rgba(0,0,0,0.5)] border border-white/10 transition-all duration-300">
        <div onClick={goHome} className="flex items-center gap-3 cursor-pointer group">
          <div className="w-10 h-10 rounded-[14px] bg-primary flex items-center justify-center text-white shadow-[0_0_15px_rgba(123,97,255,0.4)] group-hover:shadow-[0_0_20px_rgba(123,97,255,0.6)] transition-all">
            <Shield size={20} className="group-hover:scale-110 transition-transform" />
          </div>
          <span className="font-head text-lg font-bold tracking-tight">DepShield</span>
        </div>

        {phase === "main" && (
          <nav className="hidden md:flex items-center gap-1">
            {TABS.map(t => (
              <button key={t.id} onClick={() => setTab(t.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-full font-body text-sm font-medium transition-all duration-300 relative overflow-hidden ${tab === t.id ? "text-primary bg-primary/10 shadow-[inner_0_0_10px_rgba(123,97,255,0.1)]" : "text-ghost/60 hover:text-ghost hover:bg-white/5"
                  }`}>
                {tab === t.id && <span className="absolute bottom-0 left-1/2 -translate-x-1/2 w-8 h-1 bg-primary rounded-t-full shadow-[0_0_8px_rgba(123,97,255,0.8)]" />}
                <span className={`${tab === t.id ? "text-primary" : "text-ghost/40"}`}>{t.icon}</span>
                {t.label}
              </button>
            ))}
          </nav>
        )}

        <div className="flex items-center gap-4">
          {phase === "main" && (
            <div className="hidden lg:flex items-center gap-4 mr-2">
              <span className="text-xs text-ghost/40 font-mono tracking-wide truncate max-w-[150px]">{url || "scanned project"}</span>
              <span className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-teal-400/10 border border-teal-400/20 text-teal-400 text-xs font-mono tracking-wide relative overflow-hidden">
                <span className="w-1.5 h-1.5 rounded-full bg-teal-400 shadow-[0_0_5px_currentColor] animate-pulse" />
                <span className="font-semibold mix-blend-screen text-[10px] uppercase">System Operational</span>
              </span>
            </div>
          )}
        </div>
      </header>

      <main ref={mainRef} className="min-h-screen pt-32 pb-20 px-6 sm:px-12 relative z-10">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[800px] bg-primary/20 blur-[120px] rounded-full pointer-events-none opacity-20" />

        {/* ── INPUT SCREEN ── */}
        {phase === "input" && (
          <div className="max-w-2xl mx-auto pt-16">
            <div className="text-center mb-16 gsap-stagger">
              <h1 className="font-drama text-6xl md:text-7xl lg:text-[80px] leading-[0.9] tracking-tight mb-6">
                Dependency Risk <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary via-purple-400 to-ghost italic pr-2">Analyzer</span>
              </h1>
              <p className="text-ghost/60 text-lg font-body max-w-lg mx-auto leading-relaxed">
                Genome-level sequencing for your frontend ecosystem. Detect vulnerabilities, abandoned packages, and prototype pollution in real time.
              </p>
            </div>

            <div className="glass-panel p-8 rounded-[2rem] gsap-stagger relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-b from-white-[0.03] to-transparent pointer-events-none" />

              <div className="flex gap-2 mb-8 bg-surface border border-white/10 p-1.5 rounded-2xl relative z-10">
                {[{ id: "url", label: "GitHub URL", icon: <Github size={16} /> }, { id: "file", label: "Upload Manifest", icon: <PackageOpen size={16} /> }].map(t => (
                  <button key={t.id} onClick={() => setInputTab(t.id)}
                    className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-xl font-body text-sm font-semibold transition-all duration-300 ${inputTab === t.id ? "bg-background text-ghost shadow-lg border border-white/5" : "text-ghost/40 hover:text-ghost/80"
                      }`}>
                    {t.icon} {t.label}
                  </button>
                ))}
              </div>

              {scanError && <div className="bg-red-500/10 border border-red-500/20 text-red-500 rounded-xl p-4 mb-6 text-sm font-mono flex items-center gap-3">
                <AlertTriangle size={16} /> {scanError}
              </div>}

              {inputTab === "url" ? (
                <div className="relative z-10">
                  <div className="mb-6 relative">
                    <input type="text" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://github.com/owner/repo"
                      className="w-full bg-background border border-white/10 rounded-2xl px-5 py-4 text-ghost font-mono text-sm focus:outline-none focus:border-primary/50 focus:ring-4 focus:ring-primary/10 transition-all placeholder:text-ghost/20" />
                    <div className="absolute right-4 top-1/2 -translate-y-1/2 px-2 py-1 rounded bg-white/5 text-[10px] font-mono text-ghost/40 border border-white/10">URL</div>
                  </div>
                  <button onClick={startURLScan}
                    className="w-full btn-vapor-primary text-lg py-4">
                    <span className="mr-2 text-xl">✦</span> Extract & Analyze
                  </button>
                </div>
              ) : (
                <label onDrop={e => { e.preventDefault(); const file = e.dataTransfer.files[0]; if (file) startFileScan(file); }}
                  onDragOver={e => e.preventDefault()}
                  className="relative z-10 flex flex-col items-center justify-center border-2 border-dashed border-white/10 hover:border-primary/50 hover:bg-primary/5 rounded-2xl p-12 cursor-pointer transition-all duration-300 group">
                  <div className="w-16 h-16 rounded-2xl bg-surface border border-white/10 flex items-center justify-center mb-6 group-hover:scale-110 group-hover:shadow-[0_0_20px_rgba(123,97,255,0.3)] transition-all">
                    <Download size={24} className="text-primary" />
                  </div>
                  <div className="text-ghost font-semibold text-[15px] mb-2 tracking-wide">Drop package.json here</div>
                  <div className="text-ghost/40 text-xs font-mono">or click to browse local files</div>
                  <input type="file" accept=".json" className="hidden" onChange={(e) => { const file = e.target.files[0]; if (file) startFileScan(file); }} />
                </label>
              )}
            </div>
          </div>
        )}

        {/* ── PIPELINE ── */}
        {phase === "pipeline" && (
          <div className="max-w-2xl mx-auto pt-16">
            <div className="text-center mb-12 gsap-stagger">
              <div className="inline-flex w-16 h-16 bg-primary/10 border border-primary/20 rounded-2xl items-center justify-center mb-6 shadow-[0_0_30px_rgba(123,97,255,0.2)]">
                <Zap size={28} className="text-primary animate-pulse" />
              </div>
              <h2 className="font-drama text-5xl leading-none mb-4 italic tracking-tight">Sequencing Repository</h2>
              <p className="text-ghost/40 text-sm font-mono max-w-md mx-auto truncate px-4">{url || "Local manifest file"}</p>
            </div>

            <div className="glass-panel rounded-3xl overflow-hidden gsap-stagger p-2">
              {PIPE.map((s, i) => {
                const isDone = done.includes(i), isAct = step === i && !isDone;
                return (
                  <div key={i} className={`flex items-center gap-4 px-6 py-4 rounded-2xl transition-all duration-500 relative overflow-hidden ${isAct ? "bg-primary/10 border border-primary/20 shadow-[inset_0_0_20px_rgba(123,97,255,0.1)]" : "border border-transparent"
                    }`} style={{ opacity: step < i && !isDone ? 0.3 : 1 }}>

                    {isAct && <div className="absolute top-0 left-0 w-1 h-full bg-primary shadow-[0_0_10px_rgba(123,97,255,0.8)] animate-pulse" />}

                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 transition-all duration-500 border ${isDone ? "bg-teal-400/10 border-teal-400/30 shadow-[0_0_15px_rgba(45,212,191,0.2)]" : isAct ? "bg-primary border-primary shadow-[0_0_15px_rgba(123,97,255,0.4)] text-[#0A0A14]" : "bg-white/5 border-white/10"
                      }`}>
                      {isDone ? <CheckCircle2 size={16} className="text-teal-400" /> : isAct ? <span className="spinner-vapor !border-[#0A0A14]/20 !border-t-[#0A0A14]" /> : <span className="text-xs font-mono font-bold text-ghost/40">{i + 1}</span>}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className={`text-sm font-bold tracking-wide transition-colors duration-500 ${isDone ? "text-teal-400" : isAct ? "text-primary" : "text-ghost/80"}`}>{s.label}</div>
                      <div className="text-xs text-ghost/40 mt-1 font-mono tracking-wide">{s.desc}</div>
                    </div>

                    {isAct && (
                      <div className="w-20 h-1.5 bg-background rounded-full overflow-hidden shrink-0 border border-white/5">
                        <div className="w-1/2 h-full bg-primary rounded-full animate-[shimmer-move_1s_linear_infinite]" />
                      </div>
                    )}
                    {isDone && <span className="text-teal-400 text-[10px] font-mono font-bold uppercase tracking-widest shrink-0">Done</span>}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── MAIN VIEWS ── */}
        {phase === "main" && (
          <div className="max-w-[1400px] mx-auto">

            {/* DASHBOARD */}
            {tab === "dashboard" && (
              <div className="flex flex-col gap-6">
                {/* Stats Row */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 gsap-stagger">
                  <Stat label="Total Scanned" val={activeDeps.length} color="#7B61FF" sub="Packages mapped" />
                  <Stat label="Critical Vulns" val={crit} color="#ef4444" sub="Immediate action needed" />
                  <Stat label="Need Upgrade" val={upg} color="#f97316" sub="Outdated versions" />
                  <Stat label="Abandoned Libs" val={aband} color="#f59e0b" sub="No maintainer" />
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  {/* Grade Card */}
                  <div className="lg:col-span-3 glass-panel rounded-3xl p-8 flex flex-col items-center justify-center text-center gsap-stagger relative overflow-hidden">
                    <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,var(--tw-gradient-stops))] from-white/5 to-transparent pointer-events-none" />
                    <GaugeArc value={risk} size={140} />
                    <div className="mt-8 font-drama text-8xl leading-none italic" style={{ color: gc, textShadow: `0 0 30px color-mix(in srgb, ${gc} 40%, transparent)` }}>{grade}</div>
                    <div className="mt-4 text-[11px] font-bold uppercase tracking-widest text-ghost/40 font-mono">System Grade</div>
                  </div>

                  {/* Critical List */}
                  <div className="lg:col-span-6 glass-panel rounded-3xl overflow-hidden flex flex-col gsap-stagger">
                    <div className="p-6 border-b border-white/10 flex items-center justify-between bg-white/[0.02]">
                      <h3 className="text-sm font-bold tracking-wide flex items-center gap-3">
                        <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.8)] animate-pulse" />
                        Critical Vulnerabilities
                      </h3>
                      <Chip sev="CRITICAL" />
                    </div>
                    <div className="flex-1 overflow-y-auto max-h-[400px] divide-y divide-white/5">
                      {activeDeps.filter(d => d.sev === "CRITICAL").map(d => (
                        <div key={d.id} onClick={() => setSel(d)} className="p-5 flex justify-between items-center hover:bg-white/5 cursor-pointer transition-colors group">
                          <div>
                            <div className="font-bold text-sm tracking-wide gap-3 flex items-center">
                              {d.name} <span className="text-xs font-mono text-ghost/40 font-normal">v{d.version}</span>
                            </div>
                            <div className="text-[11px] text-red-500/80 font-mono tracking-wider mt-2 flex items-center gap-2">
                              <ShieldAlert size={12} /> {d.cves.join(" · ")}
                            </div>
                          </div>
                          <div className="text-right">
                            <div className="font-head text-2xl font-bold text-red-500 leading-none group-hover:scale-110 transition-transform origin-right drop-shadow-[0_0_10px_rgba(239,68,68,0.3)]">{d.score}</div>
                            <div className="text-[10px] text-ghost/40 font-mono mt-1">CVSS</div>
                          </div>
                        </div>
                      ))}
                      {activeDeps.filter(d => d.sev === "CRITICAL").length === 0 && (
                        <div className="p-12 text-center text-ghost/40 flex flex-col items-center justify-center border-2 border-dashed border-white/5 m-6 rounded-2xl">
                          <CheckCircle2 size={32} className="text-teal-400/50 mb-4" />
                          <div className="font-mono text-sm">No critical vulnerabilities detected.</div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Severity Breakdown */}
                  <div className="lg:col-span-3 glass-panel rounded-3xl p-6 relative overflow-hidden gsap-stagger flex flex-col justify-center">
                    <h3 className="text-sm font-bold tracking-wide mb-8">Severity Breakdown</h3>
                    <div className="flex flex-col gap-5">
                      {["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"].map(s => {
                        const cnt = activeDeps.filter(d => d.sev === s).length;
                        const pct = activeDeps.length ? (cnt / activeDeps.length) * 100 : 0;
                        const c = SEV[s];
                        return (
                          <div key={s}>
                            <div className="flex justify-between items-center mb-3">
                              <Chip sev={s} />
                              <span className="text-xs font-mono font-bold text-ghost/60">{cnt}</span>
                            </div>
                            <div className="bg-background rounded-full h-1.5 overflow-hidden border border-white/5">
                              <div className="h-full rounded-full transition-all duration-1000 ease-out" style={{ width: `${pct}%`, backgroundColor: c.hex, boxShadow: `0 0 10px ${c.hex}` }} />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {/* Abandoned Libs Section */}
                <div className="glass-panel rounded-3xl overflow-hidden gsap-stagger">
                  <div className="p-6 border-b border-white/10 flex items-center justify-between bg-white/[0.02]">
                    <h3 className="text-sm font-bold tracking-wide">Abandoned & Inactive Libraries</h3>
                    <span className="px-3 py-1 bg-amber-500/10 border border-amber-500/20 text-amber-500 rounded-full text-xs font-mono font-bold">
                      {activeDeps.filter(d => d.maint !== "Active").length} found
                    </span>
                  </div>
                  <div className="p-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-4">
                    {activeDeps.filter(d => d.maint !== "Active").map(d => (
                      <div key={d.id} onClick={() => setSel(d)}
                        className={`bg-surface/50 border rounded-2xl p-5 cursor-pointer transition-all duration-300 relative overflow-hidden group ${d.maint === "Abandoned" ? "border-amber-500/30 hover:border-amber-500/60 shadow-[inset_0_0_15px_rgba(245,158,11,0.05)] hover:shadow-[0_0_20px_rgba(245,158,11,0.2)]" : "border-white/10 hover:border-white/30"
                          }`}>
                        {d.maint === "Abandoned" && <div className="absolute top-0 right-0 w-16 h-16 bg-amber-500 opacity-20 blur-2xl group-hover:opacity-40 transition-opacity" />}
                        <div className="flex justify-between items-start mb-4 relative z-10">
                          <div className="font-bold text-sm truncate pr-2 tracking-wide">{d.name}</div>
                        </div>
                        <div className="text-xs text-ghost/40 font-mono mb-4 relative z-10">v{d.version}</div>
                        <div className="flex justify-between items-center relative z-10">
                          <Chip sev={d.sev} />
                          <span className={`text-[10px] uppercase font-bold tracking-widest ${d.maint === "Abandoned" ? "text-amber-500" : "text-ghost/40"}`}>{d.maint}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* GRAPH */}
            {tab === "graph" && (
              <div className="gsap-stagger">
                <div className="mb-6 flex justify-between items-end flex-wrap gap-4">
                  <div>
                    <h2 className="font-drama text-4xl italic leading-none mb-3">Dependency Topology</h2>
                    <p className="text-sm text-ghost/60 font-body">Interactive force-directed visualization of {activeDeps.length} packages</p>
                  </div>
                </div>
                <Graph deps={activeDeps} onPick={setSel} />
              </div>
            )}

            {/* VULNS */}
            {tab === "vulns" && (
              <div className="gsap-stagger">
                <div className="mb-6 flex justify-between items-end flex-wrap gap-6">
                  <div>
                    <h2 className="font-drama text-4xl italic leading-none mb-3">Vulnerability Directory</h2>
                    <p className="text-sm text-ghost/60 font-body">Sortable ledger of all mapped dependencies and risks</p>
                  </div>
                  <div className="flex gap-2 p-1.5 bg-surface border border-white/5 rounded-2xl">
                    {["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"].map(f => {
                      const c = SEV[f];
                      const active = filt === f;
                      return (
                        <button key={f} onClick={() => setFilt(f)}
                          className={`px-4 py-2 rounded-xl text-xs font-bold tracking-wide transition-all ${active
                              ? `${c ? c.bg : 'bg-background'} ${c ? c.color : 'text-ghost'} shadow-lg border ${c ? c.border : 'border-white/10'}`
                              : "bg-transparent text-ghost/40 hover:text-ghost/80 border border-transparent"
                            }`}>
                          {f}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="glass-panel rounded-3xl overflow-hidden shadow-2xl">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-white/[0.02]">
                          {[["name", "Library"], ["version", "Version"], ["latest", "Latest"], ["sev", "Severity"], ["score", "Danger"], ["vulns", "CVEs"], ["maint", "Maintainer"]].map(([c, l]) => (
                            <th key={c} onClick={() => doSort(c)} className="p-5 text-[11px] font-bold uppercase tracking-widest text-ghost/40 border-b border-white/10 cursor-pointer hover:text-ghost/80 hover:bg-white/5 transition-all outline-none whitespace-nowrap">
                              <div className="flex items-center gap-2">
                                {l}
                                <span className={`text-[#7B61FF] ${sCol === c ? 'opacity-100' : 'opacity-0'}`}>{sDir === "asc" ? "↑" : "↓"}</span>
                              </div>
                            </th>
                          ))}
                          <th className="p-5 text-[11px] font-bold uppercase tracking-widest text-ghost/40 border-b border-white/10">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        {rows.map(d => (
                          <tr key={d.id} onClick={() => setSel(d)} className="hover:bg-white/5 cursor-pointer transition-colors group">
                            <td className="p-5"><span className="font-bold tracking-wide whitespace-nowrap">{d.name}</span></td>
                            <td className="p-5"><code className="text-xs font-mono text-ghost/50">{d.version}</code></td>
                            <td className="p-5"><code className={`text-xs font-mono ${d.version !== d.latest ? 'text-teal-400 font-bold' : 'text-ghost/50'}`}>{d.latest}</code></td>
                            <td className="p-5"><Chip sev={d.sev} /></td>
                            <td className="p-5 w-40"><Bar score={d.score} /></td>
                            <td className="p-5"><span className={`font-mono font-bold ${d.vulns > 0 ? 'text-red-500' : 'text-ghost/20'}`}>{d.vulns}</span></td>
                            <td className="p-5">
                              <span className="flex items-center gap-2 text-xs font-mono font-bold">
                                <span className={`w-1.5 h-1.5 rounded-full ${d.maint === "Active" ? "bg-teal-400" : d.maint === "Abandoned" ? "bg-amber-500" : "bg-ghost/40"}`} />
                                <span className={d.maint === "Active" ? "text-teal-400" : d.maint === "Abandoned" ? "text-amber-500" : "text-ghost/40"}>{d.maint}</span>
                              </span>
                            </td>
                            <td className="p-5">
                              {d.fix
                                ? <button className="opacity-0 group-hover:opacity-100 btn-vapor py-2 text-xs px-4" onClick={(e) => { e.stopPropagation(); setSel(d); }}>Inspect <ArrowRight size={14} /></button>
                                : <span className="text-teal-400/50 text-xs font-bold font-mono py-2 uppercase tracking-widest flex items-center gap-1"><CheckCircle2 size={12} /> Safe</span>
                              }
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* FIXES */}
            {tab === "fixes" && (
              <div className="gsap-stagger max-w-5xl mx-auto">
                <div className="text-center mb-12">
                  <h2 className="font-drama text-5xl italic leading-none mb-4">Remediation Protocol</h2>
                  <p className="text-base text-ghost/60 font-body max-w-lg mx-auto">Ranked actionable intelligence prioritizing highest CVSS score vectors. Resolve top-down to immediately reduce surface area.</p>
                </div>

                <div className="space-y-6">
                  {fixes.map((d, i) => {
                    const eff = d.effort === "Easy" ? "text-teal-400 border-teal-400/30 bg-teal-400/10" : d.effort === "Medium" ? "text-yellow-500 border-yellow-500/30 bg-yellow-500/10" : "text-red-500 border-red-500/30 bg-red-500/10";
                    const col = SEV[d.sev]?.hex;

                    return (
                      <div key={d.id} className="glass-panel rounded-3xl overflow-hidden border-none shadow-[0_10px_30px_rgba(0,0,0,0.5)] relative">
                        {/* Status accent line */}
                        <div className="absolute left-0 top-0 bottom-0 w-1.5 shadow-[0_0_15px_currentColor]" style={{ backgroundColor: col, color: col }} />

                        <div className="p-8 md:p-10 pl-12 relative z-10">
                          <div className="flex flex-col md:flex-row justify-between md:items-start gap-6 mb-8">
                            <div className="flex gap-6 items-start">
                              <div className="font-drama text-5xl font-bold italic leading-none opacity-40 mt-1">
                                {String(i + 1).padStart(2, '0')}
                              </div>
                              <div>
                                <h3 className="text-2xl font-bold font-head tracking-tight mb-2">{d.name}</h3>
                                <div className="flex items-center gap-3 font-mono text-sm bg-background border border-white/5 rounded-lg px-3 py-1.5 w-max">
                                  <span className="text-red-500/80 line-through">v{d.version}</span>
                                  <ArrowRight size={14} className="text-ghost/40" />
                                  <span className="text-teal-400 font-bold drop-shadow-[0_0_8px_rgba(45,212,191,0.5)]">v{d.fixv}</span>
                                </div>
                              </div>
                            </div>

                            <div className="flex items-center flex-wrap gap-3 self-start">
                              <Chip sev={d.sev} />
                              <span className={`px-3 py-1 border rounded-lg text-xs font-mono font-bold uppercase tracking-widest ${eff}`}>{d.effort} fix</span>
                              <div className="px-4 py-2 border rounded-xl font-mono text-lg font-bold shadow-[inset_0_0_10px_currentColor]" style={{ color: col, borderColor: `${col}40`, backgroundColor: `${col}10` }}>
                                {d.score.toFixed(1)}
                              </div>
                            </div>
                          </div>

                          <div className="mb-8">
                            <p className="text-ghost/70 leading-relaxed font-body text-sm md:text-base border-l-2 border-white/10 pl-4">{d.desc}</p>
                          </div>

                          <div className="bg-[#0A0A14] border border-primary/30 rounded-2xl p-4 flex flex-col md:flex-row justify-between md:items-center gap-4 shadow-[0_0_20px_rgba(123,97,255,0.05)]">
                            <code className="text-primary font-mono text-sm break-all">{d.fix}</code>
                            <div className="shrink-0"><Copy text={d.fix} size="md" /></div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

          </div>
        )}
      </main>

      {/* FOOTER */}
      <footer className="relative z-10 border-t border-white/5 bg-[#0A0A14] rounded-t-[4rem] mt-20 pt-16 pb-8 px-12">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-8 border-b border-white/5 pb-10 mb-8">
          <div className="flex items-center gap-3 opacity-60 hover:opacity-100 transition-opacity">
            <Shield size={24} className="text-primary" />
            <span className="font-head text-xl font-bold tracking-tight">DepShield</span>
          </div>

          <div className="flex items-center gap-3 px-4 py-2 rounded-full border border-white/10 bg-surface/50 font-mono text-xs">
            <span className="w-2 h-2 rounded-full bg-teal-400 shadow-[0_0_8px_#2dd4bf] animate-pulse" />
            <span className="text-ghost/60 uppercase tracking-widest">System Operational</span>
          </div>
        </div>
      </footer>

      <Panel dep={sel} onClose={() => setSel(null)} />
    </>
  );
}
