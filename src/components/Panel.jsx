import { useState, useRef, useEffect } from "react";
import { Copy, Chip } from "./UI";
import { SEV } from "./Data";
import { X, AlertTriangle, ShieldAlert, GitBranch, ArrowRight, Activity, Zap } from "lucide-react";
import gsap from "gsap";

export default function Panel({ dep, onClose }) {
  const [pr, setPr] = useState(false);
  const panelRef = useRef(null);
  const overlayRef = useRef(null);

  useEffect(() => {
    if (!dep) return;
    const ctx = gsap.context(() => {
      // Entrance animation
      gsap.fromTo(overlayRef.current, { opacity: 0 }, { opacity: 1, duration: 0.3, ease: "power2.out" });
      gsap.fromTo(panelRef.current, { x: 500, opacity: 0 }, { x: 0, opacity: 1, duration: 0.5, ease: "power3.out", delay: 0.05 });

      // Stagger children
      gsap.from(".panel-item", {
        y: 20,
        opacity: 0,
        duration: 0.5,
        stagger: 0.08,
        ease: "power2.out",
        delay: 0.2
      });
    }, panelRef);

    return () => ctx.revert();
  }, [dep]);

  const handleClose = () => {
    const ctx = gsap.context(() => {
      gsap.to(overlayRef.current, { opacity: 0, duration: 0.2 });
      gsap.to(panelRef.current, { x: 500, opacity: 0, duration: 0.3, ease: "power2.inOut", onComplete: onClose });
    });
    return () => ctx.revert();
  };

  if (!dep) return null;
  const col = SEV[dep.sev]?.hex || "#2dd4bf";
  const score = dep.score || 0;
  const pct = score / 10;
  const diff = `diff --git a/package.json b/package.json\n--- a/package.json\n+++ b/package.json\n@@ -12,4 +12,4 @@\n   "dependencies": {\n-    "${dep.name}": "^${dep.version}",\n+    "${dep.name}": "^${dep.fixv}",\n   }`;

  return (
    <>
      <div
        ref={overlayRef}
        onClick={handleClose}
        className="fixed inset-0 bg-background/80 backdrop-blur-sm z-[98] transition-opacity"
      />
      <aside
        ref={panelRef}
        className="fixed top-0 right-0 w-full max-w-[500px] h-screen z-[99] bg-surface/95 backdrop-blur-xl border-l border-white/10 overflow-y-auto shadow-[-20px_0_50px_rgba(0,0,0,0.8)]"
        style={{ scrollbarWidth: "thin" }}
      >
        {/* Top bar */}
        <div className="sticky top-0 z-10 px-6 py-5 border-b border-white/10 bg-surface/90 backdrop-blur-md flex justify-between items-start">
          <div>
            <div className="text-2xl font-bold font-head text-ghost tracking-tight flex items-center gap-3">
              {dep.sev === 'CRITICAL' && <AlertTriangle size={24} color={col} className="animate-pulse" />}
              {dep.name}
            </div>
            <div className="text-[13px] text-ghost/60 mt-1 font-mono flex items-center gap-3">
              v{dep.version} <ArrowRight size={14} className="text-ghost/40" /> <span className="text-primary font-bold">v{dep.fixv}</span>
            </div>
            <div className="mt-4 flex gap-2 flex-wrap items-center">
              <Chip sev={dep.sev} />
              <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-white/5 border border-white/10 text-ghost/70 rounded-full text-xs font-mono">
                {dep.maint === "Active" ? "🟢" : dep.maint === "Abandoned" ? "🔴" : "🟡"} {dep.maint}
              </span>
              {dep.breakage_risk && (
                <span className={`inline-flex items-center gap-1.5 px-3 py-1 border rounded-full text-xs font-mono font-bold ${dep.breakage_risk === 'HIGH' ? 'bg-red-500/10 border-red-500/30 text-red-500' : dep.breakage_risk === 'MEDIUM' ? 'bg-amber-500/10 border-amber-500/30 text-amber-500' : 'bg-teal-400/10 border-teal-400/30 text-teal-400'}`}>
                  {dep.breakage_risk === 'HIGH' ? '⚠️ High Breakage Risk' : dep.breakage_risk === 'MEDIUM' ? '⚡ Med Breakage Risk' : '✓ Low Breakage Risk'}
                </span>
              )}
            </div>
          </div>
          <button
            onClick={handleClose}
            className="p-2 text-ghost/50 hover:text-ghost hover:bg-white/10 rounded-full transition-all"
          >
            <X size={20} />
          </button>
        </div>

        <div className="p-6">
          {/* CVEs */}
          {dep.cves?.length > 0 && (
            <div className="panel-item mb-8">
              <p className="text-[11px] font-bold uppercase tracking-widest text-[#ef4444] mb-3 flex items-center gap-2">
                <ShieldAlert size={14} /> Known Exploits
              </p>
              <div className="flex flex-wrap gap-2">
                {dep.cves?.map(c => (
                  <span key={c} className="bg-red-500/10 border border-red-500/30 text-red-500 rounded-md px-3 py-1.5 text-xs font-mono drop-shadow-[0_0_8px_rgba(239,68,68,0.3)]">
                    {c}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Description */}
          <div className="panel-item mb-8">
            <p className="text-[11px] font-bold uppercase tracking-widest text-ghost/40 mb-3 flex items-center gap-2">
              <Activity size={14} /> Vulnerability Details
            </p>
            <div className="bg-[#0A0A14]/60 border border-white/10 rounded-2xl p-5 text-ghost/80 text-[13px] leading-relaxed font-body shadow-inner">
              {dep.desc}
            </div>
          </div>

          {/* CVSS Gauge */}
          <div className="panel-item mb-8 bg-[#0A0A14]/80 border border-white/10 rounded-2xl p-6 flex items-center gap-6 shadow-[0_4px_20px_rgba(0,0,0,0.5)] relative overflow-hidden">
            <div className="absolute top-0 right-0 w-32 h-32 bg-[radial-gradient(ellipse_at_top_right,var(--tw-gradient-stops))] from-white/5 to-transparent blur-xl pointer-events-none" />
            <svg width={120} height={64} viewBox="0 0 200 108" className="drop-shadow-lg">
              <path d="M 20 98 A 80 80 0 0 1 180 98" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={14} strokeLinecap="round" />
              <path d="M 20 98 A 80 80 0 0 1 180 98" fill="none" stroke={col} strokeWidth={14} strokeLinecap="round"
                strokeDasharray={`${pct * 251.3} 251.3`} className="transition-all duration-1000 ease-out"
                style={{ filter: `drop-shadow(0 0 8px color-mix(in srgb, ${col} 60%, transparent))` }} />
              <text x={100} y={78} textAnchor="middle" fill={col} fontSize={36} fontFamily="Fira Code" fontWeight="700">{score.toFixed(1)}</text>
            </svg>
            <div>
              <div className="text-3xl font-bold font-head" style={{ color: col, textShadow: `0 0 15px color-mix(in srgb, ${col} 40%, transparent)` }}>
                {dep.sev}
              </div>
              <div className="text-ghost/40 text-xs mt-1 tracking-wide uppercase font-bold">CVSS Base Score</div>
              <div className="text-ghost/60 text-xs mt-2 font-mono flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-ghost/40" />
                {dep.vulns} CVE{dep.vulns !== 1 ? "s" : ""} · {dep.updated}
              </div>
            </div>
          </div>

          {/* Origin trace */}
          <div className="panel-item mb-8">
            <p className="text-[11px] font-bold uppercase tracking-widest text-ghost/40 mb-3 flex items-center gap-2">
              <GitBranch size={14} /> Origin Trace
            </p>
            <div className="flex items-center flex-wrap gap-2 font-mono text-xs">
              {dep.origin?.map((part, i) => {
                const isLast = i === dep.origin.length - 1;
                return (
                  <span key={i} className="flex items-center gap-2">
                    <span className={`px-3 py-1.5 rounded-lg border flex items-center gap-2 ${isLast
                        ? "bg-red-500/10 border-red-500/30 text-red-500 drop-shadow-[0_0_8px_rgba(239,68,68,0.2)]"
                        : "bg-primary/10 border-primary/20 text-primary"
                      }`}>
                      {isLast && <Zap size={12} className="text-red-500" />}
                      {part}
                    </span>
                    {!isLast && <ArrowRight size={14} className="text-ghost/30 mx-1" />}
                  </span>
                )
              })}
            </div>
          </div>

          {/* ── Usage Summary ── */}
          <div className="panel-item mb-8">
            <p className="text-[11px] font-bold uppercase tracking-widest text-ghost/40 mb-3 flex items-center gap-2">
              <Activity size={14} /> Usage Summary
            </p>
            <div className="bg-[#0A0A14]/60 border border-white/10 rounded-2xl p-5 text-ghost/80 text-[13px] leading-relaxed font-body shadow-inner space-y-3">
              {dep.usage_count > 0 ? (
                <>
                  <div className="flex items-center gap-2">
                    <span className="text-primary font-mono bg-primary/10 border border-primary/20 px-2 py-1 rounded text-xs font-bold">
                      Used in {dep.usage_count} file(s)
                    </span>
                  </div>
                  {dep.usage_files?.length > 0 && (
                    <div className="mt-2">
                      <span className="text-white/60 text-[11px] uppercase tracking-widest block mb-1.5">File Paths:</span>
                      <div className="space-y-1">
                        {dep.usage_files.map((f, i) => (
                          <div key={i} className="text-xs font-mono text-ghost/50 bg-white/[0.03] border border-white/5 px-3 py-1.5 rounded-lg truncate">
                            📄 {f}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {dep.used_apis?.length > 0 && (
                    <div className="mt-2">
                      <span className="text-white/60 text-[11px] uppercase tracking-widest block mb-1.5">Detected API Usage:</span>
                      <div className="flex flex-wrap gap-1.5">
                        {dep.used_apis.map((api, i) => (
                          <span key={i} className="bg-violet-500/10 border border-violet-500/20 text-violet-400 rounded-md px-2 py-0.5 text-[11px] font-mono">
                            .{api}()
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : dep.usage_count === 0 ? (
                <span className="text-amber-400 text-xs font-mono">⚠ No direct imports detected — may be unused or dynamically loaded</span>
              ) : (
                <span className="text-ghost/40 text-xs font-mono">Usage data unavailable (run a deep scan to collect)</span>
              )}
            </div>
          </div>

          {/* ── Impact Level ── */}
          {dep.impact_level && (
            <div className="panel-item mb-8">
              <p className="text-[11px] font-bold uppercase tracking-widest text-ghost/40 mb-3 flex items-center gap-2">
                <Zap size={14} /> Impact Level
              </p>
              <div className="flex items-center gap-3">
                <span className={`inline-flex items-center gap-1.5 px-4 py-2 border rounded-xl text-sm font-bold font-mono ${
                  dep.impact_level === 'HIGH' ? 'bg-red-500/10 border-red-500/30 text-red-400' :
                  dep.impact_level === 'MEDIUM' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
                  'bg-teal-400/10 border-teal-400/30 text-teal-400'
                }`}>
                  {dep.impact_level === 'HIGH' ? '🔴' : dep.impact_level === 'MEDIUM' ? '🟡' : '🟢'} {dep.impact_level}
                </span>
                <span className="text-ghost/60 text-xs">{dep.impact_reason}</span>
              </div>
            </div>
          )}

          {/* ── Why This Breakage Risk? ── */}
          {dep.breakage_reason?.length > 0 && (
            <div className="panel-item mb-8">
              <p className="text-[11px] font-bold uppercase tracking-widest text-ghost/40 mb-3 flex items-center gap-2">
                <AlertTriangle size={14} /> Why This Breakage Risk?
              </p>
              <div className="bg-[#0A0A14]/60 border border-white/10 rounded-2xl p-5 shadow-inner">
                <ul className="space-y-2">
                  {dep.breakage_reason.map((reason, i) => (
                    <li key={i} className="flex items-start gap-2 text-ghost/70 text-[13px]">
                      <span className={`mt-1 w-1.5 h-1.5 rounded-full shrink-0 ${
                        dep.breakage_risk === 'HIGH' ? 'bg-red-500' :
                        dep.breakage_risk === 'MEDIUM' ? 'bg-amber-500' : 'bg-teal-400'
                      }`} />
                      {reason}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {/* ── Smart Advisor ── */}
          {dep.reco && (
            <div className="panel-item mb-8">
              <p className="text-[11px] font-bold uppercase tracking-widest text-ghost/40 mb-3 flex items-center gap-2">
                <Activity size={14} /> Smart Advisor
              </p>
              <div className="bg-gradient-to-br from-[#0A0A14]/80 to-[#0E1025]/80 border border-primary/20 rounded-2xl p-5 text-ghost/80 text-[13px] leading-relaxed shadow-[0_0_20px_rgba(45,212,191,0.05)]">
                {dep.reco}
              </div>
            </div>
          )}

          {/* ── Confidence ── */}
          {dep.confidence && (
            <div className="panel-item mb-8 flex items-center gap-3">
              <span className="text-[11px] font-bold uppercase tracking-widest text-ghost/40">Analysis Confidence:</span>
              <span className={`inline-flex items-center gap-1 px-3 py-1 border rounded-full text-xs font-mono font-bold ${
                dep.confidence === 'HIGH' ? 'bg-teal-400/10 border-teal-400/30 text-teal-400' :
                dep.confidence === 'MEDIUM' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
                'bg-red-500/10 border-red-500/30 text-red-400'
              }`}>
                {dep.confidence === 'HIGH' ? '✓' : dep.confidence === 'MEDIUM' ? '~' : '?'} {dep.confidence}
              </span>
            </div>
          )}

          {/* Fix command */}
          {dep.fix && (
            <div className="panel-item mb-8">
              <p className="text-[11px] font-bold uppercase tracking-widest text-[#2dd4bf] mb-3 flex items-center gap-2">
                <Zap size={14} /> Recommended Fix
              </p>
              <div className="bg-[#0A0A14] border border-[#2dd4bf]/20 rounded-xl p-4 flex justify-between items-center gap-4 shadow-[0_0_15px_rgba(45,212,191,0.05)]">
                <code className="text-[#2dd4bf] text-[13px] break-all font-mono">{dep.fix}</code>
                <Copy text={dep.fix} />
              </div>
            </div>
          )}

          {/* Alternatives */}
          {dep.alts?.length > 0 && (
            <div className="panel-item mb-8">
              <p className="text-[11px] font-bold uppercase tracking-widest text-ghost/40 mb-3 flex items-center gap-2">
                <ArrowRight size={14} /> Safe Alternatives
              </p>
              {dep.alts?.map((a, i) => (
                <div key={i} className="bg-surface/50 border border-white/10 rounded-xl p-4 mb-3">
                  <div className="text-ghost/90 text-[13px] font-bold mb-3 flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-ghost/40" /> {a.name}
                  </div>
                  <div className="bg-[#0A0A14] border border-white/5 rounded-lg px-4 py-3 flex justify-between items-center gap-4">
                    <code className="text-ghost/60 text-xs break-all font-mono">{a.cmd}</code>
                    <Copy text={a.cmd} />
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Generate PR */}
          {dep.fix && (
            <div className="panel-item mt-10">
              <button
                className="w-full btn-vapor-primary py-4 text-[15px] group flex items-center justify-center gap-3"
                onClick={() => setPr(v => !v)}
              >
                {!pr ? (
                  <>✦ Generate Pull Request</>
                ) : (
                  <>▲ Hide PR Diff</>
                )}
              </button>

              {pr && (
                <div className="mt-4 bg-[#0A0A14] border border-white/10 rounded-2xl overflow-hidden shadow-2xl animate-fade-up">
                  <div className="px-5 py-3 border-b border-white/10 flex justify-between items-center bg-white/[0.02]">
                    <span className="text-ghost/40 text-xs font-mono">patch.diff</span>
                    <Copy text={diff} />
                  </div>
                  <pre className="p-5 m-0 text-xs text-ghost/70 overflow-x-auto leading-loose whitespace-pre-wrap font-mono relative">
                    <div className="absolute top-0 left-0 w-1 h-full bg-primary/50 blur-sm" />
                    {diff}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
