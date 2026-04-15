import { useState, useEffect, useRef } from "react";
import { ZoomIn, ZoomOut, RotateCcw, Search } from "lucide-react";
import { SEV } from "./Data";

export default function Graph({ deps, onPick }) {
  const [pos, setPos] = useState([]);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [hov, setHov] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState(null);

  const dragStart = useRef(null);
  const posR = useRef([]);
  const velR = useRef([]);

  const W = 1200, H = 700;
  const n = deps.length;
  const R = n > 300 ? 8 : n > 150 ? 11 : n > 60 ? 14 : n > 25 ? 17 : 20;
  const gap = R * 0.8;
  const minDist = (R * 2) + gap;

  useEffect(() => {
    if (!n) return;

    const cx = W / 2, cy = H / 2;
    const radiusX = W / 2 - R - 20;
    const radiusY = H / 2 - R - 20;

    const goldenRatio = (1 + Math.sqrt(5)) / 2;
    const initPos = new Array(n);

    for (let i = 0; i < n; i++) {
      const theta = 2 * Math.PI * i / goldenRatio;
      const phi = Math.acos(1 - (i + 0.5) / n);
      const phiHemi = phi * 0.5;
      const px = Math.sin(phiHemi) * Math.cos(theta);
      const py = Math.sin(phiHemi) * Math.sin(theta);
      initPos[i] = { x: cx + px * radiusX, y: cy + py * radiusY };
    }

    posR.current = initPos;
    velR.current = deps.map(() => ({ vx: 0, vy: 0 }));

    const repStr = minDist * minDist * 1.5;
    const totalFrames = Math.min(150, 50 + n);

    const p = posR.current, v = velR.current;

    // Compute physics synchronously to prevent React render lag
    for (let frame = 0; frame < totalFrames; frame++) {
      const cooling = Math.max(0.15, 1 - frame / totalFrames);

      for (let i = 0; i < n; i++) {
        let fx = 0, fy = 0;
        for (let j = 0; j < n; j++) {
          if (i === j) continue;
          const dx = p[i].x - p[j].x, dy = p[i].y - p[j].y;
          const d2 = dx * dx + dy * dy;
          const d = Math.sqrt(d2) || 0.5;
          if (d < minDist * 3) {
            const force = repStr / Math.max(d2, minDist * minDist * 0.1);
            fx += (dx / d) * force;
            fy += (dy / d) * force;
          }
        }
        fx += (cx - p[i].x) * 0.001;
        fy += (cy - p[i].y) * 0.001;

        const ex = (p[i].x - cx) / radiusX;
        const ey = (p[i].y - cy) / radiusY;
        const ed = ex * ex + ey * ey;
        if (ed > 0.85) {
          const pushBack = (ed - 0.85) * 8;
          fx -= ex * pushBack * radiusX;
          fy -= ey * pushBack * radiusY;
        }

        v[i].vx = (v[i].vx * 0.6 + fx * cooling);
        v[i].vy = (v[i].vy * 0.6 + fy * cooling);

        const spd = Math.sqrt(v[i].vx ** 2 + v[i].vy ** 2);
        if (spd > 4) { v[i].vx *= 4 / spd; v[i].vy *= 4 / spd; }

        p[i].x += v[i].vx;
        p[i].y += v[i].vy;

        p[i].x = Math.max(R + 5, Math.min(W - R - 5, p[i].x));
        p[i].y = Math.max(R + 5, Math.min(H - R - 5, p[i].y));
      }
    }

    setPos(p.map(pt => ({ ...pt })));
    setZoom(1);
    setPan({ x: 0, y: 0 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deps]);

  const onWheel = e => { e.preventDefault(); setZoom(z => Math.max(0.3, Math.min(3, z - e.deltaY * 0.001))); };
  const onMD = e => { setDragging(true); dragStart.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }; };
  const onMM = e => { if (dragging && dragStart.current) setPan({ x: e.clientX - dragStart.current.x, y: e.clientY - dragStart.current.y }); };
  const onMU = () => setDragging(false);

  const hovDep = hov !== null ? deps.find(d => d.id === hov) : null;
  const hovIdx = hov !== null ? deps.findIndex(d => d.id === hov) : -1;
  const maxChars = Math.max(0, Math.floor((R * 2 - 4) / 5));

  const isMatch = (d) => {
    const matchSearch = !search || d.name.toLowerCase().includes(search.toLowerCase());
    const matchSev = !sevFilter || d.sev === sevFilter;
    return matchSearch && matchSev;
  };
  const matchCount = deps.filter(isMatch).length;

  return (
    <div className="flex flex-col gap-6">
      {/* Toolbars */}
      <div className="flex flex-col gap-4">
        <div className="flex items-center gap-3 flex-wrap">
          <button className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/5 hover:bg-white/10 text-ghost text-xs tracking-wide transition-all" onClick={() => setZoom(z => Math.min(z + 0.2, 3))}>
            <ZoomIn size={14} /> Zoom In
          </button>
          <button className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/5 hover:bg-white/10 text-ghost text-xs tracking-wide transition-all" onClick={() => setZoom(z => Math.max(z - 0.2, 0.3))}>
            <ZoomOut size={14} /> Zoom Out
          </button>
          <button className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/5 hover:bg-white/10 text-ghost text-xs tracking-wide transition-all" onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}>
            <RotateCcw size={14} /> Reset
          </button>
          <span className="text-xs font-mono text-ghost/40">{Math.round(zoom * 100)}%</span>

          <div className="ml-auto relative flex items-center">
            <Search className="absolute left-3 text-ghost/40" size={14} />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search package..."
              className="pl-9 pr-8 py-2 w-64 rounded-full bg-surface border border-white/10 text-ghost font-mono text-xs focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 transition-all placeholder:text-ghost/20"
            />
            {search && <button onClick={() => setSearch("")} className="absolute right-3 text-ghost/40 hover:text-ghost transition-colors">✕</button>}
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <button onClick={() => setSevFilter(null)}
            className={`flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-semibold tracking-wide transition-all ${!sevFilter ? 'bg-primary/20 text-primary border border-primary/50 shadow-[0_0_10px_rgba(123,97,255,0.2)]' : 'bg-transparent text-ghost/40 border border-white/10 hover:border-white/20 hover:text-ghost'
              }`}>
            All <span className="font-mono text-[10px] opacity-70">({n})</span>
          </button>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"].map(sev => {
            const active = sevFilter === sev;
            const cnt = deps.filter(d => d.sev === sev).length;
            const details = SEV[sev];
            const hex = details.hex;

            return (
              <button key={sev} onClick={() => setSevFilter(active ? null : sev)}
                className={`flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-semibold tracking-wide transition-all ${active ? `bg-[${hex}]/10 text-[${hex}] border border-[${hex}]/50 drop-shadow-[0_0_8px_${hex}]` : 'bg-transparent text-ghost/40 border border-white/10 hover:border-white/20 hover:text-ghost'
                  }`}
                style={{
                  color: active ? hex : undefined,
                  borderColor: active ? hex : undefined,
                  backgroundColor: active ? `color-mix(in srgb, ${hex} 10%, transparent)` : undefined,
                  boxShadow: active ? `0 0 12px color-mix(in srgb, ${hex} 20%, transparent)` : undefined
                }}>
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: hex, boxShadow: active ? `0 0 6px ${hex}` : `0 0 3px ${hex}44` }} />
                {sev.charAt(0) + sev.slice(1).toLowerCase()}
                <span className="font-mono text-[10px] opacity-70">({cnt})</span>
              </button>
            );
          })}
          {(search || sevFilter) && <span className="text-xs font-mono text-ghost/40 ml-2">{matchCount} of {n} matched</span>}
        </div>
      </div>

      {/* Canvas */}
      <div
        className="border border-white/10 rounded-3xl overflow-hidden bg-[#05050A] shadow-2xl relative"
        onWheel={onWheel} onMouseDown={onMD} onMouseMove={onMM} onMouseUp={onMU} onMouseLeave={onMU}
      >
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full block" style={{ cursor: dragging ? "grabbing" : "grab" }} onClick={() => setHov(null)}>
          <defs>
            <radialGradient id="graphBg" cx="50%" cy="50%">
              <stop offset="0%" stopColor="#0A0A14" />
              <stop offset="100%" stopColor="#05050A" />
            </radialGradient>
            {deps.map((d, i) => pos[i] ? (
              <clipPath key={`cp${d.id}`} id={`clip-${d.id}`}>
                <circle cx={pos[i].x} cy={pos[i].y} r={R - 2} />
              </clipPath>
            ) : null)}
          </defs>

          <rect width={W} height={H} fill="url(#graphBg)" />

          {/* Neon terminal grid */}
          {[...Array(12)].map((_, i) => <line key={`h${i}`} x1={0} y1={(i / 11) * H} x2={W} y2={(i / 11) * H} stroke="rgba(123,97,255,0.03)" strokeWidth={1} />)}
          {[...Array(20)].map((_, i) => <line key={`v${i}`} x1={(i / 19) * W} y1={0} x2={(i / 19) * W} y2={H} stroke="rgba(123,97,255,0.03)" strokeWidth={1} />)}

          {/* Wireframe dome lines */}
          <ellipse cx={W / 2} cy={H / 2} rx={W / 2 - 15} ry={H / 2 - 15} fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth={1} strokeDasharray="4 6" />
          <ellipse cx={W / 2} cy={H / 2} rx={W / 3} ry={H / 3} fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth={1} strokeDasharray="2 8" />

          <g transform={`translate(${W / 2 * (1 - zoom) + pan.x * 0.5},${H / 2 * (1 - zoom) + pan.y * 0.5}) scale(${zoom})`}>
            {/* Edges */}
            {deps.map((d, i) => {
              if (!pos[i]) return null;
              const next = deps[i + 1];
              if (!next) return null;
              const ni = i + 1;
              if (!pos[ni]) return null;
              const isActive = hov === d.id || hov === next.id;
              return <line key={`e${d.id}`} x1={pos[i].x} y1={pos[i].y} x2={pos[ni].x} y2={pos[ni].y}
                stroke={isActive ? "rgba(123,97,255,0.3)" : "rgba(255,255,255,0.02)"}
                strokeWidth={isActive ? 1.5 : 0.5}
                className="transition-all duration-300" />;
            })}

            {/* Nodes */}
            {deps.map((d, i) => {
              if (!pos[i]) return null;
              const { x, y } = pos[i], isH = hov === d.id;
              const matched = isMatch(d);
              const cr = isH ? R + 4 : R;
              const isSearchHit = search && d.name.toLowerCase().includes(search.toLowerCase());
              const col = SEV[d.sev]?.hex || "#2dd4bf";

              return (
                <g key={d.id} onClick={e => { e.stopPropagation(); onPick(d); }}
                  onMouseEnter={() => setHov(d.id)} onMouseLeave={() => setHov(null)}
                  className={`cursor-pointer transition-opacity duration-300 ${matched ? 'opacity-100' : 'opacity-10'}`}>
                  {isH && <circle cx={x} cy={y} r={R + 14} fill="none" stroke={col} strokeWidth={1} strokeOpacity={0.4} className="animate-pulse" />}
                  {isH && <circle cx={x} cy={y} r={R + 8} fill="none" stroke={col} strokeWidth={1} strokeOpacity={0.2} />}
                  <circle cx={x} cy={y} r={cr}
                    fill={`color-mix(in srgb, ${col} 15%, #0A0A14)`}
                    stroke={col} strokeWidth={isH ? 2.5 : isSearchHit ? 2 : 1.5}
                    className="transition-all duration-300"
                    style={{ filter: isH ? `drop-shadow(0 0 15px ${col})` : isSearchHit ? `drop-shadow(0 0 10px ${col})` : `drop-shadow(0 0 4px color-mix(in srgb, ${col} 40%, transparent))` }} />

                  {maxChars >= 2 && (
                    <text x={x} y={y + 1} textAnchor="middle" dominantBaseline="middle" fill={col}
                      fontSize={Math.max(5, Math.min(8, R * 0.7))} fontFamily="Fira Code" fontWeight="700"
                      clipPath={`url(#clip-${d.id})`}
                      style={{ pointerEvents: "none" }}>
                      {d.name.length > maxChars ? d.name.slice(0, maxChars) : d.name}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Tooltip */}
            {hov !== null && hovIdx >= 0 && pos[hovIdx] && (() => {
              const { x, y } = pos[hovIdx], dep = hovDep;
              const col = SEV[dep.sev]?.hex || "#2dd4bf";
              const nameLen = dep.name.length;
              const tw = Math.max(180, Math.min(300, nameLen * 8.5 + 40)), th = 85;
              const tx = x + R + 10 + tw > W ? x - tw - R - 5 : x + R + 12;
              const tyRaw = y - th / 2;
              const ty = Math.max(10, Math.min(H - th - 10, tyRaw));
              const displayName = dep.name.length > 30 ? dep.name.slice(0, 28) + "…" : dep.name;

              return (
                <g style={{ pointerEvents: "none" }}>
                  {/* Floating neon panel */}
                  <rect x={tx} y={ty} width={tw} height={th} rx={12} fill="#0A0A14" stroke={col} strokeWidth={1.5} filter={`drop-shadow(0 10px 25px rgba(0,0,0,0.8)) drop-shadow(0 0 10px color-mix(in srgb, ${col} 30%, transparent))`} />
                  <rect x={tx + 1.5} y={ty + 1.5} width={tw - 3} height={th - 3} rx={10.5} fill={`color-mix(in srgb, ${col} 5%, transparent)`} />

                  <text x={tx + 16} y={ty + 26} fill={col} fontSize={14} fontFamily="Fira Code" fontWeight="700">{displayName}</text>
                  <text x={tx + 16} y={ty + 48} fill="#F0EFF4" fontSize={12} fontFamily="Sora" opacity={0.6}>v{dep.version}</text>
                  <text x={tx + 16} y={ty + 68} fill="#F0EFF4" fontSize={12} fontFamily="Fira Code" opacity={0.8}>Score: {dep.score.toFixed(1)} · {dep.sev}</text>

                  <circle cx={tx + tw - 24} cy={ty + 23} r={4} fill={col} filter={`drop-shadow(0 0 4px ${col})`} />
                </g>
              );
            })()}
          </g>
        </svg>
      </div>
    </div>
  );
}
