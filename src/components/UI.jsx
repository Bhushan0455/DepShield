import { useState, useEffect } from "react";
import { Copy as CopyIcon, Check } from "lucide-react";
import { SEV } from "./Data";

export function Chip({ sev }) {
  const s = SEV[sev] || SEV.SAFE;
  return (
    <span className={`inline-flex items-center px-3 py-1 text-xs font-mono font-bold tracking-wider rounded-full border ${s.bg} ${s.color} ${s.border}`}>
      {sev}
    </span>
  );
}

export function Bar({ score }) {
  const pct = (score / 10) * 100;
  const c = score >= 8 ? "bg-red-500" : score >= 6 ? "bg-orange-500" : score >= 4 ? "bg-yellow-500" : score >= 2 ? "bg-amber-500" : "bg-teal-400";
  const glow = score >= 6 ? `shadow-[0_0_8px_currentColor]` : '';

  return (
    <div className="flex items-center gap-3 w-full">
      <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
        <div className={`h-full ${c} ${glow} rounded-full transition-all duration-1000 ease-out`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-mono font-bold w-7 text-right ${SEV[score >= 8 ? 'CRITICAL' : score >= 6 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'SAFE'].color}`}>
        {score.toFixed(1)}
      </span>
    </div>
  );
}

export function Copy({ text, size = "sm" }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      className={`flex items-center gap-2 rounded-lg font-mono transition-all duration-200 ${ok ? 'text-green-400 bg-green-400/10 border border-green-400/30' : 'text-ghost/60 hover:text-ghost hover:bg-white/5 border border-transparent'
        } ${size === "sm" ? "px-2 py-1 text-xs" : "px-3 py-1.5 text-sm"}`}
      onClick={() => {
        navigator.clipboard.writeText(text);
        setOk(true);
        setTimeout(() => setOk(false), 2000);
      }}
    >
      {ok ? <Check size={14} /> : <CopyIcon size={14} />}
      {ok ? "Copied" : "Copy"}
    </button>
  );
}

export function CountUp({ n, duration = 1400 }) {
  const [v, setV] = useState(0);
  useEffect(() => {
    let t0 = null;
    let req;
    const f = ts => {
      if (!t0) t0 = ts;
      const p = Math.min((ts - t0) / duration, 1);
      setV(Math.floor(p * n));
      if (p < 1) req = requestAnimationFrame(f);
    };
    req = requestAnimationFrame(f);
    return () => cancelAnimationFrame(req);
  }, [n, duration]);
  return <>{v}</>;
}

export function GaugeArc({ value, size = 100 }) {
  const r = (size - 12) / 2;
  const circ = 2 * Math.PI * r;
  const fill = (value / 100) * circ;
  const c = value >= 75 ? "#2dd4bf" : value >= 55 ? "#f59e0b" : value >= 35 ? "#f97316" : "#ef4444";
  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={7} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={c} strokeWidth={7}
          strokeDasharray={`${fill} ${circ}`} strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          className="transition-all duration-1000 ease-out"
          style={{ filter: value > 50 ? `drop-shadow(0 0 6px ${c}66)` : 'none' }} />
        <text x={size / 2} y={size / 2 + 2} textAnchor="middle" dominantBaseline="middle" fill={c} className="font-mono font-bold" fontSize={size / 4}>
          <CountUp n={value} />
        </text>
      </svg>
      <div className="text-[10px] uppercase font-bold tracking-widest text-ghost/40">Security Score</div>
    </div>
  );
}
