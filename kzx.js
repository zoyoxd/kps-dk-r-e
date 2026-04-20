// run: node kzx.js ||path_to_p.js||
const fs = require("fs");
const vm = require("vm");

const path = process.argv[2];
let src = fs.readFileSync(path, "utf8");

src = src.replace(
  /var\s+r\s*=\s*\[[^\]]+\]\s*;\s*while\s*\(\s*(?:true|!\s*0)\s*\)\s*\{/,
  "$&\nglobal.__leaked={t:t,u:u,P:P,y:y,v:v};break;\n"
);

const box = {
  global: {},
  console: { log() {}, warn() {}, error() {} },
  window: { Promise },
  document: {},
  Proxy, Map, Array, String, Math, Number, Function,
};
vm.createContext(box);
try { vm.runInContext(src, box); } catch {}

const leak = box.global.__leaked;
if (!leak) throw new Error("leak failed");
const { t, u, P, y } = leak;

const kinds = findKinds(src);

function findKinds(s) {
  const g = s.search(/=\s*function\s*\([^)]*\)\s*\{\s*var\s+a\s*=\s*r\[v\[0\]\+\+\]/);
  if (g < 0) throw new Error("g() not found");
  let i = s.indexOf("{", g), d = 0, end = -1;
  for (; i < s.length; i++) {
    if (s[i] === "{") d++;
    else if (s[i] === "}" && --d === 0) { end = i + 1; break; }
  }
  const body = s.slice(g, end);
  const k = Array(6).fill("undef");
  const ne = body.match(/a\s*!==?\s*f\[(\d+)\]/);
  const pats = [
    [/if\s*\(a\s*===\s*f\[(\d+)\]\)\s*\{[^}]*(?:l\.d\(|String\.fromCharCode)/s, "str"],
    [/if\s*\(a\s*===\s*f\[(\d+)\]\)\s*\{[^{}]*Math\.pow\(2,32\)/s, "float"],
    [/if\s*\(a\s*===\s*f\[(\d+)\]\)\s*return\s*!\s*0/, "true"],
    [/if\s*\(a\s*===\s*f\[(\d+)\]\)\s*return\s*!\s*1/, "false"],
    [/if\s*\(a\s*===\s*f\[(\d+)\]\)\s*return\s+null/, "null"],
    [/a\s*===\s*f\[(\d+)\]\s*\?\s*null/, "null"],
    [/a\s*===\s*f\[(\d+)\]\s*\?\s*!\s*0/, "true"],
    [/a\s*===\s*f\[(\d+)\]\s*\?\s*!\s*1/, "false"],
  ];
  for (const [re, kind] of pats) {
    const m = body.match(re);
    if (m) {
      const idx = +m[1];
      if (!(k[idx] && k[idx] !== "undef")) k[idx] = kind;
    }
  }
  if (ne) k[+ne[1]] = "undef";
  return k;
}

function readC(st) {
  let ip = st.ip;
  const a = t[ip++];
  if (a === undefined) { st.ip = ip; return { kind: "undef" }; }
  if (a & 1) { st.ip = ip; return { kind: "num", value: a >> 1 }; }
  for (let i = 0; i < 6; i++) {
    if (a === y[i]) {
      const kind = kinds[i];
      if (kind === "str") {
        const len = t[ip++], off = t[ip++];
        st.ip = ip;
        let v = "";
        try { v = P.N.slice(off, off + len); } catch {}
        return { kind: "str", value: v };
      }
      if (kind === "float") { st.ip = ip + 2; return { kind: "float" }; }
      st.ip = ip;
      return { kind };
    }
  }
  st.ip = ip;
  return { kind: "reg", value: a >> 5 };
}

function classify(fn) {
  const raw = fn.toString();
  const aliases = {};
  let m, re = /(\w+)\s*=\s*r\[(\d+)\]/g;
  while ((m = re.exec(raw)) !== null) aliases[m[1]] = +m[2];
  let norm = raw;
  for (const n in aliases) norm = norm.replace(new RegExp(`\\b${n}\\(`, "g"), `__r${aliases[n]}_(`);
  const c = norm.replace(/\s+/g, "");

  if (/^function\s*\(\)\{returnnull;?\}$/.test(c)) return { sig: [] };
  if (/^function\s*\(n\)\{n\.c=void0;?\}$/.test(c)) return { sig: [] };
  if (c.includes("__r0_") && c.includes("__r1_") && c.includes("_.m")) return { sig: [] };
  if (c.includes("__r0_(n,void0)") && !c.includes("e(n)")) return { sig: [] };
  if (/^function\s*\(n,e\)\{e\(n\)\?e\(n\):\(?n\.X\[0\]=e\(n\)\)?;?\}$/.test(c)) return { sig: ["C","C"] };
  if (/^function\s*\(n,e\)\{e\(n\)\?\(?n\.X\[0\]=e\(n\)\)?:e\(n\);?\}$/.test(c)) return { sig: ["C","C"] };
  if (/^function\s*\(n,e\)\{n\.X\[0\]=e\(n\);?\}$/.test(c)) return { sig: ["C"] };
  if (c.includes("__r1_(n,") && c.includes("e(n)")) return { sig: ["C"] };
  if (c.includes("__r0_(n,") && c.includes("e(n)")) return { sig: ["C"] };
  if (c.includes("n.X[1].o=") || c.includes("n.X[1].S=")) return { sig: ["C"] };
  if (c.includes("o=r.K") && c.includes(".v[i]=o")) return { sig: ["C","S"] };
  if (c.includes(".v[i]=void0") && !c.includes("o=r.K")) return { sig: ["C","S"] };
  if (c.includes('throw"ball"')) {
    return /a\(n,\w\.v\[i\]\)/.test(c) ? { sig: ["C","S","D"] } : { sig: ["C","C","S"] };
  }
  if (c.includes("o.v[i]=r") && c.includes("vari=e(n),r=e(n),o=v(n)")) return { sig: ["C","C","S"] };
  if (/^function\s*\(n,e\)\{e\(n\)\[e\(n\)\]=e\(n\);?\}$/.test(c)) return { sig: ["C","C","C"], set: true };
  if (c.includes("Object.defineProperty") || c.includes("d[s]={H:l")) return { sig: ["C","C","C","S","D"] };
  if (c.includes("l[h]&&l[h].C===l")) return { sig: ["C","C","C"] };
  if (c.includes("Function.bind.apply")) return { sig: ["C","C","D"] };
  if (c.includes("i.push(r)") && c.includes("a(n,i)")) return { sig: ["C","D"] };

  const aM = /\ba\s*\(\s*n\s*,/.exec(norm);
  if (!aM) return { sig: [] };
  let s0 = aM.index + aM[0].length, d = 1, e0 = s0;
  while (e0 < norm.length && d > 0) {
    const ch = norm[e0];
    if (ch === "(") d++;
    else if (ch === ")" && --d === 0) break;
    e0++;
  }
  if (d !== 0) return { sig: [] };
  let er = norm.slice(s0, e0);
  const vars = [];
  let mv, vr = /(?:\bvar\s+|,\s*)(\w+)\s*=\s*e\(n\)/g;
  while ((mv = vr.exec(norm)) !== null) vars.push(mv[1]);
  for (const n of vars) er = er.replace(new RegExp(`\\b${n}\\b`, "g"), "e(n)");
  let ex = er.replace(/\s+/g, "");
  while (ex.startsWith("(") && ex.endsWith(")")) {
    let dp = 0, ok = true;
    for (let i = 0; i < ex.length - 1; i++) {
      if (ex[i] === "(") dp++;
      else if (ex[i] === ")" && --dp === 0) { ok = false; break; }
    }
    if (ok) ex = ex.slice(1, -1); else break;
  }

  const atoms = {
    "e(n)": ["C","D"],
    "__r5_(n)": ["R","D"],
    "[]": ["D"],
    "{}": ["D"],
    "n.c&&n.c.U": ["D"],
    "n.X[1].Q": ["D"],
    "i[1][0]": ["D"],
    "i[1][1]": ["D"],
    "i[0][e(n)]": ["G","D"],
    "newArray(e(n))": ["C","D"],
    "newRegExp(e(n),e(n))": ["C","C","D"],
    "typeofe(n)": ["C","D"],
    "!e(n)": ["C","D"],
    "~e(n)": ["C","D"],
    "+e(n)": ["C","D"],
    "e(n)[e(n)]": ["C","C","D"],
  };
  if (atoms[ex]) return { sig: atoms[ex] };

  const cm = ex.match(/^e\(n\)\((.*)\)$/);
  if (cm) {
    const inner = cm[1];
    if (inner === "") return { sig: ["C","D"] };
    let dp = 0, n = 1;
    for (const ch of inner) {
      if (ch === "(") dp++;
      else if (ch === ")") dp--;
      else if (ch === "," && dp === 0) n++;
    }
    return { sig: Array(n + 1).fill("C").concat(["D"]) };
  }

  if (/^deletee\(n\)\[e\(n\)\]$/.test(ex)) return { sig: ["C","C","D"] };

  const binops = ["===","!==",">>>", "==","!=",">=","<=","<<",">>","instanceof","in","+","-","*","/","%","|","&","^",">","<"];
  for (const op of binops) {
    const esc = op.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
    const r2 = new RegExp(`^(e\\(n\\)|__r5_\\(n\\))${esc}(e\\(n\\)|__r5_\\(n\\))$`);
    const bm = ex.match(r2);
    if (bm) return { sig: [bm[1] === "e(n)" ? "C" : "R", bm[2] === "e(n)" ? "C" : "R", "D"] };
  }
  return { sig: [] };
}

const info = {};
for (const op of new Set(t)) {
  let h;
  try { h = u[op]; } catch { continue; }
  if (typeof h === "function") info[op] = classify(h);
}

let version = null, kzx = null, ip = 0;
while (ip < t.length) {
  const op = t[ip++];
  const it = info[op];
  if (!it) continue;
  const st = { ip };
  const args = [];
  for (const kind of it.sig) {
    if (kind === "C" || kind === "G") args.push(readC(st));
    else { st.ip++; args.push(null); }
  }
  ip = st.ip;
  if (it.set) {
    const k = args[1], v = args[2];
    if (k && k.kind === "str" && v && v.kind === "str") {
      if (!version && /^j-\d+\.\d+\.\d+$/.test(v.value)) version = v.value;
      else if (!kzx && /^[0-9a-f]{64}$/i.test(v.value)) kzx = v.value;
    }
  }
  if (version && kzx) break;
}

if (!version || !kzx) throw new Error(`incomplete (version=${version}, kzx=${kzx})`);
process.stdout.write(JSON.stringify({ version, kzx }));
