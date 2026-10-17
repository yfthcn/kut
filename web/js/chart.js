import { clear, fmtRate, h, s } from './util.js';
import { fmtDateTime, t } from './i18n.js';

// Saat/tarih biçimi dile göre Intl'den gelir (24 saat sabit: eksen etiketleri dar).
const fmtClock = (ts, long) => fmtDateTime(ts, long
  ? { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }
  : { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });

// Düzgün (monoton) eğri: Fritsch–Carlson; tepeleri aşmaz, negatif değere inmez.
function smooth(pts) {
  const n = pts.length;
  if (n < 3) return pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const dx = [], m = [], tang = [];
  for (let i = 0; i < n - 1; i++) { dx.push(pts[i + 1][0] - pts[i][0] || 1e-6); m.push((pts[i + 1][1] - pts[i][1]) / dx[i]); }
  tang.push(m[0]);
  for (let i = 1; i < n - 1; i++) tang.push(m[i - 1] * m[i] <= 0 ? 0 : (m[i - 1] + m[i]) / 2);
  tang.push(m[n - 2]);
  for (let i = 0; i < n - 1; i++) {
    if (m[i] === 0) { tang[i] = 0; tang[i + 1] = 0; continue; }
    const a = tang[i] / m[i], b = tang[i + 1] / m[i], r = a * a + b * b;
    if (r > 9) { const k = 3 / Math.sqrt(r); tang[i] = k * a * m[i]; tang[i + 1] = k * b * m[i]; }
  }
  let d = `M${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < n - 1; i++) {
    const h3 = dx[i] / 3;
    d += ` C${(pts[i][0] + h3).toFixed(1)} ${(pts[i][1] + tang[i] * h3).toFixed(1)} ${(pts[i + 1][0] - h3).toFixed(1)} ${(pts[i + 1][1] - tang[i + 1] * h3).toFixed(1)} ${pts[i + 1][0].toFixed(1)} ${pts[i + 1][1].toFixed(1)}`;
  }
  return d;
}

function niceMax(v) {
  const e = Math.pow(2, Math.ceil(Math.log2(Math.max(v, 1024))));
  return e;
}

// rates: birikimli sayaç örneklerinden hız noktaları ve kesintiler. Örnek aralığı 3 adımı aşıyorsa panel kapalıydı:
// o aralık nokta değil boşluktur (ortalaması ipucunda). WireGuard panelden bağımsız çalıştığı için o sürede trafik
// gerçekten akmış olabilir; sıfır çizmek yanlış olur, sayaç sıfırlanmışsa fark zaten 0'a kırpılır.
export function rates(smp, interval) {
  const gap = 3 * (interval || 15);
  const T = [], rx = [], tx = [], gaps = [], segs = [];
  let seg = [];
  for (let i = 1; i < smp.length; i++) {
    const dt = Math.max(1, smp[i].t - smp[i - 1].t);
    const r = Math.max(0, (smp[i].rx - smp[i - 1].rx) / dt), x = Math.max(0, (smp[i].tx - smp[i - 1].tx) / dt);
    if (dt > gap) {
      gaps.push({ a: smp[i - 1].t, b: smp[i].t, rx: r, tx: x });
      if (seg.length) segs.push(seg);
      seg = [];
      continue;
    }
    seg.push(T.length);
    T.push(smp[i].t); rx.push(r); tx.push(x);
  }
  if (seg.length) segs.push(seg);
  const lastGap = smp.length > 1 && gaps.length > 0 && gaps[gaps.length - 1].b === smp[smp.length - 1].t;
  return { T, rx, tx, gaps, segs, lastGap };
}

// ticks: [t0, t1] aralığında eşit zaman aralıklı en çok n etiket; aynı metni veren komşular atlanır.
export function ticks(t0, t1, n, fmt) {
  const out = [];
  const k = t1 > t0 ? n : 1;
  for (let j = 0; j < k; j++) {
    const ts = k === 1 ? t0 : t0 + (j * (t1 - t0)) / (k - 1);
    const txt = fmt(ts);
    if (out.length && out[out.length - 1].txt === txt) continue;
    out.push({ ts, txt });
  }
  return out;
}

// Trafik grafiği: hist = { samples: [{t, rx, tx}], interval }. Dönüş: son hız (son aralık kesintiyse null).
// X ekseni zamana bağlıdır; panelin kapalı olduğu aralık taralı bir bant olarak görünür.
// Üzerine gelince (ya da dokununca) o anın hızını, bantta kesintinin süresini ve ortalamasını gösterir.
// range: 'hour' | 'day' | 'week' | 'month' (erişilebilir etiket seçili aralığı söyler); name: cihaz adı (yoksa genel grafik).
export function drawChart(box, hist, range, name) {
  const rl = range ? t('chart.range.' + range) : '';
  const label = !range ? t('chart.aria_default') : name ? t('webfix.chart.aria_named', { name, range: rl }) : t('webfix.chart.aria', { range: rl });
  const smp = hist.samples || [];
  const { T, rx, tx, gaps, segs, lastGap } = rates(smp, hist.interval);
  if (smp.length < 3 || !T.length) { clear(box); box.append(h('p', { class: 'muted' }, t('chart.collecting', { n: hist.interval }))); box._ro?.disconnect(); return null; }
  const D0 = Math.min(T[0], gaps.length ? gaps[0].a : T[0]), D1 = Math.max(T[T.length - 1], gaps.length ? gaps[gaps.length - 1].b : 0);
  const span = Math.max(D1 - D0, 1);
  const long = span > 6 * 3600;
  const first = !box.querySelector('svg');
  const render = (anim) => {
    const W = Math.max(280, Math.round(box.clientWidth || 600)), H = W < 420 ? 170 : 210;
    const L = 58, R = 10, Tp = 10, B = 22;
    const max = niceMax(Math.max(...rx, ...tx) * 1.1);
    const XT = (ts) => L + ((ts - D0) * (W - L - R)) / span;
    const X = (i) => XT(T[i]);
    const Y = (v) => H - B - (v / max) * (H - B - Tp);
    const base = H - B;
    const areaOf = (pts) => smooth(pts) + ` L${pts[pts.length - 1][0].toFixed(1)} ${base} L${pts[0][0].toFixed(1)} ${base} Z`;
    const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img', 'aria-label': label, class: anim ? 'draw' : '' });
    const defs = s('defs');
    for (const [id, cls] of [['gtx', 'g-tx'], ['grx', 'g-rx']]) {
      defs.append(s('linearGradient', { id: id + W, x1: 0, y1: 0, x2: 0, y2: 1 }, s('stop', { offset: '0%', class: cls + ' a' }), s('stop', { offset: '100%', class: cls + ' b' })));
    }
    defs.append(s('pattern', { id: 'gap' + W, width: 6, height: 6, patternUnits: 'userSpaceOnUse', patternTransform: 'rotate(45)' }, s('line', { x1: 0, y1: 0, x2: 0, y2: 6, class: 'gap-hatch' })));
    svg.append(defs);
    for (let k = 0; k <= 3; k++) {
      const v = (max * k) / 3, y = Y(v);
      svg.append(s('line', { x1: L, x2: W - R, y1: y, y2: y, class: 'grid' }), s('text', { x: L - 6, y: y + 3.5, 'text-anchor': 'end' }, k ? fmtRate(v) : '0'));
    }
    for (const g of gaps) svg.append(s('rect', { x: XT(g.a), y: Tp, width: Math.max(1, XT(g.b) - XT(g.a)), height: base - Tp, class: 'gap', fill: `url(#gap${W})` }));
    const tk = ticks(D0, D1, W < 420 ? 3 : 5, (ts) => fmtClock(ts, long));
    tk.forEach((k, j) => svg.append(s('text', { x: XT(k.ts), y: H - 5, 'text-anchor': j === 0 ? 'start' : j === tk.length - 1 && tk.length > 1 ? 'end' : 'middle' }, k.txt)));
    for (const seg of segs) {
      const pr = seg.map((i) => [X(i), Y(rx[i])]), pt = seg.map((i) => [X(i), Y(tx[i])]);
      if (seg.length === 1) { // tek noktalı parça: çizgi oluşmaz, nokta olarak göster
        svg.append(s('circle', { cx: pt[0][0], cy: pt[0][1], r: 2.5, class: 'p-tx' }), s('circle', { cx: pr[0][0], cy: pr[0][1], r: 2.5, class: 'p-rx' }));
        continue;
      }
      svg.append(
        s('path', { d: areaOf(pt), class: 'a-tx', fill: `url(#gtx${W})` }), s('path', { d: smooth(pt), class: 'l-tx' }),
        s('path', { d: areaOf(pr), class: 'a-rx', fill: `url(#grx${W})` }), s('path', { d: smooth(pr), class: 'l-rx' }));
    }
    // etkileşim
    const cross = s('g', { class: 'cross', visibility: 'hidden' });
    const vline = s('line', { y1: Tp, y2: base, class: 'vline' });
    const d1 = s('circle', { r: 4, class: 'pt-rx' }), d2 = s('circle', { r: 4, class: 'pt-tx' });
    const tip = s('g', { class: 'tip' });
    const bg = s('rect', { width: 150, height: 62, rx: 8, class: 'tipbg' });
    const t0 = s('text', { x: 10, y: 17, class: 'tt' }), t1 = s('text', { x: 10, y: 35 }), t2 = s('text', { x: 10, y: 52 });
    tip.append(bg, t0, t1, t2);
    cross.append(vline, d1, d2, tip);
    const hit = s('rect', { x: L, y: Tp, width: W - L - R, height: base - Tp, class: 'hit' });
    svg.append(cross, hit);
    const show = (ev) => {
      const r = svg.getBoundingClientRect();
      const px = ((ev.clientX - r.left) / r.width) * W;
      const at = D0 + ((px - L) / (W - L - R)) * span;
      const g = gaps.find((g) => at > g.a && at < g.b);
      let x;
      if (g) {
        x = Math.max(L, Math.min(W - R, px));
        d1.setAttribute('visibility', 'hidden'); d2.setAttribute('visibility', 'hidden');
        t0.textContent = t('chart.gap', { from: fmtClock(g.a, long || g.b - g.a > 6 * 3600), to: fmtClock(g.b, long || g.b - g.a > 6 * 3600) });
        t1.textContent = t('chart.gap_down', { rate: fmtRate(g.tx) }); t2.textContent = t('chart.gap_up', { rate: fmtRate(g.rx) });
      } else {
        let i = 0;
        for (let j = 1; j < T.length; j++) if (Math.abs(T[j] - at) < Math.abs(T[i] - at)) i = j;
        x = X(i);
        d1.removeAttribute('visibility'); d2.removeAttribute('visibility');
        d1.setAttribute('cx', x); d1.setAttribute('cy', Y(rx[i])); d2.setAttribute('cx', x); d2.setAttribute('cy', Y(tx[i]));
        t0.textContent = fmtClock(T[i], true);
        t1.textContent = t('chart.tip_down', { rate: fmtRate(tx[i]) }); t2.textContent = t('chart.tip_up', { rate: fmtRate(rx[i]) });
      }
      vline.setAttribute('x1', x); vline.setAttribute('x2', x);
      let bw = 150;
      try { bw = Math.max(150, Math.ceil(Math.max(t0.getComputedTextLength(), t1.getComputedTextLength(), t2.getComputedTextLength())) + 20); } catch { /* ölçülemezse sabit genişlik */ }
      bg.setAttribute('width', bw);
      const tx0 = x + 12 + bw > W - R ? Math.max(0, x - 12 - bw) : x + 12;
      tip.setAttribute('transform', `translate(${tx0.toFixed(1)} ${Tp + 4})`);
      cross.setAttribute('visibility', 'visible');
    };
    hit.addEventListener('pointermove', show);
    hit.addEventListener('pointerdown', show);
    hit.addEventListener('pointerleave', () => cross.setAttribute('visibility', 'hidden'));
    clear(box).append(svg);
    box._w = W;
  };
  render(first);
  box._ro?.disconnect();
  if (typeof ResizeObserver !== 'undefined') {
    let raf = 0;
    box._ro = new ResizeObserver(() => { if (Math.abs((box.clientWidth || 0) - (box._w || 0)) < 4) return; cancelAnimationFrame(raf); raf = requestAnimationFrame(() => render(false)); });
    box._ro.observe(box);
  }
  return lastGap ? null : { rx: rx[rx.length - 1], tx: tx[tx.length - 1] };
}
