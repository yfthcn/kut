import { h, s } from './util.js';
import { t } from './i18n.js';

// Cihaz türü simgeleri: 24x24 ızgara, tek çizgi kalınlığı, rengi currentColor'dan alır.
// Etiket kodda tutulmaz; kindLabel() çağrı anında t('kind.<tür>') ile çevirir.
const KINDS = [
  ['phone', [['rect', { x: '7', y: '2', width: '10', height: '20', rx: '2.5' }], ['path', { d: 'M11 18.5h2' }]]],
  ['tablet', [['rect', { x: '4', y: '3', width: '16', height: '18', rx: '2' }], ['path', { d: 'M11 18h2' }]]],
  ['laptop', [['rect', { x: '5', y: '5', width: '14', height: '10', rx: '1.5' }], ['path', { d: 'M2.5 19h19' }]]],
  ['desktop', [['rect', { x: '3', y: '4', width: '18', height: '12', rx: '2' }], ['path', { d: 'M9 20h6M12 16v4' }]]],
  ['tv', [['rect', { x: '3', y: '6', width: '18', height: '12', rx: '2' }], ['path', { d: 'M8 3l4 3 4-3M8 21h8' }]]],
  ['server', [['rect', { x: '3', y: '3', width: '18', height: '7', rx: '2' }], ['rect', { x: '3', y: '14', width: '18', height: '7', rx: '2' }], ['path', { d: 'M7 6.5h.01M7 17.5h.01M12 6.5h6M12 17.5h6' }]]],
  ['other', [['rect', { x: '4', y: '4', width: '16', height: '16', rx: '4' }], ['circle', { cx: '12', cy: '12', r: '2' }]]],
];
const BY = Object.fromEntries(KINDS);

export function kindLabel(k) { return t('kind.' + (k in BY ? k : 'other')); }

export function kindIcon(k, cls = 'kind') {
  const svg = s('svg', { viewBox: '0 0 24 24', class: cls, 'aria-hidden': 'true', focusable: 'false' });
  for (const [tag, attrs] of BY[k] || BY.other) svg.append(s(tag, attrs));
  return svg;
}

// Ada bakıp tür tahmini (yalnızca öneri; kullanıcı elle seçince devreye girmez).
// Anahtar kelimeler bilinçli olarak Türkçe ve İngilizce birlikte: cihaz adı hangi dilde yazılırsa yazılsın tür tahmin edilir.
export function guessKind(name) {
  const n = name.toLocaleLowerCase('tr');
  const has = (...w) => w.some((x) => n.includes(x));
  if (has('tablet', 'ipad')) return 'tablet';
  if (has('telefon', 'phone', 'mobile', 'iphone', 'pixel', 'galaxy', 'xiaomi', 'redmi')) return 'phone';
  if (has('laptop', 'notebook', 'macbook', 'airbook', 'thinkpad', 'dizüstü', 'dizustu')) return 'laptop';
  if (has('tv', 'televizyon', 'television', 'android tv', 'appletv', 'apple tv')) return 'tv';
  if (has('nas', 'server', 'sunucu', 'raspberry', 'rpi', 'proxmox')) return 'server';
  if (has('pc', 'masaüstü', 'masaustu', 'desktop', 'bilgisayar', 'computer', 'workstation')) return 'desktop';
  return '';
}

// Simge seçici: { el, get(), set(k), touched() }
export function kindPicker(value) {
  let cur = value || '';
  let touched = false;
  const btns = new Map();
  const wrap = h('div', { class: 'kindpick', role: 'group', 'aria-label': t('kind.label') });
  const paint = () => { for (const [k, b] of btns) { const on = (cur || 'other') === k; b.classList.toggle('on', on); b.setAttribute('aria-pressed', String(on)); } };
  for (const [k] of KINDS) {
    const l = kindLabel(k);
    const b = h('button', { type: 'button', title: l, 'aria-label': l, onclick: () => { cur = k; touched = true; paint(); } }, kindIcon(k), h('span', {}, l));
    btns.set(k, b); wrap.append(b);
  }
  paint();
  return {
    el: h('div', { class: 'field' }, h('span', { class: 'lbl' }, t('kind.label')), wrap),
    get: () => cur,
    set: (k) => { if (!touched) { cur = k; paint(); } },
  };
}
