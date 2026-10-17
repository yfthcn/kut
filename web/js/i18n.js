// i18n: metinler /locales/<dil>.json'dan gelir (sunucu ikiliye gömülü dosyaları sunar).
// Referans dil en: eksik anahtar ona düşer, o da yoksa anahtar basılır ve konsola uyarı yazılır.
export const LANGS = ['tr', 'en'];
const REF = 'en';
const STORE_KEY = 'kut-lang';
let lang = REF;
let dict = {};
let ref = {};
const listeners = new Set();
let gen = 0; // setLang istek sırası

function flatten(obj, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? prefix + '.' + k : k;
    if (typeof v === 'string') out[key] = v; else flatten(v, key, out);
  }
  return out;
}

async function load(l) {
  const res = await fetch('/locales/' + l + '.json', { credentials: 'same-origin' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return flatten(await res.json());
}

// normLang: "tr-TR" → "tr"; desteklenmeyen dil → "".
function normLang(s) {
  const l = String(s || '').trim().toLowerCase().split(/[-_]/)[0];
  return LANGS.includes(l) ? l : '';
}

// pickLang: adayların ilk desteklenenini döndürür; hiçbiri değilse referans dil.
export function pickLang(...cands) {
  for (const c of cands.flat()) { const l = normLang(c); if (l) return l; }
  return REF;
}

export function storedLang() {
  try { return localStorage.getItem(STORE_KEY) || ''; } catch { return ''; }
}

// setLang: kataloğu yükler, statik metinleri yeniler ve dinleyicileri çağırır (sayfa yenilenmez).
export async function setLang(l, { remember = false } = {}) {
  l = normLang(l) || REF;
  const my = ++gen;
  if (!Object.keys(ref).length) {
    // Referans katalog gelmezse hedef dil yine de uygulanır (eksik anahtar o zaman anahtarın kendisi olur).
    try { ref = await load(REF); } catch (e) { if (l === REF) throw e; }
  }
  const next = l === REF ? ref : await load(l);
  if (my !== gen) return; // daha yeni bir dil isteği var; bu yanıt bayat
  dict = next;
  lang = l;
  document.documentElement.lang = l;
  if (remember) { try { localStorage.setItem(STORE_KEY, l); } catch { /* depolama yok */ } }
  applyStatic();
  listeners.forEach((f) => f(l));
}

export const currentLang = () => lang;

// has: anahtar katalogda (ya da referans dilde, çoğul biçimiyle) var mı.
export function has(key) { return key in dict || key in ref || (key + '.other') in ref; }

export function onLang(f) { listeners.add(f); return () => listeners.delete(f); }

// t: anahtarı çevirir; {ad} yer tutucularını params ile doldurur. params.n sayıysa ve anahtar
// çoğul nesneyse (one/other) dilin çoğul kuralıyla biçim seçilir.
export function t(key, params = {}) {
  if (typeof params.n === 'number' && (key + '.other') in ref) {
    const cat = new Intl.PluralRules(lang).select(params.n);
    key += '.' + ((key + '.' + cat) in dict || (key + '.' + cat) in ref ? cat : 'other');
  }
  const s = dict[key] ?? ref[key];
  if (s == null) {
    if (Object.keys(ref).length) console.warn('i18n: eksik anahtar', key); // katalog yüklenmeden önceki çağrı eksik sayılmaz
    return key;
  }
  return s.replace(/\{([a-z_]+)\}/g, (m, p) => (p in params ? String(params[p]) : m));
}

export function fmtDateTime(ts, opts) {
  return new Intl.DateTimeFormat(lang, opts).format(new Date(ts * 1000));
}

// applyStatic: index.html'deki data-i18n (metin) ve data-i18n-attr ("aria-label:anahtar;placeholder:anahtar").
function applyStatic(root = document) {
  root.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
  root.querySelectorAll('[data-i18n-attr]').forEach((el) => {
    for (const pair of el.dataset.i18nAttr.split(';')) {
      const [attr, key] = pair.split(':');
      el.setAttribute(attr, t(key));
    }
  });
}
