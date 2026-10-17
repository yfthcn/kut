// Küçük yardımcılar: DOM kurucu, biçimleyiciler, API, bildirim, diyalog.
import { currentLang, fmtDateTime, has, t } from './i18n.js';
const SVGNS = 'http://www.w3.org/2000/svg';

export function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'hidden') el[k] = !!v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

export function s(tag, attrs = {}, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  for (const kid of kids.flat()) if (kid != null) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return el;
}

// parseSVG: sunucudan gelen SVG metnini DOM düğümüne çevirir; SVG değilse null.
export function parseSVG(txt) {
  const d = new DOMParser().parseFromString(txt, 'image/svg+xml');
  return d.documentElement.nodeName === 'svg' ? document.importNode(d.documentElement, true) : null;
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const clear = (el) => { el.replaceChildren(); return el; };

let onUnauth = () => {};
export function setUnauthHandler(f) { onUnauth = f; }

// api: JSON isteği. body bir Blob/File ise olduğu gibi gönderilir, nesneyse JSON'a çevrilir.
// Hata fırlatıldığında err.data sunucunun JSON gövdesidir (ör. need_pass gibi ek alanlar için).
export async function api(method, path, body, headers = {}) {
  const raw = body instanceof Blob;
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: { 'X-Kut': '1', 'X-Kut-Lang': currentLang(), 'Content-Type': raw ? 'application/octet-stream' : 'application/json', ...headers },
    body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* gövde yok */ }
  if (res.status === 401 && path !== '/api/login') { onUnauth(); throw new Error(t('common.session_expired')); }
  if (!res.ok) {
    const key = data && data.code ? 'err.' + data.code : '';
    const msg = key && has(key) ? t(key, data.params || {}) : (data && data.error) || t('err.http', { status: res.status });
    const e = new Error(msg); e.data = data; e.status = res.status; throw e;
  }
  return data;
}

// saveBlob: Blob'u dosya olarak indirtir. Adres hemen iptal edilirse bazı tarayıcılar indirmeyi kaçırır, bu yüzden 1 sn gecikmeli.
export function saveBlob(blob, filename) {
  const a = h('a', { href: URL.createObjectURL(blob), download: filename });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// download: oturumlu bir API yolunu dosya olarak indirir. headers: ek başlıklar (ör. sahip parolası).
// Hata fırlatmaz, bildirim gösterir; ancak başlık verildiyse ve sunucu 403 dönerse hatayı (e.status, sunucunun
// iletisiyle) fırlatır ki çağıran sahip doğrulama diyaloğunu hata metniyle yeniden açabilsin.
export async function download(path, filename, headers = {}) {
  try {
    const res = await fetch(path, { credentials: 'same-origin', headers: { 'X-Kut': '1', 'X-Kut-Lang': currentLang(), ...headers } });
    if (!res.ok) {
      let data = null;
      try { data = await res.json(); } catch { /* gövde yok */ }
      const key = data && data.code ? 'err.' + data.code : '';
      const msg = key && has(key) ? t(key, data.params || {}) : (data && data.error) || t('err.http', { status: res.status });
      const e = new Error(msg); e.status = res.status; e.data = data; throw e;
    }
    saveBlob(await res.blob(), filename);
  } catch (e) {
    if (e.status === 403 && Object.keys(headers).length) throw e;
    toast(t('common.download_failed', { msg: e.message }), true);
  }
}

export function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + u[i];
}

// reducedMotion: kullanıcı hareketi azaltmayı seçtiyse bütün JS hareketleri atlanır (CSS'teki karşılığı app.css sonunda).
export const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

// countUp: sayıyı eski değerinden yenisine kısa sürede (yavaşlayarak) sayar. İlk değer ve hareket azaltma
// tercihinde doğrudan yazılır. fmt değeri metne çevirir (ör. fmtBytes); ara değerler de onunla yazılır.
export function countUp(el, to, fmt = String, ms = 450) {
  const from = el.kutValue;
  el.kutValue = to;
  cancelAnimationFrame(el.kutRaf);
  if (from === undefined || from === to || reducedMotion() || document.hidden) { el.textContent = fmt(to); return; }
  const t0 = performance.now();
  const step = (now) => {
    const k = Math.min(1, (now - t0) / ms);
    const e = 1 - (1 - k) ** 3;
    el.textContent = fmt(k === 1 ? to : Math.round(from + (to - from) * e));
    if (k < 1) el.kutRaf = requestAnimationFrame(step);
  };
  el.kutRaf = requestAnimationFrame(step);
}

export function fmtRate(bps) { return t('time.rate', { v: fmtBytes(bps) }); }

export function ago(ts, now = Date.now() / 1000) {
  if (!ts) return t('time.never');
  const d = Math.max(0, Math.round(now - ts));
  if (d < 10) return t('time.now');
  if (d < 60) return t('time.ago_s', { n: d });
  if (d < 3600) return t('time.ago_m', { n: Math.floor(d / 60) });
  if (d < 86400) return t('time.ago_h', { n: Math.floor(d / 3600) });
  return t('time.ago_d', { n: Math.floor(d / 86400) });
}

export function until(ts, now = Date.now() / 1000) {
  const d = Math.max(0, Math.round(ts - now));
  if (d < 60) return t('time.in_s', { n: d });
  if (d < 3600) return t('time.in_m', { n: Math.ceil(d / 60) });
  if (d < 86400) return t('time.in_h', { n: Math.round(d / 3600) });
  return t('time.in_d', { n: Math.round(d / 86400) });
}

export function fmtDate(ts) {
  return fmtDateTime(ts, { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}

export function toast(msg, bad = false) {
  const el = h('div', { class: 'toast' + (bad ? ' bad' : ''), role: bad ? 'alert' : 'status' }, msg);
  $('#toasts').append(el);
  setTimeout(() => el.remove(), bad ? 6000 : 3200);
}

// modal: <dialog> açar; kapanınca DOM'dan kaldırır. body: Node. Döner: { close, el }
export function modal(title, body, { wide = false, cls = '', onClose } = {}) {
  const dlg = h('dialog', { class: [wide ? 'wide' : '', cls].join(' ').trim(), 'aria-label': title });
  const close = () => { if (dlg.open) dlg.close(); };
  dlg.append(h('div', { class: 'dlg' },
    h('div', { class: 'dlg-head' }, h('h2', {}, title), h('button', { class: 'btn ghost sm icon-btn', type: 'button', 'aria-label': t('common.close'), title: t('common.close'), onclick: close }, icon('close'))),
    body));
  // Canlı yeniden çizim açan düğmeyi DOM'dan atabilir: odak, kararlı data-focus anahtarıyla yeni düğmeye döner.
  // Açan öğe bağlı olsa da kapalı bir menünün içinde (odaklanamaz) olabilir; bu durumda da anahtara düşülür.
  const opener = document.activeElement;
  const key = opener && opener.dataset ? opener.dataset.focus : '';
  const refocus = (el) => { if (el && typeof el.focus === 'function') { el.focus(); return document.activeElement === el; } return false; };
  dlg.addEventListener('close', () => {
    dlg.remove();
    if (onClose) onClose();
    if (!refocus(opener && opener.isConnected ? opener : null) && key) refocus(document.querySelector('[data-focus="' + CSS.escape(key) + '"]'));
  });
  // Metin seçerken fare dışarı kayıp bırakılırsa kapanmasın: hem basış hem tıklama arka plandaysa kapat.
  let downOn = null;
  dlg.addEventListener('pointerdown', (e) => { downOn = e.target; });
  dlg.addEventListener('click', (e) => { if (e.target === dlg && downOn === dlg) close(); downOn = null; });
  document.body.append(dlg);
  dlg.showModal();
  return { close, el: dlg };
}

// ask: bir yanıt döndüren modal. build(done) gövdeyi üretir; done(v) diyaloğu kapatıp v ile çözer.
// Kapat/dışarı tıklama/Esc ile kapanırsa cancel değeriyle çözülür.
export function ask(title, build, { cancel = null, wide = false } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const fin = (v) => { if (!done) { done = true; resolve(v); } };
    let m;
    const body = build((v) => { fin(v); m.close(); });
    m = modal(title, body, { wide, onClose: () => fin(cancel) });
  });
}

export function confirmBox(title, text, okLabel, danger = true) {
  return ask(title, (done) => h('div', { class: 'form' },
    h('p', {}, text),
    h('div', { class: 'row end' },
      h('button', { class: 'btn', type: 'button', onclick: () => done(false) }, t('common.cancel')),
      h('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), type: 'button', onclick: () => done(true) }, okLabel))), { cancel: false });
}

// debounce: son çağrıdan ms sonra çalışır; dönen işlevin .cancel() ile bekleyen çağrı iptal edilir.
export function debounce(fn, ms) {
  let timer;
  const run = (...a) => { clearTimeout(timer); timer = setTimeout(() => fn(...a), ms); };
  run.cancel = () => clearTimeout(timer);
  return run;
}

// ikonlar: 24x24 çizgi ikonları
const ICONS = {
  panel: 'M4 13h6V4H4zM14 20h6V11h-6zM4 20h6v-4H4zM14 7h6V4h-6z',
  devices: 'M7 3h10a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zM11 18h2',
  shield: 'M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.500-7-10V6z',
  report: 'M5 4h14v16H5zM9 9h6M9 13h6M9 17h3',
  server: 'M4 5h16v5H4zM4 14h16v5H4zM8 7.500h.01M8 16.500h.01',
  settings: 'M4 7h10M18 7h2M4 17h2M10 17h10M14 4v6M6 14v6',
  log: 'M5 5h14M5 10h14M5 15h9M5 20h6',
  info: 'M12 8h.01M11 12h1v5h1M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z',
  more: 'M5 12h.01M12 12h.01M19 12h.01',
  sun: 'M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM12 2v2M12 20v2M4.900 4.900l1.400 1.400M17.700 17.700l1.400 1.400M2 12h2M20 12h2M4.900 19.100l1.400-1.400M17.700 6.300l1.400-1.400',
  moon: 'M20 14.500A8 8 0 0 1 9.500 4 8 8 0 1 0 20 14.500z',
  logout: 'M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 17l-5-5 5-5M5 12h11',
  qr: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 14h2M14 18h2v2M18 18h2v2h-2',
  close: 'M6 6l12 12M18 6L6 18',
  copy: 'M9 9h10v11H9zM5 15V5a1 1 0 0 1 1-1h9',
  download: 'M12 4v11M7 10l5 5 5-5M5 20h14',
  dots: 'M12 5h.01M12 12h.01M12 19h.01',
  chart: 'M4 19h16M7 15l4-5 3 3 5-7',
  edit: 'M4 20h4L19 9l-4-4L4 16zM13.500 6.500l4 4',
};
export function icon(name) {
  return s('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true' }, s('path', { d: ICONS[name] || '' }));
}
