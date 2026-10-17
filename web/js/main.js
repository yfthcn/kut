import { $, api, clear, h, icon, modal, reducedMotion, setUnauthHandler, toast } from './util.js';
import { LANGS, currentLang, has, onLang, pickLang, setLang, storedLang, t } from './i18n.js';
import { onStatus, refresh, startLive, state, stopLive } from './store.js';
import panel from './v-panel.js';
import devices from './v-devices.js';
import policies from './v-policies.js';
import report from './v-report.js';
import server from './v-server.js';
import settings from './v-settings.js';
import log from './v-log.js';
import about from './v-about.js';

const VIEWS = [
  { id: 'panel', label: 'nav.panel', icon: 'panel', mod: panel, main: true },
  { id: 'cihazlar', label: 'nav.devices', icon: 'devices', mod: devices, main: true },
  { id: 'profiller', label: 'nav.access', long: 'nav.access_long', icon: 'shield', mod: policies, main: true },
  { id: 'rapor', label: 'nav.report', long: 'nav.report_long', icon: 'report', mod: report, main: true },
  { id: 'sunucu', label: 'nav.server', icon: 'server', mod: server },
  { id: 'ayarlar', label: 'nav.settings', icon: 'settings', mod: settings },
  { id: 'gunluk', label: 'nav.log', icon: 'log', mod: log },
  { id: 'hakkinda', label: 'nav.about', icon: 'info', mod: about },
];
const longOf = (v) => t(v.long || v.label);

let current = null;
let cleanup = null;
let renderToken = 0;

// ---- Tema ----
// Varsayılan koyu (theme.js ilk boyamadan önce uygular); düğme açık/koyu arasında geçer.
function applyTheme(theme) {
  const light = theme === 'light';
  document.documentElement.dataset.theme = light ? 'light' : 'dark';
  $('meta[name="theme-color"]').content = light ? '#f2f4f3' : '#0d151b';
  const b = $('#theme');
  b.replaceChildren(icon(light ? 'moon' : 'sun'));
  b.setAttribute('aria-pressed', String(light));
  b.setAttribute('aria-label', t(light ? 'theme.to_dark' : 'theme.to_light'));
  b.title = b.getAttribute('aria-label');
}
function toggleTheme() {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  applyTheme(next);
  try { localStorage.setItem('kut-theme', next); } catch { /* yoksay */ }
}
applyTheme(document.documentElement.dataset.theme);
$('#theme').addEventListener('click', toggleTheme);

// ---- Gezinme ----
function navButton(v, kind) {
  const b = h('button', { type: 'button', 'data-view': v.id, onclick: () => go(v.id) }, icon(v.icon), kind === 'side' ? longOf(v) : t(v.label));
  if (v.id === 'rapor') b.append(h('span', { class: 'badge', id: 'bd-' + kind, hidden: true }));
  return b;
}

function buildNav() {
  const nav = clear($('#nav'));
  VIEWS.forEach((v) => nav.append(navButton(v, 'side')));
  const bottom = clear($('#bottom'));
  VIEWS.filter((v) => v.main).forEach((v) => bottom.append(navButton(v, 'bot')));
  bottom.append(h('button', { type: 'button', 'data-view': '_more', onclick: openMore }, icon('more'), t('common.more')));
}

function openMore() {
  const light = () => document.documentElement.dataset.theme === 'light';
  const themeBtn = h('button', { class: 'more-item', type: 'button', onclick: () => { toggleTheme(); paintTheme(); } });
  const paintTheme = () => themeBtn.replaceChildren(icon(light() ? 'moon' : 'sun'), t(light() ? 'theme.dark' : 'theme.light'));
  paintTheme();
  const body = h('div', { class: 'more-list' },
    ...VIEWS.filter((v) => !v.main).map((v) => h('button', { class: 'more-item', type: 'button', 'aria-current': current && current.id === v.id ? 'page' : false, onclick: () => { dlg.close(); go(v.id); } }, icon(v.icon), longOf(v))),
    h('hr', { class: 'sep' }),
    themeBtn,
    h('label', { class: 'more-item' }, t('lang.label'), langSelect(() => dlg.close())),
    h('button', { class: 'more-item', type: 'button', onclick: () => { dlg.close(); $('#logout').click(); } }, icon('logout'), t('common.logout')));
  dlg = modal(t('common.more'), body);
}
let dlg = null;

function markNav(id) {
  document.querySelectorAll('[data-view]').forEach((b) => {
    const on = b.dataset.view === id || (b.dataset.view === '_more' && !VIEWS.find((v) => v.id === id).main);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
}

function go(id) {
  if (location.hash !== '#' + id) location.hash = '#' + id; else show(id);
}

async function show(id, { focus = true } = {}) {
  const v = VIEWS.find((x) => x.id === id) || VIEWS[0];
  if (cleanup) { try { cleanup(); } catch { /* yoksay */ } cleanup = null; }
  current = v;
  const token = ++renderToken;
  markNav(v.id);
  $('#page-title').textContent = longOf(v);
  document.title = longOf(v) + ' · Kut';
  // Her çizim kendi kapsayıcısına yazar: gecikmiş eski görünüm, yenisinin DOM'una karışamaz.
  // İlk veri gelene kadar içeriğin geleceği yerde iskelet yer tutucular durur (görünümün başlığı hemen çizilir).
  const el = h('div', { class: 'view-body' });
  const sk = h('div', { class: 'view-skel', 'aria-hidden': 'true' }, h('i'), h('i'), h('i'));
  const view = $('#view');
  const swap = () => { view.replaceChildren(el, sk); view.setAttribute('aria-busy', 'true'); };
  // Sekmeler arası geçiş: tarayıcı destekliyorsa View Transitions ile kısa bir çapraz geçiş, desteklemiyorsa
  // ya da hareket azaltılmışsa doğrudan değişim. Çizim, yeni kapsayıcı DOM'a girdikten sonra başlar (ölçen kod için).
  if (document.startViewTransition && !reducedMotion() && view.firstChild && !document.hidden) {
    try { await document.startViewTransition(swap).updateCallbackDone; } catch { swap(); }
  } else swap();
  if (token !== renderToken) return;
  try {
    const c = await v.mod.render(el);
    if (token !== renderToken) { if (c) c(); return; }
    cleanup = c || null;
  } catch (e) {
    if (token !== renderToken) return;
    el.append(h('div', { class: 'card' }, h('h2', {}, t('common.page_failed')), h('p', { class: 'muted' }, e.message)));
  } finally {
    sk.remove();
    if (token === renderToken) view.removeAttribute('aria-busy');
  }
  if (token !== renderToken) return;
  window.scrollTo(0, 0);
  if (focus) $('#view').focus({ preventScroll: true }); // ekran okuyucu yeni içeriğe geçsin
}

addEventListener('hashchange', () => { if (!$('#app').hidden) show(location.hash.slice(1)); });

// ---- Durum çubuğu ----
let lastStatus = null;
function paintStatus(st) {
  lastStatus = st;
  const sv = st.server;
  let cls = 'chip ok', txt = t('status.running');
  if (sv.dry_run) { cls = 'chip dry'; txt = t('status.dry'); }
  else if (!sv.up) { cls = 'chip bad'; txt = t('status.iface_down'); }
  for (const c of [$('#chip'), $('#chip-m')]) { c.className = cls; c.textContent = txt; }
  $('#brand-sub').textContent = sv.iface + ' · ' + sv.subnet;
}

async function refreshBadge() {
  try {
    const r = await api('GET', '/api/report');
    const n = (r.counts.fail || 0) + (r.counts.warn || 0);
    for (const id of ['bd-side', 'bd-bot']) {
      const b = document.getElementById(id);
      if (!b) continue;
      b.hidden = n === 0;
      b.textContent = n;
      b.classList.toggle('warn', !r.counts.fail);
    }
  } catch { /* yoksay */ }
}

// ---- Giriş / çıkış ----
function showLogin() {
  stopLive();
  if (cleanup) { try { cleanup(); } catch { /* yoksay */ } cleanup = null; }
  $('#app').hidden = true;
  $('#login').hidden = false;
  resetLogin();
  $('#pw').focus();
}

async function showApp() {
  const me = await api('GET', '/api/me');
  state.me = me;
  const want = pickLang(me.lang, storedLang(), navigator.languages, me.server_lang);
  if (want !== currentLang()) await setLang(want);
  document.body.classList.toggle('viewer', me.role === 'viewer');
  paintWho();
  $('#login').hidden = true;
  $('#app').hidden = false;
  buildNav();
  const st = await refresh();
  paintStatus(st);
  startLive();
  refreshBadge();
  show(location.hash.slice(1) || 'panel');
}

function paintWho() {
  const me = state.me;
  if (me) $('#who').textContent = me.role === 'viewer' ? t('status.who_viewer', { user: me.user }) : me.user;
}

// ---- Dil ----
function langSelect(after) {
  const sel = h('select', { class: 'lang-select', 'aria-label': t('lang.label') },
    ...LANGS.map((l) => h('option', { value: l }, t('lang.' + l))));
  sel.value = currentLang();
  sel.addEventListener('change', async () => { await changeLang(sel.value); if (after) after(); });
  return sel;
}

function fillLangSelect(sel) {
  sel.replaceChildren(...LANGS.map((l) => h('option', { value: l }, t('lang.' + l))));
  sel.value = currentLang();
}

async function changeLang(l) {
  await setLang(l, { remember: true });
  if ($('#app').hidden) return; // giriş ekranı: yalnızca tarayıcıda saklanır
  try { await api('PUT', '/api/me/lang', { lang: l }); } catch (e) { toast(e.message, true); }
}

for (const id of ['#lang-login', '#lang-side']) $(id).addEventListener('change', (e) => changeLang(e.target.value));

onLang(() => {
  fillLangSelect($('#lang-login'));
  fillLangSelect($('#lang-side'));
  applyTheme(document.documentElement.dataset.theme);
  paintLoginErr();
  if ($('#app').hidden) return;
  paintWho();
  buildNav();
  if (lastStatus) paintStatus(lastStatus);
  if (current) show(current.id, { focus: false }); // dil değişiminde odak seçicide kalsın
  refreshBadge();
});

setUnauthHandler(showLogin);
onStatus(paintStatus);
setInterval(() => { if (!$('#app').hidden && !document.hidden) refreshBadge(); }, 60000);

// Giriş hatası kodu ile saklanır ki dil değişince yeniden çevrilebilsin.
let loginErr = null;
function paintLoginErr() {
  const d = loginErr && loginErr.data;
  $('#login-err').textContent = !loginErr ? '' : d && d.code && has('err.' + d.code) ? t('err.' + d.code, d.params || {}) : loginErr.message;
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  loginErr = null; paintLoginErr();
  const second = !$('#code-row').hidden;
  try {
    const r = await api('POST', '/api/login', { username: $('#user').value, password: $('#pw').value, code: second ? $('#code').value : '' });
    if (r && r.totp_required) {
      // Parola doğru; ikinci adım: kodu iste (parola alanında kalır, tekrar yazdırmayız).
      $('#code-row').hidden = false;
      $('#pw').readOnly = true; $('#user').readOnly = true;
      $('#code').focus();
      return;
    }
    resetLogin();
    await showApp();
  } catch (err) { loginErr = err; paintLoginErr(); if (second) { $('#code').select(); } }
});

function resetLogin() {
  $('#pw').value = ''; $('#code').value = '';
  $('#pw').readOnly = false; $('#user').readOnly = false; $('#code-row').hidden = true;
  if (!$('#user').value) $('#user').value = 'admin';
}

$('#logout').addEventListener('click', async () => {
  try { await api('POST', '/api/logout'); } catch { /* yoksay */ }
  showLogin();
});

(async () => {
  let srv = '';
  try { srv = (await api('GET', '/api/login-info')).server_lang; } catch { /* yoksay */ }
  const want = pickLang(storedLang(), navigator.languages, srv);
  try { await setLang(want); } catch (e) {
    console.error(e); // seçilen dilin kataloğu gelmediyse diğerini dene; o da gelmezse giriş ekranı yine açılır
    try { await setLang(LANGS.find((l) => l !== want)); } catch (e2) { console.error(e2); }
  }
  try { await showApp(); } catch { showLogin(); }
})();
