import { api, ago, ask, clear, confirmBox, debounce, fmtBytes, fmtDate, fmtRate, h, icon, modal, parseSVG, saveBlob, toast, until } from './util.js';
import { loadPolicies, onStatus, refresh, state } from './store.js';
import { drawChart } from './chart.js';
import { guessKind, kindIcon, kindLabel, kindPicker } from './icons.js';
import { currentLang, fmtDateTime, t } from './i18n.js';

const fileBase = (name) => name.replace(/[^\w.-]+/g, '_') || 'kut';

// Çizici kancası: render() kurar. Kullanıcı eyleminden sonra odak listede kalsa bile liste hemen yenilensin diye.
let forceRepaint = () => {};
const sync = () => { forceRepaint(); return refresh(); };

// tabs: erişilebilir sekme grubu. items: [[etiket, panel]]. Ok tuşlarıyla gezilir.
function tabs(label, items) {
  const list = h('div', { class: 'seg', role: 'tablist', 'aria-label': label });
  const btns = [];
  const select = (i, focus) => btns.forEach((b, k) => {
    const on = k === i;
    b.setAttribute('aria-selected', String(on)); b.tabIndex = on ? 0 : -1; items[k][1].hidden = !on;
    if (on && focus) b.focus();
  });
  items.forEach(([l, panel], i) => {
    const id = 'tab-' + Math.random().toString(36).slice(2, 8);
    panel.setAttribute('role', 'tabpanel'); panel.id = id + '-p'; panel.setAttribute('aria-labelledby', id);
    const b = h('button', { type: 'button', role: 'tab', id, 'aria-controls': id + '-p', onclick: () => select(i) }, l);
    b.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { e.preventDefault(); select((i + (e.key === 'ArrowRight' ? 1 : btns.length - 1)) % btns.length, true); }
    });
    btns.push(b); list.append(b);
  });
  select(0);
  return list;
}

// QR modalı: yapılandırma yalnızca bir kez gösterilir (özel anahtar sunucuda saklanmaz).
function showConfig(res, title = t('devices.config.title')) {
  const svg = res.qr ? parseSVG(res.qr) : null;
  if (svg) { svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', t('devices.aria.qr', { name: res.name })); }
  const base = fileBase(res.name);
  const copy = async () => {
    try { await navigator.clipboard.writeText(res.config); toast(t('devices.config.copied')); } catch { toast(t('devices.config.copy_failed'), true); }
  };
  const qrPanel = h('div', { class: 'qr-panel' },
    svg ? h('div', { class: 'qr' }, svg) : h('p', { class: 'muted' }, t('devices.config.no_qr')),
    h('ol', { class: 'qr-steps' },
      h('li', {}, t('devices.config.step1')),
      h('li', {}, t('devices.config.step2')),
      h('li', {}, t('devices.config.step3'))),
    h('p', { class: 'hint touch-only' }, t('devices.config.touch_hint')));
  const confPanel = h('div', {}, h('pre', { class: 'code wrapc' }, res.config));
  modal(title, h('div', { class: 'form' },
    h('div', { class: 'qr-meta' },
      h('b', {}, res.name),
      h('span', { class: 'mono' }, res.ip), res.ip6 ? h('span', { class: 'mono' }, res.ip6) : null,
      h('span', { class: 'tag' + (res.internet ? ' acc' : '') }, res.internet ? t('devices.config.vpn_inet') : t('devices.config.vpn_only'))),
    tabs(t('devices.config.format'), [[t('devices.config.tab_qr'), qrPanel], [t('devices.config.tab_text'), confPanel]]),
    qrPanel, confPanel,
    h('p', { class: 'notice' }, t('devices.config.notice')),
    h('div', { class: 'row end' },
      svg ? h('button', { class: 'btn', type: 'button', onclick: () => saveBlob(new Blob([res.qr], { type: 'image/svg+xml' }), base + '-qr.svg') }, icon('download'), t('devices.config.save_qr')) : null,
      h('button', { class: 'btn', type: 'button', onclick: copy }, icon('copy'), t('devices.config.copy')),
      h('button', { class: 'btn primary', type: 'button', onclick: () => saveBlob(new Blob([res.config], { type: 'text/plain' }), base + '.conf') }, icon('download'), t('devices.config.download_conf')))),
  { cls: 'qr-dlg' });
}

// Kayıtlı bir cihazın QR'ı yeniden gösterilemez: özel anahtar sunucuda yok. Yolu açıkça söyle.
function qrDialog(p) {
  ask(t('devices.qr.title', { name: p.name }), (done) => h('div', { class: 'form' },
    h('div', { class: 'qr-empty', 'aria-hidden': 'true' }, icon('qr')),
    h('p', {}, t('devices.qr.text')),
    h('p', { class: 'hint' }, t('devices.qr.hint')),
    h('div', { class: 'row end' },
      h('button', { class: 'btn', type: 'button', onclick: () => done(false) }, t('common.cancel')),
      h('button', { class: 'btn primary', type: 'button', onclick: () => done(true) }, t('devices.qr.new_key')))), { cancel: false })
    .then((go) => { if (go) regenDialog(p); });
}

function policySelect(pols, value) {
  const free = !!state.status?.server?.unprofiled_free;
  const sel = h('select', {}, h('option', { value: '' }, t(free ? 'devices.policy.none_free' : 'devices.policy.none')),
    ...pols.map((p) => h('option', { value: p.id }, p.name)));
  sel.value = value || '';
  return sel;
}

const selected = new Set(); // toplu işlem için seçili cihaz kimlikleri
const openInfo = new Set(); // "Ayrıntılar" açık kartlar; yeniden çizimde kapanmasın
let groupFilter = '';

function groupInput(value, groups) {
  const id = 'grp-' + Math.random().toString(36).slice(2, 7);
  const inp = h('input', { type: 'text', maxlength: 32, autocomplete: 'off', placeholder: t('devices.field.group_ph'), value: value || '', list: id });
  return { inp, el: h('label', {}, t('devices.field.group'), inp, h('datalist', { id }, ...groups.map((g) => h('option', { value: g })))) };
}
const groupsOf = (peers) => [...new Set(peers.map((p) => p.group).filter(Boolean))].sort((a, b) => a.localeCompare(b, currentLang()));

// Erişim saatleri: pencere dışında cihaz ya hiç bağlanamaz ya da internete çıkamaz (sunucunun yerel saatiyle).
// Gün kısaltmaları tarayıcının takviminden gelir (dil değişiminde yeniden üretilir); 2024-01-07 pazardır.
const weekdays = () => [1, 2, 3, 4, 5, 6, 0].map((d) => [d, fmtDateTime(new Date(2024, 0, 7 + d).getTime() / 1000, { weekday: 'short' })]);
function scheduleBox(cur) {
  const scope = h('select', {}, h('option', { value: '' }, t('devices.sched.always')), h('option', { value: 'tunnel' }, t('devices.sched.tunnel')), h('option', { value: 'internet' }, t('devices.sched.internet')));
  const from = h('input', { type: 'time', value: cur ? cur.from : '08:00' });
  const to = h('input', { type: 'time', value: cur ? cur.to : '22:00' });
  const dayBoxes = weekdays().map(([d, l]) => ({ d, inp: h('input', { type: 'checkbox', checked: cur ? cur.days.includes(d) : true }), l }));
  scope.value = cur ? cur.scope : '';
  const detail = h('div', { class: 'sched-detail' },
    h('div', { class: 'days' }, ...dayBoxes.map((x) => h('label', { class: 'daychk' }, x.inp, h('span', {}, x.l)))),
    h('div', { class: 'cols' }, h('label', {}, t('devices.sched.start'), from), h('label', {}, t('devices.sched.end'), to)),
    h('p', { class: 'hint' }, state.status && state.status.server.tz ? t('devices.sched.hint_tz', { tz: state.status.server.tz }) : t('devices.sched.hint')));
  const sync = () => { detail.hidden = !scope.value; };
  scope.addEventListener('change', sync); sync();
  return {
    el: h('div', { class: 'form' }, h('label', {}, t('devices.sched.label'), scope), detail),
    // create: schedule|null ; edit/bulk için clear bayrağı
    get: () => (scope.value ? { scope: scope.value, from: from.value, to: to.value, days: dayBoxes.filter((x) => x.inp.checked).map((x) => x.d) } : null),
  };
}

// Misafir/süreli cihaz: süre dolunca cihaz kendiliğinden kapanır.
// Süre etiketleri anahtarla tutulur; metin çağrı anında çevrilir.
const DUR = { 0: 'none', 60: 'h1', 360: 'h6', 480: 'h8', 1440: 'd1', 4320: 'd3', 10080: 'd7', 43200: 'd30' };
const durLabel = (m) => t('devices.dur.' + DUR[m]);
const EXPIRY_MIN = [0, 60, 480, 1440, 4320, 10080, 43200];
function expirySelect(keepLabel) {
  const sel = h('select', {}, ...(keepLabel ? [h('option', { value: '' }, keepLabel)] : []), ...EXPIRY_MIN.map((m) => h('option', { value: String(m) }, m === 0 && keepLabel ? t('devices.dur.make_none') : durLabel(m))));
  sel.value = keepLabel ? '' : '0';
  return sel;
}

async function addDialog() {
  const { policies: pols } = await loadPolicies();
  const sv = state.status.server;
  const name = h('input', { type: 'text', maxlength: 32, required: true, autocomplete: 'off', placeholder: t('devices.add_dlg.name_ph') });
  const note = h('input', { type: 'text', maxlength: 120, autocomplete: 'off', placeholder: t('devices.add_dlg.note_ph') });
  const ip = h('input', { type: 'text', class: 'mono', inputmode: 'decimal', autocomplete: 'off', placeholder: sv.next_ip ? t('devices.add_dlg.ip_auto_ph', { ip: sv.next_ip }) : t('devices.add_dlg.ip_auto') });
  const ipHint = h('p', { class: 'hint' }, t('devices.add_dlg.ip_hint'));
  const pol = policySelect(pols, '');
  const exp = expirySelect();
  const grp = groupInput('', groupsOf(state.status.peers));
  const kp = kindPicker('');
  name.addEventListener('input', () => kp.set(guessKind(name.value)));
  const sch = scheduleBox(null);
  const inet = h('input', { type: 'checkbox' });
  const err = h('p', { class: 'err', role: 'alert' });
  const ok = h('button', { class: 'btn primary', type: 'submit' }, t('devices.add_dlg.submit'));

  let seq = 0;
  const check = debounce(async () => {
    const v = ip.value.trim();
    const my = ++seq;
    if (!v) { ipHint.className = 'hint'; ipHint.textContent = t('devices.add_dlg.ip_hint'); ok.disabled = false; return; }
    try {
      const r = await api('GET', '/api/ipcheck?ip=' + encodeURIComponent(v));
      if (my !== seq) return;
      ipHint.className = 'hint ' + (r.ok ? 'ok' : 'bad');
      ipHint.textContent = r.message;
      ok.disabled = !r.ok;
    } catch (e) { ipHint.textContent = e.message; }
  }, 250);
  ip.addEventListener('input', () => { ok.disabled = true; check(); });

  const form = h('form', { class: 'form' },
    h('label', {}, t('devices.field.name'), name), kp.el,
    h('label', {}, t('devices.field.note'), note),
    h('label', {}, t('devices.field.ip'), ip), ipHint,
    h('label', {}, t('devices.field.policy'), pol), grp.el,
    h('label', {}, t('devices.field.validity'), exp), h('p', { class: 'hint' }, t('devices.add_dlg.guest_hint')),
    sch.el,
    h('label', { class: 'check' }, inet, h('span', {}, t('devices.field.internet'), h('small', {}, t('devices.add_dlg.internet_hint')))),
    err, h('div', { class: 'row end' }, ok));
  const m = modal(t('devices.add_dlg.title'), form);
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); err.textContent = ''; ok.disabled = true;
    try {
      const res = await api('POST', '/api/peers', { name: name.value, note: note.value, internet: inet.checked, ip: ip.value.trim(), policy: pol.value, expires_minutes: parseInt(exp.value, 10), group: grp.inp.value, kind: kp.get(), schedule: sch.get() });
      m.close(); await sync(); showConfig(res, t('devices.config.added'));
    } catch (x) { err.textContent = x.message; ok.disabled = false; }
  });
  name.focus();
}

async function editDialog(p) {
  const { policies: pols } = await loadPolicies();
  const name = h('input', { type: 'text', maxlength: 32, required: true, value: p.name });
  const note = h('input', { type: 'text', maxlength: 120, value: p.note });
  const pol = policySelect(pols, p.policy);
  const grp = groupInput(p.group, groupsOf(state.status.peers));
  const kp = kindPicker(p.kind);
  const sch = scheduleBox(p.schedule);
  const exp = expirySelect(p.expires_at ? (p.state === 'expired' ? t('devices.edit_dlg.keep_expired') : t('devices.edit_dlg.keep_left', { left: until(p.expires_at) })) : t('devices.edit_dlg.keep_none'));
  const err = h('p', { class: 'err', role: 'alert' });
  const form = h('form', { class: 'form' }, h('label', {}, t('devices.field.name'), name), kp.el, h('label', {}, t('devices.field.note'), note),
    h('label', {}, t('devices.field.policy'), pol), grp.el,
    h('label', {}, t('devices.field.validity_now'), exp), sch.el,
    h('p', { class: 'hint' }, t('devices.edit_dlg.policy_hint')),
    err, h('div', { class: 'row end' }, h('button', { class: 'btn primary', type: 'submit' }, t('devices.edit_dlg.save'))));
  const m = modal(t('devices.edit_dlg.title', { name: p.name }), form);
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); err.textContent = '';
    try {
      await api('PATCH', '/api/peers/' + encodeURIComponent(p.id), { name: name.value, note: note.value, policy: pol.value, group: grp.inp.value, kind: kp.get(), ...(sch.get() ? { schedule: sch.get() } : { clear_schedule: true }), ...(exp.value === '' ? {} : { expires_minutes: parseInt(exp.value, 10) }) });
      m.close(); toast(t('devices.toast.saved')); await sync(); await loadPolicies();
    } catch (x) { err.textContent = x.message; }
  });
}

function regenDialog(p) {
  const inet = h('input', { type: 'checkbox', checked: p.internet });
  const ip = h('input', { type: 'text', class: 'mono', value: p.ip });
  const hint = h('p', { class: 'hint' });
  const err = h('p', { class: 'err', role: 'alert' });
  const go = h('button', { class: 'btn danger', type: 'submit' }, t('devices.regen.submit'));
  let seq = 0;
  const check = debounce(async () => {
    const my = ++seq;
    try {
      const r = await api('GET', '/api/ipcheck?ip=' + encodeURIComponent(ip.value.trim()) + '&id=' + encodeURIComponent(p.id));
      if (my !== seq) return;
      hint.className = 'hint ' + (r.ok ? 'ok' : 'bad'); hint.textContent = r.message; go.disabled = !r.ok;
    } catch (x) { if (my === seq) hint.textContent = x.message; }
  }, 250);
  ip.addEventListener('input', () => { go.disabled = true; check(); });
  const form = h('form', { class: 'form' },
    h('p', {}, t('devices.regen.intro_a'), h('b', {}, t('devices.regen.intro_b')), t('devices.regen.intro_c')),
    h('label', {}, t('devices.field.ip'), ip), hint,
    h('label', { class: 'check' }, inet, h('span', {}, t('devices.field.internet'), h('small', {}, t('devices.regen.internet_hint')))),
    err, h('div', { class: 'row end' }, go));
  const m = modal(t('devices.regen.title', { name: p.name }), form);
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); err.textContent = '';
    try {
      const res = await api('POST', '/api/peers/' + encodeURIComponent(p.id) + '/regenerate', { internet: inet.checked, ip: ip.value.trim() });
      m.close(); await sync(); showConfig(res, t('devices.config.new'));
    } catch (x) { err.textContent = x.message; }
  });
}

function freezeDialog(p) {
  const opts = [60, 360, 1440, 10080, 43200].map((m) => [m, durLabel(m)]);
  const custom = h('input', { type: 'number', min: 1, max: 525600, placeholder: t('devices.freeze.minutes_ph') });
  const err = h('p', { class: 'err', role: 'alert' });
  const run = async (min, m) => {
    try { await api('POST', '/api/peers/' + encodeURIComponent(p.id) + '/freeze', { minutes: min }); m.close(); toast(t('devices.toast.frozen')); await sync(); } catch (x) { err.textContent = x.message; }
  };
  const body = h('div', { class: 'form' }, h('p', {}, t('devices.freeze.text')),
    h('div', { class: 'row' }, ...opts.map(([mn, l]) => h('button', { class: 'btn', type: 'button', onclick: () => run(mn, m) }, l))),
    h('div', { class: 'row' }, h('label', {}, t('devices.freeze.custom'), custom), h('button', { class: 'btn primary', type: 'button', onclick: () => run(parseInt(custom.value, 10), m) }, t('devices.freeze.submit'))), err);
  const m = modal(t('devices.freeze.title', { name: p.name }), body);
}

async function act(fn, ok) {
  try { await fn(); if (ok) toast(ok); await sync(); } catch (e) {
    toast(e.message, true);
    forceRepaint(); await refresh().catch(() => {}); // anahtar/seçim sunucu gerçeğine dönsün
  }
}

function inetUse(p) {
  if (!p.internet) return t('devices.inet.use_off');
  if (!p.inet_last) return t('devices.inet.use_idle');
  const age = Date.now() / 1000 - p.inet_last;
  return age < 600 ? t('devices.inet.use_active', { bytes: fmtBytes(p.inet_bytes), ago: ago(p.inet_last) }) : t('devices.inet.use_stale', { ago: ago(p.inet_last) });
}

async function setInternet(p, on, sw) {
  const ok = await confirmBox(on ? t('devices.inet.allow_title') : t('devices.inet.block_title'),
    on ? t('devices.inet.allow_text', { name: p.name }) : t('devices.inet.block_text'),
    on ? t('devices.inet.allow') : t('devices.inet.block'), !on);
  if (!ok) { sw.checked = !on; return; }
  try { await api('PATCH', '/api/peers/' + encodeURIComponent(p.id), { name: p.name, note: p.note, internet: on }); toast(on ? t('devices.inet.allowed') : t('devices.inet.blocked')); await sync(); }
  catch (e) { sw.checked = !on; toast(e.message, true); }
}

function inetBox(p) {
  const sw = h('input', { type: 'checkbox', checked: p.internet, 'data-focus': `peer:${p.id}:inet`, 'aria-label': t('devices.aria.inet', { name: p.name }) });
  sw.addEventListener('change', () => setInternet(p, sw.checked, sw));
  return h('div', { class: 'inet' }, h('div', {}, h('b', {}, t('devices.inet.title')), h('p', { class: 'sm muted' }, inetUse(p))), h('label', { class: 'switch mut' }, sw, h('i')));
}

async function bulk(body, okMsg) {
  try {
    const r = await api('POST', '/api/peers/bulk', { ids: [...selected], ...body });
    toast(t('devices.bulk.done', { msg: okMsg, n: r.count }));
    if (body.action === 'delete') selected.clear();
    await sync(); await loadPolicies();
  } catch (e) { toast(e.message, true); }
}

function bulkDialog(title, control, build, okMsg, label = t('devices.bulk.apply')) {
  const ok = h('button', { class: 'btn primary', type: 'submit' }, label);
  const form = h('form', { class: 'form' }, h('p', { class: 'hint' }, t('devices.bulk.selected_n', { n: selected.size })), control, h('div', { class: 'row end' }, ok));
  const m = modal(title, form);
  form.addEventListener('submit', async (e) => { e.preventDefault(); m.close(); await bulk(build(), okMsg); });
}

async function bulkPolicy() {
  const { policies } = await loadPolicies();
  const sel = policySelect(policies, '');
  bulkDialog(t('devices.bulk.policy_title'), h('label', {}, t('devices.field.policy'), sel), () => ({ action: 'policy', policy: sel.value }), t('devices.bulk.policy_done'));
}

function bulkBar(st, paint) {
  const n = selected.size;
  const bar = h('div', { class: 'bulkbar card' + (n ? ' on' : '') });
  const vis = visiblePeers(st);
  const allOn = vis.length > 0 && vis.every((p) => selected.has(p.id));
  const all = h('input', { type: 'checkbox', checked: allOn, 'aria-label': t('devices.aria.select_all'), onchange: () => { for (const p of vis) (all.checked ? selected.add(p.id) : selected.delete(p.id)); paint(); } });
  bar.append(h('label', { class: 'check inline' }, all, h('span', {}, n ? t('devices.bulk.selected_short', { n }) : t('devices.bulk.select_all'))));
  if (!n) return bar;
  const b = (label, fn, cls = '') => h('button', { class: 'btn sm ' + cls, type: 'button', onclick: fn }, label);
  const days = h('select', {}, ...[60, 1440, 10080, 43200].map((m) => h('option', { value: m }, durLabel(m))));
  const exp = expirySelect();
  const inetSel = h('select', {}, h('option', { value: '1' }, t('devices.inet.allow')), h('option', { value: '0' }, t('devices.inet.block')));
  const gi = groupInput('', groupsOf(st.peers));
  bar.append(h('div', { class: 'row' },
    b(t('devices.bulk.enable'), () => bulk({ action: 'enable' }, t('devices.toast.enabled'))), b(t('devices.bulk.disable'), () => bulk({ action: 'disable' }, t('devices.toast.disabled'))),
    b(t('devices.freeze.submit'), () => bulkDialog(t('devices.freeze.submit'), h('label', {}, t('devices.bulk.duration'), days), () => ({ action: 'freeze', minutes: parseInt(days.value, 10) }), t('devices.toast.frozen'), t('devices.freeze.submit'))),
    b(t('devices.bulk.unfreeze'), () => bulk({ action: 'unfreeze' }, t('devices.toast.unfrozen'))),
    b(t('devices.bulk.policy'), bulkPolicy),
    b(t('devices.bulk.internet'), () => bulkDialog(t('devices.bulk.internet_title'), h('label', {}, t('devices.bulk.server_permission'), inetSel), () => ({ action: 'internet', internet: inetSel.value === '1' }), t('devices.bulk.internet_done'))),
    b(t('devices.bulk.validity'), () => bulkDialog(t('devices.bulk.validity'), h('label', {}, t('devices.bulk.validity_label'), exp), () => ({ action: 'expires', expires_minutes: parseInt(exp.value, 10) }), t('devices.bulk.validity_done'))),
    b(t('devices.bulk.hours'), () => { const sb = scheduleBox(null); bulkDialog(t('devices.sched.label'), sb.el, () => ({ action: 'schedule', schedule: sb.get() }), t('devices.bulk.hours_done')); }),
    b(t('devices.field.group'), () => bulkDialog(t('devices.bulk.group_title'), gi.el, () => ({ action: 'group', group: gi.inp.value }), t('devices.bulk.group_done'))),
    b(t('devices.bulk.delete'), async () => { if (await confirmBox(t('devices.bulk.delete_title'), t('devices.bulk.delete_text', { n }), t('devices.bulk.delete'))) bulk({ action: 'delete' }, t('devices.toast.deleted')); }, 'danger'),
    b(t('devices.bulk.clear'), () => { selected.clear(); paint(); }, 'ghost')));
  return bar;
}

function visiblePeers(st) { return st.peers.filter((p) => !groupFilter || p.group === groupFilter); }

function trafficDialog(p) {
  const box = h('div', { class: 'chart' });
  const cur = h('p', { class: 'mono muted sm' });
  const range = h('select', {}, ...['hour', 'day', 'week', 'month'].map((v) => h('option', { value: v }, t('chart.range.' + v))));
  const load = async () => {
    try {
      const hist = await api('GET', '/api/peers/' + encodeURIComponent(p.id) + '/history?range=' + range.value);
      const r = drawChart(box, hist, range.value, p.name);
      cur.textContent = r ? '↓ ' + fmtRate(r.tx) + '   ↑ ' + fmtRate(r.rx) + '   ' + t('devices.traffic.rates_note') : '';
    } catch (e) { clear(box).append(h('p', { class: 'err' }, e.message)); }
  };
  range.addEventListener('change', load);
  modal(t('devices.traffic.title', { name: p.name }), h('div', { class: 'form' }, h('label', {}, t('devices.traffic.range'), range), box, cur,
    h('p', { class: 'hint' }, t('devices.traffic.hint'))), { wide: true });
  load();
}

// WireGuard ~2 dakikada bir yeniden el sıkışır; sunucu 180 sn'den yeni el sıkışmayı "çevrimiçi" sayar.
const ONLINE_WINDOW = 180;
const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)');

function presence(p) {
  if (p.state === 'outside') return ['warn', t('devices.state.outside')];
  if (p.state === 'expired') return ['bad', t('devices.state.expired')];
  if (p.state === 'frozen') return ['ice', t('devices.state.frozen_for', { left: until(p.frozen_until) })];
  if (p.state === 'disabled') return ['off', t('devices.state.disabled')];
  return p.online ? ['ok', t('devices.state.online')] : ['idle', t('devices.state.offline')];
}

// Tazelik çubuğu: son el sıkışmadan bu yana geçen süre, 180 sn'lik pencerenin ne kadarının kaldığını gösterir.
function freshBar(p, hs) {
  const age = hs ? Date.now() / 1000 - hs : Infinity;
  const left = p.online ? Math.max(0, Math.min(1, 1 - age / ONLINE_WINDOW)) : 0;
  const fill = h('i');
  fill.style.transform = 'scaleX(' + left.toFixed(3) + ')';
  if (left > 0 && !reduceMotion.matches && fill.animate) {
    fill.animate([{ transform: 'scaleX(' + left.toFixed(3) + ')' }, { transform: 'scaleX(0)' }], { duration: left * ONLINE_WINDOW * 1000, easing: 'linear', fill: 'forwards' });
  }
  return h('div', { class: 'fresh', 'aria-hidden': 'true' }, fill);
}

// Taşma menüsü: <details> tabanlı; dışarı tıklayınca ya da Esc ile kapanır.
function menu(label, items, focusKey) {
  const pop = h('div', { class: 'menu-pop' });
  const d = h('details', { class: 'menu mut' }, h('summary', { class: 'btn sm icon-btn', 'aria-label': label, title: label, 'data-focus': focusKey }, icon('dots')), pop);
  for (const it of items) if (it) pop.append(h('button', { type: 'button', class: it.cls || '', disabled: it.disabled, 'data-focus': focusKey, onclick: () => { d.open = false; it.run(); } }, it.label));
  return d;
}
document.addEventListener('click', (e) => {
  for (const d of document.querySelectorAll('details.menu[open]')) if (!d.contains(e.target)) d.open = false;
});
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  for (const d of document.querySelectorAll('details.menu[open]')) { d.open = false; d.querySelector('summary').focus(); }
});

// Zamanlama etiketi: kapsam + saat aralığı; pencere dışındaysa ek not.
function schedTag(p) {
  const label = t(p.schedule.scope === 'internet' ? 'devices.tag.sched_internet' : 'devices.tag.sched_tunnel', { from: p.schedule.from, to: p.schedule.to });
  return p.in_window ? label : t('devices.tag.sched_off', { label });
}

function card(p, repaint) {
  const sw = h('input', { type: 'checkbox', checked: p.enabled, 'aria-label': t('devices.aria.toggle', { name: p.name }), onchange: () => act(() => api('POST', '/api/peers/' + encodeURIComponent(p.id) + '/toggle')) });
  const [pcls, plabel] = presence(p);
  const hs = p.handshake || p.last_seen;
  const row = (k, v) => [h('dt', {}, k), h('dd', {}, v)];
  const pick = h('input', { type: 'checkbox', checked: selected.has(p.id), 'aria-label': t('devices.aria.pick', { name: p.name }), onchange: () => { pick.checked ? selected.add(p.id) : selected.delete(p.id); repaint(); } });
  const io = (k, cap, v) => h('div', { class: 'io-cell' }, h('span', { class: 'io-k' }, k), h('b', { ['data-' + k.toLowerCase()]: true }, fmtBytes(v)), h('small', {}, cap));
  const frozen = p.state === 'frozen';
  const never = !hs && !p.rx && !p.tx; // hiç bağlanmamış: boş sayaç kutuları yerine durum satırı yeter
  return h('article', { 'data-id': p.id, class: 'dev ' + (p.online ? 'online ' : '') + p.state + (selected.has(p.id) ? ' picked' : ''), 'aria-label': t('devices.aria.card', { name: p.name, state: plabel }) },
    h('div', { class: 'dev-head' },
      h('label', { class: 'pick mut' }, pick),
      h('div', { class: 'kindbadge', title: kindLabel(p.kind) }, kindIcon(p.kind)),
      h('div', { class: 'grow' }, h('h3', {}, p.name), h('p', { class: 'dev-sub' }, h('span', { class: 'mono' }, p.ip), p.group ? h('span', { class: 'tag grp' }, p.group) : null)),
      h('label', { class: 'switch mut', title: p.enabled ? t('devices.card.turn_off') : t('devices.card.turn_on') }, sw, h('i'))),
    p.note ? h('p', { class: 'note' }, p.note) : null,
    h('div', { class: 'presence' },
      h('span', { class: 'state ' + pcls }, plabel),
      h('span', { class: 'hs', title: hs ? fmtDate(hs) : '' }, hs ? t('devices.card.handshake', { ago: ago(hs) }) : t('devices.card.no_handshake'))),
    never ? null : freshBar(p, hs),
    never ? null : h('div', { class: 'io' }, io('RX', t('devices.card.rx_cap'), p.rx), io('TX', t('devices.card.tx_cap'), p.tx)),
    h('div', { class: 'tags' },
      h('span', { class: 'tag' + (p.internet ? ' acc' : ''), title: p.internet ? t('devices.tag.inet_on_title') : t('devices.tag.inet_off_title') }, p.internet ? t('devices.tag.inet_on') : t('devices.tag.inet_off')),
      p.policy_name ? h('span', { class: 'tag acc', title: p.policy_src === 'group' ? t('devices.tag.group_policy_title') : '' }, p.policy_src === 'group' ? t('devices.tag.policy_group', { name: p.policy_name }) : p.policy_name) : h('span', { class: 'tag' }, t('devices.tag.no_policy')),
      p.schedule ? h('span', { class: 'tag warn', title: t('devices.tag.sched_title') }, schedTag(p)) : null,
      p.expires_at && p.state !== 'expired' ? h('span', { class: 'tag warn', title: t('devices.tag.guest_title') }, t('devices.tag.guest', { left: until(p.expires_at) })) : null),
    h('details', { class: 'more-info', open: openInfo.has(p.id), ontoggle: (e) => (e.target.open ? openInfo.add(p.id) : openInfo.delete(p.id)) }, h('summary', {}, t('devices.card.details')),
      inetBox(p),
      h('dl', { class: 'kv' },
        ...(p.ip6 ? row('IPv6', h('span', { class: 'mono' }, p.ip6)) : []),
        ...row(t('devices.card.endpoint'), h('span', { class: 'mono' }, p.endpoint || '—')),
        ...row(t('devices.card.last_seen'), ago(p.last_seen)),
        ...row(t('devices.card.added'), fmtDate(new Date(p.created).getTime() / 1000)))),
    h('div', { class: 'dev-foot' },
      h('button', { class: 'btn sm mut', type: 'button', 'data-focus': `peer:${p.id}:qr`, onclick: () => qrDialog(p) }, icon('qr'), t('devices.card.qr')),
      h('button', { class: 'btn sm', type: 'button', 'data-focus': `peer:${p.id}:traffic`, onclick: () => trafficDialog(p) }, icon('chart'), t('devices.card.traffic')),
      h('button', { class: 'btn sm mut', type: 'button', 'data-focus': `peer:${p.id}:edit`, onclick: () => editDialog(p) }, icon('edit'), t('devices.card.edit')),
      menu(t('devices.aria.more', { name: p.name }), [
        { label: frozen ? t('devices.card.unfreeze') : t('devices.card.freeze'), disabled: !p.enabled || p.state === 'expired' || p.state === 'outside', run: () => (frozen ? act(() => api('POST', '/api/peers/' + encodeURIComponent(p.id) + '/unfreeze'), t('devices.toast.unfrozen')) : freezeDialog(p)) },
        { label: t('devices.card.regen'), run: () => regenDialog(p) },
        { label: t('devices.card.delete'), cls: 'danger', run: async () => {
          if (await confirmBox(t('devices.delete.title'), t('devices.delete.text', { name: p.name }), t('devices.bulk.delete'))) act(() => api('DELETE', '/api/peers/' + encodeURIComponent(p.id)), t('devices.toast.deleted'));
        } },
      ], `peer:${p.id}:menu`)));
}

export default {
  async render(el) {
    const list = h('div', { class: 'devs' });
    const bar = h('div', { class: 'mut' });
    const filt = h('div', { class: 'row groupfilter', role: 'group', 'aria-label': t('devices.filter_label') });
    const sum = h('p', {}, t('devices.subtitle'));
    el.append(h('div', { class: 'page-head' },
      h('div', {}, h('h1', {}, t('devices.title')), sum),
      h('button', { class: 'btn primary mut', type: 'button', onclick: () => addDialog().catch((e) => toast(e.message, true)) }, t('devices.add'))), filt, bar, list);
    function paint(st = state.status) {
      pending = null;
      for (const id of [...selected]) if (!st.peers.some((p) => p.id === id)) selected.delete(id); // silinmiş cihazı seçili tutma
      const groups = groupsOf(st.peers);
      if (groupFilter && !groups.includes(groupFilter)) groupFilter = '';
      if (st.peers.length) sum.textContent = t('devices.summary', { n: st.peers.length, online: st.peers.filter((p) => p.online).length });
      clear(filt);
      if (groups.length) {
        for (const g of ['', ...groups]) filt.append(h('button', { class: 'pill', type: 'button', 'aria-pressed': String(groupFilter === g), onclick: () => { groupFilter = g; paint(); } }, g || t('devices.filter_all')));
      }
      clear(bar); if (st.peers.length) bar.append(bulkBar(st, () => paint()));
      clear(list);
      if (!st.peers.length) {
        list.append(h('div', { class: 'card empty' }, h('h2', {}, t('devices.empty_title')), h('p', {}, t('devices.empty_text')),
          h('button', { class: 'btn primary', type: 'button', onclick: () => addDialog().catch((e) => toast(e.message, true)) }, t('devices.add_first'))));
        return;
      }
      for (const p of visiblePeers(st)) list.append(card(p, () => paint()));
    }
    // Yalnızca veri değişince çiz; menü açıkken ya da odak listedeyken çizimi ertele (menü/odak bozulmasın).
    // RX/TX sürekli artar, bu yüzden anahtarda yok: hücreler her durumda yerinde güncellenir. Yalnızca ilk bağlantı
    // (sayaç kutularının ortaya çıkışı) anahtarda.
    let last = '', pending = null, force = false;
    const busy = () => !!list.querySelector('details.menu[open]') || list.contains(document.activeElement);
    const updateIO = (st) => {
      const cards = new Map([...list.querySelectorAll('article.dev')].map((a) => [a.dataset.id, a]));
      for (const p of st.peers) {
        const a = cards.get(String(p.id));
        if (!a) continue;
        const rx = a.querySelector('[data-rx]'), tx = a.querySelector('[data-tx]');
        if (rx) rx.textContent = fmtBytes(p.rx);
        if (tx) tx.textContent = fmtBytes(p.tx);
      }
    };
    const paintIfChanged = (st) => {
      updateIO(st);
      const key = JSON.stringify(st.peers.map((p) => [p.id, p.name, p.note, p.state, p.online, p.internet, p.policy, p.policy_name, p.policy_src, p.ip, p.ip6, Math.floor(p.last_seen / 20), Math.floor(p.inet_last / 60), p.inet_bytes >> 14, p.endpoint, p.kind, p.frozen_until || p.expires_at ? Math.floor(Date.now() / 60000) : 0, p.expires_at, p.group, p.in_window, JSON.stringify(p.schedule), p.handshake || p.last_seen || p.rx || p.tx ? 1 : 0]));
      if (key === last) { pending = null; return; }
      if (!force && busy()) { pending = st; return; }
      force = false; last = key; paint(st);
    };
    const flush = () => setTimeout(() => { if (pending && !busy()) paintIfChanged(pending); }, 0);
    list.addEventListener('toggle', flush, true); // toggle kabarcıklanmaz
    list.addEventListener('focusout', flush);
    forceRepaint = () => { last = ''; force = true; };
    if (state.status) paintIfChanged(state.status);
    const off = onStatus(paintIfChanged);
    return () => { off(); forceRepaint = () => {}; };
  },
};
