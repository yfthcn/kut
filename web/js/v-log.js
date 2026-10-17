import { api, clear, debounce, download, fmtDate, h, toast } from './util.js';
import { fmtDateTime, has, t } from './i18n.js';

const KIND = { login_fail: 'bad', login: 'ok', logout: '', peer_toggle: 'ice', peer_edit: '', peer_create: 'ok', peer_delete: 'bad', peer_regenerate: 'warn' };
// Grup kimlikleri sunucu API'sinin değerleridir; yalnızca etiketleri çevrilir.
const groups = () => ['giris', 'guvenlik', 'cihaz', 'profil', 'hesap', 'ayar', 'sistem'].map((k) => [k, t('logui.group.' + k)]);
const ranges = () => [['0', 'all'], ['3600', 'hour'], ['86400', 'day'], ['604800', 'week']].map(([v, k]) => [v, t('logui.range.' + k)]);

// eventText: kodlu (yeni) olay izleyenin dilinde, kodsuz (eski) olay kayıtlı metniyle gösterilir.
const ROLE = { admin: 'settings.users.role_admin', viewer: 'settings.users.role_viewer' };
const eventText = (e) => {
  if (!(e.code && has(e.code))) return e.text;
  const p = { ...(e.params || {}) };
  if (p.role && ROLE[p.role]) p.role = t(ROLE[p.role]);
  return t(e.code, p);
};

export default {
  async render(el) {
    const st = { q: '', u: '', since: '0', g: new Set(), limit: 300 };
    let seq = 0; // en son istenen yükleme dışındaki yanıtlar atılır
    const box = h('section', { class: 'card flush' });
    const chips = h('div', { class: 'row pills', role: 'group', 'aria-label': t('logui.filter_aria') });
    const search = h('input', { type: 'search', placeholder: t('logui.search_ph'), 'aria-label': t('logui.search_aria') });
    const who = h('select', { 'aria-label': t('logui.account_aria') });
    const range = h('select', { 'aria-label': t('logui.range_aria') }, ranges().map(([v, l]) => h('option', { value: v }, l)));
    const info = h('span', { class: 'muted' });
    const head = h('p', {}, t('logui.intro'));
    const more = h('button', { class: 'btn', type: 'button', onclick: () => { st.limit += 500; load().catch((e) => toast(e.message, true)); } }, t('logui.more'));

    function query() {
      const p = new URLSearchParams();
      if (st.q) p.set('q', st.q);
      if (st.u) p.set('u', st.u);
      if (st.since !== '0') p.set('since', st.since);
      if (st.g.size) p.set('g', [...st.g].join(','));
      return p;
    }
    function exportLog(fmt) {
      const p = query(); p.set('format', fmt);
      return download('/api/activity/export?' + p, 'kut-log.' + fmt);
    }
    const btn = h('button', { class: 'btn', type: 'button' }, t('logui.refresh'));
    el.append(h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, t('logui.title')), head),
      h('div', { class: 'row' }, btn, h('button', { class: 'btn', type: 'button', onclick: () => exportLog('csv') }, t('logui.csv')), h('button', { class: 'btn', type: 'button', onclick: () => exportLog('json') }, t('logui.json')))),
      h('div', { class: 'row filters' }, search, who, range, info), chips, box);

    async function load() {
      more.remove();
      const my = ++seq;
      const p = query(); p.set('limit', String(st.limit));
      const { events, counts, users, total, oldest, log_days: days } = await api('GET', '/api/activity?' + p);
      if (my !== seq) return;
      // hesap listesi
      const keep = st.u;
      clear(who);
      who.append(h('option', { value: '' }, t('logui.all_accounts')), ...(users || []).map((u) => h('option', { value: u }, u)));
      who.value = keep;
      // grup düğmeleri
      clear(chips);
      for (const [k, l] of groups()) {
        const on = st.g.has(k);
        chips.append(h('button', { type: 'button', class: 'pill', 'aria-pressed': String(on),
          onclick: () => { on ? st.g.delete(k) : st.g.add(k); load().catch((e) => toast(e.message, true)); } }, `${l} (${(counts || {})[k] || 0})`));
      }
      if (st.g.size || st.q || st.u || st.since !== '0') {
        chips.append(h('button', { type: 'button', class: 'pill clear', onclick: () => { st.q = ''; st.u = ''; st.since = '0'; st.g.clear(); search.value = ''; range.value = '0'; load().catch((e) => toast(e.message, true)); } }, t('logui.clear_filter')));
      }
      info.textContent = t('logui.showing', { n: events.length });
      head.textContent = t('logui.intro') + ' ' + (days ? t('logui.retention_days', { n: days }) : t('logui.retention_forever')) + (total ? ' · ' + t('logui.total', { n: total }) + (oldest ? ', ' + t('logui.oldest', { date: fmtDateTime(oldest, { day: '2-digit', month: '2-digit', year: 'numeric' }) }) : '') : '') + '. ' + t('logui.settings_hint');
      clear(box);
      if (!events.length) { box.append(h('div', { class: 'empty' }, t('logui.empty'))); return; }
      if (events.length >= st.limit) box.after(more); else more.remove();
      box.append(h('div', { class: 'tablewrap' }, h('table', { class: 'log' }, h('thead', {}, h('tr', {}, ...['time', 'from', 'account', 'event'].map((x) => h('th', {}, t('logui.col.' + x))))),
        h('tbody', {}, events.map((e) => h('tr', {}, h('td', { class: 'mono' }, fmtDate(e.t)), h('td', { class: 'mono' }, e.ip === 'yerel' || e.ip === 'local' ? t('logui.local') : e.ip === 'sistem' ? t('webfix.log_system') : e.ip), h('td', {}, e.u === 'yerel' ? t('logui.local') : e.u || (e.ip === 'sistem' ? t('webfix.log_system') : '')), h('td', {}, h('span', { class: 'chip ' + (KIND[e.kind] || '') }, eventText(e)))))))));
    }
    const onSearch = debounce(() => { st.q = search.value.trim(); load().catch((e) => toast(e.message, true)); }, 250);
    search.addEventListener('input', onSearch);
    who.addEventListener('change', () => { st.u = who.value; load().catch((e) => toast(e.message, true)); });
    range.addEventListener('change', () => { st.since = range.value; load().catch((e) => toast(e.message, true)); });
    btn.onclick = () => load().catch((e) => toast(e.message, true));
    await load();
    return () => { onSearch.cancel(); seq++; };
  },
};
