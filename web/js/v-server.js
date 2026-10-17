import { api, clear, confirmBox, fmtBytes, h, toast } from './util.js';
import { currentLang, has, t } from './i18n.js';

// Güvenlik duvarı durumu: [chip sınıfı, katalog anahtarı]. Durum adındaki '-' anahtarda '_' olur.
const FW = { ok: 'ok', 'out-of-sync': 'warn', 'no-jump': 'bad', down: 'bad', dry: 'dry' };
const fwChip = (state) => (state in FW ? [FW[state], t('serverui.fw.' + state.replace(/-/g, '_'))] : ['warn', state]);

// Zincir tabloları bu sırayla; açıklama anahtarı zincir adının küçük harfli, '_'li biçimidir.
const CHAINS = ['FORWARD', 'INPUT', 'POSTROUTING', 'KUT-PEERS', 'KUT-IN', 'KUT-ICMP', 'KUT-INET', 'KUT-NAT'];
const chainKey = (c) => 'serverui.fw.chain.' + c.toLowerCase().replace(/-/g, '_');

const POLL_MS = 5000;
const HIT_MS = 600;
const SYSTEM = '\u0000system'; // süzgeç değeri: cihaza bağlı olmayan kurallar (iskelet, ortak KUT-IN/ICMP kuralları)

function kindText(r) {
  if (r.kind === 'skel') {
    const k = 'serverui.fw.skel.' + r.tag.replace(/^kut:skel:/, '');
    return has(k) ? t(k) : r.tag;
  }
  const k = 'serverui.fw.kind.' + r.kind;
  const base = has(k) ? t(k) : r.kind;
  return r.reverse ? base + ' (' + t('serverui.fw.reverse') + ')' : base;
}

function targetText(r) {
  if (r.kind === 'skel') return t('serverui.fw.none');
  if (r.target_name) return r.target_name;
  if (r.target === 'server' || r.target === 'all' || r.target === 'internet') return t('serverui.fw.target.' + r.target);
  return r.target || t('serverui.fw.none');
}

function portText(r) {
  if (!r.proto) return t('serverui.fw.none');
  if (r.proto === 'any') return t('serverui.fw.any');
  return r.proto.toUpperCase() + (r.port ? ' ' + r.port : '');
}

function actionChip(a) {
  const cls = a === 'ACCEPT' ? 'ok' : a === 'DROP' ? 'bad' : 'ice';
  return h('span', { class: 'chip ' + cls }, a);
}

async function copyText(txt) {
  try { await navigator.clipboard.writeText(txt); toast(t('serverui.fw.copied')); } catch { toast(t('serverui.fw.copy_failed'), true); }
}

// rulesView: zincir başına bir tablo, cihaz süzgeci, satır açınca ham iptables satırı. Sayaçlar yerinde güncellenir;
// paket sayısı artan satır kısa süre vurgulanır.
function rulesView(fw) {
  const num = new Intl.NumberFormat(currentLang());
  const wrap = h('div', { class: 'stack' });
  const rows = new Map(); // anahtar -> { tr, pk, by, last }
  let filter = '';
  const open = new Set(); // açık satırların anahtarları (süzgeç değişince korunur)

  const devices = new Map();
  for (const r of fw.rules) {
    if (r.device_id) devices.set(r.device_id, r.device_name || r.device_id);
    if (r.target_name) devices.set(r.target, r.target_name);
  }
  const devList = [...devices].sort((a, b) => a[1].localeCompare(b[1], currentLang()));
  const pills = h('div', { class: 'row pills', role: 'group', 'aria-label': t('serverui.fw.filter_label') });

  const matches = (r) => !filter || (filter === SYSTEM ? !r.device_id : r.device_id === filter || r.target === filter);

  function counterCells(r, row) {
    const c = fw.counters[r.key];
    row.pk.textContent = c ? num.format(c[0]) : t('serverui.fw.none');
    row.by.textContent = c ? fmtBytes(c[1]) : t('serverui.fw.none');
    row.last = c ? c[0] : null;
  }

  function ruleRows(r) {
    const pk = h('td', { class: 'num' });
    const by = h('td', { class: 'num' });
    const btn = h('button', { class: 'rowbtn' + (r.device_id ? '' : ' sys'), type: 'button', 'aria-expanded': String(open.has(r.key)), 'aria-label': t('serverui.fw.show_raw') + ': ' + kindText(r) },
      r.device_name || (r.device_id ? r.device_id : t('serverui.fw.none')));
    const tr = h('tr', { class: 'fwrow' + (r.family === 'ipv6' ? ' v6' : '') },
      h('td', {}, btn, r.family === 'ipv6' ? h('span', { class: 'tag' }, 'IPv6') : null),
      h('td', {}, kindText(r)),
      h('td', { class: 'wrap-any' }, targetText(r)),
      h('td', { class: 'mono' }, portText(r)),
      h('td', {}, actionChip(r.action)),
      pk, by);
    const raw = h('tr', { class: 'fwraw', hidden: !open.has(r.key) },
      h('td', { colspan: '7' }, h('div', { class: 'rawline' },
        h('pre', { class: 'code wrapc flow', 'aria-label': t('serverui.fw.raw') }, r.raw),
        h('button', { class: 'btn sm', type: 'button', onclick: () => copyText(r.raw) }, t('serverui.fw.copy')))));
    const toggle = () => {
      const on = raw.hidden;
      raw.hidden = !on;
      btn.setAttribute('aria-expanded', String(on));
      if (on) open.add(r.key); else open.delete(r.key);
    };
    tr.addEventListener('click', (e) => { if (e.target !== btn && !window.getSelection().toString()) toggle(); });
    btn.addEventListener('click', toggle);
    const row = { tr, pk, by, last: null };
    counterCells(r, row);
    rows.set(r.key, row);
    return [tr, raw];
  }

  function paint() {
    clear(pills);
    if (devList.length) {
      for (const [id, label] of [['', t('serverui.fw.filter_all')], [SYSTEM, t('serverui.fw.filter_system')], ...devList]) {
        pills.append(h('button', { class: 'pill', type: 'button', 'aria-pressed': String(filter === id), onclick: () => { filter = id; paint(); } }, label));
      }
    }
    clear(wrap);
    rows.clear();
    if (fw.simulated) wrap.append(h('p', { class: 'hint' }, t('serverui.fw.simulated')));
    for (const chain of CHAINS) {
      const list = fw.rules.filter((r) => r.chain === chain);
      if (!list.length) continue;
      const shown = list.filter(matches);
      const head = h('thead', {}, h('tr', {}, ...['device', 'kind', 'target', 'port', 'action'].map((c) => h('th', { scope: 'col' }, t('serverui.fw.col.' + c))),
        h('th', { scope: 'col', class: 'num' }, t('serverui.fw.col.packets')), h('th', { scope: 'col', class: 'num' }, t('serverui.fw.col.bytes'))));
      wrap.append(h('section', { class: 'card fwchain' },
        h('h3', { class: 'mono' }, chain),
        h('p', { class: 'sm muted' }, t(chainKey(chain))),
        shown.length
          ? h('div', { class: 'tablewrap' }, h('table', { class: 'fwtable' }, head, h('tbody', {}, ...shown.flatMap(ruleRows))))
          : h('p', { class: 'muted sm' }, t('serverui.fw.chain_empty'))));
    }
  }

  // update: yeni sayaçları yerinde yazar; paket sayısı artan satırı HIT_MS boyunca vurgular.
  function update(counters) {
    fw.counters = counters;
    for (const r of fw.rules) {
      const row = rows.get(r.key);
      if (!row) continue;
      const prev = row.last;
      counterCells(r, row);
      if (prev !== null && row.last !== null && row.last > prev) {
        row.tr.classList.remove('hit');
        void row.tr.offsetWidth; // aynı satır art arda artarsa vurgu yeniden başlasın
        row.tr.classList.add('hit');
        clearTimeout(row.timer);
        row.timer = setTimeout(() => row.tr.classList.remove('hit'), HIT_MS);
      }
    }
  }

  paint();
  return { el: h('div', {}, pills, wrap), update };
}

export default {
  async render(el) {
    const body = h('div', { class: 'stack wrap-any' });
    const apply = h('button', { class: 'btn mut', type: 'button' }, t('serverui.apply'));
    el.append(h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, t('serverui.title')), h('p', {}, t('serverui.intro'))), apply), body);
    let view = null;
    let confOpen = false;
    async function load() {
      const d = await api('GET', '/api/server');
      clear(body);
      const fw = fwChip(d.firewall.state);
      body.append(h('section', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, d.iface), h('span', { class: 'chip ' + (d.dry_run ? 'dry' : d.up ? 'ok' : 'bad') }, d.dry_run ? t('status.dry') : d.up ? t('status.running') : t('serverui.down'))),
        h('dl', { class: 'kv' }, ...[[t('serverui.kv.address'), d.address], [t('serverui.kv.endpoint'), d.endpoint], [t('serverui.kv.public_key'), d.public_key], [t('serverui.kv.conf'), d.conf_path], [t('serverui.kv.mtu'), d.mtu || t('serverui.default')], [t('serverui.kv.listen'), d.listen], [t('serverui.kv.devices'), t('serverui.peers_line', { active: d.peers_active, total: d.peers_total, kernel: d.peers_in_kernel })]]
          .flatMap(([k, v]) => [h('dt', {}, k), h('dd', { class: 'mono' }, String(v))]))));
      body.append(h('section', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, t('serverui.fw.title')), h('span', { class: 'chip ' + fw[0] }, fw[1])),
        d.firewall.detail ? h('p', { class: 'muted sm' }, d.firewall.detail) : null,
        h('p', { class: 'sm muted' }, t('serverui.fw.note'))));
      const rules = d.firewall.rules || [];
      view = rules.length ? rulesView({ rules, counters: d.firewall.counters || {}, simulated: d.firewall.simulated }) : null;
      body.append(h('section', { class: 'fwrules' }, h('h2', {}, t('serverui.fw.rules')), h('p', { class: 'sm muted' }, t('serverui.fw.rules_intro')),
        view ? view.el : h('p', { class: 'muted' }, t('serverui.fw.rules_empty'))));
      // PostUp/PostDown satırlarıyla uzun: varsayılan kapalı, yeniden çizimde açık/kapalı durumu korunur.
      body.append(h('section', { class: 'card' }, h('h2', { class: 'wrap-any' }, d.conf_path), h('p', { class: 'sm muted' }, t('serverui.conf_note')),
        h('details', { class: 'more-info', open: confOpen, ontoggle: (e) => { confOpen = e.target.open; } }, h('summary', {}, t('serverui.conf_show')), h('pre', { class: 'code wrap-any flow' }, d.conf))));
    }
    apply.onclick = async () => {
      if (!(await confirmBox(t('serverui.apply'), t('serverui.apply_text'), t('serverui.apply_ok'), false))) return;
      try { await api('POST', '/api/server/apply'); toast(t('serverui.applied')); await load(); } catch (e) { toast(e.message, true); }
    };
    await load();
    // Sayaçlar yalnızca sekme görünürken yoklanır; görünüm değişince main.js bu temizleyiciyi çağırır.
    let busy = false;
    const timer = setInterval(async () => {
      if (document.hidden || !view || busy) return;
      busy = true;
      try { view.update(await api('GET', '/api/server/counters')); } catch { /* geçici hata: bir sonraki turda yeniden denenir */ } finally { busy = false; }
    }, POLL_MS);
    return () => clearInterval(timer);
  },
};
