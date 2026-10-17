import { ago, api, clear, countUp, fmtBytes, fmtRate, h, s } from './util.js';
import { onStatus, state } from './store.js';
import { drawChart } from './chart.js';
import { kindIcon } from './icons.js';
import { t } from './i18n.js';

const isOff = (p) => p.state === 'disabled' || p.state === 'expired' || p.state === 'outside';

// Ağ haritası: ortada sunucu, çevresinde cihazlar. Çevrimiçi cihazın hattı akar.
function drawMap(box, st) {
  clear(box);
  const peers = st.peers;
  const W = 420, H = 300, cx = W / 2, cy = H / 2;
  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'map', role: 'img', 'aria-label': t('panel.map.aria') });
  const n = peers.length;
  const R = Math.min(105, 62 + n * 8);
  const nodes = peers.map((p, i) => {
    const a = (-Math.PI / 2) + (2 * Math.PI * i) / Math.max(n, 1);
    return { p, x: cx + R * 1.45 * Math.cos(a), y: cy + R * Math.sin(a) };
  });
  for (const nd of nodes) svg.append(s('line', { x1: cx, y1: cy, x2: nd.x, y2: nd.y, class: 'link' + (nd.p.online ? ' on' : '') }));
  svg.append(s('circle', { cx, cy, r: 38, class: 'hub' }), s('text', { x: cx, y: cy - 4, 'text-anchor': 'middle', 'font-weight': 700 }, t('panel.map.server')), s('text', { x: cx, y: cy + 13, 'text-anchor': 'middle', class: 'sub' }, st.server.server_ip));
  for (const nd of nodes) {
    const cls = nd.p.state === 'frozen' ? 'frozen' : isOff(nd.p) ? 'off' : nd.p.online ? 'on' : '';
    const nm = nd.p.name.length > 14 ? nd.p.name.slice(0, 13) + '…' : nd.p.name;
    // Ad, düğümün sunucudan uzak yanına yazılır: üst yarıda düğümün üstüne, alt yarıda altına; böylece hat üstünden geçmez.
    const ly = nd.y < cy - 1 ? nd.y - 25 : nd.y + 33;
    svg.append(s('circle', { cx: nd.x, cy: nd.y, r: 17, class: 'node ' + cls }),
      s('text', { x: nd.x, y: nd.y + 3.5, 'text-anchor': 'middle', class: 'sub' }, '.' + nd.p.ip.split('.').pop()),
      s('text', { x: nd.x, y: ly, 'text-anchor': 'middle', class: 'lbl' }, nm));
  }
  box.append(svg);
  if (!n) box.append(h('p', { class: 'muted sm' }, t('panel.map.empty')));
}

export default {
  async render(el) {
    const wrap = h('div', { class: 'stack' });
    const stats = h('div', { class: 'stats' });
    const mapBox = h('div');
    const attn = h('ul', { class: 'todo' });
    const chartBox = h('div', { class: 'chart' });
    const now = h('span', { class: 'mono muted' });
    const range = h('select', { 'aria-label': t('panel.range_label'), class: 'sm' }, ...['hour', 'day', 'week', 'month'].map((v) => h('option', { value: v }, t('chart.range.' + v))));
    const liveList = h('div', { class: 'tablewrap' });

    el.append(h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, t('panel.title')), h('p', {}, t('panel.subtitle')))), wrap);
    wrap.append(stats,
      h('div', { class: 'hero' },
        h('section', { class: 'card' }, h('h2', {}, t('panel.map.title')), mapBox),
        h('section', { class: 'card' }, h('h2', {}, t('panel.attention')), attn)),
      h('section', { class: 'card' },
        h('div', { class: 'card-head' }, h('h2', {}, t('panel.traffic')), h('div', { class: 'row' }, now, range)),
        chartBox,
        h('div', { class: 'legend' }, h('span', {}, h('i', { class: 'dot ok' }), t('panel.legend_up')), h('span', {}, h('i', { class: 'dot info' }), t('panel.legend_down')))),
      h('section', { class: 'card flush' }, liveList));

    function paint(st) {
      const ps = st.peers;
      const on = ps.filter((p) => p.online).length;
      const total = ps.reduce((a, p) => a + p.rx + p.tx, 0);
      stat('devices', ps.length, t('panel.stat.devices'));
      stat('online', on, t('devices.state.online'), 'ok');
      stat('frozen', ps.filter((p) => p.state === 'frozen').length, t('devices.state.frozen'), 'ice');
      stat('off', ps.filter(isOff).length, t('panel.stat.off'));
      stat('internet', ps.filter((p) => p.internet).length, t('panel.stat.internet'));
      stat('total', total, t('panel.stat.total'), '', fmtBytes);
      drawMap(mapBox, st);
      clear(liveList).append(table(ps));
    }
    // stat: kutular bir kez kurulur, değerleri yerinde güncellenir; değişen sayı kısa bir sayımla yeni değerine geçer.
    const cells = new Map();
    function stat(key, n, l, cls = '', fmt = String) {
      let c = cells.get(key);
      if (!c) {
        c = { b: h('b', {}), span: h('span', {}) };
        stats.append(h('div', { class: 'stat ' + cls }, c.b, c.span));
        cells.set(key, c);
      }
      c.span.textContent = l;
      countUp(c.b, n, fmt);
    }
    function table(ps) {
      if (!ps.length) return h('div', { class: 'empty' }, h('p', {}, t('panel.table.empty')));
      return h('table', {},
        h('thead', {}, h('tr', {}, ...[t('panel.table.device'), 'IP', t('panel.table.state'), t('panel.table.handshake')].map((x) => h('th', {}, x)), h('th', { class: 'num' }, 'RX'), h('th', { class: 'num' }, 'TX'))),
        h('tbody', {}, ps.map((p) => h('tr', {},
          h('td', {}, h('span', { class: 'nm' }, kindIcon(p.kind, 'kind sm'), p.name)),
          h('td', { class: 'mono' }, p.ip),
          h('td', {}, h('span', { class: 'chip ' + (p.state === 'frozen' ? 'ice' : isOff(p) ? '' : p.online ? 'ok' : '') }, t('devices.state.' + (['frozen', 'outside', 'expired', 'disabled'].includes(p.state) ? p.state : p.online ? 'online' : 'offline')))),
          h('td', {}, ago(p.handshake || p.last_seen)),
          h('td', { class: 'num' }, fmtBytes(p.rx)),
          h('td', { class: 'num' }, fmtBytes(p.tx))))));
    }

    let seq = 0; // en son istenen yükleme dışındaki yanıtlar atılır
    async function loadSide() {
      const my = ++seq;
      try {
        const [hist, rep] = await Promise.all([api('GET', '/api/history?range=' + range.value), api('GET', '/api/report')]);
        if (my !== seq) return;
        const cur = drawChart(chartBox, hist, range.value);
        now.textContent = cur ? '↓ ' + fmtRate(cur.tx) + '   ↑ ' + fmtRate(cur.rx) : '';
        const items = rep.checks.filter((c) => c.level === 'fail' || c.level === 'warn');
        clear(attn);
        if (!items.length) attn.append(h('li', {}, h('span', { class: 'dot ok' }), h('div', {}, h('b', {}, t('panel.all_ok')), h('p', { class: 'muted sm' }, t('panel.checks_passed', { n: rep.checks.length })))));
        for (const c of items.slice(0, 5)) attn.append(h('li', {}, h('span', { class: 'dot ' + c.level }), h('div', {}, h('b', {}, c.title), c.fix ? h('p', { class: 'muted sm' }, c.fix) : h('p', { class: 'muted sm' }, c.detail || ''))));
      } catch (e) { if (my === seq) clear(attn).append(h('li', {}, e.message)); }
    }

    range.addEventListener('change', () => loadSide());
    if (state.status) paint(state.status);
    loadSide();
    const off = onStatus(paint);
    const timer = setInterval(() => { if (!document.hidden) loadSide(); }, 30000);
    return () => { off(); clearInterval(timer); seq++; };
  },
};
