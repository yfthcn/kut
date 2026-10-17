import { api, clear, fmtDate, h } from './util.js';
import { t } from './i18n.js';

const groups = () => ['wireguard', 'firewall', 'network', 'security', 'devices'];
const HEALTH_SYM = { ok: '✓', warn: '!', fail: '✕' };
const SYM = { allow: '✓', deny: '✕', host: '?', self: '–' };

function matrix(rep) {
  if (!rep.matrix_devices || !rep.matrix_devices.length) return h('p', { class: 'muted' }, t('reportui.matrix.empty'));
  const ds = rep.matrix_devices;
  const head = h('tr', {}, h('th', {}, t('reportui.matrix.corner')), ...ds.map((d) => h('th', { title: d.ip }, d.name)), h('th', {}, t('reportui.matrix.server')));
  const body = rep.matrix.map((row, i) => h('tr', {}, h('td', {}, ds[i].name),
    ...row.map((c) => h('td', {}, h('span', { class: 'cell ' + c.result, title: c.text || '', role: 'img', 'aria-label': c.text || (c.result in SYM ? t('reportui.matrix.' + c.result) : c.result) }, SYM[c.result] || '?')))));
  return h('div', { class: 'stack' },
    h('div', { class: 'tablewrap' }, h('table', { class: 'mx' }, h('thead', {}, head), h('tbody', {}, body))),
    h('p', { class: 'sm muted' }, t('reportui.matrix.legend')));
}

export default {
  async render(el) {
    const body = h('div', { class: 'stack' });
    const btn = h('button', { class: 'btn', type: 'button' }, t('reportui.refresh'));
    el.append(h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, t('reportui.title')), h('p', {}, t('reportui.intro'))), btn), body);
    async function load() {
      btn.disabled = true;
      try {
        const [rep, st] = await Promise.all([api('GET', '/api/report'), api('GET', '/api/status')]);
        clear(body);
        const health = rep.health in HEALTH_SYM ? rep.health : 'ok';
        const c = rep.counts;
        body.append(h('section', { class: 'card' }, h('div', { class: 'health' }, h('span', { class: 'big ' + rep.health, 'aria-hidden': 'true' }, HEALTH_SYM[health]),
          h('div', {}, h('h2', {}, t('reportui.health.' + health)), h('p', { class: 'muted sm' }, [t('reportui.counts_ok', { n: c.ok || 0 }), t('reportui.counts_warn', { n: c.warn || 0 }), t('reportui.counts_fail', { n: c.fail || 0 }), t('reportui.as_of', { date: fmtDate(rep.generated) })].join(' · '))))));
        // Kontroller (gruplu), sorunlular üstte
        const order = { fail: 0, warn: 1, info: 2, ok: 3 };
        const grid = h('div', { class: 'grid2' });
        for (const g of groups()) {
          const cs = rep.checks.filter((x) => x.group === g).sort((a, b) => order[a.level] - order[b.level]);
          if (!cs.length) continue;
          grid.append(h('section', { class: 'card flush' }, h('div', { class: 'card-head' }, h('h2', { class: 'pad' }, t('reportui.group.' + g))),
            cs.map((x) => h('div', { class: 'check-item' }, h('span', { class: 'dot ' + x.level }), h('div', {}, h('b', {}, x.title)),
              x.detail ? h('p', {}, x.detail) : null, x.fix ? h('p', { class: 'fix' }, t('reportui.fix', { fix: x.fix })) : null))));
        }
        body.append(grid);
        body.append(h('section', { class: 'card' }, h('h2', {}, t('reportui.structure')), h('p', { class: 'sm muted' }, t('reportui.structure_line', { endpoint: st.server.endpoint, iface: st.server.iface, ip: st.server.server_ip, devices: t('reportui.structure_devices', { n: st.peers.length }) })),
          h('dl', { class: 'kv' }, rep.structure.flatMap((x) => [h('dt', {}, x.k), h('dd', { class: 'mono' }, x.v)]))));
        body.append(h('section', { class: 'card' }, h('h2', {}, t('reportui.matrix_title')), matrix(rep)));
        body.append(h('section', { class: 'card' }, h('h2', {}, t('reportui.system')), h('dl', { class: 'kv' }, rep.system.flatMap((x) => [h('dt', {}, x.k), h('dd', { class: 'mono' }, x.v)]))));
      } catch (e) { clear(body).append(h('div', { class: 'card' }, h('p', { class: 'err' }, e.message))); }
      btn.disabled = false;
    }
    btn.onclick = load;
    await load();
  },
};
