import { api, clear, confirmBox, h, modal, toast } from './util.js';
import { loadPolicies, refresh, state } from './store.js';
import { t } from './i18n.js';

const presets = () => [
  { l: t('policies.preset.ssh'), proto: 'tcp', ports: '22', note: t('policies.preset.note_ssh') },
  { l: t('policies.preset.web80'), proto: 'tcp', ports: '80', note: t('policies.preset.note_http') },
  { l: t('policies.preset.web443'), proto: 'tcp', ports: '443', note: t('policies.preset.note_https') },
  { l: t('policies.preset.jellyfin'), proto: 'tcp', ports: '8096', note: t('policies.preset.note_jellyfin') },
  { l: t('policies.preset.dns'), proto: 'udp', ports: '53', note: t('policies.preset.note_dns') },
  { l: t('policies.preset.rdp'), proto: 'tcp', ports: '3389', note: t('policies.preset.note_rdp') },
  { l: t('policies.preset.smb'), proto: 'tcp', ports: '445', note: t('policies.preset.note_smb') },
  { l: t('policies.preset.ping'), proto: 'icmp', ports: '', note: t('policies.preset.note_ping') },
];

const protoName = (k) => t('policies.proto.' + k);

function devName(id) {
  const p = (state.status?.peers || []).find((x) => x.id === id);
  return p ? p.name : t('policies.deleted_device');
}

function ruleSentence(r) {
  const who = r.target === 'server' ? t('policies.to_server') : r.target === 'all' ? t('policies.to_all') : t('policies.to_device', { name: devName(r.device) });
  let what;
  if (r.proto === 'icmp') what = t('policies.what_ping');
  else if (r.proto === 'any') what = t('policies.what_any');
  else what = r.ports ? t('policies.what_ports', { proto: protoName(r.proto), ports: r.ports }) : t('policies.what_all_ports', { proto: protoName(r.proto) });
  return t('policies.sentence', { who, what }) + (r.both ? t('policies.both_suffix') : '') + (r.schedule ? ' · ' + schedText(r.schedule) : '');
}

function ruleList(rules) {
  if (!rules.length) return h('p', { class: 'muted sm' }, t('policies.no_rules'));
  return h('ul', { class: 'rules' }, rules.map((r) => h('li', {},
    h('span', { class: 'port' }, r.proto === 'icmp' ? t('policies.port_ping') : r.proto === 'any' ? t('policies.port_all') : (r.ports || t('policies.port_any')) + '/' + r.proto),
    h('span', {}, ruleSentence(r), r.note ? h('small', {}, r.note) : null))));
}

const wdays = () => [[1, 'mon'], [2, 'tue'], [3, 'wed'], [4, 'thu'], [5, 'fri'], [6, 'sat'], [0, 'sun']].map(([d, k]) => [d, t('policies.days.' + k)]);
const schedText = (s) => s ? wdays().filter(([d]) => s.days.includes(d)).map(([, l]) => l).join(', ') + ' ' + s.from + '–' + s.to : '';

function blankRule() { return { target: 'server', device: '', proto: 'tcp', ports: '', note: '', both: false }; }

async function editor(existing, done) {
  const peers = state.status.peers;
  const rules = existing ? existing.rules.map((r) => ({ ...r })) : [];
  const name = h('input', { type: 'text', maxlength: 32, required: true, value: existing?.name || '', placeholder: t('policies.f.name_ph') });
  const desc = h('input', { type: 'text', maxlength: 200, value: existing?.desc || '', placeholder: t('policies.f.desc_ph') });
  const groups = h('input', { type: 'text', maxlength: 400, value: (existing?.groups || []).join(', '), placeholder: t('policies.f.groups_ph') });
  const rulesBox = h('div', { class: 'stack' });
  const err = h('p', { class: 'err', role: 'alert' });

  function ruleRow(r, i) {
    const target = h('select', {}, h('option', { value: 'server' }, t('policies.f.target_server')), h('option', { value: 'device' }, t('policies.f.target_device')), h('option', { value: 'all' }, t('policies.f.target_all')));
    target.value = r.target;
    target.onchange = () => { r.target = target.value; if (r.target !== 'device') { r.device = ''; r.both = false; } else if (!r.device && peers[0]) r.device = peers[0].id; paint(); };
    const dev = h('select', { 'aria-label': t('policies.f.target_device_aria') }, ...peers.map((p) => h('option', { value: p.id }, p.name)));
    dev.value = r.device; dev.onchange = () => { r.device = dev.value; sentence(); };
    const proto = h('select', { 'aria-label': t('policies.f.proto_aria') }, ...['tcp', 'udp', 'icmp', 'any'].map((k) => h('option', { value: k }, t('policies.proto_opt.' + k))));
    proto.value = r.proto;
    proto.onchange = () => { r.proto = proto.value; if (r.proto === 'icmp' || r.proto === 'any') r.ports = ''; paint(); };
    const ports = h('input', { type: 'text', class: 'mono', 'aria-label': t('policies.f.ports_aria'), placeholder: t('policies.f.ports_ph'), value: r.ports, disabled: r.proto === 'icmp' || r.proto === 'any' });
    ports.oninput = () => { r.ports = ports.value; sentence(); };
    const note = h('input', { type: 'text', maxlength: 80, 'aria-label': t('policies.f.note_aria'), placeholder: t('policies.f.note_ph'), value: r.note });
    note.oninput = () => { r.note = note.value; sentence(); };
    const both = h('input', { type: 'checkbox', checked: r.both });
    both.onchange = () => { r.both = both.checked; sentence(); };
    const sOn = h('input', { type: 'checkbox', checked: !!r.schedule });
    const sFrom = h('input', { type: 'time', value: r.schedule?.from || '08:00', 'aria-label': t('policies.f.from') });
    const sTo = h('input', { type: 'time', value: r.schedule?.to || '22:00', 'aria-label': t('policies.f.to') });
    const sDays = wdays().map(([d, l]) => ({ d, inp: h('input', { type: 'checkbox', checked: r.schedule ? r.schedule.days.includes(d) : true }), l }));
    const sDetail = h('div', { class: 'sched-detail', hidden: !r.schedule },
      h('div', { class: 'days' }, ...sDays.map((x) => h('label', { class: 'daychk' }, x.inp, h('span', {}, x.l)))),
      h('div', { class: 'cols' }, h('label', {}, t('policies.f.from'), sFrom), h('label', {}, t('policies.f.to'), sTo)),
      h('p', { class: 'hint' }, t('policies.f.sched_hint')));
    const syncS = () => {
      sDetail.hidden = !sOn.checked;
      r.schedule = sOn.checked ? { days: sDays.filter((x) => x.inp.checked).map((x) => x.d), from: sFrom.value, to: sTo.value } : undefined;
      sentence();
    };
    for (const e of [sOn, sFrom, sTo, ...sDays.map((x) => x.inp)]) e.addEventListener('change', syncS);
    const sen = h('p', { class: 'sm muted' });
    function sentence() { sen.textContent = t('policies.allow_prefix', { sentence: ruleSentence(r) }) + (r.note ? ' — ' + r.note : ''); }
    sentence();
    return h('div', { class: 'rule-ed' },
      h('div', { class: 'cols' }, h('label', {}, t('policies.f.where'), target), r.target === 'device' ? h('label', {}, t('policies.f.which_device'), dev) : null, h('label', {}, t('policies.f.kind'), proto)),
      h('label', {}, t('policies.f.ports'), ports), h('label', {}, t('policies.f.note'), note),
      h('label', { class: 'check' }, sOn, h('span', {}, t('policies.f.sched_on'), h('small', {}, t('policies.f.sched_example')))), sDetail,
      r.target === 'device' ? h('label', { class: 'check' }, both, h('span', {}, t('policies.f.both'), h('small', {}, t('policies.f.both_hint')))) : null,
      h('div', { class: 'row' }, sen, h('button', { class: 'btn sm danger', type: 'button', onclick: () => { rules.splice(i, 1); paint(); } }, t('policies.f.delete_rule'))));
  }
  function paint() {
    clear(rulesBox);
    if (!rules.length) rulesBox.append(h('p', { class: 'muted sm' }, t('policies.f.no_rules_edit')));
    rules.forEach((r, i) => rulesBox.append(ruleRow(r, i)));
  }
  paint();

  const form = h('form', { class: 'form' },
    h('label', {}, t('policies.f.name'), name), h('label', {}, t('policies.f.desc'), desc),
    h('label', {}, t('policies.f.groups'), groups), h('p', { class: 'hint' }, t('policies.f.groups_hint')),
    h('h3', {}, t('policies.f.rules_title')),
    h('p', { class: 'hint' }, t('policies.f.rules_hint')),
    rulesBox,
    h('div', { class: 'presets' }, ...presets().map((p) => h('button', { class: 'btn sm', type: 'button', onclick: () => { rules.push({ ...blankRule(), proto: p.proto, ports: p.ports, note: p.note }); paint(); } }, '+ ' + p.l)),
      h('button', { class: 'btn sm', type: 'button', onclick: () => { rules.push(blankRule()); paint(); } }, t('policies.f.blank_rule'))),
    err, h('div', { class: 'row end' }, h('button', { class: 'btn primary', type: 'submit' }, existing ? t('policies.f.save') : t('policies.f.create'))));
  const m = modal(existing ? t('policies.edit_title') : t('policies.new_title'), form, { wide: true });
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); err.textContent = '';
    const body = { name: name.value, desc: desc.value, groups: groups.value.split(',').map((x) => x.trim()).filter(Boolean), rules: rules.map((r) => ({ target: r.target, device: r.target === 'device' ? r.device : undefined, proto: r.proto, ports: r.ports || undefined, note: r.note || undefined, both: r.both || undefined, schedule: r.schedule ? { ...r.schedule, scope: 'tunnel' } : undefined })) };
    try {
      if (existing) await api('PUT', '/api/policies/' + existing.id, body); else await api('POST', '/api/policies', body);
      m.close(); toast(t('policies.saved')); await done();
    } catch (x) { err.textContent = x.message; }
  });
  name.focus();
}

function reachCard() {
  const peers = state.status.peers;
  const out = h('div', { class: 'sentence', hidden: true, 'aria-live': 'polite' });
  if (peers.length < 1) return null;
  const src = h('select', {}, ...peers.map((p) => h('option', { value: p.id }, p.name)));
  const dst = h('select', {}, h('option', { value: 'server' }, t('policies.f.target_server')), ...peers.map((p) => h('option', { value: p.id }, p.name)));
  const proto = h('select', {}, h('option', { value: 'tcp' }, protoName('tcp')), h('option', { value: 'udp' }, protoName('udp')), h('option', { value: 'icmp' }, t('policies.reach.ping')));
  const port = h('input', { type: 'number', min: 1, max: 65535, value: 443, 'aria-label': t('policies.reach.port') });
  proto.onchange = () => { port.disabled = proto.value === 'icmp'; };
  const run = async () => {
    try {
      const r = await api('GET', '/api/reach?' + new URLSearchParams({ src: src.value, dst: dst.value, proto: proto.value, port: port.value }));
      out.hidden = false;
      out.textContent = t('policies.reach.' + (r.result === 'allow' ? 'allow' : r.result === 'deny' ? 'deny' : 'host'), { reason: r.reason });
    } catch (e) { out.hidden = false; out.textContent = e.message; }
  };
  return h('section', { class: 'card' }, h('h2', {}, t('policies.reach.title')),
    h('p', { class: 'muted sm' }, t('policies.reach.intro')),
    h('div', { class: 'cols' }, h('label', {}, t('policies.reach.src'), src), h('label', {}, t('policies.reach.dst'), dst), h('label', {}, t('policies.reach.kind'), proto), h('label', {}, t('policies.reach.port'), port)),
    h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'button', onclick: run }, t('policies.reach.run'))), out);
}

export default {
  async render(el) {
    const list = h('div', { class: 'grid2' });
    const test = h('div');
    el.append(h('div', { class: 'page-head' },
      h('div', {}, h('h1', {}, t('policies.title')), h('p', {}, t('policies.intro'))),
      h('button', { class: 'btn primary mut', type: 'button', onclick: () => editor(null, load) }, t('policies.add'))), h('div', { class: 'stack' }, list, test));
    async function load() {
      const data = await loadPolicies();
      await refresh();
      clear(list);
      if (!data.policies.length) {
        list.append(h('div', { class: 'card empty' }, h('h2', {}, t('policies.empty_title')),
          h('p', {}, t('policies.empty_text')),
          h('button', { class: 'btn primary mut', type: 'button', onclick: () => editor(null, load) }, t('policies.create_first'))));
      }
      for (const p of data.policies) {
        list.append(h('article', { class: 'card pol' },
          h('div', { class: 'card-head' }, h('h2', {}, p.name), h('span', { class: 'tag' }, t('policies.device_count', { n: p.devices.length + (p.group_devices || []).length }))),
          (p.groups || []).length ? h('p', { class: 'sm' }, h('span', { class: 'muted' }, t('policies.default_group')), p.groups.join(', ')) : null,
          p.desc ? h('p', { class: 'muted' }, p.desc) : null,
          ruleList(p.rules),
          p.devices.length ? h('p', { class: 'sm' }, h('span', { class: 'muted' }, t('policies.assigned')), p.devices.map((d) => d.name).join(', ')) : (p.group_devices || []).length ? null : h('p', { class: 'sm muted' }, t('policies.unassigned')),
          (p.group_devices || []).length ? h('p', { class: 'sm' }, h('span', { class: 'muted' }, t('policies.from_group')), p.group_devices.map((d) => d.name).join(', ')) : null,
          h('div', { class: 'row' },
            h('button', { class: 'btn sm mut', type: 'button', onclick: () => editor(p, load) }, t('policies.edit')),
            h('button', { class: 'btn sm danger mut', type: 'button', onclick: async () => {
              if (p.devices.length) { toast(t('policies.delete_blocked'), true); return; }
              if (await confirmBox(t('policies.delete_title'), t('policies.delete_confirm', { name: p.name }), t('policies.delete'))) { try { await api('DELETE', '/api/policies/' + p.id); toast(t('policies.deleted')); await load(); } catch (e) { toast(e.message, true); } }
            } }, t('policies.delete')))));
      }
      clear(test);
      const rc = reachCard();
      if (rc) test.append(rc);
      list.append(h('section', { class: 'card' }, h('h2', {}, t('policies.how.title')),
        h('ul', { class: 'rules' },
          h('li', {}, h('span', { class: 'port' }, t('policies.how.allowlist_k')), h('span', {}, t('policies.how.allowlist'))),
          h('li', {}, h('span', { class: 'port' }, t('policies.how.directed_k')), h('span', {}, t('policies.how.directed'))),
          h('li', {}, h('span', { class: 'port' }, t('policies.how.time_k')), h('span', {}, t('policies.how.time'))),
          h('li', {}, h('span', { class: 'port' }, t('policies.how.group_k')), h('span', {}, t('policies.how.group'))),
          h('li', {}, h('span', { class: 'port' }, t('policies.how.internet_k')), h('span', {}, t('policies.how.internet'))),
          h('li', {}, h('span', { class: 'port' }, t('policies.how.panel_k')), h('span', {}, t('policies.how.panel', { port: data.panel_port || '?' }))))));
    }
    await load();
  },
};
