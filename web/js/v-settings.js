import { api, confirmBox, h, modal, parseSVG, toast } from './util.js';
import { LANGS, t } from './i18n.js';
import { state } from './store.js';
import { notifyCard } from './v-notify.js';
import { maintCards } from './v-maint.js';

// İki adımlı doğrulama (TOTP) kartı
async function twoFactorCard() {
  const box = h('section', { class: 'card form' });
  async function paint() {
    const st = await api('GET', '/api/totp');
    box.replaceChildren(h('h2', {}, t('settings.tfa.title')));
    if (!st.enabled) {
      box.append(h('p', { class: 'hint' }, t('settings.tfa.intro')),
        h('div', { class: 'row end' }, h('button', { class: 'btn', type: 'button', onclick: () => setup().catch((e) => toast(e.message, true)) }, t('settings.tfa.setup'))));
    } else {
      box.append(h('p', {}, h('span', { class: 'chip ok' }, t('settings.tfa.on')), ' ', t('settings.tfa.recovery_left', { n: st.recovery_left })),
        h('p', { class: 'hint' }, t('settings.tfa.lost_pre'), h('code', {}, 'sudo kut 2fa-off'), t('settings.tfa.lost_post')),
        h('div', { class: 'row end' }, h('button', { class: 'btn danger', type: 'button', onclick: disable }, t('settings.tfa.disable'))));
    }
  }
  async function setup() {
    const r = await api('POST', '/api/totp/setup');
    const svg = r.qr ? parseSVG(r.qr) : null;
    if (svg) svg.setAttribute('aria-label', t('webfix.qr_label'));
    const code = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 6, required: true, placeholder: '123456' });
    const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    const err = h('p', { class: 'err', role: 'alert' });
    const form = h('form', { class: 'form' },
      h('p', {}, t('settings.tfa.scan')),
      svg ? h('div', { class: 'qr' }, svg) : null,
      h('p', { class: 'hint' }, t('settings.tfa.manual'), h('span', { class: 'mono' }, r.secret)),
      h('label', {}, t('settings.tfa.app_code'), code), h('label', {}, t('settings.tfa.account_pw'), pw), err,
      h('div', { class: 'row end' }, h('button', { class: 'btn primary', type: 'submit' }, t('settings.tfa.verify'))));
    const m = modal(t('settings.tfa.setup_title'), form);
    form.addEventListener('submit', async (e) => {
      e.preventDefault(); err.textContent = '';
      try {
        const res = await api('POST', '/api/totp/enable', { code: code.value, password: pw.value });
        m.close(); showRecovery(res.recovery); await paint();
      } catch (x) { err.textContent = x.message; }
    });
    code.focus();
  }
  function showRecovery(codes) {
    modal(t('settings.tfa.rec_title'), h('div', { class: 'form' },
      h('p', { class: 'hint bad' }, t('settings.tfa.rec_warn')),
      h('pre', { class: 'code' }, codes.join('\n')),
      h('div', { class: 'row end' }, h('button', { class: 'btn', type: 'button', onclick: async () => { try { await navigator.clipboard.writeText(codes.join('\n')); toast(t('settings.tfa.copied')); } catch { toast(t('settings.tfa.copy_failed'), true); } } }, t('settings.tfa.copy')))));
  }
  function disable() {
    const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    const code = h('input', { type: 'text', autocomplete: 'one-time-code', maxlength: 24, required: true, placeholder: t('settings.tfa.code_ph') });
    const err = h('p', { class: 'err', role: 'alert' });
    const form = h('form', { class: 'form' }, h('label', {}, t('settings.tfa.password'), pw), h('label', {}, t('settings.tfa.code'), code), err,
      h('div', { class: 'row end' }, h('button', { class: 'btn danger', type: 'submit' }, t('settings.tfa.off_btn'))));
    const m = modal(t('settings.tfa.off_title'), form);
    form.addEventListener('submit', async (e) => {
      e.preventDefault(); err.textContent = '';
      try { await api('POST', '/api/totp/disable', { password: pw.value, code: code.value }); m.close(); toast(t('settings.tfa.off_done')); await paint(); } catch (x) { err.textContent = x.message; }
    });
    pw.focus();
  }
  await paint();
  return box;
}

// Hesaplar (yalnızca yönetici): ek kullanıcı ekle, rol ver, parola sıfırla, sil
async function usersCard() {
  const box = h('section', { class: 'card form' });
  async function paint() {
    const { users } = await api('GET', '/api/users');
    const del = async (u) => {
      if (!(await confirmBox(t('settings.users.del_title'), t('settings.users.del_confirm', { name: u.name }), t('settings.users.delete')))) return;
      try { await api('DELETE', '/api/users/' + encodeURIComponent(u.name)); toast(t('settings.users.deleted')); await paint(); } catch (e) { toast(e.message, true); }
    };
    const row = (u) => h('tr', {}, h('td', { class: 'mono' }, u.name), h('td', {}, u.role === 'admin' ? t('settings.users.role_admin') : t('settings.users.role_viewer')), h('td', {}, u.totp ? t('settings.users.tfa_on') : '—'),
      h('td', {}, u.owner ? '' : h('div', { class: 'row end' },
        h('button', { class: 'btn sm', type: 'button', onclick: () => edit(u) }, t('settings.users.edit')),
        h('button', { class: 'btn sm danger', type: 'button', onclick: () => del(u) }, t('settings.users.delete')))));
    box.replaceChildren(h('h2', {}, t('settings.users.title')),
      h('p', { class: 'hint' }, t('settings.users.intro')),
      h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ...[t('settings.users.col_account'), t('settings.users.col_role'), t('settings.users.col_2fa'), ''].map((x) => h('th', {}, x)))), h('tbody', {}, users.map(row)))),
      h('div', { class: 'row end' }, h('button', { class: 'btn', type: 'button', onclick: add }, t('settings.users.add'))));
  }
  const roleSel = (v) => { const r = h('select', {}, h('option', { value: 'viewer' }, t('settings.users.role_viewer_long')), h('option', { value: 'admin' }, t('settings.users.role_admin'))); r.value = v; return r; };
  function add() {
    const name = h('input', { type: 'text', maxlength: 32, required: true, autocomplete: 'off', autocapitalize: 'none', placeholder: t('settings.users.name_ph') });
    const pw = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
    const role = roleSel('viewer'); const err = h('p', { class: 'err', role: 'alert' });
    const form = h('form', { class: 'form' }, h('label', {}, t('settings.users.name'), name), h('label', {}, t('settings.users.password'), pw), h('label', {}, t('settings.users.role'), role), err,
      h('div', { class: 'row end' }, h('button', { class: 'btn primary', type: 'submit' }, t('settings.users.add_submit'))));
    const m = modal(t('settings.users.add_title'), form);
    form.addEventListener('submit', async (e) => { e.preventDefault(); err.textContent = ''; try { await api('POST', '/api/users', { name: name.value, password: pw.value, role: role.value }); m.close(); toast(t('settings.users.added')); await paint(); } catch (x) { err.textContent = x.message; } });
    name.focus();
  }
  function edit(u) {
    const pw = h('input', { type: 'password', autocomplete: 'new-password', minlength: 10, placeholder: t('settings.users.new_pw_ph') });
    const role = roleSel(u.role); const err = h('p', { class: 'err', role: 'alert' });
    const form = h('form', { class: 'form' }, h('label', {}, t('settings.users.role'), role), h('label', {}, t('settings.users.new_pw'), pw), h('p', { class: 'hint' }, t('settings.users.edit_hint')), err,
      h('div', { class: 'row end' }, h('button', { class: 'btn primary', type: 'submit' }, t('settings.users.save'))));
    const m = modal(t('settings.users.edit_title', { name: u.name }), form);
    form.addEventListener('submit', async (e) => { e.preventDefault(); err.textContent = ''; const body = {}; if (role.value !== u.role) body.role = role.value; if (pw.value) body.password = pw.value;
      try { if (Object.keys(body).length) await api('PATCH', '/api/users/' + encodeURIComponent(u.name), body); m.close(); toast(t('settings.users.saved')); await paint(); } catch (x) { err.textContent = x.message; } });
  }
  await paint();
  return box;
}

// Sunucu varsayılan dili (yalnızca yönetici): bildirim, CLI ve kut doctor dili. Değişince hemen kaydedilir.
async function serverLangCard(cfg) {
  const srv = cfg.server_lang || (await api('GET', '/api/me')).server_lang;
  const sel = h('select', {}, ...LANGS.map((l) => h('option', { value: l }, t('lang.' + l))));
  sel.value = srv;
  let cur = sel.value;
  sel.addEventListener('change', async () => {
    const want = sel.value;
    sel.disabled = true;
    try {
      await api('PUT', '/api/settings/lang', { lang: want });
      cur = want;
      if (state.me) state.me.server_lang = want;
      toast(t('settings.srvlang.saved'));
    } catch (x) { sel.value = cur; toast(x.message, true); }
    sel.disabled = false;
  });
  return h('section', { class: 'card form' }, h('h2', {}, t('settings.srvlang.title')),
    h('label', {}, t('settings.srvlang.label'), sel),
    h('p', { class: 'hint' }, t('settings.srvlang.hint')));
}

export default {
  async render(el) {
    const c = await api('GET', '/api/settings');
    const f = {
      endpoint: h('input', { type: 'text', class: 'mono', value: c.endpoint, required: true }),
      port: h('input', { type: 'number', min: 1, max: 65535, value: c.port, required: true }),
      dns: h('input', { type: 'text', class: 'mono', value: c.dns, placeholder: '1.1.1.1, 9.9.9.9' }),
      mtu: h('input', { type: 'number', min: 0, max: 1500, value: c.mtu || 0 }),
      keep: h('input', { type: 'number', min: 0, max: 120, value: c.keepalive }),
      block: h('input', { type: 'checkbox', checked: c.block_private }),
      free: h('input', { type: 'checkbox', checked: c.unprofiled_free }),
      upd: h('input', { type: 'checkbox', checked: c.update_check }),
      v6: h('input', { type: 'checkbox', checked: c.ipv6 }),
    };
    const err = h('p', { class: 'err', role: 'alert' });
    const form = h('form', { class: 'card form' }, h('h2', {}, t('settings.conn.title')),
      h('div', { class: 'cols' }, h('label', {}, t('settings.conn.endpoint'), f.endpoint), h('label', {}, t('settings.conn.port'), f.port)),
      h('div', { class: 'cols' }, h('label', {}, t('settings.conn.dns'), f.dns), h('label', {}, t('settings.conn.mtu'), f.mtu), h('label', {}, t('settings.conn.keepalive'), f.keep)),
      h('p', { class: 'hint' }, t('settings.conn.hint')),
      h('label', { class: 'check' }, f.block, h('span', {}, t('settings.conn.block_private'), h('small', {}, t('settings.conn.block_private_hint')))),
      h('label', { class: 'check' }, f.free, h('span', {}, t('settings.conn.unprofiled_free'), h('small', {}, t('settings.conn.unprofiled_free_hint')))),
      h('label', { class: 'check' }, f.upd, h('span', {}, t('settings.conn.update_check'), h('small', {}, t('settings.conn.update_check_hint')))),
      h('label', { class: 'check' }, f.v6, h('span', {}, t('settings.conn.ipv6'), h('small', {}, t('settings.conn.ipv6_hint', { ula: c.ula || 'fdXX:…::/64' }) + ' ' +
        (c.ipv6_tools ? '' : t('settings.conn.ipv6_no_tools') + ' ') +
        (c.ipv6_route ? t('settings.conn.ipv6_route_yes') : t('settings.conn.ipv6_route_no')) +
        ' ' + t('settings.conn.ipv6_ra')))),
      err, h('div', { class: 'row end' }, h('button', { class: 'btn primary', type: 'submit' }, t('settings.conn.save'))));
    form.addEventListener('submit', async (e) => {
      e.preventDefault(); err.textContent = '';
      try {
        await api('PUT', '/api/settings', { endpoint: f.endpoint.value, port: parseInt(f.port.value, 10), dns: f.dns.value, mtu: parseInt(f.mtu.value || '0', 10), keepalive: parseInt(f.keep.value || '0', 10), block_private: f.block.checked, unprofiled_free: f.free.checked, update_check: f.upd.checked, ipv6: f.v6.checked });
        toast(t('settings.conn.saved'));
      } catch (x) { err.textContent = x.message; }
    });

    const cur = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    const nw = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
    const perr = h('p', { class: 'err', role: 'alert' });
    const pform = h('form', { class: 'card form' }, h('h2', {}, t('settings.pw.title')),
      h('div', { class: 'cols' }, h('label', {}, t('settings.pw.current'), cur), h('label', {}, t('settings.pw.new'), nw)),
      perr, h('div', { class: 'row end' }, h('button', { class: 'btn', type: 'submit' }, t('settings.pw.change'))));
    pform.addEventListener('submit', async (e) => {
      e.preventDefault(); perr.textContent = '';
      try { await api('POST', '/api/password', { current: cur.value, new: nw.value }); cur.value = nw.value = ''; toast(t('settings.pw.changed')); } catch (x) { perr.textContent = x.message; }
    });

    el.append(h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, t('settings.title')), h('p', {}, t('settings.net_line', { subnet: c.subnet, iface: c.iface })))), h('div', { class: 'stack' }, ...(state.me && state.me.role === 'viewer' ? [] : [form, await serverLangCard(c)]), pform, await twoFactorCard(), ...(state.me && state.me.role === 'viewer' ? [] : [...(await maintCards()), await notifyCard(), await usersCard()])));
  },
};
