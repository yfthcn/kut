import { api, h, toast } from './util.js';
import { fmtDateTime, t } from './i18n.js';

// Bildirimler kartı (yalnızca admin). Tek yönlü: Kut mesaj yollar, dışarıdan komut kabul etmez.
export async function notifyCard() {
  const c = await api('GET', '/api/notify');
  const tokenPh = (set) => (set ? t('notifyui.token_saved_ph') : '123456789:AA…');
  const tgOn = h('input', { type: 'checkbox', checked: c.telegram.enabled });
  const token = h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: tokenPh(c.telegram.token_set) });
  const chat = h('input', { type: 'text', inputmode: 'numeric', class: 'mono', value: c.telegram.chat_id || '', placeholder: t('notifyui.chat_ph') });
  const found = h('p', { class: 'hint' });
  const whOn = h('input', { type: 'checkbox', checked: c.webhook.enabled });
  // Webhook adresi sırdır (Slack/Discord adresi anahtar içerir): sunucu geri göndermez. Boş bırakılırsa mevcut korunur.
  const whUrl = h('input', { type: 'url', autocomplete: 'off', spellcheck: 'false' });
  let whDrop = false;
  const whDel = h('button', { class: 'btn sm', type: 'button', hidden: !c.webhook_set, onclick: () => {
    whDrop = true; whOn.checked = false; whUrl.value = '';
    paintWh({ webhook_set: false });
    whDel.hidden = true;
  } }, t('notifyui.wh_delete'));
  const paintWh = (d) => {
    whUrl.placeholder = d.webhook_set ? t('notifyui.wh_saved_ph', { host: d.webhook_host }) : 'https://…';
    whDel.hidden = !d.webhook_set;
  };
  paintWh(c);
  const ev = { sec: h('input', { type: 'checkbox', checked: c.ev_security }), sys: h('input', { type: 'checkbox', checked: c.ev_system }), dev: h('input', { type: 'checkbox', checked: c.ev_device }) };
  const qf = h('input', { type: 'time', value: c.quiet_from || '' });
  const qt = h('input', { type: 'time', value: c.quiet_to || '' });
  const err = h('p', { class: 'err', role: 'alert' });
  const status = h('p', { class: 'hint' });
  const paintStatus = (d) => {
    status.textContent = d.last_error ? t('notifyui.last_failed', { err: d.last_error }) : d.last_ok ? t('notifyui.last_ok', { when: fmtDateTime(d.last_ok, { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }) }) : '';
  };
  paintStatus(c);

  const body = () => ({
    telegram: { enabled: tgOn.checked, token: token.value.trim(), chat_id: chat.value.trim() },
    webhook: { enabled: whOn.checked, url: whUrl.value.trim() },
    drop_webhook: whDrop,
    ev_security: ev.sec.checked, ev_system: ev.sys.checked, ev_device: ev.dev.checked,
    quiet_from: qf.value && qt.value ? qf.value : '', quiet_to: qf.value && qt.value ? qt.value : '',
  });
  const save = async () => {
    err.textContent = '';
    const d = await api('PUT', '/api/notify', body());
    token.value = ''; token.placeholder = tokenPh(d.telegram.token_set);
    whUrl.value = ''; whDrop = false; whOn.checked = d.webhook.enabled; paintWh(d);
    paintStatus(d);
    return d;
  };
  const find = h('button', { class: 'btn', type: 'button', onclick: async () => {
    found.textContent = t('notifyui.searching'); found.className = 'hint';
    try {
      const r = await api('POST', '/api/notify/telegram-find', { token: token.value.trim() });
      found.className = 'hint ok';
      found.replaceChildren(t('notifyui.found', { name: r.name, user: r.username ? ' (@' + r.username + ')' : '', bot: r.bot }), h('button', { class: 'btn sm', type: 'button', onclick: () => { chat.value = r.chat_id; found.textContent = t('notifyui.chat_filled'); } }, t('notifyui.found_yes')));
    } catch (x) { found.className = 'hint bad'; found.textContent = x.message; }
  } }, t('notifyui.find'));
  const test = h('button', { class: 'btn', type: 'button', onclick: async () => {
    try {
      await save();
      const r = await api('POST', '/api/notify/test');
      const bad = Object.entries(r).filter(([, v]) => v !== 'ok');
      if (bad.length) err.textContent = bad.map(([k, v]) => k + ': ' + v).join(' · '); else toast(t('notifyui.test_sent'));
    } catch (x) { err.textContent = x.message; }
  } }, t('notifyui.save_test'));

  const form = h('form', { class: 'card form' }, h('h2', {}, t('notifyui.title')),
    h('p', { class: 'hint' }, t('notifyui.intro')),
    h('label', { class: 'check' }, tgOn, h('span', {}, t('notifyui.telegram'), h('small', {}, t('notifyui.telegram_hint')))),
    h('label', {}, t('notifyui.bot_token'), token),
    h('div', { class: 'row' }, h('label', { class: 'grow' }, t('notifyui.chat_id'), chat), find), found,
    h('label', { class: 'check' }, whOn, h('span', {}, t('notifyui.webhook'), h('small', {}, t('notifyui.webhook_hint')))),
    h('label', {}, t('notifyui.webhook_url'), whUrl), h('div', { class: 'row' }, whDel),
    h('fieldset', { class: 'form' }, h('legend', {}, t('notifyui.events')),
      h('label', { class: 'check' }, ev.sec, h('span', {}, t('notifyui.ev_security'), h('small', {}, t('notifyui.ev_security_hint')))),
      h('label', { class: 'check' }, ev.sys, h('span', {}, t('notifyui.ev_system'), h('small', {}, t('notifyui.ev_system_hint')))),
      h('label', { class: 'check' }, ev.dev, h('span', {}, t('notifyui.ev_device'), h('small', {}, t('notifyui.ev_device_hint'))))),
    h('div', { class: 'cols' }, h('label', {}, t('notifyui.quiet_from'), qf), h('label', {}, t('notifyui.quiet_to'), qt)),
    h('p', { class: 'hint' }, t('notifyui.quiet_hint')),
    err, status,
    h('div', { class: 'row end' }, test, h('button', { class: 'btn primary', type: 'submit' }, t('notifyui.save'))));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try { await save(); toast(t('notifyui.saved')); } catch (x) { err.textContent = x.message; }
  });
  return form;
}
