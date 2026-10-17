import { api, ask, confirmBox, download, fmtBytes, h, toast } from './util.js';
import { currentLang, fmtDateTime, has, t } from './i18n.js';
import { state } from './store.js';

const freqs = () => [['daily', t('maint.freq_daily')], ['weekly', t('maint.freq_weekly')], ['monthly', t('maint.freq_monthly')]];
const days = () => [0, 1, 2, 3, 4, 5, 6].map((i) => t('maint.day_' + i));
const kindLabel = (k) => (['oto', 'elle', 'oncesi'].includes(k) ? t('maint.kind_' + k) : k);
const dt = (ts) => fmtDateTime(ts, { dateStyle: 'medium', timeStyle: 'short' });

// Geri yükleme sonrası servis yeniden başlar; yanıt verene kadar bekle, sonra sayfayı yenile.
async function waitRestart() {
  toast(t('maint.restarting'));
  await new Promise((r) => setTimeout(r, 2500));
  for (let i = 0; i < 40; i++) {
    try { const r = await fetch('/api/login-info', { cache: 'no-store' }); if (r.ok) { location.reload(); return; } } catch { /* bekle */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  location.reload();
}

function askPass(msg) {
  return ask(t('maint.enc_title'), (done) => {
    const inp = h('input', { type: 'password', autocomplete: 'off', required: true, autofocus: true });
    const form = h('form', { class: 'form' }, h('p', {}, msg), h('label', {}, t('maint.passphrase'), inp),
      h('div', { class: 'row end' }, h('button', { class: 'btn', type: 'button', onclick: () => done(null) }, t('maint.cancel')), h('button', { class: 'btn primary', type: 'submit' }, t('maint.continue'))));
    form.addEventListener('submit', (e) => { e.preventDefault(); done(inp.value); });
    return form;
  });
}

// ownerFields: sahip parolası ve (2FA açıksa) doğrulama kodu alanları. value() { owner_password, owner_code } döner.
function ownerFields(totp) {
  const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const code = totp ? h('input', { type: 'text', autocomplete: 'one-time-code', maxlength: 24, required: true, placeholder: t('maint.owner_code_ph') }) : null;
  return {
    pw,
    nodes: [h('label', {}, t('maint.owner_pw'), pw), code ? h('label', {}, t('maint.owner_code'), code) : null],
    missing: () => (!pw.value ? pw : code && !code.value.trim() ? code : null),
    value: () => ({ owner_password: pw.value, owner_code: code ? code.value.trim() : '' }),
  };
}

// ownerTOTP: 2FA durumu her seferinde sunucudan okunur (oturum içinde açılmış ya da kapatılmış olabilir).
async function ownerTOTP() {
  try { return !!(await api('GET', '/api/me')).totp; } catch { return !!(state.me && state.me.totp); }
}

// askOwner: sahip parolası (+ 2FA açıksa kod) ister; { owner_password, owner_code } ya da null döner.
async function askOwner(title, why, error = '') {
  const totp = await ownerTOTP();
  return ask(title, (done) => {
    const f = ownerFields(totp);
    const form = h('form', { class: 'form' }, h('p', {}, why), h('p', { class: 'hint' }, t('maint.owner_why')), ...f.nodes,
      error ? h('p', { class: 'err', role: 'alert' }, error) : null,
      h('div', { class: 'row end' }, h('button', { class: 'btn', type: 'button', onclick: () => done(null) }, t('maint.cancel')), h('button', { class: 'btn primary', type: 'submit' }, t('maint.continue'))));
    form.addEventListener('submit', (e) => { e.preventDefault(); const m = f.missing(); if (m) { m.focus(); return; } done(f.value()); });
    f.pw.autofocus = true; // showModal ilk autofocus alanına odaklanır (askPass kalıbı)
    return form;
  });
}

// withOwner: askOwner → run(ow). Yanlış parola/kodda (403) diyalog hata metniyle yeniden açılır.
// Döner: true = yapıldı, false = vazgeçildi. Diğer hatalar fırlatılır.
async function withOwner(title, why, run) {
  let error = '';
  for (;;) {
    const ow = await askOwner(title, why, error);
    if (!ow) return false;
    try { await run(ow); return true; } catch (e) {
      if (e.status !== 403) throw e;
      error = e.message;
    }
  }
}

// Önizleme: yedeğin içinde ne olduğunu ve taşıma durumunda ne değişeceğini gösterir; { endpoint, owner } ya da null döner.
function previewDialog(label, pv, totp, prev = {}) {
  return ask(t('maint.restore_title'), (done) => {
    const moved = !pv.same_server;
    const epDiff = pv.endpoint !== pv.this_endpoint;
    const chg = h('input', { type: 'checkbox', checked: prev.endpoint !== undefined ? !!prev.endpoint : moved && epDiff });
    const ep = h('input', { type: 'text', class: 'mono', value: prev.endpoint || pv.this_endpoint, 'aria-label': t('maint.new_endpoint') });
    const owner = ownerFields(totp);
    const notes = [];
    if (moved) notes.push(h('p', { class: 'hint' }, t('maint.moved_note')));
    if (pv.port !== pv.this_port) notes.push(h('p', { class: 'hint bad' }, t('maint.port_note', { port: pv.port, current: pv.this_port })));
    if (pv.subnet !== pv.this_subnet) notes.push(h('p', { class: 'hint' }, t('maint.subnet_note', { subnet: pv.subnet, current: pv.this_subnet })));
    return h('div', { class: 'form' },
      h('p', {}, h('b', {}, label), ': ' + t('maint.preview', { devices: t('maint.n_devices', { n: pv.devices }), profiles: t('maint.n_profiles', { n: pv.profiles }), subnet: pv.subnet, endpoint: pv.endpoint, port: pv.port }) + (pv.encrypted ? t('maint.preview_enc') : '') + '.'),
      ...notes,
      h('label', { class: 'check' }, chg, h('span', {}, t('maint.change_endpoint'), h('small', {}, t('maint.change_endpoint_hint')))),
      h('label', {}, t('maint.new_endpoint'), ep),
      h('p', { class: 'hint' }, t('maint.restore_warn')),
      ...owner.nodes,
      prev.error ? h('p', { class: 'err', role: 'alert' }, prev.error) : null,
      h('div', { class: 'row end' }, h('button', { class: 'btn', type: 'button', onclick: () => done(null) }, t('maint.cancel')),
        h('button', { class: 'btn danger', type: 'button', onclick: () => { const m = owner.missing(); if (m) { m.focus(); return; } done({ endpoint: chg.checked ? ep.value.trim() : '', owner: owner.value() }); } }, t('maint.restore'))));
  });
}

// uploadBackup: yedek dosyasını multipart/form-data olarak yollar (sözleşme 7). Parolalar başlıkta değil gövdede gider;
// başlıklar ters vekil günlüklerine düşebilir. Metin alanları dosyadan ÖNCE eklenir: sunucu akışlı okur ve dosyaya
// gelmeden parolayı bilmelidir. api() ile aynı hata biçimi: err.data gövde, err.status durum kodu.
async function uploadBackup(f, o) {
  const fd = new FormData();
  fd.append('passphrase', o.passphrase || '');
  fd.append('endpoint', o.endpoint || '');
  fd.append('owner_password', o.owner_password || '');
  fd.append('owner_code', o.owner_code || '');
  fd.append('inspect', o.inspect ? '1' : '');
  fd.append('file', f, f.name);
  const res = await fetch('/api/backups/upload', { method: 'POST', credentials: 'same-origin', headers: { 'X-Kut': '1', 'X-Kut-Lang': currentLang() }, body: fd });
  let data = null;
  try { data = await res.json(); } catch { /* gövde yok */ }
  if (res.status === 401) throw new Error(t('common.session_expired'));
  if (!res.ok) {
    const key = data && data.code ? 'err.' + data.code : '';
    const msg = key && has(key) ? t(key, data.params || {}) : (data && data.error) || t('err.http', { status: res.status });
    const e = new Error(msg); e.data = data; e.status = res.status; throw e;
  }
  return data;
}

// restoreFlow: önizleme → (şifreliyse parola) → onay → geri yükleme. send(o) isteği yapar, JSON döner ya da fırlatır.
async function restoreFlow(label, send) {
  let pass = '';
  let pv;
  for (;;) {
    try { pv = await send({ passphrase: pass, inspect: true }); break; } catch (e) {
      if (!e.data?.need_pass) { toast(e.message, true); return; }
      pass = await askPass(pass ? e.message : t('maint.enc_prompt', { label }));
      if (pass === null) return;
    }
  }
  let prev = {};
  for (;;) {
    const ch = await previewDialog(label, pv, await ownerTOTP(), prev);
    if (!ch) return;
    try {
      const r = await send({ passphrase: pass, endpoint: ch.endpoint, ...ch.owner, inspect: false });
      r.restarting ? waitRestart() : toast(t('maint.restored_dry'));
      return;
    } catch (e) {
      if (e.status !== 403) { toast(e.message, true); return; }
      prev = { endpoint: ch.endpoint, error: e.message }; // yanlış sahip parolası/kodu: diyalog hata metniyle yeniden açılır
    }
  }
}

export async function maintCards() {
  // Yedek işlemleri ve bu kartlardaki ayarlar yalnızca sahibe açık (sunucu da 403 döner); diğer yöneticiler listeyi görür.
  const isOwner = !!(state.me && state.me.owner);
  const ownerHint = isOwner ? null : h('p', { class: 'hint' }, t('maint.owner_hint'));
  let d = await api('GET', '/api/maint');
  const c = d.cfg;
  const en = h('input', { type: 'checkbox', checked: c.backup.enabled });
  const freq = h('select', {}, freqs().map(([v, l]) => h('option', { value: v }, l)));
  freq.value = c.backup.freq;
  const wd = h('select', {}, days().map((l, i) => h('option', { value: String(i) }, l)));
  wd.value = String(c.backup.weekday);
  const time = h('input', { type: 'time', value: c.backup.time, required: true });
  const keep = h('input', { type: 'number', min: 1, max: 60, value: c.backup.keep });
  const wdRow = h('label', {}, t('maint.day'), wd);
  const syncRows = () => { wdRow.hidden = freq.value !== 'weekly'; };
  freq.addEventListener('change', syncRows); syncRows();

  const logDays = h('select', {}, ['30', '90', '180', '365', '0'].map((v) => [v, t('maint.ld_' + v)]).map(([v, l]) => h('option', { value: v }, l)));
  logDays.value = String(c.log_days);
  if (!logDays.value) logDays.value = '90';
  const arch = h('input', { type: 'checkbox', checked: c.log_archive });
  const archM = h('select', {}, ['3', '6', '12', '24', '0'].map((v) => [v, t('maint.am_' + v)]).map(([v, l]) => h('option', { value: v }, l)));
  archM.value = String(c.archive_months);
  if (!archM.value) archM.value = '12';

  const passPh = () => (d.has_pass ? t('maint.pass_set_ph') : t('maint.pass_none_ph'));
  const pass = h('input', { type: 'password', autocomplete: 'new-password', maxlength: 200, placeholder: passPh() });
  let clearPass = false;
  const err = h('p', { class: 'err', role: 'alert' });
  const list = h('div', { class: 'blist' });
  const status = h('p', { class: 'hint' });
  const sizes = h('p', { class: 'hint' });

  const body = () => ({
    enabled: en.checked, freq: freq.value, time: time.value, weekday: parseInt(wd.value, 10), keep: parseInt(keep.value, 10),
    new_pass: pass.value, clear_pass: clearPass, log_days: parseInt(logDays.value, 10), log_archive: arch.checked, archive_months: parseInt(archM.value, 10),
  });
  const paint = () => {
    const bc = d.cfg.backup;
    status.textContent = (d.has_pass ? t('maint.enc_on') : t('maint.enc_off')) + ' ' + (!bc.enabled ? t('maint.auto_off') :
      (bc.last_error ? t('maint.last_failed', { err: bc.last_error }) + ' · ' : bc.last_run ? t('maint.last_auto', { when: dt(bc.last_run) }) + ' · ' : '') + t('maint.next_run', { when: dt(d.next_run) }));
    sizes.textContent = t('maint.sizes', { backups: fmtBytes(d.disk.backups), archive: fmtBytes(d.log.archive_bytes), history: fmtBytes(d.disk.history), dir: d.dir });
    list.replaceChildren();
    if (!d.backups.length) { list.append(h('p', { class: 'hint' }, t('maint.no_backups'))); return; }
    for (const b of d.backups) {
      list.append(h('div', { class: 'brow' },
        h('div', { class: 'grow' }, h('b', {}, dt(b.t)), ' ', h('span', { class: 'tag' }, kindLabel(b.kind)), b.enc ? h('span', { class: 'tag acc' }, t('maint.tag_enc')) : null, h('small', { class: 'muted' }, ' ' + fmtBytes(b.size))),
        h('div', { class: 'row', hidden: !isOwner },
          h('button', { class: 'btn sm', type: 'button', onclick: async () => {
            try {
              await withOwner(t('maint.download_title'), t('maint.download_why', { when: dt(b.t) }), (ow) => download('/api/backups/' + encodeURIComponent(b.name), b.name,
                { 'X-Kut-Owner-Pass': encodeURIComponent(ow.owner_password), 'X-Kut-Owner-Code': encodeURIComponent(ow.owner_code) }));
            } catch (x) { toast(x.message, true); }
          } }, t('maint.download')),
          h('button', { class: 'btn sm', type: 'button', onclick: async () => {
            await restoreFlow(t('maint.backup_dated', { when: dt(b.t) }), (o) => api('POST', '/api/backups/' + encodeURIComponent(b.name) + '/restore', o));
          } }, t('maint.restore')),
          h('button', { class: 'btn sm danger', type: 'button', onclick: async () => {
            if (!(await confirmBox(t('maint.delete_title'), t('maint.delete_confirm', { when: dt(b.t) }), t('maint.delete')))) return;
            try { await api('DELETE', '/api/backups/' + encodeURIComponent(b.name)); await reload(); } catch (x) { toast(x.message, true); }
          } }, t('maint.delete')))));
    }
  };
  const reload = async () => { d = await api('GET', '/api/maint'); paint(); };
  // save: ayarları yazar; yedek parolası değişiyor ya da şifreleme kapanıyorsa sahip doğrulaması ister.
  // Döner: true = kaydedildi, false = sahip doğrulamasından vazgeçildi.
  const save = async () => {
    err.textContent = '';
    const b = body();
    if (b.new_pass || b.clear_pass) {
      const ok = await withOwner(b.clear_pass ? t('maint.enc_off_title') : t('maint.pass_change_title'), b.clear_pass ? t('maint.enc_off_why') : t('maint.pass_change_why'),
        async (ow) => { d = await api('PUT', '/api/maint', { ...b, ...ow }); });
      if (!ok) { clearPass = false; return false; }
    } else d = await api('PUT', '/api/maint', b);
    pass.value = ''; clearPass = false; pass.placeholder = passPh(); paint();
    return true;
  };

  const file = h('input', { type: 'file', accept: '.gz,.tgz,application/gzip', hidden: true });
  file.addEventListener('change', async () => {
    const f = file.files[0]; file.value = '';
    if (!f) return;
    await restoreFlow(f.name, (o) => uploadBackup(f, o));
  });

  const bform = h('form', { class: 'card form' }, h('h2', {}, t('maint.backup_title')),
    h('p', { class: 'hint' }, t('maint.backup_intro')),
    h('label', { hidden: !isOwner }, t('maint.pass_label'), pass),
    h('p', { class: 'hint', hidden: !isOwner }, t('maint.pass_hint')),
    h('label', { class: 'check' }, en, h('span', {}, t('maint.auto_backup'), h('small', {}, t('maint.auto_backup_hint')))),
    h('div', { class: 'cols' }, h('label', {}, t('maint.freq'), freq), wdRow, h('label', {}, t('maint.time'), time), h('label', {}, t('maint.keep'), keep)),
    status, ownerHint, err,
    h('div', { class: 'row', hidden: !isOwner }, h('button', { class: 'btn', type: 'button', onclick: async () => {
        try {
          if (!(await save())) return;
          if (!(await withOwner(t('maint.backup_now_title'), t('maint.backup_now_why'), (ow) => api('POST', '/api/backups', ow)))) return;
          toast(t('maint.backup_made')); await reload();
        } catch (x) { err.textContent = x.message; }
      } }, t('maint.backup_now')),
      h('button', { class: 'btn', type: 'button', onclick: () => file.click() }, t('maint.from_file')), file,
      h('button', { class: 'btn', type: 'button', onclick: async () => { if (!d.has_pass) { toast(t('maint.enc_already_off')); return; } if (!(await confirmBox(t('maint.enc_off_title'), t('maint.enc_off_confirm'), t('maint.enc_off_btn')))) return; clearPass = true; try { if (await save()) toast(t('maint.enc_off_done')); } catch (x) { clearPass = false; err.textContent = x.message; } } }, t('maint.enc_off_title')),
      h('span', { class: 'grow' }), h('button', { class: 'btn primary', type: 'submit' }, t('maint.save'))),
    list, sizes);
  bform.addEventListener('submit', async (e) => { e.preventDefault(); if (!isOwner) return; try { if (await save()) toast(t('maint.backup_saved')); } catch (x) { err.textContent = x.message; } });

  const lform = h('form', { class: 'card form' }, h('h2', {}, t('maint.retention_title')),
    h('p', { class: 'hint' }, t('maint.retention_intro')),
    h('div', { class: 'cols' }, h('label', {}, t('maint.log_days'), logDays)),
    h('label', { class: 'check' }, arch, h('span', {}, t('maint.archive'), h('small', {}, t('maint.archive_hint')))),
    h('div', { class: 'cols' }, h('label', {}, t('maint.archive_keep'), archM)),
    h('p', { class: 'hint' }, t('maint.log_line', { count: t('maint.log_events', { n: d.log.total }), oldest: d.log.oldest ? t('maint.log_oldest', { when: dt(d.log.oldest) }) : '' })),
    isOwner ? null : h('p', { class: 'hint' }, t('maint.owner_only')),
    h('div', { class: 'row end', hidden: !isOwner }, h('button', { class: 'btn primary', type: 'submit' }, t('maint.save'))));
  lform.addEventListener('submit', async (e) => { e.preventDefault(); if (!isOwner) return; try { if (await save()) toast(t('maint.retention_saved')); } catch (x) { err.textContent = x.message; toast(x.message, true); } });
  paint();
  // Sahip olmayan hesap bu ayarları göremez ama değiştiremez de: alanlar salt okunur görünsün, Enter gizli Kaydet'i tetiklemesin.
  if (!isOwner) for (const f of [bform, lform]) f.querySelectorAll('input, select, textarea').forEach((el) => { el.disabled = true; });
  const sform = h('div', { class: 'card form' }, h('h2', {}, t('maint.service_title')),
    h('p', { class: 'hint' }, t('maint.service_intro')),
    h('div', { class: 'row end' }, h('button', { class: 'btn', type: 'button', onclick: async () => {
      if (!(await confirmBox(t('maint.restart_title'), t('maint.restart_confirm'), t('maint.restart_btn')))) return;
      try { const r = await api('POST', '/api/server/restart'); r.restarting ? waitRestart() : toast(t('maint.restart_dry')); } catch (x) { toast(x.message, true); }
    } }, t('maint.restart_title'))));
  return [bform, lform, sform];
}
