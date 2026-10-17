import { api, clear, fmtDate, h, s, toast } from './util.js';
import { t } from './i18n.js';

export default {
  async render(el) {
    const a = await api('GET', '/api/about');
    const upd = h('div', { class: 'stack' });
    function paintUpd(u, enabled) {
      clear(upd);
      if (!u || !u.checked_at) {
        upd.append(h('p', { class: 'muted' }, enabled ? t('about.not_checked') : t('about.check_off')));
        return;
      }
      if (u.error) upd.append(h('p', { class: 'hint bad' }, u.error));
      else if (u.newer) upd.append(h('p', {}, h('b', {}, t('about.new_version', { version: u.latest })), ' ', /^https:\/\//.test(u.url) ? h('a', { href: u.url, target: '_blank', rel: 'noopener noreferrer' }, t('about.release_notes')) : null));
      else upd.append(h('p', { class: 'hint ok' }, t('about.up_to_date', { version: a.version })));
      upd.append(h('p', { class: 'sm muted' }, t('about.last_check', { when: fmtDate(u.checked_at) })));
    }
    paintUpd(a.update, a.update_check);
    const chk = h('button', { class: 'btn mut', type: 'button' }, t('about.check_now'));
    chk.onclick = async () => {
      chk.disabled = true;
      try { paintUpd(await api('POST', '/api/update/check'), a.update_check); } catch (e) { toast(e.message, true); }
      chk.disabled = false;
    };
    const kv = [[t('about.k_version'), a.version], [t('about.k_schema'), String(a.schema)], [t('about.k_build'), [a.commit, a.commit_time].filter(Boolean).join(' · ') || '—'], [t('about.k_go'), a.go + ' · ' + a.os + '/' + a.arch], [t('about.k_data_dir'), a.data_dir], [t('about.k_started'), fmtDate(a.started)]];
    el.append(s('svg', { class: 'about-logo', 'aria-hidden': 'true' }, s('use', { href: '/img/kut-logo.svg#logo' })),
      h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, t('about.title')))),
      h('div', { class: 'grid2' },
        h('section', { class: 'card' }, h('h2', {}, a.name + ' ' + a.version), h('p', { class: 'muted' }, t('about.tagline', { tagline: a.tagline })),
          h('dl', { class: 'kv' }, kv.flatMap(([k, v]) => [h('dt', {}, k), h('dd', { class: 'mono' }, v)]))),
        h('section', { class: 'card' }, h('h2', {}, t('about.links')),
          h('p', {}, h('a', { href: a.repo, target: '_blank', rel: 'noopener noreferrer' }, t('about.github', { repo: a.repo.replace('https://github.com/', '') }))),
          h('p', {}, h('a', { href: a.github, target: '_blank', rel: 'noopener noreferrer' }, '@' + a.github_user)),
          h('p', {}, h('a', { href: a.site, target: '_blank', rel: 'noopener noreferrer' }, a.site_name)),
          h('hr', { class: 'sep' }), h('h2', {}, t('about.updates')), upd, h('div', { class: 'row' }, chk)),
      ));
  },
};
