// README ekran görüntüleri: sahte verili bir dry-run sunucusu kurar, headless Chrome ile çeker,
// her karenin DOM metnini gizlilik desenlerine karşı denetler ve docs/screenshots/ altına yazar.
// Ürün kodunu değiştirmez. Yalnızca geliştirme zamanı: go, google-chrome (ya da CHROME), magick.
//   make screenshots
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { hostname, userInfo } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT = join(ROOT, 'docs', 'screenshots');
const DEMO = '/tmp/kut-demo';
const MARK = join(DEMO, '.kut-demo'); // yalnızca bu betiğin açtığı dizini silmek için
const DATA = join(DEMO, 'data');
const BIN = join(DEMO, 'kut');
const LISTEN = '127.0.0.1:5099';
const BASE = `http://${LISTEN}`;
const CDP_PORT = 9339;
const CHROME = process.env.CHROME || 'google-chrome';
const PW = randomBytes(18).toString('base64url');
const MAX_BYTES = 300 * 1024;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'inherit'], ...opts });

// Gizlilik: yakalanan her alanın DOM metninde bunlardan biri varsa betik durur, dosya yazılmaz.
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const PRIVACY = [
  ['hostname', new RegExp(esc(hostname()), 'i')],
  ['$USER', new RegExp(`\\b${esc(process.env.USER || userInfo().username)}\\b`, 'i')],
  ['/home/', /\/home\//],
  ['/tmp/kut-demo', /\/tmp\/kut-demo/],
  ['81.x address', /(^|[^\d.])81\.\d{1,3}\.\d{1,3}\.\d{1,3}/],
  ['10.10.x address', /(^|[^\d.])10\.10\.\d{1,3}\.\d{1,3}/],
  ['name Fatih', /fatih/i],
  ['name Cagkan', /ca[gğ]kan/i],
  ['name Levent', /levent/i],
  ['ergenekon', /ergenekon/i],
];

// ---- Demo dizini ----
function freshDemo() {
  if (existsSync(DEMO)) {
    if (!existsSync(MARK)) throw new Error(`${DEMO} var ama bu betiğe ait değil (${MARK} yok); el ile bak.`);
    rmSync(DEMO, { recursive: true, force: true });
  }
  mkdirSync(DATA, { recursive: true });
  writeFileSync(MARK, '');
}
function cleanupDemo() {
  if (existsSync(MARK)) rmSync(DEMO, { recursive: true, force: true });
}
// Veri dizini başkalarına okunur kalırsa rapor tam yolu gösteren bir uyarı basar; izinleri kapat.
function lockDown(p) {
  chmodSync(p, statSync(p).isDirectory() ? 0o700 : 0o600);
  if (statSync(p).isDirectory()) for (const f of readdirSync(p)) lockDown(join(p, f));
}

// ---- Trafik geçmişi: birikimli sayaçlar [t, rx, tx], kesintisiz 60 dakika. Son örnek HOLD sn ileridedir:
// series.add (tiers.go) son örnekten 14 sn'den yakın örneği eklemez, bu yüzden çekim bitene kadar canlı dry-run
// örnekleri (sayaçları bambaşka bir yerden başlar) grafiğe girmez; ne boşluk bandı ne sıfıra düşüş olur.
// Grafik ekseni örneklerden alınır; sağ uç en çok HOLD sn ileriyi gösterir. ----
const HOLD = 150;
let seedEnd = 0;
function seedHistory() {
  const now = Math.floor(Date.now() / 1000);
  const end = (seedEnd = now + HOLD);
  const rate = (t) => {
    const h = ((t / 3600) % 24 + 24) % 24;
    const day = 0.55 + 0.45 * Math.sin(((h - 9) / 24) * 2 * Math.PI); // gündüz yüksek
    const wob = 1 + 0.35 * Math.sin(t / 410) + 0.2 * Math.sin(t / 97);
    // Ölçek dry-run'ın sahte sayaçlarına yakın (wg.go: ~34 KB/s alım, ~134 KB/s gönderim) ki grafik tek parça okunsun.
    return { rx: 34_000 * day * wob, tx: 134_000 * day * wob * (1 + 0.25 * Math.sin(t / 233)) };
  };
  const tier = (step, keep) => {
    const out = [];
    let rx = 40_000_000, tx = 120_000_000;
    for (let i = keep - 1; i >= 0; i--) {
      const t = end - i * step;
      const r = rate(t);
      rx += Math.round(r.rx * step);
      tx += Math.round(r.tx * step);
      out.push([t, rx, tx]);
    }
    return out;
  };
  // tiers.go: 1 saat @15 sn · 24 saat @5 dk · 7 gün @30 dk · 30 gün @2 sa
  const f = { v: 1, saved: now, global: [tier(15, 240), tier(300, 288), tier(1800, 336), tier(7200, 360)], peers: {} };
  writeFileSync(join(DATA, 'history.json.gz'), gzipSync(JSON.stringify(f)), { mode: 0o600 });
}

// ---- Panel API'si ----
let cookie = '';
async function api(method, path, body) {
  const r = await fetch(BASE + path, {
    method,
    headers: { 'X-Kut': '1', 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const sc = r.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  const txt = await r.text();
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${txt}`);
  return txt ? JSON.parse(txt) : null;
}
// Ada göre cihaz kimliği: yanıt şekline bağlanmamak için durum JSON'unda {id, name} çiftlerini arar.
function findIds(obj, names, acc = {}) {
  if (Array.isArray(obj)) obj.forEach((x) => findIds(x, names, acc));
  else if (obj && typeof obj === 'object') {
    if (typeof obj.id === 'string' && names.includes(obj.name) && obj.public_key !== undefined) acc[obj.name] = obj.id;
    Object.values(obj).forEach((x) => findIds(x, names, acc));
  }
  return acc;
}

async function populate() {
  await api('POST', '/api/login', { username: 'admin', password: PW, code: '' });
  await api('PUT', '/api/me/lang', { lang: 'en' });
  // Sıra önemli: dry-run sahte trafiği ilk iki etkin cihaza verir (laptop, phone).
  const devs = [
    { name: 'laptop', kind: 'laptop', group: 'Personal' },
    { name: 'phone', kind: 'phone', group: 'Personal', internet: true },
    { name: 'tablet', kind: 'tablet', group: 'Personal' },
    { name: 'home-server', kind: 'server', group: 'Home' },
    { name: 'nas', kind: 'server', group: 'Home' },
    { name: 'guest-laptop', kind: 'laptop', expires_minutes: 3 * 24 * 60 },
  ];
  for (const d of devs) await api('POST', '/api/peers', d);
  const names = devs.map((d) => d.name);
  const ids = findIds(await api('GET', '/api/status'), names);
  for (const n of names) if (!ids[n]) throw new Error(`cihaz kimliği bulunamadı: ${n}`);
  const pol = await api('POST', '/api/policies', {
    name: 'Personal',
    desc: 'Laptop reaches the home server and NAS; laptop and phone reach each other.',
    rules: [
      { target: 'device', device: ids['home-server'], proto: 'tcp', ports: '22', note: 'SSH' },
      { target: 'device', device: ids.nas, proto: 'tcp', ports: '445', note: 'SMB' },
      { target: 'device', device: ids.phone, proto: 'any', both: true, note: 'laptop <-> phone' },
    ],
    groups: [],
  });
  await api('PATCH', `/api/peers/${ids.laptop}`, { name: 'laptop', policy: pol.id });
}

// ---- Chrome / DevTools protokolü ----
async function chrome() {
  const proc = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${join(DEMO, 'chrome')}`,
    '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', '--lang=en-US', '--force-color-profile=srgb', 'about:blank'], { stdio: 'ignore' });
  let targets;
  for (let i = 0; i < 60 && !targets; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json`)).json(); } catch { await sleep(250); }
  }
  if (!targets) throw new Error('Chrome DevTools uç noktası açılmadı');
  const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.addEventListener('open', r, { once: true }); ws.addEventListener('error', j, { once: true }); });
  let id = 0;
  const pend = new Map();
  const errors = [];
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); return; }
    if (m.method === 'Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
    if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error' && !/status of 401/.test(m.params.entry.text)) errors.push(m.params.entry.text);
  });
  const send = (method, params = {}) => new Promise((r, j) => {
    const i = ++id;
    pend.set(i, (m) => (m.error ? j(new Error(`${method}: ${m.error.message}`)) : r(m.result)));
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  for (const d of ['Page', 'Runtime', 'Log', 'DOM', 'CSS']) await send(`${d}.enable`);
  const ev = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  };
  return { proc, ws, send, ev, errors };
}

async function main() {
  freshDemo();
  run('go', ['build', '-o', BIN, '.'], { cwd: ROOT, env: { ...process.env, CGO_ENABLED: '0' } });
  run(BIN, ['init', '-dry-run', '-data', DATA, '-endpoint', '203.0.113.10', '-subnet', '10.77.0.0/24', '-lang', 'en']);
  run(BIN, ['passwd', '-data', DATA, '-lang', 'en'], { env: { ...process.env, KUT_PASSWORD: PW } });
  seedHistory();
  lockDown(DATA);

  // Tek sunucu, yeniden başlatma yok: geçmiş açılışta yüklenir, cihazlar sonra eklenir.
  const srv = spawn(BIN, ['serve', '-dry-run', '-data', DATA, '-listen', LISTEN, '-lang', 'en'], { stdio: 'ignore' });
  const stop = (p) => new Promise((r) => { if (p.exitCode !== null) return r(); p.once('exit', r); p.kill(); });
  let br;
  try {
    for (let i = 0; i < 60; i++) { try { await fetch(BASE + '/'); break; } catch { await sleep(250); } }
    await populate();
    await sleep(10_000); // anlık hız (SSE, 4 sn) iki ölçümle oturur
    br = await chrome();
    const { send, ev, errors } = br;

    const DASH_H = 1040; // panel: trafik grafiği de görünsün (kenar çubuğu 100vh, bu yüzden kırpma değil görünüm yüksekliği)
    const view = (w, h) => send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: w < 600 });
    // Yalnızca bu betikte: dry-run rozetlerini gizle. CSS alanı sayfanın CSP'sine takılmaz.
    const hideDry = async () => {
      const { frameTree } = await send('Page.getFrameTree');
      const { styleSheetId } = await send('CSS.createStyleSheet', { frameId: frameTree.frame.id });
      await send('CSS.setStyleSheetText', { styleSheetId, text: '.chip.dry, .fwrules p.hint { display: none !important; }' });
    };
    const open = async (hash, theme) => {
      await send('Page.navigate', { url: BASE + '/' });
      await sleep(400);
      await ev(`localStorage.setItem('kut-theme', '${theme}')`);
      await ev(`fetch('/api/login', { method: 'POST', headers: { 'X-Kut': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: ${JSON.stringify(PW)}, code: '' }) }).then((r) => r.status)`);
      await send('Page.navigate', { url: BASE + '/?shot=' + Date.now() + '#' + hash });
      await sleep(2500);
      await hideDry();
      await sleep(300);
    };
    // Rapordaki yedek kartı veri dizinini yazar; demo yolunu gerçek kurulumdaki varsayılanla (/var/lib/kut) göster.
    // Yalnızca ekrandaki metin değişir; gizlilik denetimi bundan sonra çalışır.
    const maskDataDir = () => ev(`(() => { const tw = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let n; (n = tw.nextNode());) if (n.data.includes(${JSON.stringify(DATA)})) n.data = n.data.split(${JSON.stringify(DATA)}).join('/var/lib/kut'); })()`);
    // Bir alandaki görünür metin + öznitelik değerleri (title, aria-label, alt, placeholder, value).
    const areaText = (clip) => ev(`(() => {
      const c = ${JSON.stringify(clip)}, out = [];
      const hit = (r) => r.width > 0 && r.height > 0 && r.right > c.x && r.left < c.x + c.width && r.bottom > c.y && r.top < c.y + c.height;
      const sx = scrollX, sy = scrollY;
      const abs = (r) => ({ left: r.left + sx, right: r.right + sx, top: r.top + sy, bottom: r.bottom + sy, width: r.width, height: r.height });
      const tw = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let n; (n = tw.nextNode());) {
        const el = n.parentElement;
        if (!n.data.trim() || !el || !el.checkVisibility({ visibilityProperty: true, opacityProperty: true })) continue;
        const rg = document.createRange(); rg.selectNodeContents(n);
        if ([...rg.getClientRects()].some((r) => hit(abs(r)))) out.push(n.data);
      }
      for (const el of document.body.querySelectorAll('*')) {
        if (!el.checkVisibility() || !hit(abs(el.getBoundingClientRect()))) continue;
        for (const a of ['title', 'aria-label', 'alt', 'placeholder']) if (el.getAttribute(a)) out.push(el.getAttribute(a));
        if ('value' in el && typeof el.value === 'string' && el.value) out.push(el.value);
      }
      return out.join('\\n');
    })()`);
    const viewportClip = (w, h) => ({ x: 0, y: 0, width: w, height: h });
    const rectOf = (sel) => ev(`(() => { const r = [...document.querySelectorAll(${JSON.stringify(sel)})].map((e) => e.getBoundingClientRect());
      if (!r.length) return null; const x = Math.min(...r.map((q) => q.left)) + scrollX, y = Math.min(...r.map((q) => q.top)) + scrollY;
      return { x, y, width: Math.max(...r.map((q) => q.right)) + scrollX - x, height: Math.max(...r.map((q) => q.bottom)) + scrollY - y }; })()`);
    const pad = (r, p) => ({ x: Math.max(0, Math.floor(r.x - p)), y: Math.max(0, Math.floor(r.y - p)), width: Math.ceil(r.width + 2 * p), height: Math.ceil(r.height + 2 * p) });

    const report = [];
    const shoot = async (file, clip, beyond = false) => {
      await maskDataDir();
      const text = await areaText(clip);
      const hits = PRIVACY.filter(([, re]) => re.test(text)).map(([n]) => n);
      if (hits.length) {
        const lines = text.split('\n').filter((l) => PRIVACY.some(([, re]) => re.test(l)));
        throw new Error(`${file}: gizlilik denetimi başarısız: ${hits.join(', ')}\n  ${lines.join('\n  ')}`);
      }
      const r = await send('Page.captureScreenshot', { format: 'png', clip: { ...clip, scale: 1 }, captureBeyondViewport: beyond });
      const raw = join(DEMO, file);
      writeFileSync(raw, Buffer.from(r.data, 'base64'));
      const dst = join(OUT, file);
      run('magick', [raw, '-strip', '-define', 'png:compression-level=9', '-define', 'png:compression-filter=5', dst]);
      if (statSync(dst).size > MAX_BYTES) run('magick', [raw, '-strip', '+dither', '-colors', '256', '-define', 'png:compression-level=9', dst]);
      const size = statSync(dst).size;
      if (size > MAX_BYTES) throw new Error(`${file}: ${size} B > 300 KB`);
      report.push({ file, size, w: clip.width, h: clip.height, chars: text.length });
    };

    mkdirSync(OUT, { recursive: true });
    await view(1400, 900);

    // Panel: trafik kartının altına kadar; görünüm o yüksekliğe ayarlanır ki kenar çubuğu zemini kesilmesin.
    const dash = async (theme, file) => {
      await view(1400, DASH_H);
      await open('panel', theme);
      const r = await rectOf('#view section.card:has(.legend)');
      const hgt = Math.min(DASH_H, Math.ceil(r.y + r.height + 12));
      await view(1400, hgt);
      await sleep(400);
      await shoot(file, viewportClip(1400, hgt));
      await view(1400, 900);
    };
    await dash('dark', '01-dashboard.png');

    await open('cihazlar', 'dark');
    await shoot('02-devices.png', viewportClip(1400, 900));

    // Rapor: yalnızca Security ve Devices kartları ve erişim matrisi; geri kalan her bölüm gizlenir.
    await open('rapor', 'dark');
    await ev(`(() => { const keep = (s) => s.querySelector('table') || (s.closest('.grid2') && ['Security', 'Devices'].includes(s.querySelector('h2')?.textContent.trim()));
      for (const s of document.querySelectorAll('#view section.card')) if (!keep(s)) s.hidden = true; })()`);
    await sleep(200);
    await shoot('03-status-report.png', pad(await rectOf('#view .grid2, #view section.card:not([hidden]):has(table)'), 16), true);

    // Sunucu: yalnızca kural tabloları.
    await open('sunucu', 'dark');
    await ev(`(() => { for (const s of document.querySelectorAll('#view section')) if (!s.closest('.fwrules')) s.hidden = true; })()`);
    await sleep(200);
    await shoot('04-server-rules.png', pad(await rectOf('#view section.fwrules'), 16), true);

    await view(390, 844);
    await open('cihazlar', 'dark');
    await shoot('05-devices-mobile.png', viewportClip(390, 844));

    await view(1400, 900);
    await dash('light', '06-dashboard-light.png');

    if (errors.length) throw new Error('tarayıcı konsolunda hata:\n' + errors.join('\n'));
    // Çekim, canlı örneklerin saatlik grafiğe girmeye başladığı andan (seedEnd + 14 sn) önce bitmiş olmalı.
    const left = seedEnd + 14 - Math.floor(Date.now() / 1000);
    if (left <= 0) throw new Error(`çekim ${-left} sn geç bitti; canlı örnekler grafiğe girmiş olabilir (HOLD'u büyüt)`);
    console.log('Gizlilik denetimi (her karenin görünür DOM metni + title/aria-label/alt/placeholder/value):');
    for (const [n, re] of PRIVACY) console.log(`  - ${n}: ${re}`);
    for (const r of report) console.log(`${r.file}: ${r.w}x${r.h}, ${(r.size / 1024).toFixed(0)} KB, ${r.chars} karakter denetlendi, eşleşme yok`);
  } finally {
    // Chrome kapanırken profile yazar: düzgün kapat ve çıkmasını bekle, yoksa silinen dizini yeniden açar.
    if (br) {
      const gone = new Promise((r) => (br.proc.exitCode !== null ? r() : br.proc.once('exit', r)));
      await Promise.race([br.send('Browser.close').catch(() => {}), sleep(3000)]);
      await Promise.race([gone, sleep(5000).then(() => br.proc.kill('SIGKILL'))]);
      await gone;
      br.ws.close();
    }
    await stop(srv);
    cleanupDemo();
  }
}

main().catch((e) => { console.error(e.message); cleanupDemo(); process.exit(1); });
