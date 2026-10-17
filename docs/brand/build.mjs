// Logo dosyalarını docs/brand/source.png'den yeniden üretir. Yalnızca geliştirme zamanı:
// ImageMagick (magick), potrace ve rsvg-convert gerekir; ikili bunların hiçbirine ihtiyaç duymaz.
//   node docs/brand/build.mjs
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const brand = dirname(fileURLToPath(import.meta.url));
const web = join(brand, '..', '..', 'web');
const src = join(brand, 'source.png');
const tmp = mkdtempSync(join(tmpdir(), 'kut-brand-'));
const run = (cmd, ...args) => execFileSync(cmd, args, { stdio: ['ignore', 'ignore', 'inherit'] });
const t = (f) => join(tmp, f);

// 1) Renk ayrıştırma, 2x örneklemde (kenarlar yumuşak çıksın). PBM'de siyah = dolu.
//    Krem: mavi kanal > %60. Altın: R-B > %26 (zemin ve kremde fark ~0).
run('magick', src, '-filter', 'Lanczos', '-resize', '200%', '-channel', 'B', '-separate', '-threshold', '60%', '-negate', t('cream.pbm'));
run('magick', src, '-filter', 'Lanczos', '-resize', '200%', '-fx', 'r-b', '-threshold', '26%', '-negate', t('gold.pbm'));

// 2) Sağ kulağın yanındaki ince ayrı parça (kremde 3 numaralı bileşen, ~47x158 px @2x) atılır; kulak tek parça kalır.
run('magick', t('cream.pbm'), '-negate', '-define', 'connected-components:remove-ids=3', '-define', 'connected-components:mean-color=true',
  '-connected-components', '8', '-threshold', '50%', '-negate', t('cream1.pbm'));

// 3) Parçalar: işaret (y < 1790 @2x) ve yazı/alt çizgi ayrı.
const cut = (inp, out, rect) => run('magick', inp, '-fill', 'white', '-draw', `rectangle ${rect}`, out);
cut(t('cream1.pbm'), t('wolf.pbm'), '0,1790 2508,2508');
cut(t('cream1.pbm'), t('word.pbm'), '0,0 2508,1789');
cut(t('gold.pbm'), t('ring.pbm'), '0,2050 2508,2508');
cut(t('gold.pbm'), t('uline.pbm'), '0,0 2508,2049');
// Küçük boy için dolu siluet: kapat (Disk:32), sonra dış zemin dışında her şeyi doldur (göz/yele/kulak içi gider).
run('magick', t('wolf.pbm'), '-negate', '-morphology', 'Close', 'Disk:32', '-threshold', '50%', '-fill', 'red', '-draw', 'color 2,2 floodfill',
  '-fill', 'black', '+opaque', 'red', '-fill', 'white', '-opaque', 'red', t('wolfs.pbm'));

const trace = (name, extra = ['-t', '40', '-a', '1.0', '-O', '0.4']) => {
  run('potrace', t(`${name}.pbm`), '-b', 'svg', '-u', '1', '--flat', ...extra, '-o', t(`${name}.svg`));
  return [...readFileSync(t(`${name}.svg`), 'utf8').matchAll(/ d="([^"]+)"/g)].map((m) => m[1].replace(/\s+/g, ' ').trim()).join(' ');
};
const P = { wolf: trace('wolf'), word: trace('word'), ring: trace('ring'), uline: trace('uline'), wolfs: trace('wolfs', ['-t', '200', '-a', '1.2', '-O', '0.8']) };

const G = 'matrix(.5 0 0 -.5 0 1254)'; // potrace (2x, y yukarı) → 1x, y aşağı

// Halka: kaynaktaki halkaya oturtulmuş daire (merkez 617.7,546.5; r 343). Basit işarette kalın, nodsuz yaylar.
const C = { x: 617.7, y: 546.5, r: 343 };
const pt = (a) => [(C.x + C.r * Math.cos((a * Math.PI) / 180)).toFixed(1), (C.y + C.r * Math.sin((a * Math.PI) / 180)).toFixed(1)];
const arc = (a0, a1) => {
  const [x0, y0] = pt(a0), [x1, y1] = pt(a1);
  return `M${x0} ${y0}A${C.r} ${C.r} 0 ${(a1 - a0 + 360) % 360 > 180 ? 1 : 0} 1 ${x1} ${y1}`;
};
const ringS = arc(286, 40) + arc(143, 250);

const write = (path, s) => { writeFileSync(path, s); console.log(`${path.replace(join(brand, '..', '..') + '/', '')}: ${Buffer.byteLength(s)} B`); };

// Tam logo (yazılı), docs/brand: zemin dahil, sabit renkler.
const full = (bg, fg, acc) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1254 1254" role="img" aria-label="Kut">
<rect width="1254" height="1254" fill="${bg}"/>
<g transform="${G}"><path fill="${fg}" d="${P.wolf} ${P.word}"/><path fill="${acc}" d="${P.ring} ${P.uline}"/></g>
</svg>
`;
write(join(brand, 'kut-logo-dark.svg'), full('#0d151b', '#f3efe6', '#e3b55f'));
write(join(brand, 'kut-logo-light.svg'), full('#f2f4f3', '#13212b', '#a8740f'));

// Panel işaretleri: <use> ile çağrılır, renkler panelin tema değişkenlerinden gelir (CSP: <style> yok).
// 26 px'te de ayrıntılı işaret kullanılır: sade siluet (favicon) o boyda kurt olarak okunmuyordu (2x ve 1x çizimle karşılaştırıldı).
write(join(web, 'img', 'kut-mark.svg'), `<svg xmlns="http://www.w3.org/2000/svg">
<symbol id="mark" viewBox="252 124 762 762"><g transform="${G}"><path fill="var(--fg)" d="${P.wolf}"/><path fill="var(--accent)" d="${P.ring}"/></g></symbol>
</svg>
`);
// Hakkında sayfası: yazılı tam logo, zeminsiz, temaya uyar.
write(join(web, 'img', 'kut-logo.svg'), `<svg xmlns="http://www.w3.org/2000/svg">
<symbol id="logo" viewBox="236 120 790 970"><g transform="${G}"><path fill="var(--fg)" d="${P.wolf} ${P.word}"/><path fill="var(--accent)" d="${P.ring} ${P.uline}"/></g></symbol>
</svg>
`);

// Favicon: yuvarlak kare üzerinde sade işaret, sabit renkler.
const icon = (rx) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="208 116 820 820">
<rect x="208" y="116" width="820" height="820" rx="${rx}" fill="#0d151b"/>
<path d="${ringS}" fill="none" stroke="#e3b55f" stroke-width="64" stroke-linecap="round"/>
<path fill="#f3efe6" transform="${G}" d="${P.wolfs}"/>
</svg>
`;
write(join(web, 'favicon.svg'), icon(170));

// PNG'ler: apple-touch-icon (180, saydamlık yok; köşeleri iOS yuvarlar) ve GitHub sosyal önizleme (1280x640).
const iconSq = t('icon.svg');
writeFileSync(iconSq, icon(0));
run('rsvg-convert', '-w', '180', '-h', '180', '-b', '#0d151b', iconSq, '-o', t('ati.png'));
run('magick', t('ati.png'), '-alpha', 'off', '-strip', join(web, 'apple-touch-icon.png'));
run('rsvg-convert', '-h', '600', '-b', '#0d151b', join(brand, 'kut-logo-dark.svg'), '-o', t('logo600.png'));
run('magick', '-size', '1280x640', 'xc:#0d151b', t('logo600.png'), '-gravity', 'center', '-composite', '-alpha', 'off', '-strip', join(brand, 'social-preview.png'));
rmSync(tmp, { recursive: true });
for (const f of [join(web, 'apple-touch-icon.png'), join(brand, 'social-preview.png')]) console.log(`${f.replace(join(brand, '..', '..') + '/', '')}: ${readFileSync(f).length} B`);
