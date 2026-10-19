// Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
// Screenshots + feature clips of the Observatory demo for the user manual and sales material.
// Usage: node capture.js <base-url> <out-dir> [shots|clips|all]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const BASE = process.argv[2] || 'http://127.0.0.1:8799';
const OUT = path.resolve(process.argv[3] || './out');
const WHAT = process.argv[4] || 'all';
const AUTH = { username: 'admin', password: process.env.DEMO_PASS || 'demo-password-1' };
const VW = { width: 1600, height: 1000 };
const IMG = path.join(OUT, 'images'), VID = path.join(OUT, 'raw-video');
fs.mkdirSync(IMG, { recursive: true }); fs.mkdirSync(VID, { recursive: true });

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function launch() {
  return chromium.launch({ channel: 'chrome' });
}

async function ready(page) {
  await page.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#mapWrap.has-base', { timeout: 30000 });
  await page.waitForFunction(() => /Running/.test((document.getElementById('statusText') || {}).textContent || ''), null, { timeout: 30000 });
  await sleep(4500);                                   // tiles, first geo answer, animations settled
}

async function shot(page, name, opts = {}) {
  await page.screenshot({ path: path.join(IMG, name + '.png'), ...opts });
  console.log('shot', name);
}

async function closeAll(page) {
  for (let i = 0; i < 3; i++) { await page.keyboard.press('Escape'); await sleep(250); }
}

async function screen(page, label) {
  await page.locator('#screenTabs .tab', { hasText: label }).first().click();
  await sleep(2500);
}

async function flyTo(page, center, zoom, ms = 2500) {
  await page.evaluate(([c, z, d]) => { const m = document.getElementById('mapBase').__map; m.flyTo({ center: c, zoom: z, duration: d }); },
    [center, zoom, ms]);
  await sleep(ms + 600);
}

const RECTS = {};
async function rects(page, name, sels) {
  // element boxes as % of the viewport, for the clickable tour's hotspots
  RECTS[name] = await page.evaluate(sels => {
    const W = innerWidth, H = innerHeight, out = {};
    for (const s of sels) {
      const e = document.querySelector(s); if (!e) continue;
      const r = e.getBoundingClientRect(); if (!r.width || r.bottom < 0 || r.top > H) continue;
      out[s] = { x: +(100 * r.left / W).toFixed(2), y: +(100 * Math.max(0, r.top) / H).toFixed(2),
                 w: +(100 * r.width / W).toFixed(2), h: +(100 * (Math.min(H, r.bottom) - Math.max(0, r.top)) / H).toFixed(2) };
    }
    return out;
  }, sels);
  fs.writeFileSync(path.join(OUT, 'rects.json'), JSON.stringify(RECTS, null, 1));
}

async function shots(browser) {
  const ctx = await browser.newContext({ httpCredentials: AUTH, viewport: VW, deviceScaleFactor: 2, colorScheme: 'dark' });
  const page = await ctx.newPage();
  await ready(page);
  await shot(page, '01-overview'); await rects(page, '01-overview', ['#envBadge','#rangeSeg','#wallBtn','#trendsBtn','#reportsBtn','#settingsBtn','#screenTabs','#editBtn','#kSrcSec','#kEvSec','#kAlSec','#kLagSec','#mapPanel','#donutTitle','#sideTabs','#logoBtn']); 
  await shot(page, '01b-overview-full', { fullPage: true });

  await screen(page, 'Live map');
  await shot(page, '02-live-map'); await rects(page, '02-live-map', ['#mapWin','#mapTypeSeg','#mapDirSeg','#mapOutSeg','#mapNetSeg','#mapPortForm','#mapStats','#mapCountries','#mapTicker','#mapZoomIn','#mapZoomReset','#mapSummary']); 
  await page.click('#mapNetSeg [data-net="tor"]'); await sleep(900); await shot(page, '03-map-tor');
  await page.click('#mapNetSeg [data-net="all"]');
  await page.fill('#mapPort', '22'); await page.press('#mapPort', 'Enter'); await sleep(3500);
  await shot(page, '04-map-port-22');
  await page.click('#mapPortClear'); await sleep(3000);
  await flyTo(page, [4.9, 52.37], 11.5, 1500); await shot(page, '05-map-street-zoom');
  await page.click('#mapZoomReset'); await sleep(2500);
  // hover a city dot for its tooltip
  await page.click('#mapTypeSeg [data-type="syslog"]'); await sleep(3500);
  await shot(page, '06-map-syslog-attackers');
  await page.click('#mapTypeSeg [data-type="all"]'); await sleep(3000);
  // attacker panel: open the newest blocked row (the ticker re-renders, so click it by script)
  await page.evaluate(() => document.querySelector('#mapTicker .tk[data-lat]').click()); await sleep(4500);
  await shot(page, '22-attacker'); await rects(page, '22-attacker', ['#digTitle', '#atk0', '#rep0']);
  await closeAll(page);

  await screen(page, 'Overview');
  await page.locator('#top5Body [data-rule]').first().click(); await sleep(1800);
  await shot(page, '07-alerts-for-rule'); await rects(page, '07-alerts-for-rule', ['#fSev','#fSrc','#fRule','#fQ','#digBody table','#digBack']); 
  await page.locator('#digBody tr[data-act="alert"]').first().click(); await sleep(3500);
  await shot(page, '08-alert-detail'); await rects(page, '08-alert-detail', ['#digTitle','#digBody .advice','#digBody .actions','#rep0','#whois0']); 
  await closeAll(page);

  await page.click('#kpiBand [data-open="sources"]'); await sleep(1800); await shot(page, '09-data-sources'); await rects(page, '09-data-sources', ['#digBody']); 
  await page.locator('#digBody tr[data-act="source"]').first().click(); await sleep(2000); await shot(page, '10-source-detail');
  await closeAll(page);
  await page.click('#kpiBand [data-open="lag"]'); await sleep(1800); await shot(page, '11-ingest-lag'); await closeAll(page);
  await page.click('#envBadge'); await sleep(1800); await shot(page, '12-cluster-health'); await rects(page, '12-cluster-health', ['#digTitle','#digBody','#copyDiag']);  await closeAll(page);
  await page.click('#trendsBtn'); await sleep(2500); await shot(page, '13-trends'); await rects(page, '13-trends', ['#histMetric','#histCanvas','#dailyCmp','#weeklyCmp']);  await closeAll(page);
  await page.click('#reportsBtn'); await sleep(1800); await shot(page, '14-reports'); await rects(page, '14-reports', ['#repGenerate','#repBody']);  await closeAll(page);
  await page.click('#settingsBtn'); await sleep(1800); await shot(page, '15-settings'); await rects(page, '15-settings', ['#setBody','#setSave','#setOpenLayout']);  await closeAll(page);
  await page.click('#editBtn'); await sleep(1200); await shot(page, '16-edit-layout'); await rects(page, '16-edit-layout', ['#addWidgetBtn','#addScreenBtn','#renameScreenBtn','#wallScreenBtn','#deleteScreenBtn','#resetShared','#saveShared','#editBtn','.w-drag']); 
  await page.click('#editBtn'); await sleep(800);
  await page.locator('#tabAi').click().catch(() => {}); await sleep(1200); await shot(page, '17-ai-traffic');
  await page.locator('#tabRules').click().catch(() => {});
  await ctx.close();

  const m = await browser.newContext({ httpCredentials: AUTH, viewport: { width: 390, height: 844 }, deviceScaleFactor: 3,
                                       isMobile: true, hasTouch: true, colorScheme: 'dark' });
  const mp = await m.newPage();
  await ready(mp);
  await shot(mp, '18-mobile-overview');
  await mp.evaluate(() => document.getElementById('mapPanel').scrollIntoView({ block: 'start' })); await sleep(2000);
  await shot(mp, '19-mobile-map');
  await m.close();
}

async function clip(browser, name, fn) {
  // CDP screencast frames + their timestamps, stitched by the system ffmpeg (Playwright's own recorder is not installed)
  const ctx = await browser.newContext({ httpCredentials: AUTH, viewport: VW, colorScheme: 'dark' });
  const page = await ctx.newPage();
  await ready(page);
  const dir = path.join(VID, name); fs.rmSync(dir, { recursive: true, force: true }); fs.mkdirSync(dir, { recursive: true });
  const cdp = await ctx.newCDPSession(page);
  const frames = [];
  cdp.on('Page.screencastFrame', async f => {
    const file = path.join(dir, String(frames.length).padStart(5, '0') + '.jpg');
    fs.writeFileSync(file, Buffer.from(f.data, 'base64'));
    frames.push({ file, t: f.metadata.timestamp });
    cdp.send('Page.screencastFrameAck', { sessionId: f.sessionId }).catch(() => {});
  });
  await cdp.send('Page.startScreencast', { format: 'jpeg', quality: 88, maxWidth: VW.width, maxHeight: VW.height, everyNthFrame: 1 });
  await sleep(600);
  await fn(page);
  await sleep(800);
  await cdp.send('Page.stopScreencast');
  await sleep(300);
  const end = Date.now() / 1000;
  let list = '';
  frames.forEach((f, i) => {
    const next = i + 1 < frames.length ? frames[i + 1].t : end;
    list += `file '${f.file}'\nduration ${Math.max(0.01, next - f.t).toFixed(3)}\n`;
  });
  if (frames.length) list += `file '${frames[frames.length - 1].file}'\n`;
  fs.writeFileSync(path.join(dir, 'frames.txt'), list);
  await ctx.close();
  console.log('clip', name, frames.length, 'frames');
}

async function clips(browser) {
  await clip(browser, 'map-filters', async p => {
    await screen(p, 'Live map');
    for (const t of ['firewall-sophos-xg', 'syslog', 'o365', 'all']) { await p.click(`#mapTypeSeg [data-type="${t}"]`); await sleep(2600); }
    for (const d of ['in', 'out', 'all']) { await p.click(`#mapDirSeg [data-dir="${d}"]`); await sleep(1800); }
    for (const o of ['denied', 'allowed', 'all']) { await p.click(`#mapOutSeg [data-out="${o}"]`); await sleep(1800); }
    for (const n of ['hosting', 'vpn', 'tor', 'all']) { await p.click(`#mapNetSeg [data-net="${n}"]`); await sleep(1800); }
  });
  await clip(browser, 'port-search', async p => {
    await screen(p, 'Live map');
    for (const port of ['22', '3389']) {
      await p.click('#mapPort'); await p.fill('#mapPort', ''); await p.type('#mapPort', port, { delay: 180 });
      await p.press('#mapPort', 'Enter'); await sleep(4200);
    }
    await p.click('#mapPortClear'); await sleep(3000);
  });
  await clip(browser, 'zoom-street-map', async p => {
    await screen(p, 'Live map');
    await flyTo(p, [-20, 45], 3, 2200);
    await flyTo(p, [4.9, 52.37], 8, 3000);
    await flyTo(p, [4.89, 52.373], 13.5, 3000);
    await p.click('#mapZoomReset'); await sleep(3200);
  });
  await clip(browser, 'alert-drilldown', async p => {
    await p.locator('#top5Body [data-rule]').nth(1).click(); await sleep(2200);
    await p.locator('#digBody tr[data-act="alert"]').first().click(); await sleep(4000);
    await p.mouse.wheel(0, 500); await sleep(2000);
    await closeAll(p);
  });
  await clip(browser, 'blocked-row-zoom', async p => {
    await screen(p, 'Live map');
    const rows = p.locator('#mapTicker .tk[data-lat]');
    for (let i = 0; i < 3; i++) { await rows.nth(i).hover(); await sleep(2600); }
    await p.mouse.move(5, 5); await sleep(2000);
  });
  await clip(browser, 'edit-layout', async p => {
    await p.click('#editBtn'); await sleep(1000);
    const h = p.locator('[data-widget="donut"] .w-drag');
    const b = await h.boundingBox();
    if (b) {
      await p.mouse.move(b.x + b.width / 2, b.y + b.height / 2); await p.mouse.down();
      await p.mouse.move(b.x - 900, b.y + 700, { steps: 30 }); await sleep(600); await p.mouse.up(); await sleep(1500);
    }
    await p.click('#editBtn'); await sleep(1500);
  });
}

(async () => {
  const browser = await launch();
  if (WHAT === 'shots' || WHAT === 'all') await shots(browser);
  if (WHAT === 'clips' || WHAT === 'all') await clips(browser);
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
