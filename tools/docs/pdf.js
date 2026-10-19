// Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
// node pdf.js in.html out.pdf  -- print an HTML file to PDF with Chrome
const { chromium } = require('playwright'); const path = require('path');
(async () => {
  const b = await chromium.launch({ channel: 'chrome' }); const p = await b.newPage();
  await p.goto('file://' + path.resolve(process.argv[2]), { waitUntil: 'networkidle' });
  // logo on every page (Chrome only allows inline images in header templates) and the copyright in the footer
  const logoFile = process.argv[4] || path.join(__dirname, '..', '..', 'docs', 'media', 'brand', 'logo.png');
  const logo = require('fs').existsSync(logoFile) ? require('fs').readFileSync(logoFile).toString('base64') : '';
  await p.pdf({ path: process.argv[3], format: 'Letter', printBackground: true, displayHeaderFooter: true,
    headerTemplate: '<div style="width:100%;padding:0 16mm;display:flex;justify-content:space-between;align-items:center;border-bottom:1.5px solid #0A9FC4;padding-bottom:2mm;margin-bottom:2mm">' +
      (logo ? '<img src="data:image/png;base64,' + logo + '" style="height:8mm">' : '<span></span>') +
      '<span style="font:8px Helvetica,Arial,sans-serif;color:#5B7083"><span class="title"></span></span></div>',
    footerTemplate: '<div style="font:8px Helvetica,Arial,sans-serif;color:#5B7083;width:100%;padding:0 16mm;display:flex;justify-content:space-between">' +
      '<span>© 2026 Victor Beitner. All rights reserved.</span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>',
    margin: { top: '22mm', bottom: '16mm', left: '0', right: '0' } });
  await b.close(); console.log('pdf', process.argv[3]);
})();
