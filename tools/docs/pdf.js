// node pdf.js in.html out.pdf  -- print an HTML file to PDF with Chrome
const { chromium } = require('playwright'); const path = require('path');
(async () => {
  const b = await chromium.launch({ channel: 'chrome' }); const p = await b.newPage();
  await p.goto('file://' + path.resolve(process.argv[2]), { waitUntil: 'networkidle' });
  await p.pdf({ path: process.argv[3], format: 'Letter', printBackground: true, displayHeaderFooter: true,
    headerTemplate: '<span></span>',
    footerTemplate: '<div style="font:8px sans-serif;color:#6b8193;width:100%;padding:0 16mm;display:flex;justify-content:space-between"><span>UTMStack Observatory</span><span class="pageNumber"></span></div>',
    margin: { top: '16mm', bottom: '16mm', left: '0', right: '0' } });
  await b.close(); console.log('pdf', process.argv[3]);
})();
