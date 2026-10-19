// Stampa la guida in PDF: node docs/guida/pdf.mjs (serve Playwright con Chromium; percorsi
// alternativi con PLAYWRIGHT_MODULE e CHROMIUM_PATH). Scrive docs/NetMon-sonda-Home-Assistant.pdf.
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
const here = path.dirname(fileURLToPath(import.meta.url));
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const b = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const p = await b.newPage();
await p.goto(pathToFileURL(path.join(here, "NetMon-sonda-Home-Assistant.html")).href, { waitUntil: "load" });
await p.pdf({
  path: path.join(here, "..", "NetMon-sonda-Home-Assistant.pdf"), format: "A4", printBackground: true,
  displayHeaderFooter: true, headerTemplate: "<span></span>",
  footerTemplate: '<div style="width:100%;text-align:center;font-size:8px;color:#556171;font-family:sans-serif">'
    + 'NetMon sonda su Home Assistant · pagina <span class="pageNumber"></span> di <span class="totalPages"></span></div>',
  margin: { top: "16mm", bottom: "18mm", left: "16mm", right: "16mm" },
});
await b.close();
