import {build} from 'esbuild';
import {mkdir,copyFile,readFile} from 'node:fs/promises';
await mkdir('dist',{recursive:true});
for(const name of ['background','app','bridge','content'])await build({entryPoints:[`src/${name}.mjs`],outfile:`dist/${name}.js`,bundle:true,format:'iife',platform:'browser',target:'firefox150',legalComments:'eof',define:{'import.meta.url':'""'},inject:name==='background'?['src/node-shims.mjs']:[]});
for(const name of ['manifest.json','app.html','app.css'])await copyFile(name,`dist/${name}`);
await copyFile('pkg/kagitaba_browser_bg.wasm','dist/kagitaba_browser_bg.wasm');
const manifest=JSON.parse(await readFile('dist/manifest.json','utf8'));
console.log(`Built ${manifest.name} ${manifest.version} in extension/firefox/dist`);

await copyFile('../../assets/fonts/DejaVuSansMono.ttf','dist/DejaVuSansMono.ttf');
await copyFile('../../assets/fonts/LICENSE','dist/FONT-LICENSE');
