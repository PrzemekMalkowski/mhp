// Offline copy boot: runs before the UI script. The UI talks to mhp only through fetch() and EventSource; here
// fetch() of a local path is answered by mhp's own handlers compiled to WebAssembly (cmd/mhpwasm), on the state
// embedded below, and EventSource never fires (nothing is live).
(()=>{
const st=document.getElementById('st'),say=t=>{st.textContent=t};
const b64=async id=>{const s=document.getElementById(id).textContent.trim();
 try{return new Uint8Array(await (await fetch('data:application/octet-stream;base64,'+s)).arrayBuffer())}
 catch(_){const bin=atob(s),u=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);return u}};
const gunzip=async u=>new Uint8Array(await new Response(new Blob([u]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer());
const ready=(async()=>{
 say('loading offline copy…');
 const go=new Go(),up=new Promise(r=>globalThis.mhpReady=r);
 const {instance}=await WebAssembly.instantiate(await gunzip(await b64('mhp-wasm')),go.importObject);
 go.run(instance);await up;
 const err=mhpLoad(await b64('mhp-data'));if(err)throw new Error(err);
 const info=JSON.parse(new TextDecoder().decode(mhpServe('/info').body)),o=info.offline||{};
 say(`offline copy taken ${new Date(o.created).toLocaleString()} · ${o.views} views`);
})();
ready.catch(e=>{say('offline copy failed to load: '+e.message);console.error(e)});
const serve=async url=>{await ready;return mhpServe(String(url))};
const origFetch=window.fetch.bind(window);
window.fetch=async(u,opt)=>{const s=String(u);if(!s.startsWith('/'))return origFetch(u,opt);
 if(opt&&opt.method&&opt.method!=='GET')return new Response('read-only offline copy',{status:405});
 const r=await serve(s);return new Response(r.body,{status:r.status,headers:{'Content-Type':r.type||'text/plain'}})};
window.EventSource=class{constructor(){}close(){}};
// downloads (exports, reports) are generated in the page and saved from a blob
window.mhpOffline={download:async url=>{const r=await serve(url);if(r.status!==200){alert(new TextDecoder().decode(r.body));return}
 const m=/filename="([^"]+)"/.exec(r.disp||''),name=m?m[1]:'mhp-'+url.slice(1).split('?')[0].replace(/[^\w.-]/g,'_');
 const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([r.body],{type:r.type}));a.download=name;
 document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),60000)}};
document.addEventListener('click',e=>{const a=e.target.closest&&e.target.closest('a[href^="/"]');if(!a)return;
 e.preventDefault();mhpOffline.download(a.getAttribute('href'))},true);
// show everything that was kept, and do not poll: the data does not change
try{localStorage.setItem('win','86400')}catch(_){}
const xa=document.getElementById('xa');if(xa)xa.checked=false;
const ob=document.getElementById('offl');if(ob)ob.classList.add('hidden'); // keep it: the UI script sets its handler
})();
