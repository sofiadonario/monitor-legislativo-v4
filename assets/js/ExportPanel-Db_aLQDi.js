var M=Object.defineProperty;var O=(i,e,a)=>e in i?M(i,e,{enumerable:!0,configurable:!0,writable:!0,value:a}):i[e]=a;var w=(i,e,a)=>O(i,typeof e!="symbol"?e+"":e,a);import{j as s}from"./index-BtoLpdDV.js";import{r as $}from"./leaflet-vendor-CjtGvW3T.js";import{g as A}from"./react-vendor-BtP0CW_r.js";import{r as F,h as B}from"./utils-BBf_8Sh2.js";const P=i=>{const e=i.map(l=>{const d=l.source.includes("Câmara")?"Brasil. Câmara dos Deputados":l.source.includes("Senado")?"Brasil. Senado Federal":l.source.includes("LexML")?"Brasil. LexML":"Brasil",c=new Date(l.date).getFullYear();return`@legislation{${`${l.type}${l.number.replace(/[^0-9]/g,"")}${c}`},
  title={${l.title}},
  author={${d}},
  year={${c}},
  type={${l.type}},
  number={${l.number}},
  institution={${l.source}},
  url={${l.url||""}},
  note={Accessed: ${new Date().toLocaleDateString("en-CA")}}
}`}).join(`

`),a=`% BibTeX export from Brazilian Transport Legislation Monitor
% Generated: ${new Date().toISOString()}
% Total entries: ${i.length}

${e}`,t=new Blob([a],{type:"text/plain;charset=utf-8"}),o=URL.createObjectURL(t),r=document.createElement("a");r.href=o,r.download=`transport-legislation-${new Date().toISOString()}.bib`,document.body.appendChild(r),r.click(),document.body.removeChild(r),URL.revokeObjectURL(o)};var z=F();const _=A(z),K=(i,e)=>{const a=i.map(o=>({ID:o.id,Título:o.title,Tipo:o.type,Número:o.number,Data:o.date,Estado:o.state||"",Município:o.municipality||"",Resumo:o.summary,"Palavras-chave":o.keywords.join(", "),...e.includeMetadata&&{Fonte:o.source,Citação:o.citation,URL:o.url||""}})),t=_.unparse(a);L(t,`transport-legislation-data-${new Date().toISOString()}.csv`,"text/csv")},q=(i,e)=>{const a=`<?xml version="1.0" encoding="UTF-8"?>
`,t=`<documentos_legislativos>
`,o=`  <metadata>
    <data_exportacao>${new Date().toISOString()}</data_exportacao>
    <total_documentos>${i.length}</total_documentos>
  </metadata>
`,r=i.map(c=>{const h=c.keywords.map(m=>`      <palavra_chave>${f(m)}</palavra_chave>`).join(`
`);return`  <documento>
    <id>${c.id}</id>
    <titulo>${f(c.title)}</titulo>
    <tipo>${c.type}</tipo>
    <numero>${f(c.number)}</numero>
    <data>${c.date}</data>
    ${c.state?`<estado>${c.state}</estado>`:""}
    ${c.municipality?`<municipio>${f(c.municipality)}</municipio>`:""}
    <resumo>${f(c.summary)}</resumo>
    <palavras_chave>
${h}
    </palavras_chave>
    ${e.includeMetadata?`<metadados>
      <fonte>${f(c.source)}</fonte>
      <citacao>${f(c.citation)}</citacao>
      ${c.url?`<url>${f(c.url)}</url>`:""}
    </metadados>`:""}
  </documento>`}).join(`
`),d=a+t+o+r+`
</documentos_legislativos>`;L(d,`transport-legislation-data-${new Date().toISOString()}.xml`,"application/xml")},G=(i,e)=>{const a=`<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Dados Legislativos</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2196F3;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2196F3;
            margin: 0;
        }
        .summary {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        .document {
            border: 1px solid #ddd;
            margin-bottom: 20px;
            padding: 20px;
            border-radius: 5px;
            background: #fafafa;
        }
        .document h3 {
            color: #1976D2;
            margin-top: 0;
        }
        .doc-meta {
            background: #fff;
            padding: 10px;
            border-left: 4px solid #4CAF50;
            margin: 10px 0;
        }
        .keywords {
            background: #f0f0f0;
            padding: 5px 10px;
            border-radius: 15px;
            display: inline-block;
            margin: 2px;
            font-size: 0.9em;
        }
        .citation {
            background: #fff3e0;
            padding: 10px;
            border-left: 4px solid #FF9800;
            margin-top: 10px;
            font-style: italic;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Transport Legislation Academic Report</h1>
            <p>Brazilian Transport Legislation Monitor - Academic Research Platform</p>
            <p>Gerado em: ${new Date().toLocaleDateString("pt-BR",{year:"numeric",month:"long",day:"numeric",hour:"2-digit",minute:"2-digit"})}</p>
        </div>
        
        <div class="summary">
            <h2>Resumo da Pesquisa</h2>
            <p><strong>Total de documentos encontrados:</strong> ${i.length}</p>
            <p><strong>Estados com legislação:</strong> ${[...new Set(i.filter(t=>t.state).map(t=>t.state))].length}</p>
            <p><strong>Tipos de documentos:</strong> ${[...new Set(i.map(t=>t.type))].join(", ")}</p>
            <p><strong>Período:</strong> ${X(i)}</p>
        </div>
        
        <div class="documents">
            ${i.map((t,o)=>`
                <div class="document">
                    <h3>${o+1}. ${f(t.title)}</h3>
                    
                    <div class="doc-meta">
                        <strong>Tipo:</strong> ${t.type.charAt(0).toUpperCase()+t.type.slice(1)} | 
                        <strong>Número:</strong> ${f(t.number)} | 
                        <strong>Data:</strong> ${new Date(t.date).toLocaleDateString("pt-BR")}
                        ${t.state?` | <strong>Estado:</strong> ${t.state}`:""}
                        ${t.municipality?` | <strong>Município:</strong> ${f(t.municipality)}`:""}
                    </div>
                    
                    <p><strong>Resumo:</strong> ${f(t.summary)}</p>
                    
                    <div>
                        <strong>Palavras-chave:</strong><br>
                        ${t.keywords.map(r=>`<span class="keywords">${f(r)}</span>`).join(" ")}
                    </div>
                    
                    ${e.includeMetadata?`
                        <div class="citation">
                            <strong>Citação acadêmica:</strong><br>
                            ${f(t.citation)}
                            ${t.url?`<br><strong>URL:</strong> <a href="${t.url}" target="_blank">${t.url}</a>`:""}
                        </div>
                    `:""}
                </div>
            `).join("")}
        </div>
        
        <div class="footer">
            <p><strong>Citação sugerida para esta pesquisa:</strong></p>
            <p>Academic Transport Legislation Monitor. Brazilian transport legislation georeferenced data. 
               Exportado em ${new Date().toLocaleDateString("pt-BR")}. 
               Disponível em: [URL da aplicação].</p>
            <p><em>Este relatório foi gerado automaticamente. Sempre verifique as fontes originais.</em></p>
        </div>
    </div>
</body>
</html>`;L(a,`transport-legislation-report-${new Date().toISOString()}.html`,"text/html")},f=i=>i.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"),X=i=>{if(i.length===0)return"N/A";const e=i.map(o=>new Date(o.date)),a=new Date(Math.min.apply(null,e)),t=new Date(Math.max.apply(null,e));return`${a.toLocaleDateString("pt-BR")} a ${t.toLocaleDateString("pt-BR")}`},L=(i,e,a)=>{const t=new Blob([i],{type:a}),o=URL.createObjectURL(t),r=document.createElement("a");r.href=o,r.download=e,document.body.appendChild(r),r.click(),document.body.removeChild(r),URL.revokeObjectURL(o)},N=async(i={})=>{const{quality:e=.9,scale:a=2,includeControls:t=!1,includeLegend:o=!0,backgroundColor:r="#ffffff",filename:l="legislative-map"}=i;try{const d=document.querySelector(".map-wrapper");if(!d)throw new Error("Map container not found");const c=d.querySelectorAll(".map-controls"),h=[];t||c.forEach((n,p)=>{const g=n;h[p]=g.style.display,g.style.display="none"});const m=d.querySelector(".map-legend");let x="";!o&&m&&(x=m.style.display,m.style.display="none");const b={allowTaint:!0,useCORS:!0,scale:a,backgroundColor:r,width:d.offsetWidth,height:d.offsetHeight,logging:!1,removeContainer:!1,imageTimeout:15e3,onclone:n=>{const p=n.querySelector(".map-wrapper");p&&(p.style.transform="none",p.style.position="static")}},C=await B(d,b);t||c.forEach((n,p)=>{const g=n;g.style.display=h[p]||""}),!o&&m&&(m.style.display=x);const S=new Date().toISOString().slice(0,19).replace(/:/g,"-"),j=`${l}-${S}.png`;C.toBlob(n=>{if(n)H(n,j);else throw new Error("Failed to create image blob")},"image/png",e)}catch(d){throw console.error("Map export failed:",d),new Error(`Failed to export map: ${d instanceof Error?d.message:"Unknown error"}`)}},J=async(i,e,a={})=>{const{filename:t="legislative-map-with-data"}=a;try{const o=W(i,e),r=document.querySelector(".map-wrapper");if(!r)throw new Error("Map container not found");r.appendChild(o);try{await N({...a,filename:t})}finally{r.removeChild(o)}}catch(o){throw console.error("Map export with metadata failed:",o),o}},W=(i,e)=>{const a=document.createElement("div");a.className="map-export-overlay",a.style.cssText=`
    position: absolute;
    top: 10px;
    left: 10px;
    background: rgba(255, 255, 255, 0.95);
    padding: 16px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    line-height: 1.4;
    max-width: 300px;
    z-index: 1000;
    border: 1px solid #e0e0e0;
  `;const t=document.createElement("h3");t.textContent="Monitor Legislativo de Transportes",t.style.cssText=`
    margin: 0 0 12px 0;
    font-size: 16px;
    font-weight: 600;
    color: #2196F3;
  `;const o=document.createElement("div"),r=new Date().toLocaleDateString("pt-BR");return o.innerHTML=`
    <div style="margin-bottom: 8px;"><strong>Data de exportação:</strong> ${r}</div>
    <div style="margin-bottom: 8px;"><strong>Documentos encontrados:</strong> ${i.length}</div>
    
    <div style="margin-bottom: 8px;"><strong>Fonte:</strong> Dados Abertos do Governo Federal</div>
    <div style="font-size: 12px; color: #666; margin-top: 12px; padding-top: 12px; border-top: 1px solid #e0e0e0;">
      Plataforma Acadêmica de Pesquisa<br>
      Legislação de Transportes do Brasil
    </div>
  `,a.appendChild(t),a.appendChild(o),a},H=(i,e)=>{const a=URL.createObjectURL(i),t=document.createElement("a");t.href=a,t.download=e,t.style.display="none",document.body.appendChild(t),t.click(),document.body.removeChild(t),setTimeout(()=>URL.revokeObjectURL(a),100)},D=()=>{var i;try{const e=!!document.createElement("canvas").getContext,a=!!window.Blob,t=!!((i=window.URL)!=null&&i.createObjectURL);return e&&a&&t}catch{return!1}};class V{constructor(e){w(this,"prefix","legislativo_");w(this,"maxAge",36e5);w(this,"maxSize",5*1024*1024);w(this,"version","1.0.0");w(this,"stats",{hits:0,misses:0,itemCount:0,totalSize:0});e!=null&&e.prefix&&(this.prefix=e.prefix),e!=null&&e.maxAge&&(this.maxAge=e.maxAge),e!=null&&e.maxSize&&(this.maxSize=e.maxSize),e!=null&&e.version&&(this.version=e.version),this.updateStats(),this.cleanup()}set(e,a,t=this.maxAge){try{const o={value:a,expires:Date.now()+t,version:this.version,size:this.estimateSize(a)},r=JSON.stringify(o),l=this.prefix+e;return r.length>this.maxSize?(console.warn(`Cache item too large: ${e}`),!1):(this.getTotalSize()+r.length>this.maxSize&&this.evictOldest(r.length),localStorage.setItem(l,r),this.updateStats(),!0)}catch(o){if(o instanceof Error&&o.name==="QuotaExceededError"){console.warn("LocalStorage quota exceeded, cleaning up..."),this.cleanup();try{const r={value:a,expires:Date.now()+t,version:this.version};return localStorage.setItem(this.prefix+e,JSON.stringify(r)),!0}catch{return!1}}return console.error("Cache set error:",o),!1}}get(e){try{const a=this.prefix+e,t=localStorage.getItem(a);if(!t)return this.stats.misses++,null;const o=JSON.parse(t);return o.expires<Date.now()?(localStorage.removeItem(a),this.stats.misses++,this.updateStats(),null):o.version!==this.version?(localStorage.removeItem(a),this.stats.misses++,this.updateStats(),null):(this.stats.hits++,o.value)}catch(a){return console.error("Cache get error:",a),this.stats.misses++,null}}async getOrFetch(e,a,t=this.maxAge){const o=this.get(e);if(o!==null)return o;try{const r=await a();return this.set(e,r,t),r}catch(r){const l=`stale_${e}`,d=this.get(l);if(d!==null)return console.warn("Using stale cache for:",e),d;throw r}}remove(e){localStorage.removeItem(this.prefix+e),this.updateStats()}clear(){this.getAllKeys().forEach(a=>localStorage.removeItem(a)),this.updateStats()}cleanup(){const e=Date.now();this.getAllKeys().forEach(t=>{try{const o=localStorage.getItem(t);if(o){const r=JSON.parse(o);(r.expires<e||r.version!==this.version)&&localStorage.removeItem(t)}}catch{localStorage.removeItem(t)}}),this.updateStats()}getStats(){const e=this.stats.hits+this.stats.misses,a=e>0?this.stats.hits/e*100:0;return{...this.stats,hitRate:a}}async getBatch(e){const a=new Map;return e.forEach(t=>{a.set(t,this.get(t))}),a}setBatch(e){e.forEach((a,t)=>{this.set(t,a.value,a.ttl||this.maxAge)})}async warm(e,a){const t=e.map(async o=>{if(this.get(o)===null)try{const l=await a(o);this.set(o,l)}catch(l){console.error(`Failed to warm cache for key: ${o}`,l)}});await Promise.all(t)}getAllKeys(){return Object.keys(localStorage).filter(e=>e.startsWith(this.prefix))}getTotalSize(){let e=0;return this.getAllKeys().forEach(a=>{const t=localStorage.getItem(a);t&&(e+=t.length)}),e}estimateSize(e){try{return JSON.stringify(e).length}catch{return 0}}evictOldest(e){const a=[];this.getAllKeys().forEach(o=>{try{const r=localStorage.getItem(o);if(r){const l=JSON.parse(r);a.push({key:o,expires:l.expires||0,size:r.length})}}catch{localStorage.removeItem(o)}}),a.sort((o,r)=>o.expires-r.expires);let t=0;for(const o of a){if(t>=e)break;localStorage.removeItem(o.key),t+=o.size}}updateStats(){const e=this.getAllKeys();this.stats.itemCount=e.length,this.stats.totalSize=this.getTotalSize()}}const v=new V({prefix:"legislativo_",maxAge:36e5,maxSize:5*1024*1024,version:"1.0.0"}),k={generateKey(i,e){const a=Object.keys(e).sort().map(t=>`${t}:${e[t]}`).join("_");return`${i}_${a}`},async cacheAPIResponse(i,e,a=9e5){const t=k.generateKey("api",{url:i,method:(e==null?void 0:e.method)||"GET"});return v.getOrFetch(t,async()=>{const o=await fetch(i,e);if(!o.ok)throw new Error(`API error: ${o.statusText}`);return o.json()},a)},clearAPICache(){Object.keys(localStorage).filter(e=>e.startsWith("legislativo_api_")).forEach(e=>localStorage.removeItem(e))}},Y=!1,Q=!0,Z={production:"https://monitor-legislativo-v4-production.up.railway.app"},I=()=>Z.production,ee=(i,e)=>`${I()}${i}`,E={timeout:3e4,headers:{"Content-Type":"application/json",Accept:"application/json","X-Client":"monitor-legislativo-frontend","X-Version":"4.0.0"}},te={credentials:"same-origin",mode:"cors"};console.log("API Configuration initialized:",{mode:"production",baseUrl:I(),isDevelopment:Y,isProduction:Q});const T={"/api/v1/search":{ttl:9e5,priority:"high"},"/api/v1/proposals":{ttl:72e5,priority:"high"},"/api/v1/sources":{ttl:864e5,priority:"low"},"/api/v1/geography":{ttl:2592e6,priority:"low"},"/api/v1/export":{ttl:18e5,priority:"medium"}};class ae{constructor(){w(this,"abortControllers",new Map);w(this,"pendingRequests",new Map)}async fetch(e,a={}){var j;const{ttl:t,retry:o=3,timeout:r=E.timeout,fallbackToCache:l=!0,...d}=a,c=e.startsWith("http")?e:ee(e),h={...te,...d,headers:{...E.headers,...d.headers}},m=this.generateCacheKey(c,h),x=this.pendingRequests.get(m);if(x)return x;if(!h.method||h.method==="GET"){const n=v.get(m);if(n!==null)return"headers"in n&&((j=n.headers)!=null&&j["X-Cache"])&&console.log(`Cache HIT: ${c}`),n}const b=new AbortController;this.abortControllers.set(m,b);const C=setTimeout(()=>{b.abort()},r),S=this.fetchWithRetry(c,{...h,signal:b.signal},o).then(async n=>{clearTimeout(C);const p=n.headers.get("X-Cache")||"MISS";n.headers.get("X-Cache-Time"),console.log(`API ${p}: ${c}`);const g=await n.json();if(n.ok&&(!h.method||h.method==="GET")){const u=t||this.getTTLForURL(c);v.set(m,g,u),v.set(`stale_${m}`,g,u*2)}return g}).catch(async n=>{if(clearTimeout(C),l&&(!h.method||h.method==="GET")){const p=v.get(m);if(p!==null)return console.warn(`Using cached data due to error: ${c}`),p;const g=v.get(`stale_${m}`);if(g!==null)return console.warn(`Using stale cache due to error: ${c}`),g}throw n}).finally(()=>{this.abortControllers.delete(m),this.pendingRequests.delete(m)});return this.pendingRequests.set(m,S),S}async fetchWithRetry(e,a,t){let o=null;for(let r=0;r<=t;r++)try{const l=await fetch(e,a);if(l.status>=500&&r<t){await this.delay(Math.min(1e3*Math.pow(2,r),1e4));continue}return l}catch(l){if(o=l,l instanceof Error&&l.name==="AbortError")throw l;if(r<t){await this.delay(Math.min(1e3*Math.pow(2,r),1e4));continue}}throw o||new Error("Fetch failed")}generateCacheKey(e,a){const t={url:e,method:a.method||"GET",body:a.body?JSON.stringify(a.body):void 0};return k.generateKey("fetch",t)}getTTLForURL(e){const a=new URL(e,window.location.origin).pathname,t=T[a];if(t)return t.ttl;for(const[o,r]of Object.entries(T))if(a.startsWith(o))return r.ttl;return 9e5}delay(e){return new Promise(a=>setTimeout(a,e))}cancel(e){const a=this.generateCacheKey(e,{}),t=this.abortControllers.get(a);t&&t.abort()}async prefetch(e){const a=e.map(t=>this.fetch(t,{fallbackToCache:!0}).catch(()=>{}));await Promise.all(a)}clearCache(e){e?Object.keys(localStorage).filter(t=>t.includes(e)).forEach(t=>localStorage.removeItem(t)):k.clearAPICache()}getCacheStats(){return v.getStats()}}const oe=new ae,re=(i,e)=>oe.fetch(i,e),pe=({isOpen:i,onClose:e,documents:a})=>{const[t,o]=$.useState("csv"),[r,l]=$.useState(!1),[d,c]=$.useState(!0),[h,m]=$.useState("idle"),[x,b]=$.useState({from:"",to:""}),C=$.useCallback((n,p)=>{const g={format:n,documents:a.map(u=>u.id).sort(),includeMap:p.includeMap,includeMetadata:p.includeMetadata,dateRange:p.dateRange};return k.generateKey("export",g)},[a]),S=$.useCallback((n,p)=>{const g=n instanceof Blob?n:new Blob([n],{type:"text/plain"}),u=URL.createObjectURL(g),R=document.createElement("a");R.href=u,R.download=p,document.body.appendChild(R),R.click(),document.body.removeChild(R),URL.revokeObjectURL(u)},[]),j=async()=>{const n={format:t,includeMap:r,includeMetadata:d,dateRange:x.from||x.to?x:void 0};try{const p=C(t,n);m("checking");const g=v.get(p);if(g){console.log("Using cached export");const y=`monitor-legislativo-${t}-${Date.now()}.${t}`;S(g,y),m("ready");return}try{const y=await re(`/api/v1/export/cached/${encodeURIComponent(p)}`);if(y&&y.content){console.log("Using server cached export"),v.set(p,y.content,36e5);const U=`monitor-legislativo-${t}-${Date.now()}.${t}`;S(y.content,U),m("ready");return}}catch{console.log("No server cache available, generating fresh export")}m("generating");let u=a;n.dateRange&&(u=a.filter(y=>!(n.dateRange.from&&y.date<n.dateRange.from||n.dateRange.to&&y.date>n.dateRange.to)));let R,se;switch(t){case"csv":K(u,n);break;case"xml":q(u,n);break;case"html":G(u,n);break;case"bibtex":P(u);break;case"png":d?await J(u,void 0,{format:"png",includeControls:!1,includeLegend:!0}):await N({format:"png",includeControls:!1,includeLegend:!0});break}}catch(p){console.error("Export failed:",p),alert("Erro ao exportar dados. Tente novamente.")}};return i?s.jsx("div",{className:"export-panel-overlay",children:s.jsxs("div",{className:"export-panel",children:[s.jsxs("div",{className:"export-header",children:[s.jsx("h2",{children:"Exportar Dados"}),s.jsx("button",{className:"close-btn",onClick:e,"aria-label":"Fechar",children:"✕"})]}),s.jsxs("div",{className:"export-content",children:[s.jsx("div",{className:"export-summary",children:s.jsxs("p",{children:[s.jsx("strong",{children:a.length})," documentos selecionados para exportação"]})}),s.jsxs("div",{className:"export-section",children:[s.jsx("h3",{children:"Formato de Exportação"}),s.jsxs("div",{className:"format-options",children:[s.jsxs("label",{className:"radio-option",children:[s.jsx("input",{type:"radio",name:"format",value:"csv",checked:t==="csv",onChange:n=>o(n.target.value)}),s.jsxs("span",{className:"format-label",children:[s.jsx("strong",{children:"CSV"})," - Dados tabulares para análise"]})]}),s.jsxs("label",{className:"radio-option",children:[s.jsx("input",{type:"radio",name:"format",value:"xml",checked:t==="xml",onChange:n=>o(n.target.value)}),s.jsxs("span",{className:"format-label",children:[s.jsx("strong",{children:"XML"})," - Dados estruturados para sistemas"]})]}),s.jsxs("label",{className:"radio-option",children:[s.jsx("input",{type:"radio",name:"format",value:"html",checked:t==="html",onChange:n=>o(n.target.value)}),s.jsxs("span",{className:"format-label",children:[s.jsx("strong",{children:"HTML"})," - Relatório formatado para leitura"]})]}),s.jsxs("label",{className:"radio-option",children:[s.jsx("input",{type:"radio",name:"format",value:"bibtex",checked:t==="bibtex",onChange:n=>o(n.target.value)}),s.jsxs("span",{className:"format-label",children:[s.jsx("strong",{children:"BibTeX"})," - Referências bibliográficas para LaTeX"]})]}),s.jsxs("label",{className:"radio-option",children:[s.jsx("input",{type:"radio",name:"format",value:"png",checked:t==="png",disabled:!D(),onChange:n=>o(n.target.value)}),s.jsxs("span",{className:"format-label",children:[s.jsx("strong",{children:"PNG"})," - Imagem do mapa atual",!D()&&s.jsx("em",{children:" (não suportado neste navegador)"})]})]})]})]}),s.jsxs("div",{className:"export-section",children:[s.jsx("h3",{children:"Opções de Exportação"}),s.jsxs("label",{className:"checkbox-option",children:[s.jsx("input",{type:"checkbox",checked:d,onChange:n=>c(n.target.checked)}),"Incluir metadados (fonte, citação, URL)"]}),t!=="png"&&s.jsxs("label",{className:"checkbox-option",children:[s.jsx("input",{type:"checkbox",checked:r,onChange:n=>l(n.target.checked)}),"Incluir informações geográficas"]})]}),s.jsxs("div",{className:"export-section",children:[s.jsx("h3",{children:"Filtro de Data (Opcional)"}),s.jsxs("div",{className:"date-range",children:[s.jsxs("div",{className:"date-input-group",children:[s.jsx("label",{children:"Data inicial:"}),s.jsx("input",{type:"date",value:x.from,onChange:n=>b({...x,from:n.target.value}),"aria-label":"Data inicial"})]}),s.jsxs("div",{className:"date-input-group",children:[s.jsx("label",{children:"Data final:"}),s.jsx("input",{type:"date",value:x.to,onChange:n=>b({...x,to:n.target.value}),"aria-label":"Data final"})]})]})]}),s.jsxs("div",{className:"export-section citation-info",children:[s.jsx("h3",{children:"Informações para Citação Acadêmica"}),s.jsx("p",{className:"citation-note",children:"Os dados exportados incluem informações completas de citação para uso acadêmico. Recomenda-se sempre verificar a fonte original dos documentos."}),s.jsxs("div",{className:"suggested-citation",children:[s.jsx("strong",{children:"Citação sugerida para esta pesquisa:"}),s.jsxs("p",{className:"citation-text",children:["Mapa Legislativo Acadêmico. Dados legislativos georeferenciados do Brasil. Exportado em ",new Date().toLocaleDateString("pt-BR"),". Disponível em: [URL da aplicação]."]})]})]})]}),s.jsxs("div",{className:"export-actions",children:[s.jsx("button",{className:"cancel-btn",onClick:e,children:"Cancelar"}),s.jsxs("button",{className:"export-confirm-btn",onClick:j,disabled:a.length===0||h==="generating",children:[h==="checking"&&"🔍 Verificando cache...",h==="generating"&&"⏳ Gerando exportação...",h==="ready"&&"✅ Pronto!",h==="idle"&&`Exportar ${t==="png"?"Imagem PNG":t.toUpperCase()}`]})]})]})}):null};export{pe as default};
