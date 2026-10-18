const AREAS=["関西","東海","四国","その他"];
const GENRES=["HP","WEB広告","SNS","アフィリエイト"];
const TYPES=["訪問","電話","メール","オンライン","展示会","その他"];
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const pad=n=>String(n).padStart(2,"0");
const newId=()=>Date.now().toString(36)+Math.random().toString(36).slice(2,8);
const ymd=d=>`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
const todayStr=()=>ymd(new Date());
const addDays=(s,n)=>{const d=new Date(s+"T00:00:00");d.setDate(d.getDate()+n);return ymd(d)};
const addMonths=(s,n)=>{const d=new Date(s+"T00:00:00");const day=d.getDate();d.setDate(1);d.setMonth(d.getMonth()+n);const last=new Date(d.getFullYear(),d.getMonth()+1,0).getDate();d.setDate(Math.min(day,last));return ymd(d)};
const diffDays=(a,b)=>Math.round((new Date(a+"T00:00:00")-new Date(b+"T00:00:00"))/86400000);
const WD="日月火水木金土";
const jd=s=>{if(!s)return "";const d=new Date(s+"T00:00:00");return `${d.getMonth()+1}/${d.getDate()}（${WD[d.getDay()]}）`};
function rel(next){const t=todayStr(),d=diffDays(next,t);if(d<0)return{cls:"over",txt:`${-d}日遅れ`};if(d===0)return{cls:"today",txt:"今日"};if(d===1)return{cls:"soon",txt:"明日"};if(d<=14)return{cls:"soon",txt:`${d}日後`};return{cls:"",txt:`${d}日後`}}
function toast(t){const el=$("toast");el.textContent=t;el.classList.add("show");clearTimeout(toast.t);toast.t=setTimeout(()=>el.classList.remove("show"),2400)}

let db={companies:[],contacts:[]};
let ui={sel:null,q:"",area:"",genre:"",sort:"next"};

/* ---------- データ ---------- */
function normalize(j){
  const companies=(Array.isArray(j&&j.companies)?j.companies:[]).filter(c=>c&&c.name).map(c=>({
    id:String(c.id||newId()),name:String(c.name).trim(),area:AREAS.includes(c.area)?c.area:(c.area?"その他":""),pref:String(c.pref||""),
    addr:String(c.addr||""),tel:String(c.tel||""),industry:String(c.industry||""),
    genres:Array.isArray(c.genres)?c.genres.map(String).filter(Boolean):[],staff:Array.isArray(c.staff)?c.staff.map(String).filter(Boolean):[],
    memo:String(c.memo||""),sample:!!c.sample,createdAt:Number(c.createdAt)||0}));
  const ids=new Set(companies.map(c=>c.id));
  const contacts=(Array.isArray(j&&j.contacts)?j.contacts:[]).filter(x=>x&&ids.has(String(x.companyId))&&/^\d{4}-\d{2}-\d{2}$/.test(x.date)).map(x=>({
    id:String(x.id||newId()),companyId:String(x.companyId),date:x.date,type:TYPES.includes(x.type)?x.type:"その他",person:String(x.person||""),
    content:String(x.content||""),next:/^\d{4}-\d{2}-\d{2}$/.test(x.next||"")?x.next:"",nextDone:!!x.nextDone,sample:!!x.sample,createdAt:Number(x.createdAt)||0}));
  return {companies,contacts};
}
const serialize=()=>JSON.stringify({app:"gnp-crm",version:1,savedAt:new Date().toISOString(),...db},null,1);
const coById=id=>db.companies.find(c=>c.id===id);
function contactsOf(id){return db.contacts.filter(x=>x.companyId===id).sort((a,b)=>b.date.localeCompare(a.date)||b.createdAt-a.createdAt)}
// 会社ごとの「最後の接触」と「次回予定」（最新の記録の次回接触日。完了にしたら消える）
function stateOf(id){
  const list=contactsOf(id),last=list[0]||null;
  const next=last&&last.next&&!last.nextDone?last.next:"";
  return {last,next,count:list.length,list};
}

/* ---------- 端末の中の金庫（PINから作った鍵で暗号化） ---------- */
const VAULT_DB="gnp-crm-vault",ITER=310000,MAX_FAILS=10;
const URL_RE=/^https:\/\/script\.google\.com\/(a\/[^\/]+\/)?macros\/s\/[A-Za-z0-9_-]+\/exec$/;
const te=new TextEncoder(),td=new TextDecoder();
let S=null,KEY=null; // S = 接続先・合言葉・未送信の記録など（ロック中は空）
function vdb(){return new Promise((res,rej)=>{const r=indexedDB.open(VAULT_DB,1);r.onupgradeneeded=()=>r.result.createObjectStore("kv");r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)})}
async function vget(){const d=await vdb();return new Promise((res,rej)=>{const q=d.transaction("kv").objectStore("kv").get("vault");q.onsuccess=()=>res(q.result||null);q.onerror=()=>rej(q.error)})}
async function vput(v){const d=await vdb();return new Promise((res,rej)=>{const t=d.transaction("kv","readwrite");t.objectStore("kv").put(v,"vault");t.oncomplete=()=>res();t.onerror=()=>rej(t.error)})}
async function vdel(){const d=await vdb();return new Promise(res=>{const t=d.transaction("kv","readwrite");t.objectStore("kv").delete("vault");t.oncomplete=res;t.onerror=res})}
async function deriveKey(pin,salt,iter){const base=await crypto.subtle.importKey("raw",te.encode(pin),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"])}
async function seal(key,obj){const iv=crypto.getRandomValues(new Uint8Array(12));return {iv,ct:new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},key,te.encode(JSON.stringify(obj))))}}
async function unseal(key,box){return JSON.parse(td.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:box.iv},key,box.ct)))}
let saving=Promise.resolve(),saveTimer=null;
function saveNow(){
  clearTimeout(saveTimer);if(!S||!KEY)return saving;
  const snap=JSON.parse(JSON.stringify({...S,db,ui})),key=KEY;
  saving=saving.then(async()=>{const v=await vget();if(!v)return;v.box=await seal(key,snap);await vput(v)}).catch(()=>{});
  return saving;
}
function scheduleSave(){clearTimeout(saveTimer);saveTimer=setTimeout(saveNow,700)}
function weakPin(p){return /^(\d)\1{5}$/.test(p)||"0123456789".includes(p)||"9876543210".includes(p)}

/* ---------- スプレッドシートとの同期 ---------- */
const hhmm=()=>{const d=new Date();return `${d.getHours()}:${pad(d.getMinutes())}`};
function setSync(state,text){const st=$("saveState");st.classList.toggle("warn",state==="warn");st.classList.toggle("busy",state==="busy");$("saveText").textContent=text}
function outboxNote(){const n=S?S.outbox.length:0;$("pendingBadge").hidden=!n;$("pendingBadge").textContent=`未送信 ${n}件`}
// 変更は、まずこの端末に保存してから、送れるときにスプレッドシートへ送る
function commit(...ops){if(!S)return;ops.forEach(o=>S.outbox.push({k:newId(),...o}));outboxNote();saveNow();syncNow()}
function applyLocal(o){
  if(o.op==="saveCompany"){const i=db.companies.findIndex(c=>c.id===o.data.id);if(i>=0)db.companies[i]={...o.data};else db.companies.push({...o.data})}
  else if(o.op==="deleteCompany"){db.companies=db.companies.filter(c=>c.id!==o.id);db.contacts=db.contacts.filter(x=>x.companyId!==o.id)}
  else if(o.op==="saveContact"){const i=db.contacts.findIndex(x=>x.id===o.data.id);if(i>=0)db.contacts[i]={...o.data};else db.contacts.push({...o.data})}
  else if(o.op==="setDone"){const x=db.contacts.find(x=>x.id===o.id);if(x)x.nextDone=true}
  else if(o.op==="deleteContact"){db.contacts=db.contacts.filter(x=>x.id!==o.id)}
}
async function callServer(url,token,ops){
  const ctl=new AbortController(),tm=setTimeout(()=>ctl.abort(),45000);
  try{const res=await fetch(url,{method:"POST",body:JSON.stringify({token,ops}),cache:"no-store",credentials:"omit",redirect:"follow",referrerPolicy:"no-referrer",signal:ctl.signal});
    return await res.json()}finally{clearTimeout(tm)}
}
let syncing=false,again=false;
async function syncNow(){
  if(!S)return;if(syncing){again=true;return}
  if(navigator.onLine===false){setSync("warn",S.outbox.length?"圏外です。記録はこの端末に保存してあり、電波が戻ったら自動で送ります。":"圏外です。最後に同期した内容を表示しています。");return}
  syncing=true;again=false;const sending=S.outbox.slice();
  setSync("busy",sending.length?`スプレッドシートに送信中…（${sending.length}件）`:"スプレッドシートと同期中…");
  try{
    const j=await callServer(S.url,S.token,sending);
    if(!S)return;
    if(!j||!j.ok){setSync("warn",j&&j.error==="auth"?"合言葉が合いません。スプレッドシートで合言葉を作り直した場合は、設定から入れ直してください。":"スプレッドシート側でエラーが起きました。少し時間をおいて「同期」を押してください。");return}
    const sent=new Set(sending.map(o=>o.k));S.outbox=S.outbox.filter(o=>!sent.has(o.k));
    db=normalize(j.data);S.outbox.forEach(applyLocal);
    S.sheetUrl=String(j.data.url||"");S.lastSync=Date.now();
    if(ui.sel&&!coById(ui.sel))ui.sel=null;
    await saveNow();render();setSync("ok",`同期しました（${hhmm()}）`);
  }catch(e){if(S)setSync("warn",S.outbox.length?`送れませんでした。${S.outbox.length}件はこの端末に保存してあり、電波が戻ったら自動で送ります。`:"同期できませんでした。電波のいい場所で「同期」を押してください。")}
  finally{syncing=false;if(S){outboxNote();if(again)syncNow()}}
}
$("reloadBtn").onclick=()=>syncNow();
addEventListener("online",()=>syncNow());
setInterval(()=>{if(S&&!document.hidden)syncNow()},180000);
// 取り込み：同じ会社名はまとめ、新しいものだけ送る
async function importData(inc,label){
  const byName=new Map(db.companies.map(c=>[c.name,c.id])),idMap={},newCos=[],newCts=[];
  inc.companies.forEach(c=>{if(byName.has(c.name)){idMap[c.id]=byName.get(c.name)}else{byName.set(c.name,c.id);idMap[c.id]=c.id;newCos.push(c)}});
  const have=new Set(db.contacts.map(x=>x.id));
  inc.contacts.forEach(x=>{const cid=idMap[x.companyId];if(cid&&!have.has(x.id))newCts.push({...x,companyId:cid})});
  if(!newCos.length&&!newCts.length){$("status").textContent="新しく取り込めるデータはありませんでした（同じ会社名はすでに登録済みです）。";return}
  db.companies.push(...newCos);db.contacts.push(...newCts);render();
  commit(...newCos.map(c=>({op:"saveCompany",data:c})),...newCts.map(x=>({op:"saveContact",data:x})));
  toast(`${label}から会社${newCos.length}社・接触記録${newCts.length}件を取り込みました`);$("status").textContent="";
}
$("migrate").onclick=()=>$("migrateFile").click();
$("migrateFile").onchange=async e=>{const f=e.target.files[0];e.target.value="";if(!f)return;
  try{const j=JSON.parse(await f.text());const d=normalize(j);
    d.companies=d.companies.filter(c=>!c.sample);const ok=new Set(d.companies.map(c=>c.id));d.contacts=d.contacts.filter(x=>!x.sample&&ok.has(x.companyId));
    await importData(d,"PC版のデータ")}
  catch(err){$("status").textContent="読み込めませんでした。PC版の保存ファイル（GNP顧客データ.json）かバックアップを選んでください。"}};

/* ---------- CSV ---------- */
function parseCSV(text){
  const rows=[];let row=[],f="",q=false;
  for(let i=0;i<text.length;i++){const ch=text[i];
    if(q){if(ch==='"'){if(text[i+1]==='"'){f+='"';i++}else q=false}else f+=ch}
    else if(ch==='"')q=true;else if(ch===","){row.push(f);f=""}else if(ch==="\n"||ch==="\r"){if(ch==="\r"&&text[i+1]==="\n")i++;row.push(f);rows.push(row);row=[];f=""}else f+=ch}
  if(f!==""||row.length){row.push(f);rows.push(row)}
  return rows.filter(r=>r.some(c=>c.trim()!==""));
}
async function readText(file){const buf=await file.arrayBuffer();try{return new TextDecoder("utf-8",{fatal:true}).decode(buf).replace(/^﻿/,"")}catch(e){return new TextDecoder("shift_jis").decode(buf)}}
const COLS={name:["会社名","企業名","顧客名","社名","取引先"],area:["エリア","地域"],pref:["都道府県","都道府県・市町村","所在地","市町村"],addr:["住所"],tel:["電話","電話番号","TEL","tel"],
  industry:["業種"],genres:["取引製品ジャンル","製品ジャンル","ジャンル","取引製品"],staff:["担当者","担当","担当者名"],memo:["メモ","備考"],
  date:["訪問日","接触日","日付","最終訪問日"],type:["接触形態","形態"],content:["内容","商談内容"],next:["次回接触日","次回","次回予定"]};
function normDate(s){s=String(s||"").trim().replace(/[年月\.]/g,"/").replace(/日/,"");const m=s.match(/^(\d{4})[\/-](\d{1,2})[\/-](\d{1,2})/);return m?`${m[1]}-${pad(m[2])}-${pad(m[3])}`:""}
$("csvIn").onclick=()=>$("csvFile").click();
$("csvFile").onchange=async e=>{
  const f=e.target.files[0];e.target.value="";if(!f)return;
  try{
    const rows=parseCSV(await readText(f));if(rows.length<2)throw new Error("rows");
    const head=rows[0].map(h=>h.trim());const idx={};
    for(const k in COLS){idx[k]=head.findIndex(h=>COLS[k].includes(h))}
    if(idx.name<0){$("status").textContent="1行目に「会社名」の列が見つかりませんでした。1行目を見出し（会社名、エリア、担当者など）にしてください。";return}
    const get=(r,k)=>idx[k]>=0?String(r[idx[k]]||"").trim():"";
    const cos=new Map(),cts=[];
    rows.slice(1).forEach((r,i)=>{
      const name=get(r,"name");if(!name)return;
      let c=cos.get(name);
      if(!c){const a=get(r,"area");
        c={id:newId()+i,name,area:AREAS.includes(a)?a:(a?"その他":""),pref:get(r,"pref"),addr:get(r,"addr"),tel:get(r,"tel"),industry:get(r,"industry"),
          genres:get(r,"genres").split(/[、,，\/・]/).map(s=>s.trim()).filter(Boolean),staff:get(r,"staff")?[get(r,"staff")]:[],memo:get(r,"memo"),createdAt:Date.now()+i};
        cos.set(name,c)}
      else if(get(r,"staff")&&!c.staff.includes(get(r,"staff")))c.staff.push(get(r,"staff"));
      const d=normDate(get(r,"date"));
      if(d){const t=get(r,"type");cts.push({id:newId()+"c"+i,companyId:c.id,date:d,type:TYPES.includes(t)?t:(t?"その他":"訪問"),person:get(r,"staff"),content:get(r,"content"),next:normDate(get(r,"next")),nextDone:false,createdAt:Date.now()+i})}
    });
    await importData({companies:[...cos.values()],contacts:cts},"CSVのデータ");
  }catch(err){$("status").textContent="CSVを読み込めませんでした。ExcelやNumbersから「CSV」で書き出したファイルを選んでください。"}
};

/* ---------- 表示 ---------- */
function render(){
  scheduleSave();
  if(S){const u=S.sheetUrl||"";$("openSheet").href=/^https:\/\/docs\.google\.com\//.test(u)?u:"#";$("openSheet").hidden=!/^https:\/\/docs\.google\.com\//.test(u)}
  const t=todayStr();$("todayLbl").textContent=`${t.slice(0,4)}年${jd(t)}`;
  renderSummary();renderTodos();renderFilters();renderList();renderDetail();
}
function renderSummary(){
  const t=todayStr(),wk=addDays(t,7-((new Date().getDay()+6)%7)-1);
  let over=0,week=0,today=0;
  for(const c of db.companies){const n=stateOf(c.id).next;if(!n)continue;if(n<t)over++;else{if(n===t)today++;if(n<=wk)week++}}
  $("kOver").textContent=over;$("kWeek").textContent=week;$("kWeekNote").textContent=`今日 ${today}件／日曜まで`;
  const m=t.slice(0,7),mc=db.contacts.filter(x=>x.date.startsWith(m));
  $("kMonth").textContent=mc.length;
  const by={};mc.forEach(x=>by[x.type]=(by[x.type]||0)+1);
  $("kMonthNote").textContent=Object.keys(by).length?Object.entries(by).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`${k}${v}`).join("・"):"まだありません";
  $("kCo").textContent=db.companies.length;
  const ac={};db.companies.forEach(c=>{if(c.area)ac[c.area]=(ac[c.area]||0)+1});
  $("kCoNote").textContent=AREAS.filter(a=>ac[a]).map(a=>`${a}${ac[a]}`).join("・")||" ";
}
function renderTodos(){
  const t=todayStr(),lim=addDays(t,14);
  const items=db.companies.map(c=>({c,s:stateOf(c.id)})).filter(o=>o.s.next&&o.s.next<=lim).sort((a,b)=>a.s.next.localeCompare(b.s.next));
  if(!items.length){$("todos").innerHTML=`<div class="empty" style="grid-column:1/-1">2週間以内の予定はありません。接触を記録するときに「次回接触日」を入れると、ここに並びます。</div>`;return}
  $("todos").innerHTML=items.map(({c,s})=>{const r=rel(s.next);const last=s.last;
    return `<div class="todo ${r.cls}" role="button" tabindex="0" data-co="${c.id}">
      <div class="when"><span>${jd(s.next)}・${r.txt}</span><button class="done" data-done="${last.id}" title="連絡したら押す">済み</button></div>
      <div class="co-name">${esc(c.name)}</div>
      <div class="last">前回 ${jd(last.date)} ${esc(last.type)}${last.person?"・"+esc(last.person):""}：${esc(last.content.split("\n")[0])||"（内容なし）"}</div></div>`}).join("");
}
function renderFilters(){
  const a=$("fArea"),g=$("fGenre");
  a.innerHTML=`<option value="">エリア：すべて</option>`+AREAS.map(x=>`<option ${ui.area===x?"selected":""}>${x}</option>`).join("");
  const gs=[...new Set(GENRES.concat(db.companies.flatMap(c=>c.genres)))];
  g.innerHTML=`<option value="">ジャンル：すべて</option>`+gs.map(x=>`<option ${ui.genre===x?"selected":""}>${esc(x)}</option>`).join("");
  $("q").value=ui.q;$("sort").value=ui.sort;
}
function filtered(){
  const k=ui.q.trim().toLowerCase();
  let list=db.companies.filter(c=>(!ui.area||c.area===ui.area)&&(!ui.genre||c.genres.includes(ui.genre))&&
    (!k||[c.name,c.pref,c.memo,c.industry,...c.staff].join(" ").toLowerCase().includes(k)));
  const st=new Map(list.map(c=>[c.id,stateOf(c.id)]));
  const lastD=c=>(st.get(c.id).last||{}).date||"";
  const cmp={
    next:(a,b)=>{const x=st.get(a.id).next||"9999",y=st.get(b.id).next||"9999";return x.localeCompare(y)||a.name.localeCompare(b.name,"ja")},
    last:(a,b)=>lastD(b).localeCompare(lastD(a))||a.name.localeCompare(b.name,"ja"),
    long:(a,b)=>(lastD(a)||"0000").localeCompare(lastD(b)||"0000")||a.name.localeCompare(b.name,"ja"),
    name:(a,b)=>a.name.localeCompare(b.name,"ja")}[ui.sort];
  return {list:list.sort(cmp),st};
}
function renderList(){
  const {list,st}=filtered();
  $("coCount").textContent=`${list.length}社${list.length!==db.companies.length?` ／ 全${db.companies.length}社`:""}`;
  if(!db.companies.length){$("colist").innerHTML=`<div class="empty">まだ会社がありません。<br>「＋会社を追加」か「CSVで会社を取り込む」から始めてください。</div>`;return}
  if(!list.length){$("colist").innerHTML=`<div class="empty">条件に合う会社がありません</div>`;return}
  $("colist").innerHTML=list.map(c=>{const s=st.get(c.id),r=s.next?rel(s.next):null;
    const since=s.last?diffDays(todayStr(),s.last.date):null;
    return `<button class="co ${ui.sel===c.id?"sel":""}" data-co="${c.id}">
      <div class="top"><span class="nm">${esc(c.name)}</span>${r?`<span class="nx ${r.cls}">次回 ${jd(s.next)}</span>`:""}</div>
      <div class="meta">${c.area?`<span>${esc(c.area)}${c.pref?"・"+esc(c.pref):""}</span>`:""}<span>${s.last?`最終 ${jd(s.last.date)}（${since===0?"今日":since+"日前"}）`:"接触なし"}</span></div></button>`}).join("");
}
let pendingDel=null;
function renderDetail(){
  const el=$("detail"),c=ui.sel&&coById(ui.sel);
  if(!c){el.innerHTML=`<div class="empty" style="padding:60px 8px">左の一覧から会社を選ぶと、<br>会社の情報とこれまでの接触の記録がここに出ます。</div>`;return}
  const s=stateOf(c.id),r=s.next?rel(s.next):null;
  const info=[["都道府県・市町村",c.pref],["電話番号",c.tel],["業種",c.industry],["接触回数",s.count?`${s.count}回`:"まだありません"],["住所",c.addr,1],["担当者",c.staff.join(" ／ "),1],["メモ",c.memo,1]];
  el.innerHTML=`
    <div class="detail-head"><div><h3>${esc(c.name)}</h3>
      <div class="chips">${c.area?`<span class="chip area">${esc(c.area)}</span>`:""}${c.genres.map(g=>`<span class="chip g">${esc(g)}</span>`).join("")}</div></div>
      <div class="row"><button class="btn sm back" id="backList">↑ 一覧へ</button><button class="btn sm" id="editCo">会社情報を直す</button><button class="btn main" id="logHere"><span class="plus">＋</span>接触を記録</button></div></div>
    <div class="nextbox ${r?r.cls:"none"}">${s.next?`<span>次回接触日 <b>${jd(s.next)}</b>（${r.txt}）</span><button class="btn sm" data-done="${s.last.id}">連絡したので済みにする</button>`:`<span>次回接触日は決まっていません</span>`}</div>
    <div class="info">${info.map(([k,v,w])=>`<div class="${w?"wide":""}"><span>${k}</span><b>${esc(v)||"—"}</b></div>`).join("")}</div>
    <h2 style="margin-top:6px"><span>接触の記録</span><small>新しい順</small></h2>
    ${s.list.length?`<div class="timeline">${s.list.map(x=>`<div class="ev t-${esc(x.type)}">
      <div class="h"><span class="d num">${x.date.slice(0,4)}/${jd(x.date)}</span><span class="chip">${esc(x.type)}</span>${x.person?`<span>${esc(x.person)}</span>`:""}
      <button class="del ${pendingDel===x.id?"confirm":""}" data-del="${x.id}">${pendingDel===x.id?"本当に消す":"消す"}</button></div>
      ${x.content?`<div class="body">${esc(x.content)}</div>`:""}
      ${x.next?`<div class="nxt">次回接触日 ${jd(x.next)}${x.nextDone?"（済み）":""}</div>`:""}</div>`).join("")}</div>`
      :`<div class="empty">まだ接触の記録がありません</div>`}`;
}

/* ---------- 操作 ---------- */
function select(id){ui.sel=id;pendingDel=null;render();if(window.innerWidth<860)$("detail").scrollIntoView({behavior:"smooth",block:"start"})}
document.addEventListener("click",async e=>{
  const done=e.target.closest("[data-done]");
  if(done){e.stopPropagation();const x=db.contacts.find(v=>v.id===done.dataset.done);if(x){x.nextDone=true;render();toast("済みにしました。次の予定は接触を記録するときに入れてください");commit({op:"setDone",id:x.id})}return}
  const del=e.target.closest("[data-del]");
  if(del){const id=del.dataset.del;if(pendingDel!==id){pendingDel=id;renderDetail();setTimeout(()=>{if(pendingDel===id){pendingDel=null;renderDetail()}},4000);return}
    pendingDel=null;db.contacts=db.contacts.filter(v=>v.id!==id);render();toast("記録を1件消しました");commit({op:"deleteContact",id});return}
  const co=e.target.closest("[data-co]");if(co){select(co.dataset.co);return}
  if(e.target.closest("#backList")){document.querySelector(".cols>.panel").scrollIntoView({behavior:"smooth",block:"start"});return}
  if(e.target.closest("#editCo")){openCompany(coById(ui.sel));return}
  if(e.target.closest("#logHere")){openContact(coById(ui.sel));return}
});
document.addEventListener("keydown",e=>{if((e.key==="Enter"||e.key===" ")&&e.target.classList&&e.target.classList.contains("todo")){e.preventDefault();select(e.target.dataset.co)}});
$("q").addEventListener("input",e=>{ui.q=e.target.value;renderList();scheduleSave()});
$("fArea").onchange=e=>{ui.area=e.target.value;render()};
$("fGenre").onchange=e=>{ui.genre=e.target.value;render()};
$("sort").onchange=e=>{ui.sort=e.target.value;render()};

function showDlg(d){if(typeof d.showModal==="function")d.showModal();else d.setAttribute("open","")}
function closeDlg(d){if(typeof d.close==="function")d.close();else d.removeAttribute("open")}
document.querySelectorAll("[data-close]").forEach(b=>b.onclick=()=>closeDlg(b.closest("dialog")));

// 接触を記録
$("cType").innerHTML=TYPES.map((t,i)=>`<label><input type="radio" name="ctype" value="${t}" ${i===0?"checked":""}><span>${t}</span></label>`).join("");
function fillPeople(){const c=db.companies.find(x=>x.name===$("cCompany").value.trim());
  const names=c?[...new Set(c.staff.map(s=>s.split(/\s+/).slice(0,2).join(" ")).concat(contactsOf(c.id).map(x=>x.person)).filter(Boolean))]:[];
  $("personList").innerHTML=names.map(n=>`<option value="${esc(n)}">`).join("")}
$("cCompany").addEventListener("input",fillPeople);
function openContact(c){
  $("coNames").innerHTML=db.companies.map(x=>`<option value="${esc(x.name)}">`).join("");
  $("cCompany").value=c?c.name:"";$("cDate").value=todayStr();$("cPerson").value="";$("cContent").value="";$("cNext").value="";$("cMsg").textContent="";
  document.querySelector('input[name="ctype"][value="訪問"]').checked=true;fillPeople();showDlg($("dlgContact"));
  setTimeout(()=>(c?$("cContent"):$("cCompany")).focus(),30);
}
$("openContact").onclick=()=>openContact(ui.sel?coById(ui.sel):null);
$("cQuick").onclick=e=>{const b=e.target.closest("button");if(!b)return;const base=$("cDate").value||todayStr();
  $("cNext").value=b.dataset.d===""?"":b.dataset.m?addMonths(base,+b.dataset.m):addDays(base,+b.dataset.d)};
$("formContact").addEventListener("submit",async e=>{
  e.preventDefault();const m=$("cMsg");
  const c=db.companies.find(x=>x.name===$("cCompany").value.trim());
  if(!c){m.textContent=$("cCompany").value.trim()?"その会社はまだ登録されていません。先に「＋会社を追加」で登録してください。":"会社を選んでください。";return}
  const date=$("cDate").value;if(!date){m.textContent="日付を入れてください。";return}
  const next=$("cNext").value;if(next&&next<date){m.textContent="次回接触日が、今回の日付より前になっています。";return}
  const x={id:newId(),companyId:c.id,date,type:document.querySelector('input[name="ctype"]:checked').value,person:$("cPerson").value.trim(),content:$("cContent").value.trim(),next,nextDone:false,createdAt:Date.now()};
  db.contacts.push(x);ui.sel=c.id;closeDlg($("dlgContact"));render();toast(`${c.name}との接触を記録しました`);
  commit({op:"saveContact",data:x});
});

// 会社を追加・編集
let editing=null;
$("kArea").innerHTML=`<option value="">選ばない</option>`+AREAS.map(a=>`<option>${a}</option>`).join("");
$("kGenres").innerHTML=GENRES.map(g=>`<label><input type="checkbox" value="${g}"><span>${g}</span></label>`).join("");
function openCompany(c){
  editing=c||null;$("dkT").textContent=c?"会社情報を直す":"会社を追加";$("kSubmit").textContent=c?"保存する":"追加する";
  $("kDelete").hidden=!c;$("kDelete").classList.remove("armed");$("kDelete").textContent="この会社を削除";
  $("kName").value=c?c.name:"";$("kArea").value=c?c.area:"";$("kPref").value=c?c.pref:"";$("kAddr").value=c?c.addr:"";
  $("kTel").value=c?c.tel:"";$("kIndustry").value=c?c.industry:"";$("kStaff").value=c?c.staff.join("\n"):"";$("kMemo").value=c?c.memo:"";
  const gs=c?c.genres:[];document.querySelectorAll("#kGenres input").forEach(i=>i.checked=gs.includes(i.value));
  $("kGenreOther").value=gs.filter(g=>!GENRES.includes(g)).join("、");$("kMsg").textContent="";
  showDlg($("dlgCompany"));setTimeout(()=>$("kName").focus(),30);
}
$("openCompany").onclick=()=>openCompany(null);
$("formCompany").addEventListener("submit",async e=>{
  e.preventDefault();const name=$("kName").value.trim();
  if(!name){$("kMsg").textContent="会社名を入れてください。";return}
  if(db.companies.some(c=>c.name===name&&c!==editing)){$("kMsg").textContent="同じ名前の会社がすでに登録されています。";return}
  const genres=[...document.querySelectorAll("#kGenres input:checked")].map(i=>i.value).concat($("kGenreOther").value.split(/[、,，]/).map(s=>s.trim()).filter(Boolean));
  const data={name,area:$("kArea").value,pref:$("kPref").value.trim(),addr:$("kAddr").value.trim(),tel:$("kTel").value.trim(),industry:$("kIndustry").value.trim(),
    genres:[...new Set(genres)],staff:$("kStaff").value.split("\n").map(s=>s.trim()).filter(Boolean),memo:$("kMemo").value.trim()};
  let c=editing;if(c)Object.assign(c,data);else{c={id:newId(),...data,createdAt:Date.now()};db.companies.push(c);ui.sel=c.id}
  const was=editing;closeDlg($("dlgCompany"));render();toast(was?"会社情報を保存しました":`${name}を追加しました`);
  commit({op:"saveCompany",data:{...c}});
});
$("kDelete").onclick=async()=>{
  const b=$("kDelete");if(!editing)return;
  if(!b.classList.contains("armed")){b.classList.add("armed");b.textContent=`接触記録${contactsOf(editing.id).length}件ごと削除する`;return}
  const id=editing.id,nm=editing.name;db.companies=db.companies.filter(c=>c.id!==id);db.contacts=db.contacts.filter(x=>x.companyId!==id);
  if(ui.sel===id)ui.sel=null;closeDlg($("dlgCompany"));render();toast(`${nm}を削除しました`);commit({op:"deleteCompany",id});
};


/* ---------- 右下の植物（Canvasで描画） ---------- */
(function drawPlant(){
  const cv=document.getElementById("plantCv");if(!cv||!cv.getContext)return;
  const W=300,H=430,dpr=Math.min(window.devicePixelRatio||1,3);
  cv.width=W*dpr;cv.height=H*dpr;const c=cv.getContext("2d");c.scale(dpr,dpr);
  let seed=20261015;const rnd=()=>{seed|=0;seed=seed+0x6D2B79F5|0;let t=Math.imul(seed^seed>>>15,1|seed);t=t+Math.imul(t^t>>>7,61|t)^t;return((t^t>>>14)>>>0)/4294967296};
  const bez=(p,t)=>{const u=1-t;return{x:u*u*u*p[0].x+3*u*u*t*p[1].x+3*u*t*t*p[2].x+t*t*t*p[3].x,y:u*u*u*p[0].y+3*u*u*t*p[1].y+3*u*t*t*p[2].y+t*t*t*p[3].y}};
  function stem(p,w0,w1){
    const N=40;
    for(let i=0;i<N;i++){const a=bez(p,i/N),b=bez(p,(i+1)/N),t=i/N;
      c.strokeStyle=`hsl(${95+t*20},${28+t*10}%,${30+t*10}%)`;c.lineWidth=w0+(w1-w0)*t;c.lineCap="round";
      c.beginPath();c.moveTo(a.x,a.y);c.lineTo(b.x,b.y);c.stroke();}
  }
  function leaf(x,y,ang,len,wid,hue,light){
    c.save();c.translate(x,y);c.rotate(ang);
    // 葉柄
    c.strokeStyle=`hsl(${hue-10},30%,${light-6}%)`;c.lineWidth=1.6;c.beginPath();c.moveTo(0,0);c.lineTo(len*.12,0);c.stroke();
    c.translate(len*.12,0);const L=len*.88;
    const curl=(rnd()-.5)*wid*.5;
    const shape=()=>{c.beginPath();c.moveTo(0,0);
      c.bezierCurveTo(L*.22,-wid*1.05+curl,L*.68,-wid*.85+curl,L,curl*.6);
      c.bezierCurveTo(L*.7,wid*.8+curl,L*.24,wid*1.0+curl,0,0);c.closePath()};
    // 影
    c.save();c.shadowColor="rgba(40,70,30,.28)";c.shadowBlur=10;c.shadowOffsetX=2;c.shadowOffsetY=4;shape();c.fillStyle=`hsl(${hue},40%,${light}%)`;c.fill();c.restore();
    // 本体（片側が明るく、先端が少し若い色）
    const g=c.createLinearGradient(0,-wid,0,wid);
    g.addColorStop(0,`hsl(${hue+4},48%,${light+12}%)`);g.addColorStop(.48,`hsl(${hue},44%,${light+4}%)`);
    g.addColorStop(.52,`hsl(${hue-2},46%,${light-2}%)`);g.addColorStop(1,`hsl(${hue-6},50%,${light-9}%)`);
    shape();c.fillStyle=g;c.fill();
    const g2=c.createLinearGradient(0,0,L,0);g2.addColorStop(0,"rgba(255,255,255,0)");g2.addColorStop(1,"rgba(220,255,170,.22)");
    shape();c.fillStyle=g2;c.fill();
    // 光沢
    c.save();shape();c.clip();const hl=c.createRadialGradient(L*.38,-wid*.45,1,L*.38,-wid*.45,wid*1.4);
    hl.addColorStop(0,"rgba(255,255,255,.28)");hl.addColorStop(1,"rgba(255,255,255,0)");c.fillStyle=hl;c.fillRect(0,-wid*2,L,wid*4);
    // 側脈
    c.strokeStyle="rgba(235,255,215,.38)";c.lineWidth=.8;
    for(let i=1;i<=7;i++){const t=i/8.5,mx=L*t,my=curl*.6*t;
      for(const s of [-1,1]){c.beginPath();c.moveTo(mx,my);c.quadraticCurveTo(mx+L*.06,my+s*wid*.35,mx+L*.13,my+s*wid*.72*(1-t*.45));c.stroke();}}
    c.restore();
    // 主脈
    c.strokeStyle="rgba(240,255,220,.65)";c.lineWidth=1.3;c.beginPath();c.moveTo(0,0);c.quadraticCurveTo(L*.5,curl*.5,L*.96,curl*.6);c.stroke();
    // ふち
    shape();c.strokeStyle=`hsla(${hue-8},50%,${light-16}%,.35)`;c.lineWidth=.7;c.stroke();
    c.restore();
  }
  const stems=[
    {p:[{x:310,y:440},{x:270,y:340},{x:250,y:220},{x:205,y:110}],w:[5,1.4],n:9,len:[58,30]},
    {p:[{x:320,y:440},{x:260,y:380},{x:170,y:330},{x:70,y:290}],w:[4.5,1.2],n:8,len:[56,28]},
    {p:[{x:315,y:445},{x:300,y:330},{x:300,y:200},{x:282,y:40}],w:[4.5,1.2],n:9,len:[54,28]},
    {p:[{x:320,y:440},{x:240,y:410},{x:180,y:400},{x:110,y:405}],w:[3.5,1],n:5,len:[48,26]},
    {p:[{x:315,y:440},{x:270,y:320},{x:200,y:250},{x:130,y:200}],w:[4,1.1],n:8,len:[52,26]},
  ];
  // 奥の茎から順に
  stems.forEach((st,si)=>{
    stem(st.p,st.w[0],st.w[1]);
    for(let i=0;i<st.n;i++){
      const t=.18+i/(st.n)*.82,pt=bez(st.p,t),a=bez(st.p,Math.max(0,t-.02)),b=bez(st.p,Math.min(1,t+.02));
      const dir=Math.atan2(b.y-a.y,b.x-a.x),side=i%2?1:-1;
      const len=st.len[0]+(st.len[1]-st.len[0])*t+rnd()*8;
      const hue=108+rnd()*22+t*8,light=34+t*10+rnd()*6;
      leaf(pt.x,pt.y,dir+side*(.75+rnd()*.35),len,len*.34,hue,light);
    }
    const tip=bez(st.p,1),pre=bez(st.p,.97);
    leaf(tip.x,tip.y,Math.atan2(tip.y-pre.y,tip.x-pre.x),st.len[1]*.9,st.len[1]*.22,122,48);
  });
})();


/* ---------- 鍵（設定・ロック・解除） ---------- */
function showGate(mode,note){
  document.body.classList.add("locked");$("gate").hidden=false;
  $("setupForm").hidden=mode!=="setup";$("unlockForm").hidden=mode!=="unlock";
  $("gateNote").hidden=!note;$("gateNote").textContent=note||"";
  $("sMsg").textContent="";$("uMsg").textContent="";$("forgotBox").hidden=true;
  setTimeout(()=>{const f=mode==="setup"?$("sUrl"):mode==="unlock"?$("uPin"):null;if(f)f.focus()},50);
}
function openApp(){
  document.body.classList.remove("locked");$("gate").hidden=true;
  ["uPin","sPin","sPin2","sToken"].forEach(id=>$(id).value="");
  lastActive=Date.now();render();outboxNote();syncNow();
}
function clearScreen(){
  document.querySelectorAll("dialog").forEach(d=>{if(d.open)closeDlg(d)});
  ["todos","colist","detail"].forEach(id=>$(id).innerHTML="");
}
async function lock(){
  if(!S)return;await saveNow();
  S=null;KEY=null;db={companies:[],contacts:[]};clearScreen();showGate("unlock");
}
async function wipe(note){
  S=null;KEY=null;db={companies:[],contacts:[]};ui={sel:null,q:"",area:"",genre:"",sort:"next"};
  await saving;await vdel();clearScreen();showGate("setup",note);
}
$("setupForm").addEventListener("submit",async e=>{
  e.preventDefault();const m=$("sMsg");m.textContent="";
  const url=$("sUrl").value.trim(),token=$("sToken").value.trim(),pin=$("sPin").value,pin2=$("sPin2").value;
  if(!URL_RE.test(url)){m.textContent="接続先URLは「https://script.google.com/macros/s/…/exec」の形です。デプロイしたときのURLをそのまま貼り付けてください。";return}
  if(token.length<20){m.textContent="合言葉を貼り付けてください（スプレッドシートのメニュー「顧客ノート」から発行したものです）。";return}
  if(!/^\d{6}$/.test(pin)){m.textContent="PINは数字6桁にしてください。";return}
  if(weakPin(pin)){m.textContent="そのPINは推測されやすいので、別の数字にしてください。";return}
  if(pin!==pin2){m.textContent="PINが2回で一致していません。";return}
  $("sSubmit").disabled=true;$("sSubmit").textContent="つないでいます…";
  try{
    const j=await callServer(url,token,[]);
    if(!j||!j.ok){m.textContent=j&&j.error==="auth"?"合言葉が合いません。いちばん最後に発行した合言葉を貼り付けてください。":"スプレッドシート側でエラーが起きました。デプロイの設定を確認してください。";return}
    const salt=crypto.getRandomValues(new Uint8Array(16));const key=await deriveKey(pin,salt,ITER);
    const st={url,token,outbox:[],lastSync:Date.now(),sheetUrl:String(j.data.url||""),lockMin:5};const d=normalize(j.data);
    await vput({salt,iter:ITER,fails:0,box:await seal(key,{...st,db:d,ui})});
    KEY=key;S=st;db=d;
    if(navigator.storage&&navigator.storage.persist)navigator.storage.persist().catch(()=>{});
    openApp();toast("つながりました");
  }catch(err){m.textContent="つながりませんでした。電波のいい場所で、URLが正しいか確かめてもう一度押してください。"}
  finally{$("sSubmit").disabled=false;$("sSubmit").textContent="つないで始める"}
});
$("unlockForm").addEventListener("submit",async e=>{
  e.preventDefault();const m=$("uMsg"),pin=$("uPin").value;m.textContent="";
  if(!/^\d{6}$/.test(pin)){m.textContent="PINは数字6桁です。";return}
  $("uSubmit").disabled=true;
  try{
    const v=await vget();if(!v){showGate("setup");return}
    let key,st;
    try{key=await deriveKey(pin,v.salt,v.iter);st=await unseal(key,v.box)}
    catch(_){v.fails=(v.fails||0)+1;$("uPin").value="";
      if(v.fails>=MAX_FAILS){await wipe(`PINを${MAX_FAILS}回まちがえたので、この端末のデータを消しました。スプレッドシートのデータは無事です。もう一度設定してください。`);return}
      await vput(v);m.textContent=`PINがちがいます。あと${MAX_FAILS-v.fails}回まちがえると、この端末のデータを消します。`;return}
    if(v.fails){v.fails=0;await vput(v)}
    KEY=key;db=normalize(st.db||{});ui={...ui,...(st.ui||{})};delete st.db;delete st.ui;S={lockMin:5,outbox:[],...st};
    if(ui.sel&&!coById(ui.sel))ui.sel=null;openApp();
  }finally{$("uSubmit").disabled=false}
});
$("forgot").onclick=()=>{$("forgotBox").hidden=!$("forgotBox").hidden};
function armed(btn,label,fn){
  if(btn.dataset.armed!=="1"){const old=btn.textContent;btn.dataset.armed="1";btn.classList.add("armed");btn.textContent=label;
    setTimeout(()=>{if(btn.dataset.armed==="1"){btn.dataset.armed="";btn.classList.remove("armed");btn.textContent=old}},5000);return}
  btn.dataset.armed="";btn.classList.remove("armed");fn();
}
$("wipeGate").onclick=e=>armed(e.currentTarget,"本当に消す",()=>wipe("この端末のデータを消しました。もう一度設定してください。"));

/* ---------- 設定 ---------- */
$("openSettings").onclick=()=>{
  if(!S)return;const u=S.url;
  $("stUrl").textContent=u.replace(/\/s\/([A-Za-z0-9_-]{4})[A-Za-z0-9_-]+([A-Za-z0-9_-]{4})\/exec$/,"/s/$1…$2/exec");
  $("stSync").textContent=S.lastSync?new Date(S.lastSync).toLocaleString("ja-JP"):"まだ";$("stPending").textContent=`${S.outbox.length}件`;
  $("stLock").value=String(S.lockMin||5);$("stUrlIn").value=u;["stToken","stPin","stPin2"].forEach(id=>$(id).value="");$("stMsg").textContent="";
  $("wipeSettings").textContent=S.outbox.length?`この端末のデータを消す（未送信${S.outbox.length}件も消えます）`:"この端末のデータを消す";
  showDlg($("dlgSettings"));
};
$("lockNow").onclick=()=>lock();
$("stLock").onchange=e=>{if(S){S.lockMin=+e.target.value;saveNow();toast(`${S.lockMin}分使わないとロックします`)}};
$("stPinSave").onclick=async()=>{
  const p=$("stPin").value,p2=$("stPin2").value,m=$("stMsg");m.textContent="";
  if(!/^\d{6}$/.test(p)){m.textContent="PINは数字6桁にしてください。";return}
  if(weakPin(p)){m.textContent="そのPINは推測されやすいので、別の数字にしてください。";return}
  if(p!==p2){m.textContent="PINが2回で一致していません。";return}
  await saving;const salt=crypto.getRandomValues(new Uint8Array(16));const key=await deriveKey(p,salt,ITER);
  await vput({salt,iter:ITER,fails:0,box:await seal(key,{...S,db,ui})});KEY=key;
  $("stPin").value="";$("stPin2").value="";toast("PINを変えました");
};
$("stConnSave").onclick=async()=>{
  const url=$("stUrlIn").value.trim(),token=$("stToken").value.trim()||S.token,m=$("stMsg");m.textContent="";
  if(!URL_RE.test(url)){m.textContent="接続先URLの形がちがいます。";return}
  try{const j=await callServer(url,token,[]);if(!j||!j.ok){m.textContent=j&&j.error==="auth"?"合言葉が合いません。":"スプレッドシート側でエラーが起きました。";return}}
  catch(e){m.textContent="つながりませんでした。電波のいい場所でもう一度押してください。";return}
  S.url=url;S.token=token;$("stToken").value="";await saveNow();closeDlg($("dlgSettings"));toast("接続先を保存しました");syncNow();
};
$("wipeSettings").onclick=e=>armed(e.currentTarget,"本当に消す",()=>wipe("この端末のデータを消しました。"));

/* ---------- 自動ロック・のぞき見対策 ---------- */
let lastActive=Date.now(),hiddenAt=0;
["pointerdown","keydown","touchstart"].forEach(ev=>addEventListener(ev,()=>{lastActive=Date.now()},{passive:true}));
setInterval(()=>{if(S&&Date.now()-lastActive>(S.lockMin||5)*60000)lock()},15000);
document.addEventListener("visibilitychange",()=>{
  if(document.hidden){hiddenAt=Date.now();if(S){document.body.classList.add("cover");saveNow()}}
  else{document.body.classList.remove("cover");if(S&&hiddenAt&&Date.now()-hiddenAt>(S.lockMin||5)*60000)lock();else if(S)syncNow()}
});
addEventListener("pagehide",()=>{if(S)saveNow()});

/* ---------- 起動 ---------- */
(async()=>{
  if("serviceWorker" in navigator)navigator.serviceWorker.register("./sw.js").catch(()=>{});
  if(!window.isSecureContext||!window.crypto||!crypto.subtle||!window.indexedDB){showGate("none","このアプリは https のアドレスで開いたときだけ動きます。");return}
  let v=null;try{v=await vget()}catch(e){}
  showGate(v?"unlock":"setup");
})();
