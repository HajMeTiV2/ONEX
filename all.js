
const card=document.getElementById('loginCard');
if(window.matchMedia('(pointer:fine)').matches){
  document.addEventListener('mousemove',e=>{
    const r=card.getBoundingClientRect();
    const x=(e.clientX-r.left)/r.width-.5;
    const y=(e.clientY-r.top)/r.height-.5;
    if(e.clientX>=r.left-120&&e.clientX<=r.right+120&&e.clientY>=r.top-120&&e.clientY<=r.bottom+120){
      card.style.transform=`perspective(1000px) rotateX(${(-y*2.8).toFixed(2)}deg) rotateY(${(x*3.2).toFixed(2)}deg) translateZ(3px)`;
    }
  });
  document.addEventListener('mouseleave',()=>card.style.transform='');
}
function togglePassword(){
  const input=document.getElementById('loginPw');
  input.type=input.type==='password'?'text':'password';
}
document.getElementById('loginPw').focus();
document.getElementById('loginForm').addEventListener('submit',async e=>{
  e.preventDefault();
  const err=document.getElementById('loginErr');err.classList.remove('show');
  const btn=document.getElementById('loginBtn');btn.disabled=true;
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('loginPw').value,username:document.getElementById('loginUser').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'رمز اشتباه است');}
    location.href='/dashboard';
  }catch(e){err.textContent=e.message||'خطا در ورود';err.classList.add('show');btn.disabled=false;}
});




  tailwind.config = {{
    theme: {{
      extend: {{
        fontFamily: {{ vazir: ['Vazirmatn','system-ui','sans-serif'] }}
      }}
    }}
  }}


const vlessUrlData = "{vless_url}";

// Theme toggle logic with localStorage support (2 themes total)
function toggleTheme() {{
  const body = document.body;
  body.classList.toggle('theme-lighter');
  const isLighter = body.classList.contains('theme-lighter');
  localStorage.setItem('px_theme', isLighter ? 'lighter' : 'dark');
}}

// Initialize saved theme on load
(function() {{
  if (localStorage.getItem('px_theme') === 'lighter') {{
    document.body.classList.add('theme-lighter');
  }}
}})();

function openQrModal() {{
  var modal = document.getElementById('qrModal');
  var container = document.getElementById('qrcodeContainer');
  var txtEl = document.getElementById('qrModalText');
  container.innerHTML = "";
  txtEl.textContent = vlessUrlData;
  modal.classList.remove('hidden');
  try {{
    var typeNumber = 0;
    var errorCorrectionLevel = 'L';
    var qr = qrcode(typeNumber, errorCorrectionLevel);
    qr.addData(vlessUrlData);
    qr.make();
    container.innerHTML = qr.createImgTag(5, 8);
  }} catch (e) {{
    container.innerHTML = "<p class='text-xs text-black'>خطا در تولید QR Code</p>";
  }}
}}

function closeQrModal() {{
  document.getElementById('qrModal').classList.add('hidden');
}}

document.getElementById('qrModal').addEventListener('click', function(e) {{
  if (e.target === this) closeQrModal();
}});

const subUrlData = "{sub_url}";
function openQrFor(value,label) {{
  var modal=document.getElementById('qrModal'), container=document.getElementById('qrcodeContainer'), txt=document.getElementById('qrModalText');
  if(!modal||!container) return;
  container.innerHTML=''; txt.textContent=value;
  var title=modal.querySelector('p'); if(title) title.textContent=label||'QR Code';
  modal.classList.remove('hidden');
  try {{ var qr=qrcode(0,'L'); qr.addData(value); qr.make(); container.innerHTML=qr.createImgTag(5,8); }} catch(e) {{ container.innerHTML='<p class="text-xs text-black">خطا در تولید QR Code</p>'; }}
}}
function copySubLink() {{
  var text=subUrlData, btn=document.getElementById('subCopyBtn');
  var done=function(){{ if(!btn)return; var old=btn.innerHTML; btn.innerHTML='<span>✓ کپی شد</span>'; setTimeout(function(){{btn.innerHTML=old;}},1600); }};
  if(navigator.clipboard&&navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done).catch(function(){{fallbackCopy(text,done);}}); else fallbackCopy(text,done);
}}

function pxCopy(textId, btnId) {{
  var el = document.getElementById(textId);
  var btn = document.getElementById(btnId);
  if (!el || !btn) return;
  var text = el.textContent.textContext || el.textContent.trim();
  var done = function() {{
    var original = btn.getAttribute('data-original');
    if (!original) {{
      original = btn.innerHTML;
      btn.setAttribute('data-original', original);
    }}
    btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg><span>کپی شد</span>';
    btn.classList.add('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    setTimeout(function() {{
      btn.innerHTML = original;
      btn.classList.remove('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    }}, 1700);
  }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(done).catch(function() {{ fallbackCopy(text, done); }});
  }} else {{
    fallbackCopy(text, done);
  }}
}}
function fallbackCopy(text, cb) {{
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {{ document.execCommand('copy'); }} catch (e) {{}}
  document.body.removeChild(ta);
  if (cb) cb();
}}


const url = location.origin + location.pathname.replace("/p/","/sub-group/");
document.getElementById("subUrl").textContent = url;
async function copySubUrl(){
  const btn=document.getElementById("copyBtn");
  try{
    await navigator.clipboard.writeText(url);
    btn.textContent="✓ کپی شد";
  }catch(e){
    const ta=document.createElement("textarea");
    ta.value=url;document.body.appendChild(ta);ta.select();
    document.execCommand("copy");ta.remove();btn.textContent="✓ کپی شد";
  }
  setTimeout(()=>btn.textContent="کپی لینک",1800);
}



const I18N={
fa:{sec_panel:'پنل',sec_sys:'سیستم',nav_dash:'داشبورد',nav_configs:'کانفیگ‌ها',nav_groups:'گروه‌ها',nav_create:'ساخت کانفیگ',nav_stats:'آمار',nav_logs:'لاگ فعالیت',nav_settings:'تنظیمات',nav_support:'پشتیبانی',nav_donate:'حمایت مالی',nav_news:'تلگرام',nav_admins:'ادمین‌ها',refresh_news:'بروزرسانی اطلاعیه',admins_sub:'مدیریت کاربران مدیریتی و سطح دسترسی آن‌ها',admin_create:'ساخت اکانت ادمین',admin_user:'نام کاربری',admin_pw:'رمز عبور',admin_pw2:'تکرار رمز',admin_perms:'دسترسی‌ها',admin_btn:'ساخت اکانت',admin_list:'لیست ادمین‌ها',refresh:'بروزرسانی',refresh_stats:'بروزرسانی آمار',refresh_panel:'بروزرسانی پنل',panel_version:'نسخه پنل',current_version:'ورژن فعلی',nav_telegram:'ربات تلگرام',tg_sub:'توکن ربات و آیدی عددی ادمین · فعال‌سازی خودکار و وب‌هوک',tg_config:'پیکربندی ربات',tg_token:'توکن ربات (BotFather)',tg_admin:'آیدی عددی ادمین',tg_webhook:'فعال‌سازی Webhook (پیشنهادی روی Railway)',tg_activate:'ذخیره و فعال‌سازی ربات',tg_help:'راهنما',tg_h1:'از @BotFather یک ربات بساز و توکن را کپی کن',tg_h2:'آیدی عددی خودت را از @userinfobot بگیر',tg_h3:'ذخیره کن — وب‌هوک خودکار روی دامنه Railway ست می‌شود',logout:'خروج',loading:'در حال بارگذاری...',m_conns:'اتصالات فعال',m_traffic:'ترافیک کل',m_links:'کانفیگ‌ها',m_uptime:'آپتایم سرور',quick_create:'ساخت کانفیگ',quick_create_desc:'ساخت دستی با محدودیت ترافیک، سرعت و انقضا',configs_sub:'مدیریت لینک‌ها · VLESS و ساب',th_name:'نام',th_proto:'پروتکل',th_status:'وضعیت',th_usage:'مصرف',th_ops:'عملیات',manual_create:'ساخت دستی',label_name:'نام',label_proto:'پروتکل',label_limit:'محدودیت حجم',label_unit:'واحد',label_days:'انقضا (روز)',label_ip:'محدودیت IP',label_speed:'سرعت (Mbps)',btn_create:'ساخت',stats_sub:'ترافیک و اتصالات · فیلتر زمانی',r_day:'روز',r_week:'هفته',r_month:'ماه',r_all:'کل',panel_info:'اطلاعات کل پنل',lang_label:'زبان',change_pw:'تغییر رمز عبور',pw_cur:'رمز فعلی',pw_new:'رمز جدید',pw_cf:'تکرار رمز',btn_save:'ذخیره',github:'گیت‌هاب',telegram:'تلگرام',channel:'کانال پشتیبان',theme:'تم',theme_dark:'تم تیره',theme_light:'تم روشن',created_title:'کانفیگ ساخته شد',copy_vless:'کپی VLESS',copy_sub:'کپی ساب',sub_label:'سابسکریپشن'},
en:{sec_panel:'PANEL',sec_sys:'SYSTEM',nav_dash:'Dashboard',nav_configs:'Configs',nav_groups:'Groups',nav_create:'Create Config',nav_stats:'Statistics',nav_logs:'Activity Log',nav_settings:'Settings',nav_support:'Support',nav_donate:'Donate',nav_news:'Telegram',nav_admins:'Admins',refresh_news:'Refresh news',admins_sub:'Manage admin users and their access levels',admin_create:'Create admin account',admin_user:'Username',admin_pw:'Password',admin_pw2:'Confirm password',admin_perms:'Permissions',admin_btn:'Create account',admin_list:'Admin list',refresh:'Refresh',refresh_stats:'Refresh stats',refresh_panel:'Update panel',panel_version:'Panel version',current_version:'Current version',nav_telegram:'Telegram bot',tg_sub:'Bot token and numeric admin ID · auto activate and webhook',tg_config:'Bot configuration',tg_token:'Bot token (BotFather)',tg_admin:'Admin numeric ID',tg_webhook:'Enable Webhook (recommended on Railway)',tg_activate:'Save and activate bot',tg_help:'Guide',tg_h1:'Create a bot with @BotFather and copy the token',tg_h2:'Get your numeric ID from @userinfobot',tg_h3:'Save — webhook is set automatically on Railway domain',logout:'Logout',loading:'Loading...',m_conns:'Active connections',m_traffic:'Total traffic',m_links:'Configs',m_uptime:'Server uptime',quick_create:'Create Config',quick_create_desc:'Manual create with traffic, speed and expiry',configs_sub:'Manage links · VLESS and Sub',th_name:'Name',th_proto:'Protocol',th_status:'Status',th_usage:'Usage',th_ops:'Actions',manual_create:'Manual create',label_name:'Name',label_proto:'Protocol',label_limit:'Traffic limit',label_unit:'Unit',label_days:'Expiry (days)',label_ip:'IP limit',label_speed:'Speed (Mbps)',btn_create:'Create',stats_sub:'Traffic and connections · time filter',r_day:'Day',r_week:'Week',r_month:'Month',r_all:'All',panel_info:'Panel overview',lang_label:'Language',change_pw:'Change password',pw_cur:'Current password',pw_new:'New password',pw_cf:'Confirm password',btn_save:'Save',github:'GitHub',telegram:'Telegram',channel:'Support channel',theme:'Theme',theme_dark:'Dark theme',theme_light:'Light theme',created_title:'Config created',copy_vless:'Copy VLESS',copy_sub:'Copy Sub',sub_label:'Subscription'}
};
let lang=localStorage.getItem('px_lang')||'fa';
let statRange='month';
function t(k){return (I18N[lang]||I18N.fa)[k]||k}
function setVersionLabels(current,latest){
  const fallback=(document.getElementById('panelVersionValue')?.textContent||'v—').replace(/^v/i,'');
  const c=current||fallback, l=latest||c;
  const pv=document.getElementById('panelVersionValue');
  const cv=document.getElementById('currentVersionValue');
  if(pv)pv.textContent='v'+c;
  if(cv)cv.textContent='v'+c;
  const info=document.getElementById('panelVersionValue');
  if(info){info.title=(l!==c?'Latest: v'+l:'Current: v'+c);}
}
function applyLang(){
  document.getElementById('htmlRoot').lang=lang;
  document.getElementById('htmlRoot').dir=lang==='fa'?'rtl':'ltr';
  document.body.classList.toggle('en',lang==='en');
  document.querySelectorAll('[data-i18n]').forEach(el=>{const k=el.getAttribute('data-i18n');if(I18N[lang][k])el.textContent=I18N[lang][k]});
  const tl=document.getElementById('themeLabel');
  if(tl) tl.textContent=document.documentElement.classList.contains('light')?t('theme_dark'):t('theme_light');
  const lf=document.getElementById('topLangFa'),le=document.getElementById('topLangEn');
  if(lf)lf.classList.toggle('active',lang==='fa'); if(le)le.classList.toggle('active',lang==='en');
  const nb=document.getElementById('topNotifyBtn'); if(nb){const label=nb.querySelector('.notify-label');if(label)label.textContent=lang==='fa'?'اعلان‌ها':'Notifications';}
  const nt=document.getElementById('notifyPanelTitle'); if(nt)nt.textContent=lang==='fa'?'اعلان‌ها':'Notifications';
}
function setLang(l){lang=l;localStorage.setItem('px_lang',l);applyLang();toast(l==='fa'?'زبان فارسی':'English')}

function setTheme(mode){
  if(mode==='light') document.documentElement.classList.add('light');
  else document.documentElement.classList.remove('light');
  localStorage.setItem('px_theme',mode);
  applyLang();
}
function toggleTheme(){
  const isLight=document.documentElement.classList.contains('light');
  setTheme(isLight?'dark':'light');
}
(function(){const th=localStorage.getItem('px_theme')||'dark';setTheme(th)})();

const sb=document.getElementById('sidebar'),main=document.getElementById('main');
const mobMenuBtn=document.getElementById('mobMenuBtn'),overlay=document.getElementById('overlay');
function closeMobileNav(){ if(sb) sb.classList.remove('mobile-open'); if(overlay) overlay.classList.remove('show'); }
function openMobileNav(){ if(sb) sb.classList.add('mobile-open'); if(overlay) overlay.classList.add('show'); }
if(mobMenuBtn) mobMenuBtn.onclick=()=>{ if(sb.classList.contains('mobile-open')) closeMobileNav(); else openMobileNav(); };
if(overlay) overlay.onclick=closeMobileNav;

document.getElementById('sbToggle').onclick=()=>{
  sb.classList.toggle('collapsed');
  main.classList.toggle('expanded',sb.classList.contains('collapsed'));
  localStorage.setItem('sb_c',sb.classList.contains('collapsed')?'1':'0');
};
if(localStorage.getItem('sb_c')==='1'){sb.classList.add('collapsed');main.classList.add('expanded')}
function goPage(name){
  closeMobileNav();
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('on',n.dataset.page===name));
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('on',p.id==='page-'+name));
  window.scrollTo({top:0,behavior:'smooth'});
  if(name==='logs')loadLogs();
  if(name==='groups')loadGroups();
  if(name==='configs'||name==='dash')refreshAll();
  if(name==='stats'){refreshAll();loadStatsDashboard(false);}
}
document.querySelectorAll('.nav-item').forEach(el=>el.addEventListener('click',()=>goPage(el.dataset.page)));

function toast(msg){
  const el=document.getElementById('toast');
  el.textContent=msg;el.classList.add('show');
  clearTimeout(window.__tt);window.__tt=setTimeout(()=>el.classList.remove('show'),2200);
}

let __loggingOut=false;
async function logoutPanel(){
  if(__loggingOut)return;
  __loggingOut=true;
  const btn=document.getElementById('panelLogoutBtn');
  if(btn){btn.disabled=true;btn.setAttribute('aria-busy','true');}
  try{
    await fetch('/api/logout',{
      method:'POST',
      cache:'no-store',
      credentials:'same-origin',
      headers:{'X-Requested-With':'XMLHttpRequest'}
    });
  }catch(e){}
  window.location.replace('/login');
}

async function api(url,opts={}){
  try{
    const r=await fetch(url,{cache:'no-store',credentials:'same-origin',...opts});
    if(r.status===401){location.href='/login';return null}
    let data=null;try{data=await r.json()}catch{data={ok:false}}
    if(!r.ok){toast(data.detail||data.error||'Error');return null}
    return data;
  }catch(e){toast(lang==='fa'?'ارتباط برقرار نشد':'Connection failed');return null}
}
function fmtB(b){b=Number(b)||0;if(b<1024)return b+' B';if(b<1024**2)return (b/1024).toFixed(1)+' KB';if(b<1024**3)return (b/1024**2).toFixed(2)+' MB';return (b/1024**3).toFixed(2)+' GB'}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}

async function refreshAll(){
  if(typeof loadCategories==='function') try{await loadCategories()}catch(e){}
  const links=await api('/api/links');
  if(!links)return;
  const arr=Array.isArray(links.links)?links.links:(Array.isArray(links)?links:[]);
  const setRefresh=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v};
  setRefresh('mLinks',arr.length);
  let active=0,used=0;
  arr.forEach(l=>{if(l.active!==false)active++;used+=Number(l.used_bytes||0)});
  setRefresh('mTraffic',fmtB(used));
  setRefresh('sTraffic',fmtB(used));
  setRefresh('sActive',active);
  setRefresh('lastUpd',(lang==='fa'?'بروزرسانی: ':'Updated: ')+new Date().toLocaleTimeString(lang==='fa'?'fa-IR':'en-US'));
  try{
    const c=await api('/api/connections');
    const cnt=(c&&c.connections)?c.connections.length:((c&&typeof c.count==='number')?c.count:0);
    setRefresh('mConns',cnt);
    setRefresh('sConns',cnt);
  }catch(e){}
  try{
    const h=await fetch('/health',{cache:'no-store'}).then(r=>r.json());
    if(h&&h.uptime){
      document.getElementById('mUptime').textContent=h.uptime;
      const su=document.getElementById('sUptime');if(su)su.textContent=h.uptime;
    }
  }catch(e){}
    __allLinks=arr;
  softUpdateLinks(arr);
  const panelInfo=document.getElementById('panelInfo'); if(panelInfo) panelInfo.innerHTML=lang==='fa'
    ?`کل کانفیگ: <b>${arr.length}</b> · فعال: <b>${active}</b> · مصرف: <b>${fmtB(used)}</b> · بازه: <b>${statRange}</b>`
    :`Total: <b>${arr.length}</b> · Active: <b>${active}</b> · Usage: <b>${fmtB(used)}</b> · Range: <b>${statRange}</b>`;
  renderOnexRecent(arr);
  const hostEl=document.getElementById('topHost'); if(hostEl) hostEl.textContent=location.host||'ONEX SERVER';
  const ipEl=document.getElementById('serverIp'); if(ipEl) ipEl.textContent=location.hostname||'—';
  const chartEl=document.getElementById('chartTraffic'); if(chartEl) chartEl.textContent=fmtB(used);
  const upEl=document.getElementById('topUptime'); const mu=document.getElementById('mUptime'); if(upEl && mu) upEl.textContent='Uptime: '+mu.textContent;
}

function renderOnexRecent(arr){
  const el=document.getElementById('onexRecentBody'); if(!el) return;
  if(!arr.length){el.innerHTML='<tr><td colspan=5 style="text-align:center;color:var(--t3);padding:24px">کانفیگی وجود ندارد</td></tr>';return}
  el.innerHTML=arr.slice(0,5).map(l=>{
    const name=esc(l.label||l.name||String(l.uuid||l.id||'').slice(0,8));
    const proto=esc(l.protocol||'vless-ws');
    const usage=fmtB(l.used_bytes);
    const active=l.active!==false&&!l.expired;
    const uid=esc(l.uuid||l.id||'');
    return `<tr><td><b>${name}</b></td><td>${proto}</td><td>${usage}</td><td><span class="recent-status"><i></i>${active?'فعال':'متوقف'}</span></td><td><div class="recent-actions"><button class="mini-action" onclick="copyLinkById('${uid}')">⧉</button><button class="mini-action" onclick="copySubById('${uid}')">↗</button></div></td></tr>`;
  }).join('');
}


function linkBadgeClass(l){
  const conn=Number(l.connected_ips||0);
  const used=Number(l.used_bytes||0), lim=Number(l.limit_bytes||0);
  let usagePct=lim>0?(used/lim)*100:0;
  let expWarn=false, expDead=false;
  if(l.expires_at){try{const ms=new Date(l.expires_at)-Date.now();if(ms<=0)expDead=true;else if(ms<3*864e5)expWarn=true}catch(e){}}
  if(expDead||usagePct>=90) return 'conn-badge red';
  if(expWarn||usagePct>=70) return 'conn-badge orange';
  if(conn>0) return 'conn-badge green';
  return 'conn-badge gray';
}
function softUpdateLinks(arr){
  // FINAL CONFIG CARDS RENDERER — never fall back to the legacy table.
  window.__linksMap={};
  (arr||[]).forEach(l=>{window.__linksMap[String(l.uuid||l.id||'')]=l});
  renderConfigCards(getFilteredConfigs());
}
function patchLinkRow(tr, l){
  // Legacy table patcher retained for compatibility; cards are the active UI.
  renderConfigCards(getFilteredConfigs());
}
function renderLinks(arr){
  window.__linksMap={};
  (arr||[]).forEach(l=>window.__linksMap[String(l.uuid||l.id||'')]=l);
  renderConfigCards(getFilteredConfigs());
}
function getLinkUrl(l){if(!l)return '';return l.vless_full||l.vless||l.vless_link||l.link||''}
function getSubUrl(l){if(!l)return '';return l.sub||l.sub_url||l.info||''}
async function copyText(text){
  text=String(text||'').trim();
  if(!text||text==='—'){toast(lang==='fa'?'لینکی نیست':'Nothing to copy');return}
  try{
    if(navigator.clipboard&&window.isSecureContext) await navigator.clipboard.writeText(text);
    else{const ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;left:-9999px';document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta)}
    toast(lang==='fa'?'کپی شد':'Copied');
  }catch(e){toast(lang==='fa'?'کپی نشد':'Copy failed')}
}
async function copyLinkById(uid){await copyText(getLinkUrl((window.__linksMap||{})[uid]))}
async function copySubById(uid){await copyText(getSubUrl((window.__linksMap||{})[uid]))}
async function toggleLink(uid,state){
  // optimistic UI — رنگ بلافاصله عوض می‌شود
  if(window.__linksMap && window.__linksMap[uid]){
    window.__linksMap[uid].active = !!state;
    if(window.__linksMap[uid].expired && state) window.__linksMap[uid].expired = false;
  }
  if(typeof __allLinks !== 'undefined' && Array.isArray(__allLinks)){
    const item = __allLinks.find(x => (x.uuid||x.id)===uid);
    if(item) item.active = !!state;
  }
  const r=await api('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:!!state})});
  if(r===null){
    // rollback
    if(window.__linksMap && window.__linksMap[uid]) window.__linksMap[uid].active = !state;
    refreshAll();
    return;
  }
  toast(state?(lang==='fa'?'فعال شد':'Enabled'):(lang==='fa'?'غیرفعال شد':'Disabled'));
}
async function toggleConfigActive(e,uid,state){
  e.preventDefault();e.stopPropagation();
  const next=!!state;
  if(window.__linksMap&&window.__linksMap[uid])window.__linksMap[uid].active=next;
  if(typeof __allLinks!=='undefined'&&Array.isArray(__allLinks)){const item=__allLinks.find(x=>String(x.uuid||x.id)===String(uid));if(item)item.active=next;}
  const r=await api('/api/links/'+encodeURIComponent(uid),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:next})});
  if(r===null){if(window.__linksMap&&window.__linksMap[uid])window.__linksMap[uid].active=!next;const item=__allLinks?.find?.(x=>String(x.uuid||x.id)===String(uid));if(item)item.active=!next;renderConfigCards(getFilteredConfigs());return}
  toast(next?(lang==='fa'?'کانفیگ فعال شد':'Config enabled'):(lang==='fa'?'کانفیگ غیرفعال شد':'Config disabled'));
  renderConfigCards(getFilteredConfigs());
}
function openDeleteAllConfigs(){
  const modal=document.getElementById('deleteAllConfigsModal');
  if(!modal)return;
  modal.classList.add('open');modal.setAttribute('aria-hidden','false');
  document.body.style.overflow='hidden';
}
function closeDeleteAllConfigs(){
  const modal=document.getElementById('deleteAllConfigsModal');
  if(!modal)return;
  modal.classList.remove('open');modal.setAttribute('aria-hidden','true');
  document.body.style.overflow='';
}
async function confirmDeleteAllConfigs(){
  const btn=document.getElementById('deleteAllConfigsConfirm');
  if(!btn)return;
  btn.disabled=true;
  btn.innerHTML='<span class="spin" style="width:15px;height:15px;border-width:2px"></span> در حال حذف...';
  const r=await api('/api/links/delete-all',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  btn.disabled=false;
  btn.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v5M14 11v5"/></svg> حذف همه';
  if(r){
    closeDeleteAllConfigs();
    if(window.__linksMap)window.__linksMap={};
    if(typeof __allLinks!=='undefined'&&Array.isArray(__allLinks))__allLinks.length=0;
    clearSelection();
    toast(lang==='fa'?`همه کانفیگ‌ها حذف شدند (${Number(r.deleted||0)})`:`All configs deleted (${Number(r.deleted||0)})`);
    await refreshAll();
  }
}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDeleteAllConfigs()});
document.getElementById('deleteAllConfigsModal')?.addEventListener('click',e=>{if(e.target.id==='deleteAllConfigsModal')closeDeleteAllConfigs()});
async function deleteLink(uid){
  if(!confirm(lang==='fa'?'حذف شود؟':'Delete?'))return;
  const r=await api('/api/links/'+uid,{method:'DELETE'});
  if(r!==null){toast(lang==='fa'?'حذف شد':'Deleted');refreshAll()}
}
function showResult(data){
  if(!data)return;
  document.getElementById('resVless').textContent=getLinkUrl(data)||'—';
  document.getElementById('resSub').textContent=getSubUrl(data)||'—';
  document.getElementById('resultModal').classList.add('open');
}
function closeResult(){document.getElementById('resultModal').classList.remove('open')}
document.getElementById('resultModal').addEventListener('click',e=>{if(e.target.id==='resultModal')closeResult()});

function getAdvancedPorts(){
  return [...document.querySelectorAll('#advancedPorts .advanced-port-chip')].map(x=>Number(x.dataset.port)).filter(Boolean);
}
function addAdvancedPort(value){
  const input=document.getElementById('advPortInput');
  const port=Number(value||input?.value||0);
  if(!port||port<1||port>65535){toast(lang==='fa'?'پورت باید بین ۱ تا ۶۵۵۳۵ باشد':'Port must be between 1 and 65535');return}
  const ports=getAdvancedPorts(); if(ports.includes(port)){if(input)input.value='';return}
  const box=document.getElementById('advancedPorts'); if(!box)return;
  const chip=document.createElement('span'); chip.className='advanced-port-chip'+(ports.length===0?' primary':''); chip.dataset.port=port;
  chip.innerHTML=`<b>${ports.length===0?'اصلی · ':''}${port}</b><button type="button" aria-label="remove" onclick="removeAdvancedPort(${port})">×</button>`;
  box.appendChild(chip); if(input)input.value='';
}
function removeAdvancedPort(port){const chip=[...document.querySelectorAll('#advancedPorts .advanced-port-chip')].find(x=>Number(x.dataset.port)===Number(port));if(chip)chip.remove();const chips=[...document.querySelectorAll('#advancedPorts .advanced-port-chip')];chips.forEach((x,i)=>{x.classList.toggle('primary',i===0);const b=x.querySelector('b');if(b)b.textContent=(i===0?'اصلی · ':'')+x.dataset.port})}
function toggleAdvancedConfig(force){const panel=document.getElementById('advancedConfigPanel'),card=document.querySelector('.advanced-config-card');if(!panel||!card)return;const open=force===undefined?!card.classList.contains('open'):!!force;card.classList.toggle('open',open);panel.hidden=!open;document.getElementById('advancedToggleState').textContent=open?'بستن':'باز کردن';if(open)loadAdvancedDraft()}
function advancedFormObject(){
  const g=id=>document.getElementById(id); const val=id=>(g(id)?.value??'').trim(); const num=id=>Number(g(id)?.value)||0; const chk=id=>!!g(id)?.checked;
  return {tls:{enabled:val('advTlsMode')!=='none',mode:val('advTlsMode'),sni:val('advSni'),server_name:val('advSni'),alpn:val('advAlpn'),certificate_path:val('advCertPath'),key_path:val('advKeyPath'),allow_insecure:chk('advAllowInsecure'),min_version:val('advTlsMin'),max_version:val('advTlsMax'),reality:{public_key:val('advRealityPk'),private_key:val('advRealitySk'),short_id:val('advRealitySid'),spider_x:val('advRealitySpider'),fingerprint:val('advRealityFp'),handshake_server:val('advRealityHandshake'),handshake_port:num('advRealityHandshakePort'),max_time_difference:val('advRealityMaxDiff')}},host:{address:val('advAddress'),host:val('advHost'),path:val('advPath'),service_name:val('advServiceName'),authority:val('advAuthority')},fingerprint:{enabled:chk('advFpEnabled'),value:val('advFp'),randomize:chk('advFpRandom')},network:{type:val('advNetwork'),mode:val('advNetworkMode'),path:val('advPath'),service_name:val('advServiceName'),http_version:val('advHttpVersion')},headers:{host:val('advHost'),user_agent:val('advUserAgent'),extra:(g('advExtraHeaders')?.value||'').split(/\r?\n/).map(x=>x.trim()).filter(Boolean)},routing:{domain_strategy:val('advDomainStrategy'),route:val('advRoute'),proxy_protocol:chk('advProxyProtocol'),sniff:chk('advSniff'),sniff_override:chk('advSniffOverride'),sniff_timeout:val('advSniffTimeout')},transport:{packet_encoding:val('advPacketEncoding'),early_data:num('advEarlyData'),max_early_data:num('advEarlyData'),early_data_header_name:val('advEarlyDataHeader'),padding:chk('advPadding')},listener:{listen:val('advListen')||'0.0.0.0',bind_interface:val('advBindInterface'),routing_mark:num('advRoutingMark'),netns:val('advNetns'),reuse_addr:chk('advReuseAddr'),tcp_fast_open:chk('advTfo'),tcp_multi_path:chk('advMptcp'),disable_tcp_keep_alive:chk('advDisableKeepAlive'),tcp_keep_alive:val('advTcpKeepAlive'),tcp_keep_alive_interval:val('advTcpKeepAliveInterval'),udp_fragment:chk('advUdpFragment'),udp_timeout:val('advUdpTimeout')},shadowsocks:{method:val('advSsMethod')||'aes-256-gcm'},hysteria2:{up_mbps:num('advHyUp'),down_mbps:num('advHyDown'),obfs_type:val('advHyObfsType'),obfs_password:val('advHyObfsPassword'),masquerade:val('advHyMasquerade')},ports:getAdvancedPorts()};
}
function fillAdvancedForm(a){
  a=a||{}; const tls=a.tls||{},host=a.host||{},fp=a.fingerprint||{},net=a.network||{},routing=a.routing||{},transport=a.transport||{},listener=a.listener||{},reality=tls.reality||{},headers=a.headers||{},ss=a.shadowsocks||{},hy=a.hysteria2||{};
  const set=(id,v)=>{const e=document.getElementById(id);if(e)e.value=v??''}; const check=(id,v)=>{const e=document.getElementById(id);if(e)e.checked=!!v};
  set('advTlsMode',tls.mode||'tls');set('advSni',tls.sni||tls.server_name||'');set('advAlpn',tls.alpn||'');set('advTlsMin',tls.min_version||'1.2');set('advTlsMax',tls.max_version||'1.3');set('advCertPath',tls.certificate_path||'');set('advKeyPath',tls.key_path||'');check('advAllowInsecure',tls.allow_insecure);
  set('advRealityPk',reality.public_key||'');set('advRealitySk',reality.private_key||'');set('advRealitySid',reality.short_id||'');set('advRealitySpider',reality.spider_x||'');set('advRealityFp',reality.fingerprint||'chrome');set('advRealityHandshake',reality.handshake_server||'');set('advRealityHandshakePort',reality.handshake_port||443);set('advRealityMaxDiff',reality.max_time_difference||'');
  set('advAddress',host.address||'');set('advHost',host.host||headers.host||'');set('advPath',host.path||net.path||'');set('advAuthority',host.authority||'');set('advUserAgent',headers.user_agent||'');set('advServiceName',host.service_name||net.service_name||'');
  set('advFp',fp.value||'chrome');check('advFpEnabled',fp.enabled!==false);check('advFpRandom',fp.randomize);set('advNetwork',net.type||'ws');set('advNetworkMode',net.mode||'');set('advHttpVersion',net.http_version||'1.1');set('advPacketEncoding',transport.packet_encoding||'');set('advEarlyData',transport.early_data||0);set('advEarlyDataHeader',transport.early_data_header_name||'Sec-WebSocket-Protocol');check('advPadding',transport.padding);set('advDomainStrategy',routing.domain_strategy||'');set('advRoute',routing.route||'');check('advSniff',routing.sniff);check('advSniffOverride',routing.sniff_override);set('advSniffTimeout',routing.sniff_timeout||'300ms');check('advProxyProtocol',routing.proxy_protocol);set('advExtraHeaders',(headers.extra||[]).join('\n'));
  set('advListen',listener.listen||'0.0.0.0');set('advBindInterface',listener.bind_interface||'');set('advRoutingMark',listener.routing_mark||0);set('advNetns',listener.netns||'');set('advTcpKeepAlive',listener.tcp_keep_alive||'5m');set('advTcpKeepAliveInterval',listener.tcp_keep_alive_interval||'75s');set('advUdpTimeout',listener.udp_timeout||'5m');check('advReuseAddr',listener.reuse_addr!==false);check('advTfo',listener.tcp_fast_open);check('advMptcp',listener.tcp_multi_path);check('advDisableKeepAlive',listener.disable_tcp_keep_alive);check('advUdpFragment',listener.udp_fragment);set('advSsMethod',ss.method||'aes-256-gcm');set('advHyUp',hy.up_mbps||0);set('advHyDown',hy.down_mbps||0);set('advHyObfsType',hy.obfs_type||'');set('advHyObfsPassword',hy.obfs_password||'');set('advHyMasquerade',hy.masquerade||'');
  document.getElementById('advancedPorts').innerHTML=''; (a.ports&&a.ports.length?a.ports:[443]).forEach(addAdvancedPort); updateRealityVisibility();
}
function updateRealityVisibility(){const box=document.getElementById('advRealityBox'),mode=document.getElementById('advTlsMode');if(box&&mode)box.style.display=mode.value==='reality'?'block':'none'}
function resetAdvancedConfig(){fillAdvancedForm({ports:[Number(document.getElementById('cPort')?.value)||443]});localStorage.removeItem('onex_advanced_draft');toast(lang==='fa'?'تنظیمات پیشرفته بازنشانی شد':'Advanced settings reset')}
function saveAdvancedDraft(){try{localStorage.setItem('onex_advanced_draft',JSON.stringify(advancedFormObject()));toast(lang==='fa'?'تنظیمات ذخیره شد':'Settings saved')}catch(e){toast(lang==='fa'?'ذخیره انجام نشد':'Save failed')}}
function loadAdvancedDraft(){try{const raw=localStorage.getItem('onex_advanced_draft');if(raw)fillAdvancedForm(JSON.parse(raw));else if(!getAdvancedPorts().length)fillAdvancedForm({ports:[Number(document.getElementById('cPort')?.value)||443]})}catch(e){fillAdvancedForm({ports:[443]})}}
function copyAdvancedJson(){copyText(JSON.stringify(advancedFormObject(),null,2))}
let __advancedPreview = null;
function setAdvancedValidation(kind, html){const el=document.getElementById('advancedValidationStatus');if(!el)return;el.className='advanced-validation-status '+kind;el.innerHTML=html;}
async function validateAdvancedConfig(showPreview=false){const protocol=document.getElementById('cProto')?.value||'';const advanced=advancedFormObject();setAdvancedValidation('warn',lang==='fa'?'در حال اعتبارسنجی...':'Validating...');const r=await api('/api/advanced/validate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({protocol,advanced})});if(!r){setAdvancedValidation('err',lang==='fa'?'اعتبارسنجی انجام نشد':'Validation failed');return false}const parts=[];if(r.ok)parts.push('✓ '+(lang==='fa'?'تنظیمات معتبر است':'Configuration is valid'));if(r.native)parts.push('• '+(lang==='fa'?'Native sing-box فعال است':'Native sing-box is available'));(r.warnings||[]).forEach(x=>parts.push('⚠ '+esc(x)));(r.errors||[]).forEach(x=>parts.push('✕ '+esc(x)));setAdvancedValidation(r.ok?(r.warnings?.length?'warn':'ok'):'err',parts.join('<br>'));__advancedPreview=r.preview||null;const box=document.getElementById('advancedPreviewBox'),pre=document.getElementById('advancedPreviewCode');if(box&&pre){box.hidden=!showPreview||!__advancedPreview;if(__advancedPreview)pre.textContent=JSON.stringify(__advancedPreview,null,2)}await loadAdvancedCapabilities(protocol);return !!r.ok}
async function loadAdvancedCapabilities(protocol){const r=await api('/api/advanced/capabilities?protocol='+encodeURIComponent(protocol||''));const el=document.getElementById('advancedCapabilityStatus');if(!el||!r)return;const labels={tls:'TLS',reality:'Reality',sni:'SNI',alpn:'ALPN',fingerprint:'Fingerprint',ports:'چند پورت',listener:'Listener',routing:'Routing',sniffing:'Sniffing',custom_headers:'Headers'};el.innerHTML=Object.entries(r.supported||{}).map(([k,v])=>(v?'✓ ':'✕ ')+(labels[k]||k)+(v?' · پشتیبانی':' · اعمال نمی‌شود')).join(' &nbsp; | &nbsp; ');el.className='advanced-validation-status '+(r.native?'ok':'warn');el.style.display='block'}
function copyAdvancedPreview(){if(__advancedPreview)copyText(JSON.stringify(__advancedPreview,null,2));}
let __configEditUid='';let __configEditOriginalExpiresAt=null;let __configEditOriginalDays=0;
function configEditValue(id){return document.getElementById(id)?.value??''}
function setConfigEditValue(id,value){const el=document.getElementById(id);if(el)el.value=value??''}
function setConfigEditMode(on,link){
  __configEditUid=on?(String(link?.uuid||link?.id||'')):'';if(!on){__configEditOriginalExpiresAt=null;__configEditOriginalDays=0;}
  const title=document.getElementById('createPageTitle'),sub=document.getElementById('createPageSubtitle'),btn=document.getElementById('manualConfigSubmit'),cancel=document.getElementById('cancelConfigEditBtn'),banner=document.getElementById('configEditBanner'),bannerName=document.getElementById('configEditBannerName'),icon=document.getElementById('createPageTitleIcon');
  if(title)title.textContent=on?'ویرایش کانفیگ':'ساخت کانفیگ';
  if(sub)sub.textContent=on?'تنظیمات کانفیگ را تغییر دهید و در پایان ذخیره کنید':'ایجاد کانفیگ جدید با تنظیمات پایه و پیشرفته';
  if(btn){btn.innerHTML=on?'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M5 12h14M13 6l6 6-6 6"/></svg><span>ذخیره تغییرات</span>':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 5v14M5 12h14"/></svg><span>ساخت</span>';btn.setAttribute('onclick',on?'doManualCreate()':'doManualCreate()')}
  if(cancel)cancel.hidden=!on;
  if(banner){banner.hidden=!on;if(on&&bannerName)bannerName.textContent=link?.label||link?.uuid||'—'}
  if(icon)icon.innerHTML=on?'<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"/>':'<path d="M12 5v14M5 12h14"/>';
}
function cancelConfigEdit(){setConfigEditMode(false);goPage('configs')}
async function openConfigEditor(e,uid){
  e?.preventDefault();e?.stopPropagation();
  const link=(window.__linksMap||{})[uid]||__allLinks.find(x=>String(x.uuid||x.id||'')===String(uid));
  if(!link){toast(lang==='fa'?'کانفیگ پیدا نشد':'Config not found');return}
  closeConfigMenus();
  goPage('create');
  await Promise.all([loadProtocols(),loadCategories(),loadGroups()]);
  setConfigEditMode(true,link);
  setConfigEditValue('cName',link.label||'');
  const proto=document.getElementById('cProto');if(proto){proto.value=link.protocol||'vless-ws';syncProtocolPicker('cProto')}
  setConfigEditValue('cGroup',link.category_id||'0');
  setConfigEditValue('cSubGroup',link.sub_id||'');
  const limitBytes=Number(link.limit_bytes||0);let limitUnit='GB',limitValue=0;
  if(limitBytes){if(limitBytes%(1024**3)===0){limitUnit='GB';limitValue=limitBytes/(1024**3)}else if(limitBytes%(1024**2)===0){limitUnit='MB';limitValue=limitBytes/(1024**2)}else{limitUnit='KB';limitValue=limitBytes/1024}}
  setConfigEditValue('cLimit',limitValue);setConfigEditValue('cUnit',limitUnit);
  let days=0;if(link.expires_at){const ms=new Date(link.expires_at).getTime()-Date.now();days=Math.max(0,Math.ceil(ms/86400000))}
  __configEditOriginalExpiresAt=link.expires_at||null;__configEditOriginalDays=days;setConfigEditValue('cDays',days);
  setConfigEditValue('cIp',link.ip_limit||0);
  const speedBytes=Number(link.speed_limit_bytes||0);setConfigEditValue('cSpeed',speedBytes?Math.round((speedBytes*8/(1024*1024))*100)/100:0);
  const all=document.getElementById('cAllProtocols');if(all)all.checked=!!link.all_protocols;
  fillAdvancedForm(link.advanced||{ports:[Number(link.port)||443]});
  document.getElementById('advancedValidationStatus')?.replaceChildren();
  document.getElementById('advancedPreviewBox')?.setAttribute('hidden','');
  window.scrollTo({top:0,behavior:'smooth'});
  toast(lang==='fa'?'فرم ویرایش آماده شد':'Edit form loaded');
}
function collectConfigFormBody(){
  const advanced=advancedFormObject(),ports=advanced.ports.length?advanced.ports:[Number(configEditValue('cPort'))||443];
  return {label:configEditValue('cName').trim()||undefined,protocol:configEditValue('cProto')||undefined,category_id:configEditValue('cGroup')||'0',sub_id:configEditValue('cSubGroup')||undefined,limit_value:Number(configEditValue('cLimit'))||0,limit_unit:configEditValue('cUnit')||'GB',expires_days:Number(configEditValue('cDays'))||0,ip_limit:Number(configEditValue('cIp'))||0,speed_limit_value:Number(configEditValue('cSpeed'))||0,speed_limit_unit:'MBIT',all_protocols:!!document.getElementById('cAllProtocols')?.checked,port:ports[0],fingerprint:advanced.fingerprint.value,alpn:advanced.tls.alpn,advanced};
}
async function saveEditedConfig(){
  const uid=__configEditUid;if(!uid)return false;
  const valid=await validateAdvancedConfig(false);if(!valid)return false;
  const body=collectConfigFormBody();
  const currentDays=Number(configEditValue('cDays'))||0;
  if(currentDays===__configEditOriginalDays) body.expires_at=__configEditOriginalExpiresAt;
  else body.expires_days=currentDays;
  const r=await api('/api/links/'+encodeURIComponent(uid),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r)return false;
  toast(lang==='fa'?'تغییرات ذخیره شد':'Changes saved');
  setConfigEditMode(false);
  await refreshAll();
  goPage('configs');
  return true;
}
async function doManualCreate(){
  if(__configEditUid)return saveEditedConfig();
  const valid=await validateAdvancedConfig(false); if(!valid)return;
  const body=collectConfigFormBody();
  const r=await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); if(r){showResult(r);refreshAll();saveAdvancedDraft()}
}
document.addEventListener('change',e=>{if(e.target?.id==='advTlsMode')updateRealityVisibility();if(e.target?.id==='cProto')loadAdvancedCapabilities(e.target.value)});

async function doChangePw(){
  const user=document.getElementById('newUser').value.trim(),cur=document.getElementById('pwCur').value,nw=document.getElementById('pwNew').value,cf=document.getElementById('pwCf').value;
  if(nw!==cf){toast(lang==='fa'?'رمزها یکی نیستند':'Passwords mismatch');return}
  const r=await api('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_username:user,current_password:cur,new_password:nw,repeat_password:cf})});
  if(r){toast(lang==='fa'?'اطلاعات ورود تغییر کرد':'Credentials changed');document.getElementById('pwCur').value='';document.getElementById('pwNew').value='';document.getElementById('pwCf').value='';}
}
async function loadLogs(){
  const box=document.getElementById('logsBox');
  const data=await api('/api/activity');
  const logs=Array.isArray(data)?data:(data&&data.logs)||[];
  if(!logs.length){box.innerHTML=`<div style="text-align:center;color:var(--t3);padding:24px">${lang==='fa'?'لاگی نیست':'No logs'}</div>`;return}
  box.innerHTML=logs.slice().reverse().map(l=>{
    const tm=(l.time||l.ts||'').toString().slice(11,19)||'—';
    return `<div class="log-item"><div class="log-time">${esc(tm)}</div><div class="log-msg">${esc(l.message||l.msg||JSON.stringify(l))}</div></div>`;
  }).join('');
}
function statsHoursFromMap(map){
  const out=[];for(let h=0;h<24;h++){const key=String(h).padStart(2,'0')+':00';out.push({label:key,value:Number(map?.[key]||0)})}return out;
}
function makeSmoothPath(vals,w=900,h=250,pad=32){
  const max=Math.max(1,...vals);const step=(w-pad*2)/Math.max(1,vals.length-1);return vals.map((v,i)=>{const x=pad+i*step,y=h-pad-(v/max)*(h-pad*2);return [x,y]}).map((p,i)=>{if(i===0)return `M ${p[0].toFixed(1)} ${p[1].toFixed(1)}`;const a=arguments;return ` L ${p[0].toFixed(1)} ${p[1].toFixed(1)}`}).join('');
}
function drawTrafficChart(downloadMap,uploadMap){
  const svg=document.getElementById('trafficChart');if(!svg)return;
  const d=statsHoursFromMap(downloadMap),u=statsHoursFromMap(uploadMap),dv=d.map(x=>x.value),uv=u.map(x=>x.value),all=[...dv,...uv],max=Math.max(1,...all);
  const W=900,H=310,P=42, chartH=220, step=(W-P*2)/23;
  const pts=(vals)=>vals.map((v,i)=>[P+i*step,H-P-(v/max)*chartH]);
  const dp=pts(dv),up=pts(uv),line=(ps)=>ps.map((p,i)=>`${i?'L':'M'} ${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ');
  const area=(ps)=>`${line(ps)} L ${ps[ps.length-1][0].toFixed(1)} ${H-P} L ${ps[0][0].toFixed(1)} ${H-P} Z`;
  let grid='';for(let i=0;i<5;i++){const y=P+i*(chartH/4),v=max*(1-i/4);grid+=`<line class="traffic-grid" x1="${P}" y1="${y}" x2="${W-P}" y2="${y}"/><text class="traffic-axis" x="${P-8}" y="${y+4}" text-anchor="end">${fmtB(v)}</text>`}
  let labels='';for(let i=0;i<24;i+=4){const x=P+i*step;labels+=`<text class="traffic-axis" x="${x}" y="${H-8}" text-anchor="middle">${String(i).padStart(2,'0')}:00</text>`}
  svg.innerHTML=`<defs><linearGradient id="areaD" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#18aaff" stop-opacity=".24"/><stop offset="1" stop-color="#18aaff" stop-opacity="0"/></linearGradient><linearGradient id="areaU" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff2695" stop-opacity=".20"/><stop offset="1" stop-color="#ff2695" stop-opacity="0"/></linearGradient></defs>${grid}${labels}<path class="traffic-area-d" d="${area(dp)}"/><path class="traffic-area-u" d="${area(up)}"/><path class="traffic-line-d" d="${line(dp)}"/><path class="traffic-line-u" d="${line(up)}"/>`;
  const sd=document.getElementById('sparkDownload'),su=document.getElementById('sparkUpload');if(sd)sd.style.setProperty('--spark',dv.join(','));if(su)su.style.setProperty('--spark',uv.join(','));
}
function updateStatsUI(r,links,connections){
  const arr=Array.isArray(links)?links:[];const active=arr.filter(l=>l.active!==false&&!configExpired(l)).length,expired=arr.filter(configExpired).length,used=arr.reduce((n,l)=>n+Number(l.used_bytes||0),0);
  const down=Number(r.download_bytes??r.total_traffic_bytes??0),up=Number(r.upload_bytes||0),conns=Number(r.active_connections||connections||0);
  const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v};
  set('stDownload',fmtB(down));set('stUpload',fmtB(up));set('stConnections',conns);set('stUsers',active);set('stConfigs',arr.length);set('stExpiredText',expired+' منقضی');set('stServer', 'آنلاین');set('stServerHost',location.host||'ONEX');set('stHost',location.host||'—');set('stActiveConfigs',active);set('stConn2',conns);set('stErrors',Number(r.total_errors||0));set('stRequests',Number(r.total_requests||0).toLocaleString('fa-IR')+' درخواست');set('stUptime',r.uptime||'—');set('sumConfigs',arr.length);set('sumActive',active);set('sumTraffic',fmtB(used));set('sumUpload',fmtB(up));set('sumRequests',Number(r.total_requests||0).toLocaleString('fa-IR'));set('sumGroups',Number(r.subs_count||0));
  const ring=document.getElementById('uptimeRing');if(ring)ring.style.background='conic-gradient(#18e6ae 0 99.9%,rgba(55,82,117,.24) 99.9%)';
  const rangeText={day:'امروز',week:'این هفته',month:'این ماه',all:'کل'}[statRange]||'امروز';set('statsChartRange',rangeText);drawTrafficChart(r.hourly||{},r.hourly_upload||{});
}
async function loadStatsDashboard(showToast=false){
  const r=await api('/stats');if(!r)return;const linksR=await api('/api/links');const links=Array.isArray(linksR?.links)?linksR.links:(Array.isArray(linksR)?linksR:[]);let conn=0;try{const c=await api('/api/connections');conn=Number(c?.count||c?.connections?.length||0)}catch(e){}updateStatsUI(r,links,conn);if(showToast)toast(lang==='fa'?'آمار بروزرسانی شد':'Statistics refreshed');
}

function setRange(r,el){
  statRange=r;
  document.querySelectorAll('#rangeTabs .range-tab').forEach(t=>t.classList.toggle('on',t.dataset.r===r));
  loadStatsDashboard(false);
  toast(t('r_'+r));
}
function randomName(){
  const chars='abcdefghijklmnopqrstuvwxyz0123456789';
  let s='';
  for(let i=0;i<10;i++) s+=chars[Math.floor(Math.random()*chars.length)];
  if(/^[0-9]/.test(s)) s='a'+s.slice(1);
  document.getElementById('cName').value=s;
}
let __updateInfo=null;
let __updateCheckBusy=false;
let __updatePollTimer=null;
function updateText(fa,en){return lang==='fa'?fa:en}
function toggleNotifications(force){const panel=document.getElementById('topNotifyPanel'),btn=document.getElementById('topNotifyBtn');if(!panel||!btn)return;const open=typeof force==='boolean'?force:panel.hidden;panel.hidden=!open;btn.setAttribute('aria-expanded',open?'true':'false')}
function renderNotifications(){const list=document.getElementById('notifyList'),badge=document.getElementById('notifyBadge');if(!list||!badge)return;if(!__updateInfo||!__updateInfo.update_available){badge.textContent='0';badge.classList.remove('show');list.innerHTML=`<div class="notify-empty">${updateText('اعلان جدیدی وجود ندارد.','No new notifications.')}</div>`;return;}badge.textContent='1';badge.classList.add('show');const r=__updateInfo;const changes=Array.isArray(r.changelog)&&r.changelog.length?`<div class="notify-item-text" style="margin-top:5px">${r.changelog.slice(0,4).map(x=>`• ${esc(String(x))}`).join('<br>')}</div>`:'';list.innerHTML=`<div class="notify-item"><div class="notify-item-title">🔄 ${esc(r.title||updateText('بروزرسانی جدید پنل','New panel update'))}</div><div class="notify-item-text">${esc(r.message||updateText('نسخه جدید پنل منتشر شده است.','A new panel version is available.'))}</div>${changes}<div class="notify-item-meta">${updateText('نسخه فعلی','Current version')}: ${esc(r.current_version||'—')} → ${esc(r.latest_version||'—')}</div><button type="button" class="notify-update-btn" onclick="toggleNotifications(false);panelUpdate()">${updateText('مشاهده و بروزرسانی','View update')}</button></div>`}
async function checkPanelUpdateWithNotify(showToast=false){if(__updateCheckBusy)return __updateInfo;__updateCheckBusy=true;try{const r=await api('/api/update/check');if(r&&r.ok){const old=__updateInfo&&__updateInfo.latest_version;__updateInfo=r;setVersionLabels(r.current_version||'1.0.1',r.latest_version||r.current_version);renderNotifications();if(r.update_available&&showToast&&old!==r.latest_version)toast(updateText(`نسخه جدید ${r.latest_version} آماده است`,`Version ${r.latest_version} is available`));}return r}catch(e){return null}finally{__updateCheckBusy=false}}
function startUpdateNotificationPolling(){if(__updatePollTimer)clearInterval(__updatePollTimer);checkPanelUpdateWithNotify(false);__updatePollTimer=setInterval(()=>checkPanelUpdateWithNotify(false),45000)}
async function checkPanelUpdate(showToast=true){
  if(__updateCheckBusy)return __updateInfo;
  __updateCheckBusy=true;
  try{
    const r=await api('/api/update/check');
    if(r&&r.ok){
      const previousVersion=__updateInfo&&__updateInfo.latest_version;__updateInfo=r;setVersionLabels(r.current_version||'1.0.1',r.latest_version||r.current_version);renderNotifications();
      if(r.update_available&&showToast&&previousVersion!==r.latest_version){toast(updateText(`نسخه جدید ${r.latest_version} آماده است`, `Version ${r.latest_version} is available`));}
    }
    return r;
  }catch(e){return null}
  finally{__updateCheckBusy=false}
}
async function panelUpdate(){
  const m=document.getElementById('panelModal');
  const t=document.getElementById('panelModalTitle');
  const b=document.getElementById('panelModalBody');
  t.textContent=updateText('در حال بررسی نسخه جدید...','Checking for updates...');
  b.innerHTML='<div style="text-align:center;padding:20px"><div class="spin"></div></div>';
  m.classList.add('open');
  const r=await checkPanelUpdate(false);
  if(!r||!r.ok){
    t.textContent=updateText('بررسی بروزرسانی','Update check');
    b.innerHTML=`<p>${updateText('در حال حاضر امکان بررسی نسخه جدید وجود ندارد.','The update server could not be reached right now.')}</p>`;
    return;
  }
  if(!r.update_available){
    t.textContent=updateText('پنل به‌روز است','Panel is up to date');
    b.innerHTML=`<div style="text-align:center;padding:18px"><div style="font-size:34px;margin-bottom:8px">✓</div><p style="margin-bottom:6px">${updateText('نسخه فعلی پنل: ','Current panel version: ')}<strong>${esc(r.current_version)}</strong></p><p style="color:var(--t3)">${updateText('نسخه جدیدی منتشر نشده است.','No newer version has been released.')}</p></div>`;
    return;
  }
  t.textContent=updateText('بروزرسانی پنل','Panel update');
  const changes=Array.isArray(r.changelog)&&r.changelog.length?`<div style="margin:12px 0;text-align:right"><strong>${updateText('تغییرات نسخه جدید:','What’s new:')}</strong><ul style="margin:8px 0;padding-right:20px">${r.changelog.slice(0,8).map(x=>`<li>${esc(String(x))}</li>`).join('')}</ul></div>`:'';
  b.innerHTML=`<div style="padding:4px 0"><p style="margin-bottom:8px"><strong>${esc(r.title||('ONEX '+r.latest_version))}</strong></p><p style="margin-bottom:8px">${esc(r.message||updateText('نسخه جدید پنل آماده است.','A new panel version is available.'))}</p>${changes}<p style="color:var(--t3);font-size:12px">${updateText('نسخه فعلی: ','Current: ')}${esc(r.current_version)} &nbsp;→&nbsp; ${updateText('نسخه جدید: ','New: ')}${esc(r.latest_version)}</p><button type="button" class="btn btn-primary" id="panelDoUpdate" style="width:100%;margin-top:14px">${updateText('شروع بروزرسانی پنل','Update panel now')}</button></div>`;
  document.getElementById('panelDoUpdate').onclick=deployPanelUpdate;
}
async function deployPanelUpdate(){
  const btn=document.getElementById('panelDoUpdate');
  if(btn){btn.disabled=true;btn.textContent=updateText('در حال شروع بروزرسانی...','Starting update...')}
  const r=await api('/api/update/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  if(r&&r.ok&&r.update_started){
    const b=document.getElementById('panelModalBody');
    if(b)b.innerHTML=`<div style="text-align:center;padding:18px"><div class="spin" style="margin:0 auto 14px"></div><p>${updateText('بروزرسانی شروع شد. پنل پس از استقرار نسخه جدید دوباره در دسترس قرار می‌گیرد.','The update has started. The panel will become available again after the new deployment is live.')}</p><p style="color:var(--t3);font-size:12px;margin-top:8px">${esc(r.latest_version||'')}</p></div>`;
    setTimeout(()=>{location.reload()},12000);
    return;
  }
  if(btn){btn.disabled=false;btn.textContent=updateText('شروع بروزرسانی پنل','Update panel now')}
  toast((r&&r.detail)||updateText('شروع بروزرسانی ناموفق بود','Could not start the update'));
}
async function saveTelegram(){
  const token=document.getElementById('tgToken').value.trim();
  const admin=document.getElementById('tgAdmin').value.trim();
  const webhook=document.getElementById('tgWebhook').checked;
  if(!token||!admin){toast(lang==='fa'?'توکن و آیدی لازم است':'Token and admin ID required');return}
  toast(lang==='fa'?'در حال فعال‌سازی...':'Activating...');
  const r=await api('/api/telegram/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,admin_ids:admin,webhook})});
  if(r){
    document.getElementById('tgStatus').textContent=r.message||(lang==='fa'?'فعال شد':'Enabled');
    toast(r.message||'OK');
  }
}
async function loadTelegram(){
  const r=await api('/api/telegram/settings');
  if(!r)return;
  if(r.admin_ids) document.getElementById('tgAdmin').value=r.admin_ids;
  document.getElementById('tgWebhook').checked=r.webhook!==false;
  document.getElementById('tgStatus').textContent=r.has_token?(lang==='fa'?'توکن ذخیره شده: ':'Token saved: ')+(r.token_masked||''):'';
}
const _goPage=goPage;
goPage=function(name){
  _goPage(name);
  if(name==='telegram') loadTelegram();
  if(name==='news') loadNews();
  if(name==='admins') loadAdmins();
  if(name==='groups') loadGroups();
  if(name==='settings') loadSecurity();
};

const PERM_LABELS={
  fa:{dash:'داشبورد',configs:'کانفیگ‌ها',create:'ساخت',stats:'آمار',logs:'لاگ',settings:'تنظیمات',support:'پشتیبانی',telegram:'ربات',news:'اخبار',admins:'ادمین‌ها'},
  en:{dash:'Dashboard',configs:'Configs',create:'Create',stats:'Stats',logs:'Logs',settings:'Settings',support:'Support',telegram:'Bot',news:'News',admins:'Admins'}
};
let USER_PERMS=null;
let USER_ROLE='owner';
function buildPermChecks(containerId, selected){
  const box=document.getElementById(containerId);
  if(!box)return;
  const labels=PERM_LABELS[lang]||PERM_LABELS.fa;
  box.innerHTML=Object.keys(labels).map(k=>{
    const on=selected?!!selected[k]:(['dash','configs','create','stats','news'].includes(k));
    return `<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;border-radius:12px;background:var(--bg3);border:1px solid var(--card-b)">
      <span style="font-size:12px;font-weight:600">${labels[k]}</span>
      <label class="switch"><input type="checkbox" data-perm="${k}" ${on?'checked':''}><span class="slider"></span></label>
    </div>`;
  }).join('');
}
function readPermChecks(containerId){
  const out={};
  document.querySelectorAll('#'+containerId+' input[data-perm]').forEach(inp=>{out[inp.getAttribute('data-perm')]=inp.checked});
  return out;
}
async function loadMe(){
  const r=await api('/api/me');
  if(!r)return;
  USER_ROLE=r.role||'owner';
  USER_PERMS=r.permissions||{};
  const ownerUser=document.getElementById('newUser');
  if(ownerUser && USER_ROLE==='owner' && r.username) ownerUser.value=r.username;
  document.querySelectorAll('.nav-item[data-perm]').forEach(el=>{
    const p=el.getAttribute('data-perm');
    if(USER_ROLE==='owner'){el.style.display='';return}
    el.style.display=USER_PERMS[p]?'':'none';
  });
  // hide admins for non-owner always if no perm
  document.querySelectorAll('.nav-item[data-page="admins"]').forEach(el=>{
    if(USER_ROLE!=='owner') el.style.display='none';
  });
}
async function loadNews(toastOk){
  try{
    const r=await api('/api/news');
    const meta=document.getElementById('newsMeta');
    if(meta && r) meta.textContent=(lang==='fa'?'آخرین بروزرسانی: ':'Last update: ')+(r.updated_at||'—');
    if(toastOk) toast(lang==='fa'?'اطلاعات تلگرام بروزرسانی شد':'Telegram info refreshed');
  }catch(e){
    if(toastOk) toast(lang==='fa'?'خطا در بروزرسانی':'Refresh failed');
  }
}
let ADMIN_ITEMS=[];
let SELECTED_ADMIN_ID='';
const ADMIN_PERM_GROUPS={
  fa:[
    ['پنل و محتوا',['dash','configs','create','stats','logs']],
    ['سیستم و پشتیبانی',['settings','support','telegram','news']],
    ['مدیریت',['admins']]
  ],
  en:[
    ['Panel & Content',['dash','configs','create','stats','logs']],
    ['System & Support',['settings','support','telegram','news']],
    ['Management',['admins']]
  ]
};
const ADMIN_ROLE_PRESETS={
  super:['dash','configs','create','stats','logs','settings','support','telegram','news','admins'],
  admin:['dash','configs','create','stats','logs','news'],
  operator:['dash','configs','create'],
};
function adminRole(a){
  const p=a&&a.permissions||{};
  const keys=Object.keys(p).filter(k=>p[k]);
  const all=ADMIN_ROLE_PRESETS.super.every(k=>p[k]);
  const adm=ADMIN_ROLE_PRESETS.admin.every(k=>p[k]) && keys.length===ADMIN_ROLE_PRESETS.admin.length;
  const op=ADMIN_ROLE_PRESETS.operator.every(k=>p[k]) && keys.length===ADMIN_ROLE_PRESETS.operator.length;
  if(all)return 'Super Admin'; if(adm)return 'Admin'; if(op)return 'Operator'; return 'Custom';
}
function adminLastLogin(username){
  const needle=String(username||'').toLowerCase();
  const logs=window.__activityLogs||[];
  for(const l of logs.slice().reverse()){
    const m=String(l.message||'').toLowerCase();
    if(needle && m.includes(needle) && (m.includes('ورود موفق')||m.includes('login'))) return (l.time||'').slice(0,19).replace('T',' ');
  }
  return '—';
}
async function loadAdminActivityCache(){
  const r=await api('/api/activity');
  window.__activityLogs=Array.isArray(r)?r:(r&&r.logs)||[];
}
function renderAdminList(){
  const box=document.getElementById('adminsList');
  if(!box)return;
  const q=(document.getElementById('adminSearch')?.value||'').trim().toLowerCase();
  const f=document.getElementById('adminStatusFilter')?.value||'all';
  const arr=ADMIN_ITEMS.filter(a=>{
    const hay=((a.username||'')+' '+(a.label||'')).toLowerCase();
    if(q&&!hay.includes(q))return false;
    if(f==='active' && (a.blocked||!a.valid))return false;
    if(f==='blocked' && !a.blocked)return false;
    if(f==='invalid' && (a.blocked||a.valid))return false;
    return true;
  });
  const count=document.getElementById('adminsCountText');
  if(count)count.textContent=`${arr.length} مورد نمایش داده می‌شود · ${ADMIN_ITEMS.length} ادمین`;
  if(!arr.length){box.innerHTML='<div class="admin-empty">ادمینی با این فیلتر پیدا نشد.</div>';return}
  box.innerHTML=arr.map(a=>{
    const status=a.blocked?['blocked','مسدود']:a.valid?['active','فعال']:['invalid','نامعتبر'];
    const role=adminRole(a);
    const initial=String(a.username||'?').slice(0,1).toUpperCase();
    const last=adminLastLogin(a.username);
    return `<div class="admin-row ${SELECTED_ADMIN_ID===a.id?'selected':''}" onclick="selectAdmin('${esc(a.id)}')">
      <div class="admin-user"><div class="admin-avatar">${esc(initial)}</div><div class="admin-user-text"><div class="admin-user-name">${esc(a.username)}</div><div class="admin-user-label">${esc(a.label||'—')}</div></div></div>
      <div><span class="admin-role">${esc(role)}</span></div>
      <div><span class="admin-badge ${status[0]}"><i style="width:6px;height:6px;border-radius:50%;background:currentColor;display:inline-block"></i>${status[1]}</span></div>
      <div style="font-size:9px;color:var(--t3)">${esc(last)}</div>
      <div class="admin-ops" onclick="event.stopPropagation()">
        <button class="admin-op edit" title="ویرایش / جزئیات" onclick="selectAdmin('${esc(a.id)}');focusAdminDetails()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"/></svg></button>
        <button class="admin-op ${a.blocked?'unblock':'block'}" title="${a.blocked?'رفع مسدودی':'مسدود کردن'}" onclick="toggleBlockAdmin('${esc(a.id)}',${!a.blocked})"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/>${a.blocked?'<path d="M8 12h8"/>':'<path d="M8 8l8 8M16 8l-8 8"/>'}</svg></button>
        <button class="admin-op delete" title="حذف" onclick="deleteAdmin('${esc(a.id)}')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 14h10l1-14M9 7V4h6v3"/></svg></button>
      </div>
    </div>`;
  }).join('');
}
function renderAdminSelectors(){
  const sel=document.getElementById('adminPermSelect');
  if(!sel)return;
  sel.innerHTML='<option value="">انتخاب ادمین</option>'+ADMIN_ITEMS.map(a=>`<option value="${esc(a.id)}" ${a.id===SELECTED_ADMIN_ID?'selected':''}>${esc(a.username)} — ${esc(adminRole(a))}</option>`).join('');
}
function buildAdminPermEditor(a){
  const box=document.getElementById('adminPerms'),empty=document.getElementById('adminPermEmpty');
  const save=document.getElementById('saveAdminPermsBtn'),all=document.getElementById('adminAllBtn'),none=document.getElementById('adminNoneBtn');
  if(!a){if(box)box.innerHTML='';if(empty)empty.style.display='block';[save,all,none].forEach(x=>{if(x)x.disabled=true});return}
  if(empty)empty.style.display='none';[save,all,none].forEach(x=>{if(x)x.disabled=false});
  const groups=ADMIN_PERM_GROUPS[lang]||ADMIN_PERM_GROUPS.fa, perms=a.permissions||{};
  box.innerHTML=groups.map(([title,keys])=>`<div class="admin-perm-group"><h4>${title}</h4>${keys.map(k=>`<div class="admin-perm-item"><span>${(PERM_LABELS[lang]||PERM_LABELS.fa)[k]||k}</span><label class="switch"><input type="checkbox" data-admin-perm="${k}" ${perms[k]?'checked':''}><span class="slider"></span></label></div>`).join('')}</div>`).join('');
}
function selectAdmin(id){
  SELECTED_ADMIN_ID=id||'';
  const a=ADMIN_ITEMS.find(x=>x.id===SELECTED_ADMIN_ID)||null;
  renderAdminList();renderAdminSelectors();buildAdminPermEditor(a);renderAdminDetails(a);renderAdminActivity(a);
}
function setAllAdminPerms(on){document.querySelectorAll('#adminPerms input[data-admin-perm]').forEach(x=>x.checked=!!on)}
function readAdminPerms(){const out={};document.querySelectorAll('#adminPerms input[data-admin-perm]').forEach(x=>out[x.getAttribute('data-admin-perm')]=x.checked);return out}
async function saveAdminPermissions(){
  if(!SELECTED_ADMIN_ID)return;
  const r=await api('/api/admins/'+SELECTED_ADMIN_ID,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({permissions:readAdminPerms()})});
  if(r){toast('دسترسی‌ها ذخیره شد');await loadAdmins()}
}
function renderAdminDetails(a){
  const box=document.getElementById('adminDetails');if(!box)return;
  if(!a){box.innerHTML='<div class="admin-empty">برای مشاهده جزئیات، یک ادمین را انتخاب کنید.</div>';return}
  const exp=a.expires_at?String(a.expires_at).slice(0,19).replace('T',' '):'بدون انقضا';
  const perms=Object.entries(a.permissions||{}).filter(([,v])=>v).map(([k])=>(PERM_LABELS[lang]||PERM_LABELS.fa)[k]||k);
  box.innerHTML=`<div class="admin-details-grid">
    <div class="admin-detail-box"><span>نام کاربری</span><b>${esc(a.username)}</b></div><div class="admin-detail-box"><span>نقش</span><b>${esc(adminRole(a))}</b></div>
    <div class="admin-detail-box"><span>وضعیت</span><b>${a.blocked?'🔴 مسدود':a.valid?'🟢 فعال':'🟠 نامعتبر'}</b></div><div class="admin-detail-box"><span>آخرین ورود</span><b>${esc(adminLastLogin(a.username))}</b></div>
    <div class="admin-detail-box"><span>حجم مصرف</span><b>${fmtB(a.used_bytes)}${a.limit_bytes?' / '+fmtB(a.limit_bytes):' / ∞'}</b></div><div class="admin-detail-box"><span>انقضا</span><b>${esc(exp)}</b></div>
    <div class="admin-detail-box"><span>تاریخ ایجاد</span><b>${esc(String(a.created_at||'—').slice(0,19).replace('T',' '))}</b></div><div class="admin-detail-box"><span>عنوان</span><b>${esc(a.label||'—')}</b></div>
  </div><div class="admin-detail-perms">${perms.length?perms.map(x=>`<span class="admin-detail-perm">${esc(x)}</span>`).join(''):'<span style="font-size:9px;color:var(--t3)">بدون دسترسی فعال</span>'}</div>`;
}
function renderAdminActivity(a){
  const box=document.getElementById('adminActivity'),sub=document.getElementById('adminActivitySub');if(!box)return;
  if(!a){box.innerHTML='<div class="admin-empty">برای مشاهده فعالیت، یک ادمین را انتخاب کنید.</div>';if(sub)sub.textContent='فعالیت‌های ثبت‌شده برای ادمین انتخاب‌شده';return}
  const needle=String(a.username||'').toLowerCase();
  const logs=(window.__activityLogs||[]).filter(l=>String(l.message||'').toLowerCase().includes(needle));
  if(sub)sub.textContent=`فعالیت‌های ثبت‌شده برای ${a.username}`;
  if(!logs.length){box.innerHTML='<div class="admin-empty">هنوز فعالیتی برای این ادمین ثبت نشده است.</div>';return}
  box.innerHTML=logs.slice().reverse().map(l=>`<div class="admin-activity-item"><div class="admin-activity-time">${esc(String(l.time||'').slice(11,19)||'—')}</div><div class="admin-activity-msg">${esc(l.message||'—')}</div></div>`).join('');
}
function focusAdminDetails(){document.getElementById('adminDetails')?.scrollIntoView({behavior:'smooth',block:'center'})}
function focusAdminCreate(){document.getElementById('adminCreateCard')?.scrollIntoView({behavior:'smooth',block:'center'});setTimeout(()=>document.getElementById('adUser')?.focus(),250)}
async function loadAdmins(){
  const box=document.getElementById('adminsList');if(box)box.innerHTML='<div class="admin-empty">در حال دریافت...</div>';
  const r=await api('/api/admins');
  if(!r||!Array.isArray(r.admins)){if(box)box.innerHTML='<div class="admin-empty">دریافت لیست ادمین‌ها ناموفق بود.</div>';return}
  ADMIN_ITEMS=r.admins;
  await loadAdminActivityCache();
  if(!SELECTED_ADMIN_ID || !ADMIN_ITEMS.some(a=>a.id===SELECTED_ADMIN_ID)) SELECTED_ADMIN_ID=ADMIN_ITEMS[0]?.id||'';
  renderAdminList();renderAdminSelectors();
  const a=ADMIN_ITEMS.find(x=>x.id===SELECTED_ADMIN_ID)||null;
  buildAdminPermEditor(a);renderAdminDetails(a);renderAdminActivity(a);
}
async function createAdmin(){
  const user=document.getElementById('adUser').value.trim(),pw=document.getElementById('adPw').value,pw2=document.getElementById('adPw2').value;
  if(!user||!pw||!pw2){toast('نام کاربری و هر دو رمز را وارد کنید');return}
  if(pw!==pw2){toast('تکرار رمز یکسان نیست');return}
  const role=document.getElementById('adRole')?.value||'admin';const permissions={};(ADMIN_ROLE_PRESETS[role]||ADMIN_ROLE_PRESETS.admin).forEach(k=>permissions[k]=true);const body={username:user,label:document.getElementById('adLabel').value.trim()||user,password:pw,repeat_password:pw2,limit_value:Number(document.getElementById('adLimit').value)||0,limit_unit:document.getElementById('adUnit').value,expires_days:Number(document.getElementById('adDays').value)||0,permissions,active:!!document.getElementById('adActive')?.checked};
  const r=await api('/api/admins',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){toast('اکانت ادمین ساخته شد');['adUser','adLabel','adPw','adPw2'].forEach(id=>{const e=document.getElementById(id);if(e)e.value=''});document.getElementById('adLimit').value='0';document.getElementById('adDays').value='0';document.getElementById('adActive').checked=true;await loadAdmins();selectAdmin(r.id)}
}
async function toggleBlockAdmin(id,blocked){
  const r=await api('/api/admins/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({blocked})});
  if(r){toast(blocked?'ادمین مسدود شد':'مسدودی ادمین برداشته شد');await loadAdmins()}
}
async function deleteAdmin(id){
  const a=ADMIN_ITEMS.find(x=>x.id===id);if(!confirm(`اکانت «${a?.username||'ادمین'}» حذف شود؟`))return;
  const r=await api('/api/admins/'+id,{method:'DELETE'});
  if(r){if(SELECTED_ADMIN_ID===id)SELECTED_ADMIN_ID='';toast('اکانت حذف شد');await loadAdmins()}
}


async function loadProtocols(){
  window.__protocolList=window.__protocolList||[];
  const r=await api('/api/protocols');
  const list=(r&&r.protocols)||[]; window.__protocolList=list;
  const def=(r&&r.default)||'vless-ws';
  __protocolPickerOptions=list;
  ['cProto','aProto'].forEach(id=>{
    const el=document.getElementById(id);
    if(!el)return;
    el.innerHTML=list.map(p=>`<option value="${esc(p.id)}" ${p.id===def?'selected':''}>${esc(p.label||p.id)}</option>`).join('')
      ||'<option value="vless-ws">ONEX WB</option>';
  });
  setupProtocolPickers();
}
let __allLinks=[];
let cfgStatusFilter='all',cfgSortMode='newest';
function toggleConfigFilters(){document.getElementById('cfgFilterRow')?.classList.toggle('open')}
function setCfgStatus(v,el){cfgStatusFilter=v;document.querySelectorAll('#cfgFilterRow [data-status]').forEach(x=>x.classList.toggle('on',x===el));renderConfigCards(getFilteredConfigs())}
function setCfgSort(v,el){cfgSortMode=v;document.querySelectorAll('#cfgFilterRow [data-sort]').forEach(x=>x.classList.toggle('on',x===el));renderConfigCards(getFilteredConfigs())}
function configExpired(l){return !!l.expired||(l.expires_at&&new Date(l.expires_at).getTime()<=Date.now())||(Number(l.limit_bytes)>0&&Number(l.used_bytes||0)>=Number(l.limit_bytes))}
function getFilteredConfigs(){const q=(document.getElementById('cfgSearch')?.value||'').trim().toLowerCase();let a=__allLinks.filter(l=>{const dead=configExpired(l),active=l.active!==false&&!dead;if(cfgStatusFilter==='active'&&!active)return false;if(cfgStatusFilter==='expired'&&!dead)return false;if(!q)return true;return [l.label,l.name,l.protocol,l.protocol_label,l.uuid,l.id,l.sub,l.sub_url,l.vless,l.vless_full].map(x=>String(x||'').toLowerCase()).some(x=>x.includes(q))});a.sort((x,y)=>cfgSortMode==='name'?String(x.label||x.name||'').localeCompare(String(y.label||y.name||'')):cfgSortMode==='usage'?Number(y.used_bytes||0)-Number(x.used_bytes||0):String(y.created_at||'').localeCompare(String(x.created_at||'')));return a}
function filterConfigs(){renderConfigCards(getFilteredConfigs())}
function protocolUi(id){const m={'vless-ws':['ONEX WB','/api/protocol-icon/vless-ws.png'],'xhttp-packet-up':['ONEX Xhttp','/api/protocol-icon/xhttp-packet-up.png'],'xhttp-stream-up':['ONEX GAMING','/api/protocol-icon/xhttp-stream-up.png'],'xhttp-stream-one':['ONEX Stream','/api/protocol-icon/xhttp-stream-one.png']};return m[id]||[String(id||'').toUpperCase(),'/api/protocol-icon/vless-ws.png']}
function cfgDate(v){if(!v)return 'بدون انقضا';try{return new Date(v).toLocaleDateString('fa-IR',{year:'numeric',month:'2-digit',day:'2-digit'})}catch(e){return String(v).slice(0,10)}}
function updateConfigStats(){const total=__allLinks.length,expired=__allLinks.filter(configExpired).length,active=__allLinks.filter(l=>l.active!==false&&!configExpired(l)).length,used=__allLinks.reduce((n,l)=>n+Number(l.used_bytes||0),0),set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v};set('cfgStatTotal',total);set('cfgStatUsed',fmtB(used));set('cfgStatActive',active);set('cfgStatExpired',expired);set('cfgVisibleCount',`${getFilteredConfigs().length} مورد`)}
let __openConfigMenuUid='';
function closeConfigMenus(){__openConfigMenuUid='';document.querySelectorAll('.cfg-menu.open').forEach(m=>m.classList.remove('open'));document.querySelectorAll('.cfg-menu[data-portal="1"]').forEach(m=>{const hostId=m.dataset.hostId;const host=hostId?document.getElementById(hostId):null;if(host&&m.parentElement===document.body)host.appendChild(m);m.style.left='';m.style.top='';m.style.right='';m.style.bottom='';m.style.display='';m.dataset.portal='';delete m.dataset.hostId})}
function positionConfigMenu(menu,btn){if(!menu||!btn)return;const r=btn.getBoundingClientRect();const gap=8;const width=Math.min(236,window.innerWidth-16);menu.style.width=width+'px';menu.style.right='auto';menu.style.left=Math.max(8,Math.min(window.innerWidth-width-8,r.right-width))+'px';menu.style.top='0px';menu.style.display='block';const mh=menu.offsetHeight||220;let top=r.bottom+gap;if(top+mh>window.innerHeight-8)top=r.top-mh-gap;if(top<8)top=8;menu.style.top=top+'px'}
function toggleConfigMenu(e,uid){e.preventDefault();e.stopPropagation();const id='cfgMenu_'+uid.replace(/[^a-zA-Z0-9_-]/g,'_'),m=document.getElementById(id);if(!m)return;const was=(__openConfigMenuUid===uid&&m.classList.contains('open'));if(was){closeConfigMenus();return}closeConfigMenus();const btn=e.currentTarget||e.target.closest('.cfg-menu-btn');m.dataset.hostId=id.replace('cfgMenu_','cfgHost_');const host=document.createElement('span');host.id=m.dataset.hostId;host.hidden=true;m.parentElement.insertBefore(host,m);document.body.appendChild(m);m.dataset.portal='1';m.classList.add('open');__openConfigMenuUid=uid;positionConfigMenu(m,btn)}
function configMenuAction(a,uid){closeConfigMenus();if(a==='copy')return copyLinkById(uid);if(a==='sub')return copySubById(uid);if(a==='info'){window.open('/info/'+encodeURIComponent(uid),'_blank','noopener');return}if(a==='reset')return resetUsage(uid);if(a==='delete')return deleteLink(uid)}
document.addEventListener('click',e=>{if(!e.target.closest('.cfg-menu')&&!e.target.closest('.cfg-menu-btn'))closeConfigMenus()});
window.addEventListener('resize',()=>{const m=document.querySelector('.cfg-menu.open[data-portal="1"]');if(!m)return;const uid=(m.id||'').replace(/^cfgMenu_/,'');const btn=document.querySelector('.cfg-menu-btn[data-menu-uid="'+CSS.escape(uid)+'"]');if(btn)positionConfigMenu(m,btn)});
window.addEventListener('scroll',()=>{const m=document.querySelector('.cfg-menu.open[data-portal="1"]');if(!m)return;const uid=(m.id||'').replace(/^cfgMenu_/,'');const btn=document.querySelector('.cfg-menu-btn[data-menu-uid="'+CSS.escape(uid)+'"]');if(btn)positionConfigMenu(m,btn)},true);
function renderConfigCards(arr){const box=document.getElementById('cfgCards');if(!box)return;
  const selectedIds=new Set([...document.querySelectorAll('#cfgCards .cfg-chk:checked')].map(c=>String(c.value)));
  const openMenuUid=__openConfigMenuUid||'';
  const oldMenu=openMenuUid?document.getElementById('cfgMenu_'+openMenuUid):null;
  if(oldMenu)oldMenu.remove();
  updateConfigStats();
  if(!arr.length){box.innerHTML='<div class="cfg-empty">'+(lang==='fa'?'کانفیگی با این فیلتر پیدا نشد':'No configs match the filter')+'</div>';updateBulkBar();__openConfigMenuUid='';return}
  box.innerHTML=arr.map(l=>{const uid=String(l.uuid||l.id||''),dead=configExpired(l),active=l.active!==false&&!dead,[pl,icon]=protocolUi(l.protocol),used=Number(l.used_bytes||0),lim=Number(l.limit_bytes||0),pct=lim>0?Math.min(100,Math.round(used/lim*100)):0,conn=Number(l.connected_ips||0),safeUid=esc(uid),mid='cfgMenu_'+uid.replace(/[^a-zA-Z0-9_-]/g,'_'),usage=lim>0?`${fmtB(used)} / ${fmtB(lim)}`:fmtB(used),activeState=l.active!==false;return `<article class="cfg-card ${dead?'expired':''}" draggable="true" data-uid="${safeUid}" ondragstart="cfgDragStart(event)" ondragover="cfgDragOver(event)" ondrop="cfgDrop(event)" ondragend="cfgDragEnd(event)"><label class="cfg-card-check"><input type="checkbox" class="cfg-chk" value="${safeUid}" onchange="updateBulkBar()"></label><div class="cfg-proto-icon"><img src="${icon}" alt=""></div><div class="cfg-main"><div class="cfg-name-row"><b>${esc(l.label||l.name||uid.slice(0,8))}</b><button type="button" class="cfg-edit-dot" title="ویرایش کانفیگ" aria-label="ویرایش کانفیگ" onclick="openConfigEditor(event,'${safeUid}')">✎</button></div><div class="cfg-proto">${esc(pl)}</div><div class="cfg-meta"><span><i>♧</i>${conn} اتصال</span><span><i>◷</i>${dead?'منقضی شده':(l.expires_at?'انقضا '+cfgDate(l.expires_at):'بدون انقضا')}</span></div></div><div class="cfg-side"><div class="cfg-side-top"><span class="cfg-status ${active?'':'bad'}"><i></i>${active?'فعال':'غیرفعال'}</span><button type="button" class="cfg-active-toggle ${activeState?'on':''}" onclick="toggleConfigActive(event,'${safeUid}',${activeState?'false':'true'})" aria-pressed="${activeState?'true':'false'}"><span class="cfg-active-dot"></span><span>${activeState?'فعال':'خاموش'}</span></button></div><div class="cfg-usage"><div class="cfg-usage-ring" style="--pct:${pct}%"><span>${pct}%</span></div><div class="cfg-usage-copy"><b>${esc(usage)}</b>${lim>0?`<div class="cfg-usage-track"><div class="cfg-usage-fill" style="width:${pct}%"></div></div>`:''}</div></div></div><button class="cfg-menu-btn" type="button" data-menu-uid="${safeUid}" onclick="toggleConfigMenu(event,'${safeUid}')" aria-label="عملیات">⋮</button><div class="cfg-menu" id="${mid}"><div class="cfg-menu-head"><span>عملیات کانفیگ</span><small>برای بستن بیرون منو بزنید</small></div><button type="button" onclick="configMenuAction('copy','${safeUid}')">کپی VLESS</button><button type="button" onclick="configMenuAction('sub','${safeUid}')">کپی ساب</button><button type="button" onclick="configMenuAction('info','${safeUid}')">صفحه اطلاعات</button><button type="button" onclick="configMenuAction('reset','${safeUid}')">ریست مصرف</button><button type="button" class="danger" onclick="configMenuAction('delete','${safeUid}')">حذف کانفیگ</button></div></article>`}).join('');
  document.querySelectorAll('#cfgCards .cfg-chk').forEach(c=>{c.checked=selectedIds.has(String(c.value))});
  updateBulkBar();
  if(openMenuUid){const menu=document.getElementById('cfgMenu_'+openMenuUid);const btn=document.querySelector('.cfg-menu-btn[data-menu-uid="'+CSS.escape(openMenuUid)+'"]');if(menu&&btn){document.body.appendChild(menu);menu.dataset.portal='1';menu.classList.add('open');__openConfigMenuUid=openMenuUid;positionConfigMenu(menu,btn)}else{__openConfigMenuUid=''}}
}
function renderLinks(arr){window.__linksMap={};arr.forEach(l=>window.__linksMap[String(l.uuid||l.id||'')]=l);renderConfigCards(getFilteredConfigs())}
function softUpdateLinks(arr){window.__linksMap={};arr.forEach(l=>window.__linksMap[String(l.uuid||l.id||'')]=l);renderConfigCards(getFilteredConfigs())}
function patchLinkRow(tr,l){renderConfigCards(getFilteredConfigs())}
async function resetUsage(uid){
  if(!confirm(lang==='fa'?'مصرف ریست شود؟':'Reset usage?'))return;
  const r=await api('/api/links/'+uid+'/reset-usage',{method:'POST'});
  if(r!==null){toast(lang==='fa'?'مصرف ریست شد':'Usage reset');refreshAll()}
}


let __dragUid=null;
function cfgDragStart(e){__dragUid=e.currentTarget.getAttribute('data-uid');e.currentTarget.style.opacity='.5';e.dataTransfer.effectAllowed='move';}
function cfgDragOver(e){e.preventDefault();e.dataTransfer.dropEffect='move';const card=e.currentTarget;if(card&&card.classList.contains('cfg-card'))card.style.boxShadow='0 0 0 1px rgba(70,168,255,.55),0 12px 28px rgba(37,99,235,.14)';}
function cfgDragEnd(e){e.currentTarget.style.opacity='1';document.querySelectorAll('.cfg-card').forEach(card=>card.style.boxShadow='');__dragUid=null;}
async function cfgDrop(e){e.preventDefault();const target=e.currentTarget.getAttribute('data-uid');document.querySelectorAll('.cfg-card').forEach(card=>card.style.boxShadow='');if(!__dragUid||!target||__dragUid===target)return;const cards=[...document.querySelectorAll('#cfgCards .cfg-card')],ids=cards.map(card=>card.getAttribute('data-uid'));const from=ids.indexOf(__dragUid),to=ids.indexOf(target);if(from<0||to<0)return;ids.splice(from,1);ids.splice(to,0,__dragUid);const box=document.getElementById('cfgCards');ids.forEach(id=>{const el=box.querySelector('.cfg-card[data-uid="'+CSS.escape(id)+'"]');if(el)box.appendChild(el)});await api('/api/links/reorder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order:ids})});toast(lang==='fa'?'ترتیب ذخیره شد':'Order saved');__dragUid=null;}

function updateBulkBar(){
  const n=document.querySelectorAll('.cfg-chk:checked').length;
  const bar=document.getElementById('bottomBulkBar');
  const cnt=document.getElementById('bulkCount');
  if(cnt) cnt.textContent = n + (lang==='fa'?' انتخاب‌شده':' selected');
  if(bar) bar.classList.toggle('show', n>0);
  const all=document.getElementById('chkAll');
  if(all && n===0) all.checked=false;
}
function clearSelection(){
  document.querySelectorAll('.cfg-chk').forEach(c=>c.checked=false);
  const all=document.getElementById('chkAll');
  if(all) all.checked=false;
  updateBulkBar();
}
function toggleSelectAll(on){
  document.querySelectorAll('.cfg-chk').forEach(c=>c.checked=!!on);
  updateBulkBar();
}

function selectedCfgIds(){return [...document.querySelectorAll('.cfg-chk:checked')].map(c=>c.value)}
async function bulkDelete(){
  const ids=selectedCfgIds();
  if(!ids.length){toast(lang==='fa'?'چیزی انتخاب نشده':'Nothing selected');return}
  if(!confirm(lang==='fa'?`حذف ${ids.length} کانفیگ؟`:`Delete ${ids.length}?`))return;
  const r=await api('/api/links/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
  if(r){toast(lang==='fa'?`حذف شد: ${r.deleted}`:`Deleted: ${r.deleted}`);refreshAll()}
}
async function bulkMoveGroup(){
  const ids=selectedCfgIds();
  const cid=document.getElementById('bulkGroup')?.value||'0';
  if(!ids.length){toast(lang==='fa'?'چیزی انتخاب نشده':'Nothing selected');return}
  const r=await api('/api/links/bulk-category',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids,category_id:cid})});
  if(r){toast(lang==='fa'?'به گروه منتقل شد':'Moved');refreshAll()}
}
async function loadCategories(){
  const r=await api('/api/categories');
  const list=(r&&r.categories)||[];
  window.__catMap={};
  list.forEach(g=>{window.__catMap[String(g.id)]=g.name||g.id});
  const bulk=document.getElementById('bulkGroup');
  const cGroup=document.getElementById('cGroup');
  const opts=list.map(g=>`<option value="${esc(g.id)}">${esc(g.name||g.id)}</option>`).join('');
  if(bulk) bulk.innerHTML=opts||'<option value="0">عمومی</option>';
  if(cGroup) cGroup.innerHTML=opts||'<option value="0">عمومی</option>';
}

let __subGroups=[];
let __selectedSubId='';
let __groupFilter='all';
let __groupProtocols=[];

function groupProtocolLabel(id){
  const labels={'vless-ws':'ONEX WB','xhttp-packet-up':'ONEX Xhttp','xhttp-stream-up':'ONEX Gaming','xhttp-stream-one':'ONEX Stream','trojan':'Trojan','shadowsocks':'Shadowsocks','socks5':'SOCKS5','http':'HTTP Proxy','hysteria2':'Hysteria2','vless-grpc-reality':'VLESS gRPC Reality','wireguard':'WireGuard'};
  return labels[id]||id;
}
function groupProtocolIcon(id){
  const map={'vless-ws':'/api/protocol-icon/vless-ws.png','xhttp-packet-up':'/api/protocol-icon/xhttp-packet-up.png','xhttp-stream-up':'/api/protocol-icon/xhttp-stream-up.png','xhttp-stream-one':'/api/protocol-icon/xhttp-stream-one.png'};
  return map[id]||'';
}
function setGroupFilter(f,btn){__groupFilter=f;document.querySelectorAll('.group-filter').forEach(x=>x.classList.toggle('on',x===btn));renderGroupList()}
function selectedSub(){return __subGroups.find(g=>String(g.sub_id)===String(__selectedSubId))||null}
function groupIsActive(g){return g ? g.active !== false : false}
async function loadGroups(){
  const r=await api('/api/subs');
  __subGroups=(r&&r.subs)||[];
  const cSubGroup=document.getElementById('cSubGroup');
  if(cSubGroup){
    const current=cSubGroup.value;
    cSubGroup.innerHTML='<option value="">بدون گروه (عمومی)</option>'+__subGroups.map(g=>`<option value="${esc(g.sub_id)}">${esc(g.name||'گروه')}</option>`).join('');
    if(current && __subGroups.some(g=>String(g.sub_id)===String(current))) cSubGroup.value=current;
  }
  const activeUsers=__subGroups.reduce((n,g)=>n+Number(g.active_count||0),0);
  const total=document.getElementById('groupTotal'); if(total) total.textContent=__subGroups.length;
  const au=document.getElementById('groupActiveUsers'); if(au) au.textContent=activeUsers;
  const af=document.querySelector('.group-filter[data-filter="active"] em'); if(af) af.title=String(__subGroups.filter(groupIsActive).length);
  const inf=document.querySelector('.group-filter[data-filter="inactive"] em'); if(inf) inf.title=String(__subGroups.filter(g=>!groupIsActive(g)).length);
  if(!__selectedSubId || !selectedSub()) __selectedSubId=__subGroups[0]?.sub_id||'';
  renderGroupList();
  if(__selectedSubId) await loadGroupDetail(__selectedSubId);
  else renderGroupDetail(null);
}
function renderGroupList(){
  const box=document.getElementById('groupsList'); if(!box)return;
  const q=(document.getElementById('groupSearch')?.value||'').trim().toLowerCase();
  const list=__subGroups.filter(g=>{const active=groupIsActive(g); if(__groupFilter==='active'&&!active)return false; if(__groupFilter==='inactive'&&active)return false; return !q||String(g.name||'').toLowerCase().includes(q)||String(g.desc||'').toLowerCase().includes(q)});
  if(!list.length){box.innerHTML='<div class="group-empty">گروهی مطابق جستجو پیدا نشد</div>';return}
  box.innerHTML=list.map(g=>{
    const on=groupIsActive(g), selected=String(g.sub_id)===String(__selectedSubId);
    return `<article class="group-card ${selected?'selected':''}" onclick="selectGroup('${esc(g.sub_id)}')">
      <div class="group-card-top"><div class="group-card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="9" cy="9" r="3"/><circle cx="17" cy="10" r="2.5"/><path d="M3.5 20c.5-3.1 2.4-4.7 5.5-4.7s5 1.6 5.5 4.7"/><path d="M14 15.8c2.8-.8 5 .5 6 3.2"/></svg></div><div class="group-card-main"><div class="group-card-title"><b>${esc(g.name||'گروه')}</b><span class="group-status ${on?'':'off'}">${on?'● فعال':'● غیرفعال'}</span></div><div class="group-card-desc">${esc(g.desc||'گروه اشتراک ONEX')}</div></div><div class="group-card-menu">•••</div></div>
      <div class="group-card-meta"><span><strong>${Number(g.active_count||0)}</strong> کاربر فعال</span><span>•</span><span><strong>${Number(g.links_count||0)}</strong> کانفیگ</span><span>•</span><span>${g.has_password?'🔒 رمزدار':'عمومی'}</span></div>
    </article>`;
  }).join('');
}
async function selectGroup(id){__selectedSubId=id;renderGroupList();await loadGroupDetail(id)}
async function loadGroupDetail(id){
  const g=__subGroups.find(x=>String(x.sub_id)===String(id)); if(!g){renderGroupDetail(null);return}
  let links=window.__allLinks;
  if(!Array.isArray(links)||!links.length){const r=await api('/api/links');links=(r&&r.links)||[];window.__allLinks=links}
  if(!Array.isArray(window.__protocolList)||!window.__protocolList.length){try{await loadProtocols()}catch(e){}}
  __groupProtocols=Array.isArray(g.protocols)?g.protocols.slice():((window.__protocolList||[]).map(x=>x.id));
  renderGroupDetail(g,links||[]);
}
function renderGroupDetail(g,links){
  const pane=document.getElementById('groupDetailPane'); if(!pane)return;
  if(!g){pane.innerHTML='<div class="group-detail-empty"><div class="group-detail-empty-icon">◉</div><b>یک گروه را انتخاب کنید</b><span>برای مشاهده لینک اشتراک، پروتکل‌ها و کانفیگ‌های گروه</span></div>';return}
  const protocols=(window.__protocolList&&window.__protocolList.length?window.__protocolList.map(x=>x.id):['vless-ws','xhttp-packet-up','xhttp-stream-up','xhttp-stream-one','trojan','shadowsocks','socks5','http','hysteria2','vless-grpc-reality','wireguard']);
  const current=new Set(__groupProtocols.length?__groupProtocols:protocols);
  const memberIds=new Set((g.link_ids||[]).map(String));
  const allLinks=Array.isArray(links)?links:[];
  const protoRows=protocols.map(id=>{const checked=current.has(id),icon=groupProtocolIcon(id);return `<div class="group-proto-row"><div class="group-proto-icon">${icon?`<img src="${icon}" alt="">`:'◈'}</div><div class="group-proto-copy"><b>${esc(groupProtocolLabel(id))}</b><small>${checked?'پروتکل مجاز برای این گروه':'در این گروه نمایش داده نمی‌شود'}</small></div><span class="group-proto-tag">${id.startsWith('vless')||id.startsWith('xhttp')?'ONEX':'Native'}</span><label class="group-switch"><input type="checkbox" ${checked?'checked':''} onchange="toggleGroupProtocol('${esc(id)}',this.checked)"><span></span></label></div>`}).join('');
  const configRows=allLinks.slice().sort((a,b)=>String(a.label||'').localeCompare(String(b.label||''))).map(l=>{const id=String(l.uuid||l.id||'');const checked=memberIds.has(id);return `<label class="group-config-row"><input type="checkbox" class="group-config-check" value="${esc(id)}" ${checked?'checked':''}><span>${esc(l.label||id)}</span><small>${esc(groupProtocolLabel(l.protocol||''))}</small></label>`}).join('');
  pane.innerHTML=`<div class="group-detail">
    <div class="group-detail-head"><div class="group-detail-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="9" cy="9" r="3"/><circle cx="17" cy="10" r="2.5"/><path d="M3.5 20c.5-3.1 2.4-4.7 5.5-4.7s5 1.6 5.5 4.7"/><path d="M14 15.8c2.8-.8 5 .5 6 3.2"/></svg></div><div class="group-detail-title"><h2>${esc(g.name||'گروه')}</h2><p>${esc(g.desc||'گروه ویژه با بالاترین سرعت و پایداری')}</p></div><button class="group-three-dot" onclick="openGroupModal('${esc(g.sub_id)}')">•••</button></div>
    <div class="group-info-card"><div class="group-section-head"><b>⚙ اطلاعات گروه</b><span>Group profile</span></div><div class="group-info-grid"><div class="group-info-item"><small>نام گروه</small><b>${esc(g.name||'—')}</b></div><div class="group-info-item"><small>وضعیت</small><b style="color:${groupIsActive(g)?'#34d399':'#fb7185'}">${groupIsActive(g)?'فعال':'غیرفعال'}</b></div><div class="group-info-item"><small>کاربران فعال</small><b>${Number(g.active_count||0)}</b></div><div class="group-info-item"><small>تعداد کانفیگ‌ها</small><b>${Number(g.links_count||0)}</b></div></div></div>
    <div class="group-link-card"><div class="group-section-head"><b>◉ لینک اشتراک گروه</b><span>${g.has_password?'🔒 محافظت‌شده':'Public'}</span></div><div class="group-link-line"><div class="group-link-url">${esc(g.sub_url||'—')}</div><button class="group-copy-btn" onclick="copyText('${esc(g.sub_url||'')}')">کپی</button></div><div class="group-link-actions"><button onclick="openGroupQr('${esc(g.sub_url||'')}','${esc(g.name||'')}')">▦ QR کد</button><button onclick="window.open('${esc(g.public_url||g.sub_url||'')}','_blank')">↗ باز کردن لینک</button></div></div>
    <div class="group-proto-card"><div class="group-section-head"><b>⚙ پروتکل‌های فعال</b><span>کنترل خروجی اشتراک</span></div><div class="group-proto-list">${protoRows}</div></div>
    <div class="group-configs-card"><div class="group-section-head"><b>کانفیگ‌های گروه</b><span>${Number(g.links_count||0)} مورد</span></div><div class="group-config-list">${configRows||'<div class="group-empty" style="padding:18px">هنوز کانفیگی در پنل وجود ندارد؛ ابتدا از بخش کانفیگ‌ها یک کانفیگ بسازید.</div>'}</div><button class="group-config-save" onclick="saveGroupConfigs('${esc(g.sub_id)}')">ذخیره کانفیگ‌های گروه</button></div>
    <div class="group-manage-card"><div class="group-section-head"><b>مدیریت گروه</b><span>Group actions</span></div><div class="group-manage-actions"><button onclick="openGroupModal('${esc(g.sub_id)}')">✎ ویرایش</button><button onclick="toggleGroupMembership('${esc(g.sub_id)}')">${groupIsActive(g)?'⏸ غیرفعال کردن':'▶ فعال کردن'}</button><button onclick="deleteSubGroup('${esc(g.sub_id)}')">♜ حذف</button></div></div>
  </div>`;
}
async function saveGroupConfigs(subId){
  const ids=[...document.querySelectorAll('.group-config-check:checked')].map(x=>x.value);
  const r=await api('/api/subs/'+encodeURIComponent(subId)+'/sync',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({link_ids:ids})});
  if(r){toast(lang==='fa'?'کانفیگ‌های گروه ذخیره شد':'Group configs saved');await loadGroups();}
}
async function toggleGroupProtocol(id,state){
  const g=selectedSub(); if(!g)return;
  const current=new Set(Array.isArray(g.protocols)?g.protocols:(window.__protocolList||[]).map(x=>x.id));
  if(state) current.add(id); else current.delete(id);
  const protocols=[...current];
  const r=await api('/api/subs/'+encodeURIComponent(g.sub_id),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({protocols})});
  if(r){g.protocols=protocols;__groupProtocols=protocols;toast(state?'پروتکل فعال شد':'پروتکل غیرفعال شد');renderGroupDetail(g,window.__allLinks||[])}
}
async function toggleGroupMembership(subId){
  const g=__subGroups.find(x=>String(x.sub_id)===String(subId));if(!g)return;
  const next=g.active===false;
  const r=await api('/api/subs/'+encodeURIComponent(subId),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:next})});
  if(r){
    g.active=next;
    toast(next?'گروه فعال شد':'گروه غیرفعال شد');
    renderGroupList();
    renderGroupDetail(g,window.__allLinks||[]);
  }
}
function openGroupModal(subId=''){
  const modal=document.getElementById('groupModal');if(!modal)return;
  modal.hidden=false;modal.classList.add('open');
  const g=__subGroups.find(x=>String(x.sub_id)===String(subId));
  document.getElementById('groupModalTitle').textContent=g?'ویرایش گروه':'ساخت گروه جدید';
  document.getElementById('groupFormName').value=g?.name||'';document.getElementById('groupFormDesc').value=g?.desc||'';document.getElementById('groupFormPassword').value='';
  modal.dataset.subId=g?.sub_id||'';
}
function closeGroupModal(){const m=document.getElementById('groupModal');if(m){m.hidden=true;m.classList.remove('open')}}
async function saveGroupForm(){
  const m=document.getElementById('groupModal');const name=document.getElementById('groupFormName').value.trim();if(!name){toast('نام گروه لازم است');return}
  const subId=m?.dataset.subId||'';const body={name,desc:document.getElementById('groupFormDesc').value.trim()};const pw=document.getElementById('groupFormPassword').value.trim();if(pw)body.password=pw;
  const r=await api(subId?'/api/subs/'+encodeURIComponent(subId):'/api/subs',{method:subId?'PATCH':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){closeGroupModal();toast(subId?'گروه ویرایش شد':'گروه ساخته شد');await loadGroups()}
}
async function deleteSubGroup(id){if(!confirm('این گروه حذف شود؟ کانفیگ‌ها حذف نمی‌شوند و فقط از گروه خارج می‌شوند.'))return;const r=await api('/api/subs/'+encodeURIComponent(id),{method:'DELETE'});if(r){toast('گروه حذف شد');__selectedSubId='';await loadGroups()}}
function openGroupQr(url,label){const m=document.getElementById('groupQrModal'),box=document.getElementById('groupQrBox'),txt=document.getElementById('groupQrText');if(!m||!box||!url)return;txt.textContent=url;document.getElementById('groupQrTitle').textContent=label||'لینک اشتراک';box.innerHTML='';try{if(typeof qrcode==='function'){const qr=qrcode(0,'M');qr.addData(url);qr.make();box.innerHTML=qr.createImgTag(6,8)}else{box.innerHTML='<div style="color:#111;font:12px sans-serif;padding:30px">QR آماده نشد</div>'}}catch(e){box.innerHTML='<div style="color:#111;font:12px sans-serif;padding:30px">خطا در تولید QR</div>'}m.hidden=false;m.classList.add('open')}
function closeGroupQr(){const m=document.getElementById('groupQrModal');if(m){m.hidden=true;m.classList.remove('open')}}


async function loadSecurity(){
  const r=await api('/api/security/status');
  const el=document.getElementById('secStatus');
  if(!r||!el)return;
  const locked=(r.locked_ips||[]).map(x=>`${x.ip} (${Math.ceil(x.remaining_sec/60)}د)`).join(' · ')||'—';
  el.innerHTML=`حداکثر تلاش: <b>${r.max_attempts}</b> · قفل: <b>${Math.round(r.lockout_seconds/60)} دقیقه</b><br>IPهای مسدود: ${locked}`;
}
async function unlockAllIps(){
  if(!confirm('رفع مسدودی همه؟'))return;
  const r=await api('/api/security/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
  if(r){toast('انجام شد');loadSecurity()}
}


async function downloadBackup(kind){
  try{
    const url = kind==='bot' ? '/api/backup/bot' : '/api/backup/users';
    const r = await fetch(url, {credentials:'same-origin', cache:'no-store'});
    if(r.status===401){ location.href='/login'; return; }
    if(!r.ok){
      let msg='خطا';
      try{ const j=await r.json(); msg=j.detail||msg; }catch(e){}
      toast(String(msg)); return;
    }
    const text = await r.text();
    // validate json
    try{ JSON.parse(text); }catch(e){ toast('پاسخ نامعتبر'); return; }
    const blob = new Blob([text], {type:'application/json;charset=utf-8'});
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
    a.href = URL.createObjectURL(blob);
    a.download = kind==='bot' ? ('pxpanel-bot-'+stamp+'.json') : ('pxpanel-users-'+stamp+'.json');
    document.body.appendChild(a);
    a.click();
    setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 500);
    toast(lang==='fa'?'دانلود شد':'Downloaded');
  }catch(e){ toast(String(e.message||e)); }
}
function readJsonFile(inputId){
  return new Promise((resolve,reject)=>{
    const inp=document.getElementById(inputId);
    if(!inp||!inp.files||!inp.files[0]){ reject(new Error(lang==='fa'?'فایل انتخاب نشده':'No file')); return; }
    const fr=new FileReader();
    fr.onload=()=>{ try{ resolve(JSON.parse(fr.result)); }catch(e){ reject(new Error('JSON نامعتبر')); } };
    fr.onerror=()=>reject(new Error('خواندن فایل ناموفق'));
    fr.readAsText(inp.files[0],'utf-8');
  });
}
async function restoreUsers(mode){
  try{
    const data = await readJsonFile('restoreUsersFile');
    data.mode = mode||'merge';
    if(mode==='replace' && !confirm(lang==='fa'?'همه داده‌های فعلی پاک و جایگزین می‌شود. مطمئنی؟':'Replace all current data?')) return;
    const r = await api('/api/restore/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    if(r){ toast(lang==='fa'?('بازیابی شد: '+r.links+' کانفیگ'):('Restored: '+r.links)); refreshAll(); }
  }catch(e){ toast(e.message||String(e)); }
}
async function restoreBot(){
  try{
    const data = await readJsonFile('restoreBotFile');
    const r = await api('/api/restore/bot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    if(r) toast(r.message||(lang==='fa'?'ربات بازیابی شد':'Bot restored'));
  }catch(e){ toast(e.message||String(e)); }
}


/* ============================================================
   LIGHT STATIC 3D PROTOCOL PICKER
   ============================================================ */
const PROTOCOL_PICKER_GROUPS=[
  {title:'',ids:['vless-ws','xhttp-packet-up','xhttp-stream-up','xhttp-stream-one']}
];
const PROTOCOL_PICKER_NAMES={"vless-ws":"ONEX WB","xhttp-packet-up":"ONEX Xhttp","xhttp-stream-up":"ONEX Gaming","xhttp-stream-one":"ONEX Stream","trojan":"Trojan","shadowsocks":"Shadowsocks","socks5":"SOCKS5","http":"HTTP Proxy","hysteria2":"Hysteria2","vless-grpc-reality":"VLESS gRPC Reality"};
const PROTOCOL_PICKER_DESCS={"vless-ws":"VLESS + WebSocket","xhttp-packet-up":"VLESS + XHTTP","xhttp-stream-up":"VLESS + XHTTP","xhttp-stream-one":"VLESS + XHTTP","trojan":"Trojan","shadowsocks":"Shadowsocks","socks5":"SOCKS5","http":"HTTP Proxy","hysteria2":"Hysteria2","vless-grpc-reality":"VLESS + gRPC + Reality"};
const PROTOCOL_3D_ICONS={
  "vless-ws":{c1:"#24a9ff",c2:"#1264ff",c3:"#6d3cff",mark:"V",glow:"#168cff"},
  "xhttp-packet-up":{c1:"#35c8ff",c2:"#0877d8",c3:"#3155ff",mark:"XP",glow:"#21b8ff"},
  "xhttp-stream-up":{c1:"#36e6ff",c2:"#0894c9",c3:"#16b7d1",mark:"XS",glow:"#21d9ee"},
  "xhttp-stream-one":{c1:"#b04cff",c2:"#6b1fe1",c3:"#3b25ad",mark:"XC",glow:"#a14cff"},
  "vmess-ws":{c1:"#d05cff",c2:"#7726e8",c3:"#4522a6",mark:"M",glow:"#a54cff"},
  "trojan":{c1:"#ff6676",c2:"#e51c35",c3:"#a90f2b",mark:"T",glow:"#ff4058"},
  "shadowsocks":{c1:"#54e887",c2:"#11ae57",c3:"#078341",mark:"S",glow:"#22d66c"},
  "socks5":{c1:"#45dfff",c2:"#0b9fc8",c3:"#08779e",mark:"5",glow:"#20d5ff"},
  "http":{c1:"#78a7ff",c2:"#3975e8",c3:"#2448a9",mark:"H",glow:"#4d8cff"},
  "hysteria2":{c1:"#55e9ff",c2:"#08a9c5",c3:"#087b99",mark:"H2",glow:"#21dfff"},
  "vless-grpc-reality":{c1:"#b04cff",c2:"#6b1fe1",c3:"#3b25ad",mark:"GR",glow:"#a14cff"},
};
let __protocolPickerTarget='' ;
let __protocolPickerOptions=[];
function protocolPickerLabel(id){const p=__protocolPickerOptions.find(x=>x.id===id);return PROTOCOL_PICKER_NAMES[id]||p?.label||id||'Vortex Link'}
function protocolPickerShort(id){return PROTOCOL_PICKER_NAMES[id]||id}
const PROTOCOL_ICON_DATA={"vless-ws":"/api/protocol-icon/vless-ws.png","xhttp-packet-up":"/api/protocol-icon/xhttp-packet-up.png","xhttp-stream-up":"/api/protocol-icon/xhttp-stream-up.png","xhttp-stream-one":"/api/protocol-icon/xhttp-stream-one.png"};
function protocolIconMarkup(id){
  const srcMap=PROTOCOL_ICON_DATA;
  const src=srcMap[id]||srcMap["vless-ws"];
  return `<span class="protocol-option-icon proto-3d" aria-hidden="true"><img class="protocol-art-icon" src="${src}" alt="" loading="eager" decoding="async"></span>`
}
function setupProtocolPickers(){['cProto','aProto'].forEach(id=>{const sel=document.getElementById(id);if(!sel)return;sel.classList.add('protocol-native');sel.style.setProperty('display','none','important');sel.setAttribute('aria-hidden','true');let trigger=sel.parentNode.querySelector(`.protocol-trigger[data-for="${id}"]`);if(!trigger){trigger=document.createElement('button');trigger.type='button';trigger.className='protocol-trigger';trigger.dataset.for=id;sel.parentNode.insertBefore(trigger,sel.nextSibling)}trigger.onclick=e=>{e.preventDefault();openProtocolPicker(id)};syncProtocolPicker(id)})}
function syncProtocolPicker(id){const sel=document.getElementById(id),trigger=document.querySelector(`.protocol-trigger[data-for="${id}"]`);if(!sel||!trigger)return;const value=sel.value||'vless-ws';trigger.innerHTML=`<span class="protocol-trigger-main"><span class="protocol-trigger-icon">${protocolIconMarkup(value)}</span><span class="protocol-trigger-text"><span class="protocol-trigger-name">${esc(protocolPickerShort(value))}</span><span class="protocol-trigger-sub">${lang==='fa'?'برای تغییر، انتخاب کنید':'Tap to choose another protocol'}</span></span></span><span class="protocol-trigger-arrow">⌄</span>`}
function ensureProtocolPicker(){let bg=document.getElementById('protocolPickerBg');if(bg)return bg;bg=document.createElement('div');bg.id='protocolPickerBg';bg.className='protocol-picker-bg';bg.innerHTML=`<div class="protocol-picker" role="dialog" aria-modal="true"><div class="protocol-picker-head"><div class="protocol-picker-head-icon"><span>✦</span></div><div class="protocol-picker-head-text"><div class="protocol-picker-title">${lang==='fa'?'انتخاب پروتکل':'Select Protocol'}</div><div class="protocol-picker-subtitle">${lang==='fa'?'پروتکل موردنظر را انتخاب کنید':'Choose the protocol you want to use'}</div></div><button type="button" class="protocol-picker-close" id="protocolPickerClose">×</button></div><div class="protocol-picker-scroll" id="protocolPickerScroll"></div><div class="protocol-picker-foot"><div class="protocol-selected-info" id="protocolSelectedInfo">—</div><button type="button" class="protocol-picker-confirm" id="protocolPickerConfirm">${lang==='fa'?'تأیید و ادامه →':'Confirm & Continue →'}</button></div></div>`;document.body.appendChild(bg);bg.addEventListener('click',e=>{if(e.target===bg)closeProtocolPicker()});bg.querySelector('#protocolPickerClose').onclick=closeProtocolPicker;bg.querySelector('#protocolPickerConfirm').onclick=confirmProtocolPicker;return bg}
function openProtocolPicker(targetId){const sel=document.getElementById(targetId);if(!sel)return;const bg=ensureProtocolPicker();__protocolPickerTarget=targetId;const current=sel.value||'vless-ws';const available=new Set([...sel.options].map(o=>o.value));const ids=PROTOCOL_PICKER_GROUPS[0].ids.filter(id=>available.has(id));const scroll=bg.querySelector('#protocolPickerScroll');scroll.innerHTML=`<div class="protocol-grid protocol-grid-all">${ids.map(id=>`<button type="button" class="protocol-option ${id===current?'selected':''}" data-proto="${id}"><span class="protocol-option-radio"></span>${protocolIconMarkup(id)}<span class="protocol-option-name">${esc(protocolPickerShort(id))}</span><span class="protocol-option-desc">${id===current?(lang==='fa'?'انتخاب‌شده · ':'Selected · ')+(PROTOCOL_PICKER_DESCS[id]||''):(PROTOCOL_PICKER_DESCS[id]|| (lang==='fa'?'برای انتخاب کلیک کنید':'Tap to choose'))}</span></button>`).join('')}</div>`;scroll.querySelectorAll('.protocol-option').forEach(btn=>btn.addEventListener('click',()=>chooseProtocol(btn.dataset.proto)));bg.querySelector('#protocolSelectedInfo').textContent=(lang==='fa'?'پروتکل انتخاب‌شده: ':'Selected: ')+protocolPickerShort(current);bg.classList.add('open');document.body.style.overflow='hidden'}
function chooseProtocol(id){const sel=document.getElementById(__protocolPickerTarget),bg=document.getElementById('protocolPickerBg');if(!sel||!bg)return;sel.value=id;bg.querySelectorAll('.protocol-option').forEach(x=>x.classList.toggle('selected',x.dataset.proto===id));bg.querySelector('#protocolSelectedInfo').textContent=(lang==='fa'?'پروتکل انتخاب‌شده: ':'Selected: ')+protocolPickerShort(id);syncProtocolPicker(__protocolPickerTarget);sel.dispatchEvent(new Event('change',{bubbles:true}))}
function confirmProtocolPicker(){if(__protocolPickerTarget){const sel=document.getElementById(__protocolPickerTarget);if(sel)sel.dispatchEvent(new Event('change',{bubbles:true}))}closeProtocolPicker()}
function closeProtocolPicker(){const bg=document.getElementById('protocolPickerBg');if(bg)bg.classList.remove('open');document.body.style.overflow=''}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeProtocolPicker()});
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',setupProtocolPickers);else setupProtocolPickers();setTimeout(setupProtocolPickers,300);setTimeout(setupProtocolPickers,1000);

applyLang();loadMe();loadProtocols();loadCategories();loadGroups();refreshAll();setTimeout(()=>{if(document.getElementById('advancedPorts')&&!getAdvancedPorts().length)fillAdvancedForm({ports:[443]});loadAdvancedCapabilities(document.getElementById('cProto')?.value||'vless-ws')},250);
setTimeout(()=>{startUpdateNotificationPolling()},1200);
setTimeout(()=>checkPanelUpdate(true),2500);
setInterval(()=>checkPanelUpdate(true),10*60*1000);
// Protocol picker bootstrap: keep the native select only as the data/control source.
function bootProtocolPickers(){ try{ setupProtocolPickers(); }catch(e){ console.warn('Protocol picker:',e); } }
if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',bootProtocolPickers); else bootProtocolPickers();
setTimeout(bootProtocolPickers,300);
setTimeout(bootProtocolPickers,1000);
setInterval(refreshAll,1000);




        location.href='/dashboard'
        