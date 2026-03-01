// ═══════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════
const API = window.PUBLIX_API_URL || 'https://YOUR_API_GATEWAY_URL';

let token     = localStorage.getItem('pdc_token') || null;
let userEmail = localStorage.getItem('pdc_email') || null;
let prefs     = null;
let adminKey  = sessionStorage.getItem('pdc_admin') || null;

// Deal state
let _allDeals      = [];       // raw from API
let _dealCounts    = {};       // type counts
let _deptCounts    = {};       // dept counts
let _dealsUpdated  = '';       // WeeklyAdLatestUpdatedDateTime from last fetch
let _dealsStoreId  = '';       // which store these deals are for
let _allMatches    = [];       // computed matches
let _dealHistory   = null;    // { num_weeks, snapshots } for current store
let _corpusTitles  = [];      // global autocomplete corpus
let _matchDeptCts  = {};
let _savingTypes   = [];       // dynamic saving_type values from API

// ── Item shape helpers ────────────────────────────────────────────────────────
// prefs.items is an array of either plain strings (legacy) or
// objects { name: string, mode: 'fuzzy'|'exact' } (v6.1+).
// All code goes through these helpers so both shapes are handled transparently.

function itemName(item)  { return typeof item === 'string' ? item : (item?.name  || ''); }
function itemMode(item)  { return typeof item === 'string' ? 'fuzzy' : (item?.mode || 'fuzzy'); }
function itemObj(name, mode) { return { name, mode: mode || 'fuzzy' }; }

// Return all item names as a plain string array (for display, autocomplete, etc.)
function itemNames() { return (prefs?.items || []).map(itemName); }

// Toggle mode for item at index i and save
function toggleItemMode(i) {
  if (!prefs?.items) return;
  const item = prefs.items[i];
  const cur  = itemMode(item);
  prefs.items[i] = itemObj(itemName(item), cur === 'fuzzy' ? 'exact' : 'fuzzy');
  renderItems();
  savePrefs('list').catch(() => {});
  computeMatches();
}

// ── History badge thresholds ──────────────────────────────────────────────────
const HIST_MIN = {
  bestYear:   8,
  best6weeks: 6,
  repeat:     2,
  rareOnSale: 12,
  freqHint:   4,
  banner:     4,
};

function parseSavingsAmount(str) {
  if (!str) return null;
  const m = str.match(/\$(\d+(?:\.\d+)?)/);
  return m ? parseFloat(m[1]) : null;
}

// For sorting purposes, extract the most meaningful savings number from a deal.
// save_line (e.g. "Save Up To $10.98 on 2") is more meaningful than the display
// price when it contains a dollar amount — use it preferentially.
// For bundle prices like "2 for $25.00" we can't compare to per-item prices, so
// we leave them at face value (they'll cluster together near the top).
function dealSortSavings(d) {
  const fromSaveLine = parseSavingsAmount(d.save_line);
  if (fromSaveLine !== null) return fromSaveLine;
  return parseSavingsAmount(d.savings) || 0;
}

function computeBadge(deal, history) {
  if (!history || !history.snapshots || !history.snapshots.length) return null;
  const numWeeks   = history.num_weeks || 0;
  const snapshots  = history.snapshots;
  const dealTitle  = (deal.title || '').toLowerCase();
  const currentAmt = parseSavingsAmount(deal.savings);

  const pastAppearances = [];
  snapshots.forEach((snap, snapIdx) => {
    snap.deals.forEach(pastDeal => {
      const pastTitle = (pastDeal.title || '').toLowerCase();
      if (dealTitle && pastTitle && fuzzyScore(dealTitle, pastTitle) >= 75) {
        pastAppearances.push({ snap, snapIdx, pastDeal });
      }
    });
  });

  if (numWeeks >= HIST_MIN.repeat && snapshots.length >= 2) {
    const prevWeek = snapshots[1];
    if (prevWeek && prevWeek.deals.some(pd =>
      fuzzyScore((pd.title || '').toLowerCase(), dealTitle) >= 80
    )) {
      return { type: 'repeat', label: '🔁 Repeat deal' };
    }
  }

  if (numWeeks >= HIST_MIN.rareOnSale) {
    const pastCount = pastAppearances.filter(a => a.snapIdx > 0).length;
    if (pastCount < 3) return { type: 'rare', label: '📅 Rarely on sale' };
  }

  if (currentAmt !== null) {
    const historicalAmts = pastAppearances
      .filter(a => a.snapIdx > 0)
      .map(a => parseSavingsAmount(a.pastDeal.savings))
      .filter(v => v !== null);

    if (historicalAmts.length > 0) {
      const maxHistorical = Math.max(...historicalAmts);
      if (numWeeks >= HIST_MIN.bestYear && currentAmt >= maxHistorical)
        return { type: 'best', label: '🔥 Best price this year' };
      if (numWeeks >= HIST_MIN.best6weeks) {
        const sixWeekAmts = pastAppearances
          .filter(a => a.snapIdx > 0 && a.snapIdx <= 6)
          .map(a => parseSavingsAmount(a.pastDeal.savings))
          .filter(v => v !== null);
        if (sixWeekAmts.length > 0 && currentAmt >= Math.max(...sixWeekAmts))
          return { type: 'recent', label: '✨ Best price in 6 weeks' };
      }
    }
  }
  return null;
}

function computeFreqHint(itemName, history) {
  if (!history || (history.num_weeks || 0) < HIST_MIN.freqHint) return '';
  const name = itemName.toLowerCase();
  const snapshots = history.snapshots || [];
  let count = 0;
  snapshots.forEach((snap, idx) => {
    if (idx === 0) return;
    if (snap.deals.some(d => fuzzyScore(name, (d.title || '').toLowerCase()) >= 70)) count++;
  });
  const weeksOfHistory = Math.max(snapshots.length - 1, 1);
  const annualRate = Math.round((count / weeksOfHistory) * 52);
  if (annualRate === 0)  return 'rarely on sale';
  if (annualRate <= 2)   return `on sale ~${annualRate}x/year`;
  if (annualRate <= 8)   return 'on sale a few times a year';
  if (annualRate <= 20)  return 'on sale most months';
  return 'on sale most weeks';
}

function buildQualityBanner(matches, history) {
  if (!history || (history.num_weeks || 0) < HIST_MIN.banner) return null;
  const bestItems = [], repeatItems = [];
  matches.forEach(deal => {
    const badge = computeBadge(deal, history);
    if (!badge) return;
    const name = deal.my_item || deal.title || '';
    if (badge.type === 'best' || badge.type === 'recent') bestItems.push(name);
    else if (badge.type === 'repeat') repeatItems.push(name);
  });
  if (!bestItems.length && !repeatItems.length) return null;
  const parts = [];
  if (bestItems.length)   parts.push(`🔥 <strong>${bestItems.slice(0,3).join(' & ')}</strong> ${bestItems.length===1?'is':'are'} at their best price this year.`);
  if (repeatItems.length) parts.push(`🔁 <strong>${repeatItems.slice(0,2).join(' & ')}</strong> ${repeatItems.length===1?'is a repeat':'are repeats'} from last week.`);
  return parts.join(' ');
}

async function loadDealHistory() {
  const storeId = prefs?.store_id;
  if (!storeId) return;
  try {
    const res = await fetch(API + `/deals/history?store_id=${encodeURIComponent(storeId)}`, {
      headers: { Authorization: 'Bearer ' + token }
    });
    if (!res.ok) return;
    _dealHistory = await res.json();
    renderMatches && renderMatches();
    renderDeals && renderDeals();
    renderFreqHints();
    // Show badge legends if enough history
    document.querySelectorAll('.badge-legend').forEach(el => {
      el.style.display = (_dealHistory && _dealHistory.num_weeks >= HIST_MIN.repeat) ? '' : 'none';
    });
  } catch (e) { console.warn('History load failed:', e); }
}

async function loadCorpus() {
  if (_corpusTitles.length) return;
  const cached = sessionStorage.getItem('pdc_corpus');
  if (cached) { _corpusTitles = JSON.parse(cached); return; }
  try {
    const res = await fetch(API + '/deals/corpus', { headers: { Authorization: 'Bearer ' + token } });
    if (!res.ok) return;
    const data = await res.json();
    _corpusTitles = data.titles || [];
    sessionStorage.setItem('pdc_corpus', JSON.stringify(_corpusTitles));
  } catch (e) { console.warn('Corpus load failed:', e); }
}

function renderFreqHints() {
  if (!_dealHistory || (_dealHistory.num_weeks || 0) < HIST_MIN.freqHint) return;
  document.querySelectorAll('.list-item-freq').forEach(el => {
    const item = el.dataset.item || '';
    el.textContent = computeFreqHint(item, _dealHistory);
  });
}
// ═══════════════════════════════════════════════════════════════════
// PIN INPUTS
// ═══════════════════════════════════════════════════════════════════
function initPins(sel, onSubmit) {
  const ds = document.querySelectorAll(sel);
  ds.forEach((el,i) => {
    el.addEventListener('input', () => {
      el.value = el.value.replace(/\D/g,'').slice(-1);
      if (el.value && i < ds.length-1) ds[i+1].focus();
    });
    el.addEventListener('keydown', e => {
      if (e.key==='Backspace' && !el.value && i>0) ds[i-1].focus();
      if (e.key==='Enter' && onSubmit) onSubmit();
    });
    el.addEventListener('focus', () => el.select());
  });
}
function getPin(sel) { return [...document.querySelectorAll(sel)].map(e=>e.value).join(''); }
function clrPin(sel) { document.querySelectorAll(sel).forEach(e=>e.value=''); const f=document.querySelector(sel); if(f) f.focus(); }

function initPinInputs(selector) {
  document.querySelectorAll(selector).forEach((inp, i, all) => {
    inp.addEventListener('keydown', e => {
      if (e.key === 'Backspace' && !inp.value && i > 0) {
        all[i-1].focus();
        all[i-1].value = '';
        e.preventDefault();
      }
    });
    inp.addEventListener('input', e => {
      // strip non-digits
      inp.value = inp.value.replace(/\D/g, '').slice(-1);
      if (inp.value && i < all.length - 1) all[i+1].focus();
      // if last digit filled and it's the auth form, attempt login
      if (inp.value && i === all.length - 1 && selector === '.auth-pin') {
        const allFilled = Array.from(all).every(d => d.value);
        if (allFilled) doAuth();
      }
    });
    inp.addEventListener('focus', () => inp.select());
    inp.addEventListener('paste', e => {
      e.preventDefault();
      const digits = (e.clipboardData.getData('text').replace(/\D/g, '')).slice(0, all.length);
      digits.split('').forEach((d, j) => { if (all[i+j]) all[i+j].value = d; });
      const next = all[Math.min(i + digits.length, all.length - 1)];
      next.focus();
    });
  });
}


initPins('.auth-pin', doAuth);
initPins('.cur-pin', null);
initPins('.new-pin', null);
initPins('.ap-pin', null);
initPins('.ac-pin', null);

// Paste support on auth pins
document.querySelectorAll('.auth-pin').forEach((el,i,arr) => {
  el.addEventListener('paste', e => {
    const t=(e.clipboardData||window.clipboardData).getData('text').replace(/\D/g,'').slice(0,4);
    if(t.length===4){e.preventDefault();arr.forEach((d,j)=>d.value=t[j]||'');arr[3].focus();}
  });
});

// ═══════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════
let authMode = 'login';
function switchTab(m) {
  authMode=m;
  document.querySelectorAll('.auth-tab').forEach((t,i)=>t.classList.toggle('active',(m==='login'&&i===0)||(m==='register'&&i===1)));
  document.getElementById('auth-btn').textContent = m==='login'?'Sign In':'Create Account';
  setMsg('auth-msg','','');
}
function setMsg(id,txt,cls){ const el=document.getElementById(id); if(!el) return; el.textContent=txt; el.className='msg'+(cls?' '+cls:''); }
let _lockoutTimer = null;
function _startLockoutCountdown(retryAfterSeconds) {
  clearInterval(_lockoutTimer);
  const btn = document.getElementById('auth-btn');
  btn.disabled = true;
  let remaining = retryAfterSeconds;
  function tick() {
    const m = Math.floor(remaining / 60), s = remaining % 60;
    const display = m > 0 ? `${m}m ${String(s).padStart(2,'0')}s` : `${s}s`;
    setMsg('auth-msg', `Account locked. Try again in ${display}.`, 'err');
    btn.textContent = `Locked (${display})`;
    if (remaining <= 0) {
      clearInterval(_lockoutTimer);
      _lockoutTimer = null;
      btn.disabled = false;
      btn.textContent = authMode === 'login' ? 'Sign In' : 'Create Account';
      setMsg('auth-msg', 'Account unlocked. You may try again.', 'ok');
    }
    remaining--;
  }
  tick();
  _lockoutTimer = setInterval(tick, 1000);
}

async function doAuth() {
  const em = document.getElementById('auth-email').value.trim().toLowerCase();
  const pin = getPin('.auth-pin');
  if(!em){ setMsg('auth-msg','Please enter your email.','err'); return; }
  if(pin.length!==4){ setMsg('auth-msg','Please enter your 4-digit PIN.','err'); return; }
  const btn=document.getElementById('auth-btn');
  btn.disabled=true; btn.textContent=authMode==='login'?'Signing in…':'Creating account…';
  try{
    const res=await fetch(API+(authMode==='login'?'/auth/login':'/auth/register'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:em,pin})});
    const data=await res.json();
    if(!res.ok){
      if(res.status===429 && data.retry_after_seconds){
        _startLockoutCountdown(data.retry_after_seconds);
        return;
      }
      setMsg('auth-msg',data.error||'Something went wrong.','err');
      return;
    }
    if(authMode==='register'){setMsg('auth-msg','Account created! Signing you in…','ok');await new Promise(r=>setTimeout(r,700));authMode='login';
      token=null; prefs=null;
      localStorage.removeItem('pdc_token'); localStorage.removeItem('pdc_email');
      await doAuth();return;}
    clearInterval(_lockoutTimer); _lockoutTimer=null;
    token=data.token;userEmail=data.email;
    localStorage.setItem('pdc_token',token);localStorage.setItem('pdc_email',userEmail);
    prefs=data.prefs;
    const _isNew = authMode==='register' || !(prefs && prefs.store_id);
    enterApp({isFirstLogin: _isNew});
  }catch(e){setMsg('auth-msg','Could not reach the server.','err');}
  finally{if(!_lockoutTimer){btn.disabled=false;btn.textContent=authMode==='login'?'Sign In':'Create Account';}}
}

// ═══════════════════════════════════════════════════════════════════
// APP ENTRY
// ═══════════════════════════════════════════════════════════════════
function enterApp(opts) {
  // opts.isFirstLogin = true means brand-new account (no store set yet)
  const isFirstLogin = (opts && opts.isFirstLogin) ||
    (!localStorage.getItem('pdc_welcomed_'+userEmail) && !(prefs && prefs.store_id));
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('app-screen').classList.add('visible');
  document.getElementById('topbar-email').textContent=userEmail;
  document.getElementById('acct-email-disp').textContent=userEmail;
  document.getElementById('acct-avatar').textContent=(userEmail[0]||'?').toUpperCase();
  loadPrefs();
  if(isFirstLogin){
    // Show welcome wizard; on dismiss it will navigate to Store
    showPanel('store');
    setTimeout(()=>wlcShow(), 120);
  } else {
    // Returning user: go straight to My Matches
    showPanel('matches');
  }
  preloadDeals();
  loadDealHistory();
  loadCorpus();
}
async function doLogout(){
  if(token){try{await fetch(API+'/auth/logout',{method:'POST',headers:{'Authorization':'Bearer '+token}});}catch(_){}}
  token=null;userEmail=null;prefs=null;_allDeals=[];_allMatches=[];_dealsStoreId='';_storeData=null;
  localStorage.removeItem('pdc_token');localStorage.removeItem('pdc_email');
  // Reset store UI so it doesn't bleed into the next session
  document.getElementById('store-card-wrap').style.display='none';
  document.getElementById('store-search-ui').style.display='';
  document.getElementById('store-card-el').innerHTML='';
  document.getElementById('store-id-input').value='';
  document.getElementById('store-results').innerHTML='';
  document.getElementById('app-screen').classList.remove('visible');
  document.getElementById('auth-screen').style.display='';
  clrPin('.auth-pin');
}
function showPanel(name) {
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
  const sideNav=document.getElementById('nav-'+name);
  if(sideNav) sideNav.classList.add('active');
  const mobileNav=document.getElementById('mnav-'+name);
  if(mobileNav) mobileNav.classList.add('active');
  if(name==='admin') initAdmin();
  // Always force a fresh load when opening Matches so it reflects the latest scrape.
  // Deals panel uses the cached version (fast, once per session).
  if(name==='matches') loadDeals(false);
  else if(name==='deals') preloadDeals();
}
function openMobileNav(){
  document.getElementById('mobile-nav').classList.add('open');
  document.body.style.overflow='hidden';
}
function closeMobileNav(){
  document.getElementById('mobile-nav').classList.remove('open');
  document.body.style.overflow='';
}

// ═══════════════════════════════════════════════════════════════════
// PREFS
// ═══════════════════════════════════════════════════════════════════
function loadPrefs() {
  if(!prefs) return;
  const sid=prefs.store_id||'';
  if(sid){
    // Set basic info immediately, then enrich with full store details in background.
    // Capture token now so a logout before the fetch returns can't corrupt the new session.
    const _tokenAtLoad = token;
    setStoreSel({id:sid, name:prefs.store_name||'', address:prefs.store_address||'', street:prefs.store_address||''});
    fetch(API+'/stores/search?q='+encodeURIComponent(sid),{headers:{'Authorization':'Bearer '+token}})
      .then(r=>r.json()).then(data=>{
        if(token !== _tokenAtLoad) return; // session changed — discard stale result
        const s=(data.stores||[])[0];
        if(s && s.id===sid) setStoreSel(s);
      }).catch(()=>{});
  } else {
    // No store set — ensure the UI shows the search form, not a card left over from a previous session
    document.getElementById('store-card-wrap').style.display = 'none';
    document.getElementById('store-search-ui').style.display = '';
  }
  const emailEnabled = prefs.email_enabled !== false; // default true
  document.getElementById('email-enabled').checked = emailEnabled;
  document.getElementById('email-settings-wrap').style.display = emailEnabled ? '' : 'none';
  document.getElementById('notify-email').value = prefs.notify_email || userEmail || '';
  renderItems();
  const t=((prefs.matching||{}).threshold)||75;
  document.getElementById('threshold').value=t;
  document.getElementById('threshold-val').textContent=t;
  const s=prefs.schedule||{};
  document.getElementById('sched-day').value  = s.days?.[0]??3;
  document.getElementById('sched-hour').value = s.hour??8;
  document.getElementById('sched-ampm').value = s.ampm??'AM';
}
function collectPrefs(){
  return {
    store_id:      prefs?.store_id||'',
    store_name:    prefs?.store_name||'',
    store_address: prefs?.store_address||'',
    notify_email:  document.getElementById('notify-email').value.trim()||userEmail,
    email_enabled: document.getElementById('email-enabled').checked,
    items:         prefs?.items||[],
    matching:      {threshold:parseInt(document.getElementById('threshold').value)},
    schedule:      {days:[parseInt(document.getElementById('sched-day').value)],
                    hour:parseInt(document.getElementById('sched-hour').value),
                    minute:0, ampm:document.getElementById('sched-ampm').value},
  };
}
let _saveToastTimer=null;
function showSaveToast(){
  const t=document.getElementById('save-toast');
  if(!t) return;
  t.classList.add('show');
  clearTimeout(_saveToastTimer);
  _saveToastTimer=setTimeout(()=>t.classList.remove('show'),2000);
}
async function savePrefs(ctx){
  const p=collectPrefs();
  if(prefs) p.items=prefs.items||[];
  try{
    const res=await fetch(API+'/user/prefs',{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({prefs:p})});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Save failed');
    prefs=data.prefs;
    showSaveToast();
  }catch(e){console.error('Save failed:',e.message);}
}

// ═══════════════════════════════════════════════════════════════════
// STORE
// ═══════════════════════════════════════════════════════════════════
// ── Store panel ────────────────────────────────────────────────────
let _storeData = null; // full store object from API

function fmtPhone(p){
  if(!p) return '';
  const d=p.replace(/\D/g,'');
  if(d.length===10) return `(${d.slice(0,3)}) ${d.slice(3,6)}-${d.slice(6)}`;
  return p;
}

function storeCardHtml(s){
  const addr = [s.street, s.city, s.state, s.zip].filter(Boolean).join(', ');
  const mapsUrl = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(addr)}`;
  const hero = s.img_hero
    ? `<img class="store-card-hero" src="${escH(s.img_hero)}" alt="${escH(s.name)}" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">`
    + `<div class="store-card-hero-ph" style="display:none">🏪</div>`
    : `<div class="store-card-hero-ph">🏪</div>`;

  // Hours grid
  const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const todayIdx = new Date().getDay();
  let hoursGrid = '';
  if(s.hours_raw && s.hours_raw.length){
    // hours_raw[0] = today, build forward
    hoursGrid = `<div class="store-hours-grid">`;
    for(let i=0;i<Math.min(7,s.hours_raw.length);i++){
      const h = s.hours_raw[i];
      const dt = new Date(h.openTime||h.closeTime||'');
      const dayIdx = dt.getDay ? dt.getDay() : (todayIdx+i)%7;
      const isToday = i===0;
      let timeStr = '';
      if(h.isClosed) timeStr='Closed';
      else if(h.isOpen24Hours) timeStr='24h';
      else{
        const fmt=iso=>{try{const t=new Date(iso);return t.toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit',hour12:true}).replace(':00','').replace(' ','');}catch{return'';}};
        timeStr=`${fmt(h.openTime)}<br>${fmt(h.closeTime)}`;
      }
      hoursGrid+=`<div class="store-hour-day${isToday?' today':''}">
        <div class="store-hour-day-name">${days[dayIdx]}</div>
        <div class="store-hour-time">${timeStr}</div>
      </div>`;
    }
    hoursGrid+='</div>';
  }

  const phone = fmtPhone(s.phone);
  const pharmPhone = fmtPhone(s.pharmacy_phone);

  return `<div>
    ${hero}
    <div class="store-card-body">
      <div class="store-card-name">${escH(s.name)}</div>
      <div class="store-card-id">Store #${escH(s.id)}</div>
      ${addr?`<div class="store-card-row"><span class="store-card-row-icon">📍</span>
        <span><a href="${escH(mapsUrl)}" target="_blank">${escH(addr)}</a></span></div>`:''}
      ${phone?`<div class="store-card-row"><span class="store-card-row-icon">📞</span>
        <span><a href="tel:+1${escH(s.phone)}">${escH(phone)}</a></span></div>`:''}
      ${pharmPhone?`<div class="store-card-row"><span class="store-card-row-icon">💊</span>
        <span>Pharmacy: <a href="tel:+1${escH(s.pharmacy_phone)}">${escH(pharmPhone)}</a></span></div>`:''}
      ${s.hours_today?`<div class="store-card-row"><span class="store-card-row-icon">🕐</span>
        <span>Today: <strong>${escH(s.hours_today)}</strong></span></div>`:''}
      ${hoursGrid?`<div style="margin-top:10px">${hoursGrid}</div>`:''}
    </div>
    <div class="store-card-footer">
      <span style="font-size:12px;color:var(--ink-soft)">
        <a href="https://www.publix.com/locations/${escH(s.name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,''))}" target="_blank" style="color:var(--green)">View on Publix.com ↗</a>
      </span>
      <button class="btn-change" onclick="clearStore()">Change Store</button>
    </div>
  </div>`;
}

function setStoreSel(s){
  if(!prefs) prefs={};
  prefs.store_id      = s.id||'';
  prefs.store_name    = s.name||'';
  prefs.store_address = s.address||s.street||'';
  _storeData = s;
  if(s.id){
    document.getElementById('store-card-el').innerHTML = storeCardHtml(s);
    document.getElementById('store-card-wrap').style.display = '';
    document.getElementById('store-search-ui').style.display = 'none';
  }
}

function clearStore(){
  document.getElementById('store-card-wrap').style.display = 'none';
  document.getElementById('store-search-ui').style.display = '';
  document.getElementById('store-id-input').value = '';
  document.getElementById('store-results').innerHTML = '';
  if(prefs){prefs.store_id='';prefs.store_name='';prefs.store_address='';}
  _storeData = null;
  _dealsStoreId='';_allDeals=[];_allMatches=[];
  document.getElementById('deals-browser').style.display='none';
  document.getElementById('matches-browser').style.display='none';
}

function onStoreInputType(){
  // typing — do nothing until Search is clicked or Enter pressed
}

function onStoreInput(){
  doStoreSearch();
}

let _storeSearchTimer = null;
async function doStoreSearch(){
  const q = (document.getElementById('store-id-input').value||'').trim();
  if(!q) return;
  const resultsEl = document.getElementById('store-results');
  resultsEl.innerHTML = '<div class="store-no-results">Searching…</div>';
  try{
    const res = await fetch(API+'/stores/search?q='+encodeURIComponent(q),
      {headers:{'Authorization':'Bearer '+token}});
    const data = await res.json();
    if(!res.ok) throw new Error(data.error||'Search failed');
    const stores = data.stores||[];
    if(!stores.length){
      resultsEl.innerHTML = '<div class="store-no-results">No stores found. Try a different city, ZIP, or store #.</div>';
      return;
    }
    resultsEl.innerHTML = stores.map((s,i)=>{
      const thumb = s.img_thumb
        ? `<img class="store-result-thumb" src="${escH(s.img_thumb)}" alt="" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"><div class="store-result-thumb-ph" style="display:none">🏪</div>`
        : `<div class="store-result-thumb-ph">🏪</div>`;
      const dist = s.distance!=null ? `<div class="store-result-dist">${(+s.distance).toFixed(1)} mi away</div>` : '';
      const addr = [s.street, s.city, s.state].filter(Boolean).join(', ');
      return `<div class="store-result-item" onclick="selectStore(${i})">
        ${thumb}
        <div style="flex:1;min-width:0">
          <div class="store-result-name">${escH(s.name)} <span style="font-weight:400;color:var(--ink-soft);font-size:11px">#${escH(s.id)}</span></div>
          <div class="store-result-addr">${escH(addr)}</div>
          ${dist}
        </div>
        <span style="color:var(--green);font-size:18px">›</span>
      </div>`;
    }).join('');
    // cache stores for selectStore
    window._storeSearchResults = stores;
  }catch(e){
    resultsEl.innerHTML = `<div class="store-no-results" style="color:var(--red)">Search failed: ${escH(e.message)}</div>`;
  }
}

function selectStore(idx){
  const s = (window._storeSearchResults||[])[idx];
  if(!s) return;
  setStoreSel(s);
  savePrefs('store').catch(()=>{});
  if(s.id !== _dealsStoreId) preloadDeals();
}

// ═══════════════════════════════════════════════════════════════════
// ITEMS
// ═══════════════════════════════════════════════════════════════════
// Items stored as strings; deal-checkbox adds title string
function renderItems(){
  const items=(prefs&&prefs.items)||[];
  document.getElementById('items-ul').innerHTML=items.map((item,i)=>{
    const name=itemName(item);
    const mode=itemMode(item);
    return `<li class="item-row">
      <span class="item-name">${escH(name)}<br><span class="item-freq list-item-freq" data-item="${escH(name)}"></span></span>
      <div class="item-row-actions">
        <button class="mode-toggle${mode==='exact'?' exact':''}" onclick="toggleItemMode(${i})" title="${mode==='exact'?'Exact match — click for fuzzy':'Fuzzy match — click for exact'}">${mode==='exact'?'✓ exact':'fuzzy'}</button>
        <button class="btn-rm" onclick="removeItem(${i})">×</button>
      </div>
    </li>`;
  }).join('');
  document.getElementById('items-ct').textContent=items.length+' item'+(items.length!==1?'s':'');
  renderFreqHints();
}
function addItem(){
  const inp=document.getElementById('new-item');const v=inp.value.trim();
  if(!v) return;if(!prefs) prefs={};if(!prefs.items) prefs.items=[];
  if(!itemNames().includes(v)){prefs.items.push(itemObj(v,'fuzzy'));renderItems();savePrefs('list').catch(()=>{});}
  inp.value='';inp.focus();
}
function removeItem(i){if(!prefs||!prefs.items) return;prefs.items.splice(i,1);renderItems();syncDealCheckboxes();savePrefs('list').catch(()=>{});}
function bulkImport(){
  const lines=document.getElementById('bulk-ta').value.split('\n').map(l=>l.trim()).filter(Boolean);
  if(!prefs) prefs={};if(!prefs.items) prefs.items=[];
  lines.forEach(l=>{if(!itemNames().includes(l)) prefs.items.push(itemObj(l,'fuzzy'));});
  renderItems();document.getElementById('bulk-ta').value='';syncDealCheckboxes();
  savePrefs('list').catch(()=>{});
}
function copyInboundAddr(){
  const addr=document.getElementById('inbound-addr-display').textContent.trim();
  const btn=document.getElementById('copy-inbound-btn');
  const flash=()=>{btn.textContent='Copied!';btn.style.color='var(--green)';setTimeout(()=>{btn.textContent='Copy';btn.style.color='';},2000);};
  if(navigator.clipboard&&window.isSecureContext){
    navigator.clipboard.writeText(addr).then(flash).catch(()=>{});
  } else {
    const ta=document.createElement('textarea');
    ta.value=addr;ta.style.position='fixed';ta.style.opacity='0';
    document.body.appendChild(ta);ta.select();
    try{document.execCommand('copy');flash();}catch(_){}
    document.body.removeChild(ta);
  }
}
function exportListDownload(){
  const names=itemNames();
  if(!names.length){alert('Your list is empty.');return;}
  const text=names.join('\n');
  const blob=new Blob([text],{type:'text/plain'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='shopping-list.txt';
  a.click();
  URL.revokeObjectURL(a.href);
}
async function exportListCopy(btn){
  const names=itemNames();
  if(!names.length){alert('Your list is empty.');return;}
  try{
    await navigator.clipboard.writeText(names.join('\n'));
    const orig=btn.textContent;
    btn.textContent='✓ Copied!';
    setTimeout(()=>btn.textContent=orig,2000);
  }catch(e){
    // Fallback for browsers that block clipboard without user gesture
    const ta=document.createElement('textarea');
    ta.value=names.join('\n');
    ta.style.position='fixed';ta.style.opacity='0';
    document.body.appendChild(ta);ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    const orig=btn.textContent;
    btn.textContent='✓ Copied!';
    setTimeout(()=>btn.textContent=orig,2000);
  }
}

// ═══════════════════════════════════════════════════════════════════
// ACCOUNT
// ═══════════════════════════════════════════════════════════════════
async function changePin(){
  const cur=getPin('.cur-pin'),nw=getPin('.new-pin');
  if(cur.length!==4||nw.length!==4){setMsg('pin-msg','Fill in both PINs.','err');return;}
  try{
    const res=await fetch(API+'/auth/change-pin',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({current_pin:cur,new_pin:nw})});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    setMsg('pin-msg','✓ PIN updated','ok');clrPin('.cur-pin');clrPin('.new-pin');
    setTimeout(()=>setMsg('pin-msg','',''),3000);
  }catch(e){setMsg('pin-msg',e.message,'err');}
}
async function deleteAccount(){
  closeOv('del-overlay');
  try{await fetch(API+'/user/account',{method:'DELETE',headers:{'Authorization':'Bearer '+token}});}catch(_){}
  doLogout();
}
async function sendTestEmail(){
  const btn=document.getElementById('btn-test-email');
  const msgEl=document.getElementById('test-email-msg');
  btn.disabled=true;msgEl.textContent='Sending…';msgEl.className='';
  try{
    const res=await fetch(API+'/user/test-email',{method:'POST',headers:{'Authorization':'Bearer '+token}});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    msgEl.textContent='✓ '+data.message;msgEl.style.color='var(--green)';
    setTimeout(()=>{msgEl.textContent='';},5000);
  }catch(e){msgEl.textContent='✗ '+e.message;msgEl.style.color='var(--red)';}
  finally{btn.disabled=false;}
}

// ═══════════════════════════════════════════════════════════════════
// DEALS — PRELOAD + RENDER
// ═══════════════════════════════════════════════════════════════════
const DEPT_EMOJI={
  'Meat':'🥩','Produce':'🥦','Dairy':'🧀','Deli':'🥪','Bakery':'🍞',
  'Frozen':'🧊','Seafood':'🐟','Beverages':'🥤','Floral':'💐',
  'Pharmacy':'💊','Health & Beauty':'💄','Household':'🧹','Baby':'👶',
  'Pet':'🐾','Pets':'🐾','Natural Foods':'🌿','Snacks':'🍿',
  'Canned & Packaged':'🥫','Breakfast':'🥞','Condiments':'🫙',
  'International':'🌍','Pasta & Grains':'🍝','default':'🏷️'
};
function deptEmoji(d){
  if(!d) return DEPT_EMOJI.default;
  for(const[k,v] of Object.entries(DEPT_EMOJI)){if(d.toLowerCase().includes(k.toLowerCase()))return v;}
  return DEPT_EMOJI.default;
}

// Preload: called on login and on store change. Skips if same store & already loaded.
// Helper: is a deal a BOGO — trust server-side flag first, fall back to title/categories
function isBogo(d){
  if(d.is_bogo===true) return true;
  if(Array.isArray(d.categories) && d.categories.includes('bogo')) return true;
  const combined=((d.title||'')+' '+(d.savings||'')).toLowerCase();
  return /\bbogo\b|b1g1|b2g1|buy \d.{0,8}get \d|buy one.{0,10}get one/.test(combined);
}
// Helper: is a deal "extra savings"
function isExtra(d){
  return d.saving_type==='ExtraSavings' || d.saving_type==='Stacked' || d.is_extra===true;
}
// Helper: is a deal a digital coupon
function isCoupon(d){
  return d.saving_type==='DigitalCoupon' || d.has_coupon;
}

async function preloadDeals() {
  const sid=prefs?.store_id;
  if(!sid) return;
  // Only reload if we don't have deals yet for this store,
  // or if the server's updated_at timestamp is newer than what we last loaded.
  // We do a lightweight check: if _allDeals is empty or store changed, always load.
  // Otherwise, reload only when navigating to deals/matches if the server timestamp changed.
  if(_dealsStoreId !== sid || !_allDeals.length) {
    await loadDeals(false);
  } else {
    // Already have deals for this store — check if server has newer data
    const cachedTs = localStorage.getItem('pdc_deals_ts_'+sid) || '';
    if(_dealsUpdated && cachedTs === _dealsUpdated) return; // still fresh
    await loadDeals(false);
  }
}

async function loadDeals(forceRefresh=false){
  const sid=prefs?.store_id;
  if(!sid){
    document.getElementById('deals-err').textContent='Set your store first (Store panel).';
    document.getElementById('deals-err').style.display='';
    return;
  }
  // Show loading state
  document.getElementById('deals-err').style.display='none';
  document.getElementById('deals-browser').style.display='none';
  document.getElementById('deals-loading').style.display='block';
  const refreshBtn=document.getElementById('btn-refresh-deals');
  if(refreshBtn) refreshBtn.disabled=true;

  try{
    const res=await fetch(API+'/deals?store_id='+encodeURIComponent(sid),{headers:{'Authorization':'Bearer '+token}});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed to load deals');

    _allDeals     = data.deals||[];
    _dealCounts   = data.counts||{};
    _deptCounts   = data.dept_counts||{};
    _dealsUpdated = data.updated_at||'';
    _dealsStoreId = sid;
    _savingTypes  = data.saving_types||[];

    // Cache the timestamp so preloadDeals can skip reloading when data hasn't changed
    if(_dealsUpdated) localStorage.setItem('pdc_deals_ts_'+sid, _dealsUpdated);

    // Populate Savings filter counts using correct saving_type mappings
    document.getElementById('fcnt-all').textContent    = _allDeals.length||'';
    document.getElementById('fcnt-weekly').textContent = _allDeals.filter(d=>d.saving_type==='WeeklyAd'&&!isBogo(d)).length||'';
    document.getElementById('fcnt-bogo').textContent   = _allDeals.filter(d=>isBogo(d)).length||'';
    document.getElementById('fcnt-coupon').textContent = _allDeals.filter(d=>isCoupon(d)).length||'';
    document.getElementById('fcnt-extra').textContent  = _allDeals.filter(d=>isExtra(d)).length||'';

    // Validity sublabels on banner
    const wa=_allDeals.find(d=>d.saving_type==='WeeklyAd'&&(d.valid_from||d.valid_thru));
    const ex=_allDeals.find(d=>d.is_extra&&(d.valid_from||d.valid_thru));

    // Validity banner
    if(wa){
      const vb=document.getElementById('deals-vbar');
      vb.innerHTML=`📅 Weekly Ad: Valid <strong>${wa.valid_from}</strong> to <strong>${wa.valid_thru}</strong> &nbsp;·&nbsp; ${_allDeals.length} total deals`;
      vb.classList.add('vis');
    }

    // Dept filters
    buildDeptFilters('dept-deals', _deptCounts, 'renderDeals');

    const storeName=prefs?.store_name||('Store #'+sid);
    document.getElementById('deals-sub').textContent=`${storeName} · ${_allDeals.length} all deals`;

    document.getElementById('deals-loading').style.display='none';
    document.getElementById('deals-browser').style.display='';
    document.getElementById('deals-q').value='';
    renderDeals();

    // After deals load, compute matches
    computeMatches();

  }catch(e){
    document.getElementById('deals-loading').style.display='none';
    document.getElementById('deals-err').textContent=e.message;
    document.getElementById('deals-err').style.display='';
  }finally{
    if(refreshBtn) refreshBtn.disabled=false;
  }
}

function buildDeptFilters(containerId, deptCounts, renderFn){
  const el=document.getElementById(containerId);
  if(!el) return;
  const depts=Object.keys(deptCounts).sort();
  el.innerHTML=depts.map(dept=>{
    const label=decodeEntities(dept);
    return `<label class="filter-opt">
      <input type="checkbox" class="dept-cb" data-container="${containerId}" data-dept="${escH(dept)}" onchange="${renderFn}()">
      <div><div class="filter-opt-label">${escH(label)}</div></div>
      <span class="filter-opt-cnt">${deptCounts[dept]}</span>
    </label>`;
  }).join('');
}

function getCheckedDepts(cid){
  return [...document.querySelectorAll(`#${cid} .dept-cb:checked`)].map(c=>c.dataset.dept);
}
function clearDeptCB(cid, dept){
  const el=document.querySelector(`#${cid} .dept-cb[data-dept="${dept}"]`);
  if(el) el.checked=false;
}

// Savings filter: selecting one unchecks others; if none checked, default to Weekly ad
function onSavingsFilter(changed){
  const ids=['f-all','f-weekly','f-bogo','f-coupon','f-extra'];
  const els=Object.fromEntries(ids.map(id=>[id,document.getElementById(id)]));
  if(changed==='all' && els['f-all'].checked){
    // All deals — uncheck everything else
    ['f-weekly','f-bogo','f-coupon','f-extra'].forEach(id=>els[id].checked=false);
  } else if(changed!=='all'){
    els['f-all'].checked=false;
    // If nothing checked, revert to Weekly ad
    const anyChecked=['f-weekly','f-bogo','f-coupon','f-extra'].some(id=>els[id].checked);
    if(!anyChecked) els['f-weekly'].checked=true;
  }
  renderDeals();
}

// ── Sort helper ───────────────────────────────────────────────────────────────
function applySortOrder(arr, sortVal) {
  const a = arr.slice(); // don't mutate original
  if (sortVal === 'name-az') {
    a.sort((x,y) => (x.title||'').localeCompare(y.title||''));
  } else if (sortVal === 'name-za') {
    a.sort((x,y) => (y.title||'').localeCompare(x.title||''));
  } else if (sortVal === 'savings-desc') {
    a.sort((x,y) => dealSortSavings(y) - dealSortSavings(x));
  } else if (sortVal === 'score-desc') {
    a.sort((x,y) => (y.match_score||0) - (x.match_score||0));
  }
  // 'default' — leave in original order
  return a;
}

function renderDeals(){
  const q    =(document.getElementById('deals-q').value||'').toLowerCase();
  const fAll =document.getElementById('f-all').checked;
  const fW   =document.getElementById('f-weekly').checked;
  const fBogo=document.getElementById('f-bogo').checked;
  const fCo  =document.getElementById('f-coupon').checked;
  const fE   =document.getElementById('f-extra').checked;
  const depts=getCheckedDepts('dept-deals');

  let deals=_allDeals.filter(d=>{
    if(fAll) return true;
    if(fBogo && isBogo(d))   return true;
    if(fCo   && isCoupon(d)) return true;
    if(fE    && isExtra(d))  return true;
    if(fW    && d.saving_type==='WeeklyAd' && !isBogo(d)) return true;
    return false;
  });
  if(depts.length) deals=deals.filter(d=>depts.includes(d.department||''));
  if(q) deals=deals.filter(d=>
    (d.title||'').toLowerCase().includes(q)||
    (d.description||'').toLowerCase().includes(q)||
    (d.brand||'').toLowerCase().includes(q)||
    (d.department||'').toLowerCase().includes(q)
  );

  document.getElementById('deals-meta').textContent=deals.length+' of '+_allDeals.length+' deals';

  // Active chips — dept filters only (savings are visible checkboxes)
  const chips=[];
  depts.forEach(d=>chips.push(decodeEntities(d)));
  document.getElementById('deals-chips').innerHTML=chips.map(lbl=>
    `<span class="chip" onclick="clearDeptCB('dept-deals','${escH(lbl)}');renderDeals()">${escH(lbl)} <span class="chip-x">×</span></span>`
  ).join('');

  const grid=document.getElementById('deals-grid');
  if(!deals.length){grid.innerHTML='<div class="empty"><div class="empty-icon">🔍</div>No deals match your filters.</div>';return;}
  const dealsSortVal = (document.getElementById('deals-sort')||{}).value || 'default';
  const sortedDeals = applySortOrder(deals, dealsSortVal);
  grid.innerHTML=sortedDeals.map(d=>dealCardHtml(d)).join('');
  syncDealCheckboxes();
  attachDealCBListeners();
}


// ── Deal type helpers ─────────────────────────────────────────────────────────
// Returns a small coloured tag showing the deal type on every card.
function dealTypeTag(d) {
  if (isBogo(d))              return `<span class="deal-type-tag bogo">BOGO</span>`;
  if (d.saving_type === 'StackedDeals') return `<span class="deal-type-tag stacked">Stacked</span>`;
  if (d.saving_type === 'ExtraSavings') return `<span class="deal-type-tag extra">Extra Savings</span>`;
  if (isCoupon(d))            return `<span class="deal-type-tag coupon">Coupon</span>`;
  if (d.saving_type === 'WeeklyAd')     return `<span class="deal-type-tag weekly">Weekly Ad</span>`;
  return '';
}

// For ExtraSavings and StackedDeals the `savings` field is a discount amount
// (e.g. "$0.99 off"), not a sale price. Prefix those with "Save" so the user
// isn't confused into thinking a $15 bottle of wine costs $0.99.
function savingsDisplay(d) {
  const s = decodeEntities(d.savings || '');
  if (!s) return '';
  const isDiscount = d.saving_type === 'ExtraSavings' ||
                     d.saving_type === 'StackedDeals'  ||
                     d.is_extra;
  // If the string already starts with "Save" or "save", don't double-prefix
  if (isDiscount && !/^save/i.test(s)) {
    return { text: 'Save ' + s, isDiscount: true };
  }
  return { text: s, isDiscount: false };
}

// Generate deal card HTML (checkbox overlay)
// ── Deal detail modal ─────────────────────────────────────────────────────────

// Human-readable labels for saving_type values from the Publix API
const SAVING_TYPE_LABEL = {
  WeeklyAd:        'Weekly Ad',
  AllDeals:        'All Deals',
  DigitalCoupon:   'Digital Coupon',
  PrintableCoupon: 'Printable Coupon',
  ExtraSavings:    'Extra Savings',
  StackedDeals:    'Stacked Deal',
};

// Build an inline SVG price history chart inside svgEl for the given deal + history.
// History dots are plotted as a scatter with a connecting polyline.
// Current week (newest) dot is highlighted green with a glow ring.
// A dashed amber line marks the best (lowest) price point.
function buildDealChart(svgEl, deal, history) {
  if (!history || !history.snapshots) return;

  const dealTitle = (deal.title || '').toLowerCase();
  const pts = [];

  // Collect historical appearances, oldest-first for left-to-right plotting
  const snaps = [...history.snapshots].reverse(); // API returns newest-first; reverse to chronological
  snaps.forEach(snap => {
    snap.deals.forEach(pastDeal => {
      if (fuzzyScore(dealTitle, (pastDeal.title || '').toLowerCase()) >= 75) {
        const amt = parseSavingsAmount(pastDeal.savings);
        if (amt !== null) {
          pts.push({ week: snap.week, amt, savings: pastDeal.savings });
        }
      }
    });
  });

  // Deduplicate by week (keep first match per week)
  const seen = new Set();
  const uniq = pts.filter(p => { if (seen.has(p.week)) return false; seen.add(p.week); return true; });

  const W   = Math.max(svgEl.getBoundingClientRect().width || 0, 240);
  const H   = 90;
  const PAD = { l: 36, r: 14, t: 12, b: 26 };

  if (uniq.length < 2) {
    svgEl.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svgEl.innerHTML = `<text x="${W/2}" y="${H/2}" text-anchor="middle" font-size="11" fill="#aaa" dy=".35em">Not enough history yet</text>`;
    return;
  }

  const amts   = uniq.map(p => p.amt);
  const minAmt = Math.min(...amts);
  const maxAmt = Math.max(...amts);
  const aRange = maxAmt - minAmt || 1;

  // Parse week strings to timestamps for linear x positioning
  const dates  = uniq.map(p => new Date(p.week).getTime());
  const minD   = Math.min(...dates);
  const maxD   = Math.max(...dates);
  const dRange = maxD - minD || 1;

  const cx = d => PAD.l + ((new Date(d).getTime() - minD) / dRange) * (W - PAD.l - PAD.r);
  // Lower price = better deal = higher on chart (inverted y)
  const cy = a => PAD.t + (1 - (a - minAmt) / aRange) * (H - PAD.t - PAD.b);

  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  let svg = '';

  // Axes
  svg += `<line x1="${PAD.l}" y1="${PAD.t}" x2="${PAD.l}" y2="${H-PAD.b}" stroke="#ddd8ce" stroke-width="1"/>`;
  svg += `<line x1="${PAD.l}" y1="${H-PAD.b}" x2="${W-PAD.r}" y2="${H-PAD.b}" stroke="#ddd8ce" stroke-width="1"/>`;

  // Y axis labels: best and worst price
  svg += `<text x="${PAD.l-4}" y="${cy(minAmt)}" text-anchor="end" font-size="8" fill="#aaa" dy=".35em">$${minAmt.toFixed(2)}</text>`;
  if (maxAmt !== minAmt)
    svg += `<text x="${PAD.l-4}" y="${cy(maxAmt)}" text-anchor="end" font-size="8" fill="#aaa" dy=".35em">$${maxAmt.toFixed(2)}</text>`;

  // Best-price dashed reference line (amber, subtle)
  const bestY = cy(minAmt);
  svg += `<line x1="${PAD.l}" y1="${bestY}" x2="${W-PAD.r}" y2="${bestY}" stroke="rgba(180,83,9,.25)" stroke-width="1" stroke-dasharray="3,4"/>`;

  // Month labels on x axis — one label per unique month, avoid crowding
  const seenM = new Set();
  uniq.forEach(p => {
    const d   = new Date(p.week);
    const mk  = `${d.getFullYear()}-${d.getMonth()}`;
    const x   = cx(p.week);
    if (!seenM.has(mk) && x > PAD.l + 10 && x < W - PAD.r - 10) {
      seenM.add(mk);
      svg += `<text x="${x}" y="${H-PAD.b+11}" text-anchor="middle" font-size="8" fill="#aaa">${months[d.getMonth()]}</text>`;
    }
  });

  // Connecting polyline (very subtle)
  const linePts = uniq.map(p => `${cx(p.week).toFixed(1)},${cy(p.amt).toFixed(1)}`).join(' ');
  svg += `<polyline points="${linePts}" fill="none" stroke="rgba(26,107,60,.15)" stroke-width="1.5" stroke-linejoin="round"/>`;

  // Historical dots
  uniq.forEach((p, i) => {
    const x        = cx(p.week).toFixed(1);
    const y        = cy(p.amt).toFixed(1);
    const isCur    = i === uniq.length - 1;
    if (isCur) {
      // Glow ring
      svg += `<circle cx="${x}" cy="${y}" r="9" fill="#1a6b3c" opacity=".13"/>`;
      // Filled dot
      svg += `<circle cx="${x}" cy="${y}" r="5.5" fill="#1a6b3c"/>`;
      // Price label above
      svg += `<text x="${x}" y="${parseFloat(y)-10}" text-anchor="middle" font-size="8.5" fill="#1a6b3c" font-weight="700">$${p.amt.toFixed(2)}</text>`;
    } else {
      svg += `<circle cx="${x}" cy="${y}" r="3.5" fill="var(--green-dim)" stroke="#1a6b3c" stroke-width="1.5"/>`;
    }
  });

  svgEl.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svgEl.innerHTML = svg;
}

let _modalDeal = null;

function openDealModal(dealId) {
  const d = _allDeals.find(x => x.id === dealId);
  if (!d) return;
  _modalDeal = d;

  const emoji   = deptEmoji(d.department);
  const title   = decodeEntities(d.title);
  const desc    = decodeEntities(d.description);
  const savings = decodeEntities(d.savings);
  const saveLine= decodeEntities(d.save_line);
  const fine    = decodeEntities(d.fine_print);

  // ── Image / placeholder ───────────────────────────────────────────────────
  const img = d.image_url
    ? `<img class="deal-modal-img" src="${escH(d.image_url)}" alt="${escH(title)}"
         onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">
       <div class="deal-modal-img-ph" style="display:none">${emoji}</div>`
    : `<div class="deal-modal-img-ph">${emoji}</div>`;

  // ── Badges ────────────────────────────────────────────────────────────────
  const badges = [];
  if (d.is_publix_brand) badges.push(`<span class="badge badge-publix">Publix Brand</span>`);
  if (d.is_bogo)         badges.push(`<span class="badge badge-bogo">BOGO</span>`);
  if (d.has_coupon)      badges.push(`<span class="badge badge-coupon">Digital Coupon</span>`);
  if (d.is_extra)        badges.push(`<span class="badge badge-extra">Extra Savings</span>`);
  if (d.is_stacked)      badges.push(`<span class="badge badge-stacked">Stacked Deal</span>`);
  const histBadge = computeBadge(d, _dealHistory);
  if (histBadge) badges.push(`<span class="badge badge-${histBadge.type}">${histBadge.label}</span>`);

  // ── Structured data rows (Option C influence) ─────────────────────────────
  const rows = [];
  const dr = (lbl, val, cls='') =>
    `<div class="dm-data-row"><span class="dm-data-lbl">${lbl}</span><span class="dm-data-val${cls?' '+cls:''}">${val}</span></div>`;

  if (d.department)
    rows.push(dr('Department', escH(decodeEntities(d.department))));
  if (d.brand)
    rows.push(dr('Brand', escH(decodeEntities(d.brand))));
  if (d.valid_from || d.valid_thru)
    rows.push(dr('Valid', `${escH(decodeEntities(d.valid_from))} – ${escH(decodeEntities(d.valid_thru))}`));
  if (d.saving_type)
    rows.push(dr('Deal type', escH(SAVING_TYPE_LABEL[d.saving_type] || d.saving_type)));
  if (fine)
    rows.push(dr('Fine print', escH(fine), 'fine'));

  // Frequency hint — only if we have enough history
  const freqHint = computeFreqHint(title, _dealHistory);
  if (freqHint)
    rows.push(dr('On sale', escH(freqHint), 'freq'));

  // ── Actions ───────────────────────────────────────────────────────────────
  const actions = [];
  if (d.has_coupon) {
    const url = `https://www.publix.com/savings/digital-coupons${d.coupon_id ? '?cid=' + d.coupon_id : ''}`;
    actions.push(`<a class="btn-clip" href="${escH(url)}" target="_blank" rel="noopener">✂️ Clip Coupon</a>`);
  }
  const onList = itemNames().map(n => n.toLowerCase()).includes(title.toLowerCase());
  actions.push(`<button class="btn-load" style="padding:8px 16px;font-size:13px" onclick="modalToggleList()"
    id="modal-list-btn">${onList ? '✓ On My List' : '+ Add to My List'}</button>`);

  // ── Timeline: only show section if history is loaded ──────────────────────
  const validCaption = (d.valid_from || d.valid_thru)
    ? `📅 Week of ${escH(decodeEntities(d.valid_from))}${d.valid_thru ? ' – ' + escH(decodeEntities(d.valid_thru)) : ''}`
    : '';

  const timelineHtml = _dealHistory
    ? `<div class="dm-timeline">
        <div class="dm-timeline-hd">Price History — past 12 months</div>
        <svg id="dm-chart-svg" class="dm-chart"></svg>
        ${validCaption ? `<div class="dm-timeline-caption">${validCaption}</div>` : ''}
      </div>`
    : '';

  // ── Render ────────────────────────────────────────────────────────────────
  document.getElementById('deal-modal-content').innerHTML = `
    ${img}
    <div class="deal-modal-body">
      ${dealTypeTag(d)}
      <div class="deal-modal-title">${escH(title)}</div>
      ${desc ? `<div class="deal-modal-desc">${escH(desc)}</div>` : ''}
      <div class="deal-modal-price">${escH(savings)}</div>
      ${saveLine ? `<div class="deal-modal-save">${escH(saveLine)}</div>` : ''}
      ${badges.length ? `<div class="deal-card-badges" style="margin-bottom:10px">${badges.join('')}</div>` : ''}
      ${rows.length ? `<div class="dm-data-rows">${rows.join('')}</div>` : ''}
      ${actions.length ? `<div class="deal-modal-actions">${actions.join('')}</div>` : ''}
      ${timelineHtml}
    </div>`;

  document.getElementById('deal-modal-overlay').classList.add('vis');
  document.body.style.overflow = 'hidden';

  // Draw chart after layout paint so SVG has real dimensions
  if (_dealHistory) {
    requestAnimationFrame(() => {
      const svgEl = document.getElementById('dm-chart-svg');
      if (svgEl) buildDealChart(svgEl, d, _dealHistory);
    });
  }
}

function closeDealModal() {
  document.getElementById('deal-modal-overlay').classList.remove('vis');
  document.body.style.overflow = '';
  _modalDeal = null;
}

function modalToggleList() {
  if (!_modalDeal) return;
  const title = decodeEntities(_modalDeal.title);
  if (!prefs) prefs = {};
  if (!prefs.items) prefs.items = [];
  const names = itemNames().map(n => n.toLowerCase());
  if (names.includes(title.toLowerCase())) {
    prefs.items = prefs.items.filter(i => itemName(i).toLowerCase() !== title.toLowerCase());
  } else {
    prefs.items.push(itemObj(title, 'fuzzy'));
  }
  renderItems();
  syncDealCheckboxes();
  savePrefs('list').catch(() => {});
  computeMatches();
  // Update button label in modal
  const onList = itemNames().map(n => n.toLowerCase()).includes(title.toLowerCase());
  const btn = document.getElementById('modal-list-btn');
  if (btn) btn.textContent = onList ? '✓ On My List' : '+ Add to My List';
}

function dealCardHtml(d){
  const emoji=deptEmoji(d.department);
  const title=decodeEntities(d.title);
  const desc=decodeEntities(d.description);
  const finePrint=decodeEntities(d.fine_print);
  const saveLine=decodeEntities(d.save_line);
  const sv=savingsDisplay(d);
  const img=d.image_url
    ?`<img class="deal-card-img" src="${escH(d.image_url)}" alt="${escH(title)}" loading="lazy"
        onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">
       <div class="deal-card-img-ph" style="display:none">${emoji}</div>`
    :`<div class="deal-card-img-ph">${emoji}</div>`;
  const badges=[];
  if(d.is_publix_brand) badges.push(`<span class="badge badge-publix">Publix</span>`);
  if(d.has_coupon)      badges.push(`<span class="badge badge-coupon">Coupon</span>`);
  if(d.is_extra)        badges.push(`<span class="badge badge-extra">Extra</span>`);
  if(d.is_stacked)      badges.push(`<span class="badge badge-stacked">Stacked</span>`);
  const histBadge = computeBadge(d, _dealHistory);
  if(histBadge) badges.push(`<span class="badge badge-${histBadge.type}">${histBadge.label}</span>`);
  const cbId=`dcb-${d.id}`;
  return `<div class="deal-card" onclick="if(!event.target.closest('.deal-add-wrap'))openDealModal('${escH(d.id)}')">
    <div class="deal-add-wrap">
      <input type="checkbox" class="deal-add-cb" id="${cbId}" data-title="${escH(title)}" data-id="${escH(d.id)}">
      <label class="deal-add-lbl" for="${cbId}" title="Add to My List"></label>
    </div>
    ${img}
    <div class="deal-card-body">
      ${dealTypeTag(d)}
      ${d.department?`<div class="deal-card-dept">${escH(decodeEntities(d.department))}</div>`:''}
      <div class="deal-card-title">${escH(title)}</div>
      ${desc?`<div class="deal-card-desc">${escH(desc)}</div>`:''}
      <div class="deal-card-price${sv.isDiscount?' is-discount':''}">${escH(sv.text)}</div>
      ${saveLine?`<div class="deal-card-save">${escH(saveLine)}</div>`:''}
      ${(d.valid_from||d.valid_thru)?`<div class="deal-card-valid">📅 Valid ${escH(decodeEntities(d.valid_from))}–${escH(decodeEntities(d.valid_thru))}</div>`:''}
      ${finePrint?`<div class="deal-card-fine">${escH(finePrint)}</div>`:''}
      ${badges.length?`<div class="deal-card-badges">${badges.join('')}</div>`:''}
      ${d.has_coupon?`<a class="btn-clip" href="https://www.publix.com/savings/digital-coupons${d.coupon_id?'?cid='+d.coupon_id:''}" target="_blank" rel="noopener">✂️ Clip Coupon</a>`:''}
    </div></div>`;
}

// Sync checkbox states to match prefs.items
function syncDealCheckboxes(){
  const names=itemNames().map(s=>s.toLowerCase());
  document.querySelectorAll('.deal-add-cb').forEach(cb=>{
    const title=(cb.dataset.title||'').toLowerCase();
    cb.checked = names.includes(title);
  });
}

// Attach listeners to deal card checkboxes (called after render)
function attachDealCBListeners(){
  document.querySelectorAll('.deal-add-cb').forEach(cb=>{
    cb.addEventListener('change', ()=>{
      const title=cb.dataset.title||'';
      if(!prefs) prefs={};if(!prefs.items) prefs.items=[];
      if(cb.checked){
        if(!itemNames().includes(title)) prefs.items.push(itemObj(title,'fuzzy'));
      } else {
        prefs.items=prefs.items.filter(i=>itemName(i)!==title);
      }
      renderItems();
      savePrefs('list').catch(()=>{});
      // Recompute matches after list changes
      computeMatches();
    });
  });
}

// ═══════════════════════════════════════════════════════════════════
// MATCHES
// ═══════════════════════════════════════════════════════════════════
function computeMatches(){
  if(!_allDeals.length) return;
  const items  =(prefs?.items||[]);
  const thresh =parseInt(document.getElementById('threshold').value)||75;

  const seen=new Set();
  _allMatches=[];
  for(const deal of _allDeals){
    const title=(deal.title||'').toLowerCase();
    for(const item of items){
      const name  = itemName(item).toLowerCase();
      const mode  = itemMode(item);
      const score = matchScore(name, title, mode);
      // exact-mode items use a fixed threshold of 70 (balanced 50/50 weights need
      // a slightly lower bar); fuzzy-mode items use the slider threshold
      const effectiveThresh = (mode === 'exact') ? Math.min(thresh, 70) : thresh;
      if(score>=effectiveThresh){
        const key=deal.id||title;
        if(!seen.has(key)){
          seen.add(key);
          _allMatches.push({...deal, my_item:itemName(item), my_item_mode:mode, match_score:score});
        }
      }
    }
  }
  _allMatches.sort((a,b)=>b.match_score-a.match_score);

  _matchDeptCts={};
  _allMatches.forEach(d=>{const dep=(d.department||'Other').trim();_matchDeptCts[dep]=(_matchDeptCts[dep]||0)+1;});

  buildDeptFilters('dept-matches',_matchDeptCts,'renderMatches');

  // Update match filter counts using same mappings as Deals page
  document.getElementById('mfcnt-all').textContent    = _allMatches.length||'';
  document.getElementById('mfcnt-weekly').textContent = _allMatches.filter(d=>d.saving_type==='WeeklyAd').length||'';
  document.getElementById('mfcnt-bogo').textContent   = _allMatches.filter(d=>isBogo(d)).length||'';
  document.getElementById('mfcnt-coupon').textContent = _allMatches.filter(d=>isCoupon(d)).length||'';
  document.getElementById('mfcnt-extra').textContent  = _allMatches.filter(d=>isExtra(d)).length||'';

  // Validity info
  const firstDeal=_allDeals.find(d=>d.valid_from||d.valid_thru);
  const banner=document.getElementById('matches-banner');
  if(firstDeal){
    banner.innerHTML=`📅 Week of <strong>${firstDeal.valid_from}–${firstDeal.valid_thru}</strong> &nbsp;·&nbsp; <strong>${_allMatches.length}</strong> match${_allMatches.length!==1?'es':''} from your list`;
  } else {
    banner.innerHTML=`<strong>${_allMatches.length}</strong> match${_allMatches.length!==1?'es':''} from your list`;
  }

  document.getElementById('matches-err').style.display='none';
  document.getElementById('matches-loading').style.display='none';
  document.getElementById('matches-browser').style.display=_allMatches.length||items.length?'':'none';
  renderMatches();
}

function onThresholdChange(){
  // Threshold is per user — save then recompute
  savePrefs('matching').catch(()=>{});
  computeMatches();
}

// ── Scoring algorithm ─────────────────────────────────────────────────────────
// matchScore(item, title, mode) → 0–100
//
// Balances two signals:
//   precision  = fraction of item words found in title  (did we find what we want?)
//   coverage   = fraction of title words matched by item (is the title actually about this?)
//
// "mode" controls the coverage weight:
//   'fuzzy' → precision 70% + coverage 30%  — good for short terms like "chicken"
//   'exact' → precision 40% + coverage 60%  — penalises long bundle titles heavily
//
// This fixes the token_set_ratio problem where "publix chicken breast" scored 100
// against a 14-word Knorr bundle because all 3 item words appeared somewhere in it.
// With coverage factored in, that deal scores ~76 (border) vs a 7-word chicken
// breast deal scoring ~83 (clear pass).
//
// The history-badge fuzzyScore calls below are title-to-title comparisons and are
// intentionally kept as precision-only — they don't have the same false-positive problem.

function matchScore(item, title, mode) {
  if (!item || !title) return 0;
  const iT = item.split(/\s+/).filter(Boolean);
  const tT = title.split(/\s+/).filter(Boolean);
  if (!iT.length || !tT.length) return 0;

  // Exact substring shortcut — only applies when title IS the item (very close match)
  if (title === item) return 100;

  let matched = 0;
  for (const iw of iT) {
    if (tT.some(tw => tw.includes(iw) || iw.includes(tw))) matched++;
  }

  const precision = matched / iT.length;
  const coverage  = matched / tT.length;

  // fuzzy: precision-heavy (65/35) — short terms like "chicken" score well
  // exact: balanced (50/50)  — penalises long bundle titles; threshold auto-drops to 70
  const pWeight = (mode === 'exact') ? 0.5 : 0.65;
  const cWeight = (mode === 'exact') ? 0.5 : 0.35;

  return Math.round((precision * pWeight + coverage * cWeight) * 100);
}

// Legacy name kept for history-badge calls (title-to-title, precision-only is correct there)
function fuzzyScore(item, title) {
  if (!item || !title) return 0;
  if (title.includes(item)) return 100;
  const iT = item.split(/\s+/).filter(Boolean);
  const tT = title.split(/\s+/).filter(Boolean);
  if (!iT.length) return 0;
  let m = 0;
  for (const t of iT) { if (tT.some(tt => tt.includes(t))) m++; }
  return Math.round((m / iT.length) * 100);
}

function onMatchFilter(changed){
  const ids=['mf-all','mf-weekly','mf-bogo','mf-coupon','mf-extra'];
  const els=Object.fromEntries(ids.map(id=>[id,document.getElementById(id)]));
  if(changed==='all' && els['mf-all'].checked){
    // "All" checked → uncheck specifics
    ['mf-weekly','mf-bogo','mf-coupon','mf-extra'].forEach(id=>els[id].checked=false);
  } else if(changed!=='all'){
    // A specific filter changed → uncheck "All"
    els['mf-all'].checked=false;
    // If nothing is checked, fall back to "All" (matches are already personal — no reason to hide)
    const anyChecked=['mf-weekly','mf-bogo','mf-coupon','mf-extra'].some(id=>els[id].checked);
    if(!anyChecked) els['mf-all'].checked=true;
  }
  renderMatches();
}

function renderMatches(){
  const q     =(document.getElementById('matches-q').value||'').toLowerCase();
  const mfAll =document.getElementById('mf-all').checked;
  const mfW   =document.getElementById('mf-weekly').checked;
  const mfBogo=document.getElementById('mf-bogo').checked;
  const mfCo  =document.getElementById('mf-coupon').checked;
  const mfE   =document.getElementById('mf-extra').checked;
  const depts =getCheckedDepts('dept-matches');

  let matches=_allMatches.filter(d=>{
    if(mfAll) return true;
    if(mfBogo && isBogo(d))   return true;
    if(mfCo   && isCoupon(d)) return true;
    if(mfE    && isExtra(d))  return true;
    // "Weekly ad" includes BOGOs that are on the weekly ad — they're weekly deals too
    if(mfW    && d.saving_type==='WeeklyAd') return true;
    return false;
  });
  if(depts.length) matches=matches.filter(d=>depts.includes(d.department||''));
  if(q) matches=matches.filter(d=>
    (d.title||'').toLowerCase().includes(q)||
    (d.my_item||'').toLowerCase().includes(q)
  );

  document.getElementById('matches-meta').textContent=matches.length+' match'+(matches.length!==1?'es':'')+' shown';

  // Quality banner
  const bannerEl=document.getElementById('quality-banner');
  if(bannerEl){
    if(_dealHistory && (_dealHistory.num_weeks||0) >= HIST_MIN.banner && matches.length){
      const bannerText=buildQualityBanner(matches,_dealHistory);
      if(bannerText){
        bannerEl.innerHTML=`<div class="quality-banner-hd">This week's highlights</div>${bannerText}`;
        bannerEl.className='quality-banner';bannerEl.style.display='';
      } else { bannerEl.style.display='none'; }
    } else { bannerEl.style.display='none'; }
  }

  const chips=[];
  depts.forEach(d=>chips.push(decodeEntities(d)));
  document.getElementById('matches-chips').innerHTML=chips.map(lbl=>
    `<span class="chip" onclick="clearDeptCB('dept-matches','${escH(lbl)}');renderMatches()">${escH(lbl)} <span class="chip-x">×</span></span>`
  ).join('');

  const grid=document.getElementById('matches-grid');
  if(!matches.length){
    const items=prefs?.items||[];
    const msg=!items.length
      ?'Add items to your shopping list first.'
      :`No matches found at threshold ${document.getElementById('threshold').value}. Try lowering the sensitivity.`;
    grid.innerHTML=`<div class="empty"><div class="empty-icon">🔍</div>${msg}</div>`;
    return;
  }
  const matchesSortVal = (document.getElementById('matches-sort')||{}).value || 'score-desc';
  const sortedMatches = applySortOrder(matches, matchesSortVal);
  grid.innerHTML=sortedMatches.map(d=>{
    const emoji=deptEmoji(d.department);
    const title=decodeEntities(d.title);
    const desc=decodeEntities(d.description);
    const sv=savingsDisplay(d);
    const saveLine=decodeEntities(d.save_line);
    const img=d.image_url
      ?`<img class="match-card-img" src="${escH(d.image_url)}" alt="${escH(title)}" loading="lazy"
          onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">
         <div class="match-card-img-ph" style="display:none">${emoji}</div>`
      :`<div class="match-card-img-ph">${emoji}</div>`;
    return `<div class="match-card" onclick="if(!event.target.closest('.btn-clip'))openDealModal('${escH(d.id)}')">${img}
      <div class="match-card-body">
        ${dealTypeTag(d)}
        <div class="match-title">${escH(title)}</div>
        ${desc?`<div class="match-desc">${escH(desc)}</div>`:''}
        <div class="match-price${sv.isDiscount?' is-discount':''}">${escH(sv.text)}</div>
        ${saveLine?`<div class="match-save">${escH(saveLine)}</div>`:''}
        ${(()=>{const hb=computeBadge(d,_dealHistory);return hb?`<span class="badge badge-${hb.type}">${hb.label}</span>`:'';})()}
        ${(d.valid_from||d.valid_thru)?`<div class="match-valid">📅 Valid ${escH(decodeEntities(d.valid_from))}–${escH(decodeEntities(d.valid_thru))}</div>`:''}
        ${d.my_item_mode==='exact'
          ? `<div class="match-reason exact">✓ exact match</div>`
          : `<div class="match-reason">matched: ${escH(d.my_item)}</div>`
        }
        <div class="match-score">${d.match_score}% match${(()=>{
          const iT=(d.my_item||'').toLowerCase().split(/\s+/).filter(Boolean);
          const tT=(d.title||'').toLowerCase().split(/\s+/).filter(Boolean);
          if(!iT.length||!tT.length) return '';
          let m=0;for(const iw of iT){if(tT.some(tw=>tw.includes(iw)||iw.includes(tw)))m++;}
          return ` · ${m}/${tT.length} title words`;
        })()}</div>
        ${d.has_coupon?`<a class="btn-clip" href="https://www.publix.com/savings/digital-coupons${d.coupon_id?'?cid='+d.coupon_id:''}" target="_blank" rel="noopener">✂️ Clip Coupon</a>`:''}
      </div></div>`;
  }).join('');
}

// ═══════════════════════════════════════════════════════════════════
// ADMIN
// ═══════════════════════════════════════════════════════════════════
// ── Admin sidebar navigation ─────────────────────────────────────────────────
let _adminActivePage = 'users';
function adminNav(name){
  _adminActivePage = name;
  ['users','reports','logging','inbound'].forEach(t=>{
    document.getElementById('anav-'+t).classList.toggle('active', t===name);
    document.getElementById('apage-'+t).classList.toggle('active', t===name);
  });
  // Lazy-load on first visit
  if(name==='reports'){
    const sb=document.getElementById('admin-stats-body');
    if(sb && (sb.textContent.includes('Loading')||sb.textContent.trim()==='')) adminLoadStats();
  }
  if(name==='logging'){
    const le=document.getElementById('admin-logs-el');
    if(le && (le.textContent.includes('Loading')||le.textContent.trim()==='')) adminLoadLogs();
  }
  if(name==='inbound'){
    const iw=document.getElementById('inbound-log-wrap');
    if(iw && iw.textContent.includes('Click Refresh')) adminLoadInboundLogs();
  }
}

// ── Email Import (inbound) log viewer ────────────────────────────────────────
let _allInboundLogs = [];
const INBOUND_ACTION_LABELS = {
  'inbound-webhook-received':  {icon:'📨', label:'Webhook received',    color:'var(--ink)'},
  'inbound-sig-fail':          {icon:'🔐', label:'Signature failed',     color:'var(--red)'},
  'inbound-sender-extracted':  {icon:'📬', label:'Sender identified',    color:'var(--ink)'},
  'inbound-no-from':           {icon:'⚠️', label:'No sender',           color:'var(--amber)'},
  'inbound-wrong-dest':        {icon:'🎯', label:'Wrong destination',    color:'var(--amber)'},
  'inbound-user-matched':      {icon:'✅', label:'User matched',         color:'var(--green)'},
  'inbound-no-user':           {icon:'👤', label:'User not found',       color:'var(--red)'},
  'inbound-user-lookup-error': {icon:'💥', label:'Lookup error',         color:'var(--red)'},
  'inbound-notify-scan-error': {icon:'💥', label:'Scan error',           color:'var(--red)'},
  'inbound-fetching-body':     {icon:'⬇️', label:'Fetching email body',  color:'var(--ink)'},
  'inbound-fetch-failed':      {icon:'❌', label:'Fetch failed',          color:'var(--red)'},
  'inbound-config-error':      {icon:'⚙️', label:'Config error',         color:'var(--red)'},
  'inbound-html-parsed':       {icon:'🔍', label:'HTML parsed',          color:'var(--ink)'},
  'inbound-no-items':          {icon:'📭', label:'No items found',       color:'var(--amber)'},
  'inbound-list-imported':     {icon:'🛒', label:'Items imported',       color:'var(--green)'},
};

async function adminLoadInboundLogs(){
  const wrap = document.getElementById('inbound-log-wrap');
  wrap.innerHTML = '<div style="color:var(--ink-soft);font-size:13px;padding:12px">Loading…</div>';
  const sender = (document.getElementById('inbound-sender-filter').value || '').trim();
  const qs = sender ? `?sender=${encodeURIComponent(sender)}&limit=300` : '?limit=300';
  try{
    const res  = await fetch(API+'/admin/inbound-logs'+qs, {headers:adminHdrs()});
    const data = await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    _allInboundLogs = data.logs || [];
    adminRenderInboundLogs(sender);
  }catch(e){
    wrap.innerHTML = `<div style="color:var(--red);font-size:13px;padding:12px">Error: ${escH(e.message)}</div>`;
  }
}

function adminRenderInboundLogs(senderFilter){
  const wrap = document.getElementById('inbound-log-wrap');
  const logs = _allInboundLogs;
  if(!logs.length){
    const hint = senderFilter
      ? `No inbound log entries found for <strong>${escH(senderFilter)}</strong>. Check the address matches the forwarding email exactly.`
      : 'No inbound email events logged yet. Forward a Publix My List email to trigger the webhook.';
    wrap.innerHTML = `<div style="color:var(--ink-soft);font-size:13px;padding:14px">${hint}</div>`;
    return;
  }

  // Group logs by email_id so each forwarded email is a collapsible chain
  const chains = {};
  const order  = [];
  logs.forEach(l => {
    const key = l.email_id || ('no-id-' + (l.sender || l.user || l.ts));
    if(!chains[key]){ chains[key]=[]; order.push(key); }
    chains[key].push(l);
  });

  const rows = order.map((key, ci) => {
    const entries = chains[key];
    const first   = entries[entries.length-1]; // oldest first
    const last    = entries[0];                // newest first
    const sender  = first.sender || last.sender || last.user || '?';
    const outcome = last.action || '';
    const outcomeInfo = INBOUND_ACTION_LABELS[outcome] || {icon:'•', label:outcome, color:'var(--ink)'};
    const dt = new Date(last.ts);
    const est = dt.toLocaleString('en-US',{timeZone:'America/New_York',month:'numeric',day:'numeric',
      hour:'numeric',minute:'2-digit',hour12:true});
    const chainId = 'ichain-'+ci;

    const stepRows = entries.slice().reverse().map(l => {
      const info = INBOUND_ACTION_LABELS[l.action] || {icon:'•', label:l.action||'?', color:'var(--ink)'};
      const extra = [];
      if(l.message) extra.push(`<span style="color:var(--ink-mid)">${escH(l.message)}</span>`);
      if(l.match_type) extra.push(`match: <strong>${escH(l.match_type)}</strong>`);
      if(l.items_found !== undefined) extra.push(`items found: <strong>${l.items_found}</strong>`);
      if(l.added !== undefined) extra.push(`added: <strong>${l.added}</strong>`);
      if(l.skipped_duplicates !== undefined) extra.push(`dupes skipped: <strong>${l.skipped_duplicates}</strong>`);
      if(l.added_items && l.added_items !== '[]') extra.push(`<span style="color:var(--green)">${escH(l.added_items)}</span>`);
      if(l.hint) extra.push(`<em style="color:var(--amber)">${escH(l.hint)}</em>`);
      if(l.html_bytes !== undefined) extra.push(`html: ${l.html_bytes}B`);
      if(l.html_snippet) extra.push(`<code style="font-size:10px;color:var(--ink-soft)">${escH((l.html_snippet||'').slice(0,120))}</code>`);
      if(l.has_svix_id !== undefined) extra.push(`svix-id present: ${l.has_svix_id}`);
      if(l.secret_configured !== undefined) extra.push(`secret configured: ${l.secret_configured}`);

      const stepTime = new Date(l.ts).toLocaleString('en-US',{timeZone:'America/New_York',
        hour:'numeric',minute:'2-digit',second:'2-digit',hour12:true});
      return `<div style="display:flex;gap:10px;padding:6px 14px;border-bottom:1px solid var(--border);font-size:12px;align-items:flex-start">
        <span style="white-space:nowrap;color:var(--ink-soft);min-width:72px">${stepTime}</span>
        <span style="min-width:18px">${info.icon}</span>
        <span style="min-width:160px;color:${info.color};font-weight:600">${escH(info.label)}</span>
        <span style="color:var(--ink-mid);flex:1">${extra.join(' &nbsp;·&nbsp; ')}</span>
      </div>`;
    }).join('');

    return `<div style="border-bottom:2px solid var(--border)">
      <div onclick="document.getElementById('${chainId}').style.display=document.getElementById('${chainId}').style.display==='none'?'block':'none'"
        style="display:flex;gap:12px;align-items:center;padding:10px 14px;cursor:pointer;background:var(--green-bg);user-select:none">
        <span style="font-size:13px;font-weight:700;color:var(--ink);flex:1">
          ${escH(sender)}
          <span style="font-weight:400;color:var(--ink-soft);margin-left:8px">${est}</span>
        </span>
        <span style="color:${outcomeInfo.color};font-size:12px;font-weight:700">${outcomeInfo.icon} ${escH(outcomeInfo.label)}</span>
        <span style="color:var(--ink-soft);font-size:11px">${entries.length} step${entries.length!==1?'s':''} ▾</span>
      </div>
      <div id="${chainId}" style="display:none">${stepRows}</div>
    </div>`;
  }).join('');

  wrap.innerHTML = `<div style="font-size:12px;color:var(--ink-soft);padding:8px 14px;border-bottom:1px solid var(--border)">
    ${logs.length} event${logs.length!==1?'s':''} across ${order.length} email attempt${order.length!==1?'s':''}
    ${senderFilter ? ' — filtered to: <strong>'+escH(senderFilter)+'</strong>' : ''}
  </div>${rows}`;
}


function adminSignOut(){
  adminKey=null;
  sessionStorage.removeItem('pdc_admin');
  document.getElementById('admin-dash').style.display='none';
  document.getElementById('admin-login-sec').style.display='';
  document.getElementById('admin-secret-inp').value='';
  setMsg('admin-login-msg','','');
}
async function initAdmin(){
  if(adminKey){
    // Verify the cached secret is still valid before showing the dashboard
    try{
      const res=await fetch(API+'/admin/scrape-logs',{headers:{'Content-Type':'application/json','Authorization':'AdminSecret '+adminKey}});
      if(res.status===401){
        adminKey=null;sessionStorage.removeItem('pdc_admin');
        return; // show login form
      }
    }catch(_){}
    document.getElementById('admin-login-sec').style.display='none';
    document.getElementById('admin-dash').style.display='block';
    adminLoadUsers();  // other tabs load lazily
  }
}
async function adminLogin(){
  const s=document.getElementById('admin-secret-inp').value.trim();
  if(!s){setMsg('admin-login-msg','Enter the admin secret.','err');return;}
  const btn=document.querySelector('#admin-login-sec .btn-save');
  if(btn){btn.disabled=true;btn.textContent='Verifying…';}
  try{
    // Verify the secret by calling a real admin endpoint before accepting it
    const res=await fetch(API+'/admin/scrape-logs',{headers:{'Content-Type':'application/json','Authorization':'AdminSecret '+s}});
    if(res.status===401){
      setMsg('admin-login-msg','Incorrect admin secret.','err');
      return;
    }
    if(!res.ok && res.status!==200){
      // Any non-auth error still means the secret was accepted
      // only 401 means wrong password
    }
    adminKey=s;sessionStorage.setItem('pdc_admin',s);
    document.getElementById('admin-login-sec').style.display='none';
    document.getElementById('admin-dash').style.display='block';
    adminLoadUsers();  // other tabs load lazily
  }catch(e){
    setMsg('admin-login-msg','Could not reach the server.','err');
  }finally{
    if(btn){btn.disabled=false;btn.textContent='Authenticate';}
  }
}
function adminHdrs(){return{'Content-Type':'application/json','Authorization':'AdminSecret '+adminKey};}


async function adminLoadStats(){
  const el=document.getElementById('admin-stats-body');
  if(!el) return;
  el.innerHTML='<div style="color:var(--ink-soft);font-size:13px">Loading…</div>';
  try{
    const res=await fetch(API+'/admin/stats',{headers:adminHdrs()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');

    const s=data;
    const totalUsers=s.total_users||0;
    const deletedUsers=s.deleted_users||0;
    const avgItems=s.avg_items||0;
    const noItems=s.no_items_count||0;
    const byMonth=s.by_month||[];
    const byGeo=s.by_geography||[];
    const popular=s.popular_items||[];

    // Monthly chart
    const maxMonth=Math.max(1,...byMonth.map(m=>m.count));
    const monthBars=byMonth.slice(-12).map(m=>{
      const pct=Math.round((m.count/maxMonth)*100);
      const lbl=m.month.slice(5); // "MM"
      return `<div class="smc-bar-wrap" title="${m.month}: ${m.count} users">
        <div class="smc-bar" style="height:${pct}%;flex:1"></div>
        <div class="smc-lbl">${lbl}</div>
      </div>`;
    }).join('');

    // Geography bars
    const maxGeo=Math.max(1,...byGeo.map(g=>g.count));
    const geoBars=byGeo.map(g=>{
      const pct=Math.round((g.count/maxGeo)*100);
      return `<li><span style="flex:0 0 130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escH(g.location)}">${escH(g.location)}</span>
        <div class="sl-bar-wrap"><div class="sl-bar" style="width:${pct}%"></div></div>
        <span class="sl-ct">${g.count}</span></li>`;
    }).join('');

    // Popular items bars
    const maxPop=Math.max(1,...popular.map(p=>p.count));
    const popBars=popular.map(p=>{
      const pct=Math.round((p.count/maxPop)*100);
      return `<li><span style="flex:0 0 160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escH(p.item)}">${escH(p.item)}</span>
        <div class="sl-bar-wrap"><div class="sl-bar" style="width:${pct}%;background:var(--amber)"></div></div>
        <span class="sl-ct">${p.count}</span></li>`;
    }).join('');

    el.innerHTML=`
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-val">${totalUsers}</div><div class="stat-lbl">Total Users</div></div>
        <div class="stat-card"><div class="stat-val">${avgItems}</div><div class="stat-lbl">Avg List Items</div></div>
        <div class="stat-card"><div class="stat-val">${totalUsers-noItems}</div><div class="stat-lbl">Active Lists</div></div>
        <div class="stat-card"><div class="stat-val">${noItems}</div><div class="stat-lbl">Empty Lists</div></div>
        <div class="stat-card"><div class="stat-val">${deletedUsers}</div><div class="stat-lbl">Users Deleted</div></div>
      </div>

      <div style="margin-bottom:8px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-soft)">Users Added by Month</div>
      ${byMonth.length
        ? `<div class="stat-month-chart">${monthBars}</div>`
        : '<div style="font-size:13px;color:var(--ink-soft)">No data yet</div>'}

      <div class="stats-two" style="margin-top:20px">
        <div>
          <div style="margin-bottom:8px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-soft)">Users by Geography</div>
          ${byGeo.length
            ? `<ul class="stat-list">${geoBars}</ul>`
            : '<div style="font-size:13px;color:var(--ink-soft)">No store data</div>'}
        </div>
        <div>
          <div style="margin-bottom:8px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-soft)">Most Popular List Items</div>
          ${popular.length
            ? `<ul class="stat-list">${popBars}</ul>`
            : '<div style="font-size:13px;color:var(--ink-soft)">No list data yet</div>'}
        </div>
      </div>`;
  }catch(e){
    el.innerHTML=`<div style="color:var(--red);font-size:13px">Failed to load stats: ${escH(e.message)}</div>`;
  }
}
async function adminLoadLogs(){
  document.getElementById('admin-logs-el').innerHTML='<div style="color:var(--ink-soft);font-size:13px;padding:12px 0">Loading…</div>';
  try{
    const res=await fetch(API+'/admin/scrape-logs',{headers:adminHdrs()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    const logs=data.logs||[];
    const bar=document.getElementById('admin-scrape-bar');
    if(logs.length){
      const last=logs[0];
      const dt=new Date(last.started_at);
      const est=dt.toLocaleString('en-US',{timeZone:'America/New_York',month:'numeric',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit',hour12:true});
      bar.className='scrape-bar';
      bar.innerHTML=`<span>Last import: <span class="scrape-stat">${est} ET</span></span>
        <span><span class="scrape-stat">${last.stores_examined||0}</span> stores examined &nbsp;·&nbsp;
              <span class="scrape-stat">${last.total_deals||0}</span> deals imported &nbsp;·&nbsp;
              <span class="scrape-stat">${last.emails_sent||0}</span> emails sent</span>`;
    } else {
      bar.className='scrape-bar loading';
      bar.innerHTML='<span>No scrape jobs recorded yet.</span>';
    }
    if(!logs.length){document.getElementById('admin-logs-el').innerHTML='<div style="color:var(--ink-soft);font-size:13px">No scrape jobs yet.</div>';return;}
    document.getElementById('admin-logs-el').innerHTML=logs.map(log=>{
      const dt=new Date(log.started_at);
      const est=dt.toLocaleString('en-US',{timeZone:'America/New_York',month:'numeric',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit',hour12:true});
      const dur=log.finished_at?Math.round((new Date(log.finished_at)-dt)/1000)+'s':'–';
      const errs=log.errors||[];
      return `<div class="log-row">
        <div class="log-icon">${errs.length?'⚠️':'✅'}</div>
        <div class="log-detail">
          <div class="log-summary">${log.stores_examined||0} stores · ${log.total_deals||0} deals · ${log.emails_sent||0} emails</div>
          <div class="log-meta">${est} ET · ${dur}</div>
          ${errs.length?`<div class="log-errors">${errs.slice(0,3).map(escH).join(' | ')}</div>`:''}
        </div></div>`;
    }).join('');
  }catch(e){
    const bar=document.getElementById('admin-scrape-bar');
    bar.className='scrape-bar error';
    bar.innerHTML=`<span>Error: ${escH(e.message)}</span>`;
  }
}
async function adminRunScrape(btn){
  btn.disabled=true;btn.textContent='Invoking…';
  try{
    const res=await fetch(API+'/admin/scrape-now',{method:'POST',headers:adminHdrs()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    btn.textContent='✓ Invoked!';
    setTimeout(()=>{btn.disabled=false;btn.textContent='▶ Run Now';},3000);
    setTimeout(adminLoadLogs,35000);
  }catch(e){alert('Error: '+e.message);btn.disabled=false;btn.textContent='▶ Run Now';}
}
async function adminLoadTail(){
  const termEl=document.getElementById('admin-tail');
  const loadEl=document.getElementById('admin-tail-loading');
  loadEl.textContent='Fetching logs…';termEl.style.display='none';
  try{
    const res=await fetch(API+'/admin/logs/tail',{headers:adminHdrs()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    const lines=data.lines||[];
    if(!lines.length){loadEl.textContent='No log events found.';return;}
    loadEl.textContent='';termEl.style.display='block';
    termEl.innerHTML=lines.map(l=>{
      const e=l.msg.toLowerCase().includes('error');
      const o=l.msg.includes('Email sent')||l.msg.includes('Done.');
      return `<div><span class="ts">${(l.ts||'').replace('T',' ').replace(/\..*/,'')}</span><span class="${e?'terr':o?'tok':''}">${escH(l.msg)}</span></div>`;
    }).join('');
    termEl.scrollTop=termEl.scrollHeight;
  }catch(e){loadEl.textContent='Error: '+e.message;}
}
let _allAdminUsers=[];
let _adminUserPage=0;
const ADMIN_PAGE_SIZE=25;

async function adminLoadUsers(){
  try{
    const res=await fetch(API+'/admin/users',{headers:adminHdrs()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    _allAdminUsers=data.users||[];
    _adminUserPage=0;
    document.getElementById('admin-user-ct').textContent=`(${_allAdminUsers.length})`;
    document.getElementById('admin-user-search').value='';
    adminRenderUsers();
  }catch(e){document.getElementById('admin-tbody').innerHTML=`<tr><td colspan="6" style="color:var(--red);font-size:13px">Error: ${escH(e.message)}</td></tr>`;}
}

function adminFilterUsers(){
  _adminUserPage=0;
  adminRenderUsers();
}

function adminRenderUsers(){
  const q=(document.getElementById('admin-user-search').value||'').toLowerCase();
  const filtered=_allAdminUsers.filter(u=>
    !q ||
    (u.email||'').toLowerCase().includes(q) ||
    (u.store_id||'').includes(q) ||
    (u.store_name||'').toLowerCase().includes(q)
  );

  const total=filtered.length;
  const totalPages=Math.max(1,Math.ceil(total/ADMIN_PAGE_SIZE));
  if(_adminUserPage>=totalPages) _adminUserPage=totalPages-1;
  const start=_adminUserPage*ADMIN_PAGE_SIZE;
  const page=filtered.slice(start, start+ADMIN_PAGE_SIZE);

  document.getElementById('admin-tbody').innerHTML=page.length
    ? page.map(u=>`
      <tr>
        <td><strong>${escH(u.email)}</strong><br><span style="font-size:11px;color:var(--ink-soft)">${escH(u.created_at?.slice(0,10)||'')}</span></td>
        <td><span style="font-size:12px">${escH(u.notify_email||u.email)}</span></td>
        <td>${u.store_id?`<span style="font-family:var(--mono);font-size:12px">#${escH(u.store_id)}</span><br><span style="font-size:11px;color:var(--ink-soft)">${escH(u.store_name||'')}</span>`:'<span style="color:var(--ink-soft);font-size:12px">—</span>'}</td>
        <td><button class="abn a" onclick="adminShowItems('${escH(u.email)}',${JSON.stringify(u.items).replace(/"/g,'&quot;')})">${u.item_count} item${u.item_count!==1?'s':''}</button></td>
        <td style="font-size:11px;color:var(--ink-soft)">${escH(u.created_at?.slice(0,10)||'—')}</td>
        <td><div style="display:flex;gap:5px;flex-wrap:wrap">
          <button class="abn g" onclick="adminShowPin('${escH(u.email)}')">Reset PIN</button>
          <button class="abn a" onclick="adminShowEmail('${escH(u.email)}')">Reset Email</button>
          <button class="abn r" onclick="adminDelUser('${escH(u.email)}')">Delete</button>
        </div></td>
      </tr>`).join('')
    : `<tr><td colspan="6" style="color:var(--ink-soft);font-size:13px;padding:16px">${q?'No users match your search.':'No users found.'}</td></tr>`;

  // Pagination controls
  const pages=document.getElementById('admin-user-pages');
  if(total<=ADMIN_PAGE_SIZE){pages.innerHTML='';return;}
  pages.innerHTML=`
    <span>Showing ${start+1}–${Math.min(start+ADMIN_PAGE_SIZE,total)} of ${total}</span>
    <div style="display:flex;gap:6px">
      <button class="abn g" onclick="adminUserPage(-1)" ${_adminUserPage===0?'disabled':''}>← Prev</button>
      <span style="padding:4px 8px">${_adminUserPage+1} / ${totalPages}</span>
      <button class="abn g" onclick="adminUserPage(1)" ${_adminUserPage>=totalPages-1?'disabled':''}>Next →</button>
    </div>`;
}

function adminUserPage(dir){
  _adminUserPage+=dir;
  adminRenderUsers();
}
function showCreateUser(){
  document.getElementById('ac-email').value='';clrPin('.ac-pin');setMsg('ac-msg','','');
  document.getElementById('admin-create-ov').classList.add('vis');
}
async function adminDoCreate(){
  const em=document.getElementById('ac-email').value.trim().toLowerCase();
  const pin=getPin('.ac-pin');
  if(!em||pin.length!==4){setMsg('ac-msg','Enter email and 4-digit PIN.','err');return;}
  try{
    const res=await fetch(API+'/admin/users',{method:'POST',headers:adminHdrs(),body:JSON.stringify({email:em,pin})});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    setMsg('ac-msg','✓ Created.','ok');
    setTimeout(()=>{closeOv('admin-create-ov');adminLoadUsers();},1000);
  }catch(e){setMsg('ac-msg',e.message,'err');}
}
async function adminDelUser(em){
  if(!confirm(`Delete ${em}? Cannot be undone.`)) return;
  try{
    const res=await fetch(API+'/admin/users/'+encodeURIComponent(em),{method:'DELETE',headers:adminHdrs()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    _allAdminUsers=_allAdminUsers.filter(u=>u.email!==em);
    document.getElementById('admin-user-ct').textContent=`(${_allAdminUsers.length})`;
    adminRenderUsers();
  }catch(e){alert('Error: '+e.message);}
}
let _apEmail='';
function adminShowPin(em){_apEmail=em;document.getElementById('apoe').textContent=em;clrPin('.ap-pin');setMsg('ap-msg','','');document.getElementById('admin-pin-ov').classList.add('vis');}
async function adminDoResetPin(){
  const pin=getPin('.ap-pin');if(pin.length!==4){setMsg('ap-msg','Enter 4-digit PIN.','err');return;}
  try{
    const res=await fetch(API+'/admin/users/'+encodeURIComponent(_apEmail)+'/reset-pin',{method:'POST',headers:adminHdrs(),body:JSON.stringify({new_pin:pin})});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    setMsg('ap-msg','✓ PIN reset.','ok');setTimeout(()=>closeOv('admin-pin-ov'),1200);
  }catch(e){setMsg('ap-msg',e.message,'err');}
}
let _aeEmail='';
function adminShowEmail(em){_aeEmail=em;document.getElementById('aeoe').textContent=em;document.getElementById('ae-new-inp').value='';setMsg('ae-msg','','');document.getElementById('admin-email-ov').classList.add('vis');}
async function adminDoResetEmail(){
  const ne=document.getElementById('ae-new-inp').value.trim().toLowerCase();
  if(!ne){setMsg('ae-msg','Enter new email.','err');return;}
  try{
    const res=await fetch(API+'/admin/users/'+encodeURIComponent(_aeEmail)+'/reset-email',{method:'POST',headers:adminHdrs(),body:JSON.stringify({new_email:ne})});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    setMsg('ae-msg','✓ Updated.','ok');setTimeout(()=>{closeOv('admin-email-ov');adminLoadUsers();},1200);
  }catch(e){setMsg('ae-msg',e.message,'err');}
}
let _aiEmail='';
function adminShowItems(em,items){
  _aiEmail=em;document.getElementById('ai-email').textContent=em;setMsg('ai-msg','','');
  document.getElementById('ai-list').innerHTML=!items.length
    ?'<p style="color:var(--ink-soft);font-style:italic">No items on list.</p>'
    :`<ol style="padding-left:20px">${items.map(i=>`<li style="padding:3px 0">${escH(i)}</li>`).join('')}</ol>`;
  document.getElementById('admin-items-ov').classList.add('vis');
}
async function adminClearItems(){
  if(!confirm(`Clear all items for ${_aiEmail}?`)) return;
  try{
    const res=await fetch(API+'/admin/users/'+encodeURIComponent(_aiEmail)+'/items',{method:'DELETE',headers:adminHdrs()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    setMsg('ai-msg','✓ Cleared.','ok');setTimeout(()=>{closeOv('admin-items-ov');adminLoadUsers();},1000);
  }catch(e){setMsg('ai-msg',e.message,'err');}
}


// ── Auth Log ──────────────────────────────────────────────────────────────────
let _allAuthLogs = [];
async function adminLoadAuthLogs(){
  document.getElementById('auth-log-wrap').innerHTML='<div style="color:var(--ink-soft);font-size:13px;padding:8px">Loading…</div>';
  try{
    const res=await fetch(API+'/admin/auth-logs?limit=200',{headers:adminHdrs()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    _allAuthLogs=data.logs||[];
    adminRenderAuthLogs();
  }catch(e){
    document.getElementById('auth-log-wrap').innerHTML=`<div style="color:var(--red);font-size:13px;padding:8px">Error: ${escH(e.message)}</div>`;
  }
}
function adminRenderAuthLogs(){
  const filter=document.getElementById('auth-log-filter').value;
  let logs=_allAuthLogs;
  if(filter==='success') logs=logs.filter(l=>l.success);
  if(filter==='fail')    logs=logs.filter(l=>!l.success);
  if(!logs.length){
    document.getElementById('auth-log-wrap').innerHTML='<div style="color:var(--ink-soft);font-size:13px;padding:10px">No auth events found.</div>';
    return;
  }
  const rows=logs.map(l=>{
    const dt=new Date(l.ts);
    const est=dt.toLocaleString('en-US',{timeZone:'America/New_York',month:'numeric',day:'numeric',hour:'numeric',minute:'2-digit',hour12:true});
    const geo=[l.city,l.region,l.country].filter(Boolean).join(', ')||'—';
    const ua=(l.user_agent||'').replace(/Mozilla\/5\.0\s*/,'').slice(0,60);
    const badge=l.success
      ?'<span class="ok">✓ Login</span>'
      :'<span class="fail">✗ Fail</span>';
    return `<tr>
      <td style="white-space:nowrap">${est}</td>
      <td>${badge}</td>
      <td><strong style="font-size:12px">${escH(l.email)}</strong></td>
      <td style="font-family:var(--mono);font-size:11px">${escH(l.ip||'—')}</td>
      <td style="font-size:11px">${escH(geo)}</td>
      <td style="font-size:11px;color:var(--ink-soft);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escH(l.user_agent||'')}">${escH(ua)}</td>
    </tr>`;
  }).join('');
  document.getElementById('auth-log-wrap').innerHTML=`
    <table class="auth-log-tbl">
      <thead><tr><th>Time (ET)</th><th>Result</th><th>Email</th><th>IP</th><th>Location</th><th>Browser</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── App / Frontend / API / Email / Cache Logs ────────────────────────────────
let _allAppLogs = [];
async function adminLoadAppLogs(){
  document.getElementById('app-log-wrap').innerHTML='<div style="color:var(--ink-soft);font-size:13px;padding:8px">Loading…</div>';
  try{
    const res=await fetch(API+'/admin/app-logs?limit=300',{headers:adminHdrs()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    _allAppLogs=data.logs||[];
    adminRenderAppLogs();
  }catch(e){
    document.getElementById('app-log-wrap').innerHTML=`<div style="color:var(--red);font-size:13px;padding:8px">Error: ${escH(e.message)}</div>`;
  }
}
function adminRenderAppLogs(){
  const filter=document.getElementById('app-log-filter').value;
  let logs=_allAppLogs;
  if(filter!=='all') logs=logs.filter(l=>l.source===filter);
  const el=document.getElementById('app-log-wrap');
  if(!logs.length){
    el.innerHTML='<div style="color:var(--ink-soft);font-size:13px;padding:10px">No logs found.</div>';
    return;
  }
  const SOURCE_ICONS={'frontend':'💻','api':'⚡','email':'✉️','cache':'🗄️'};
  const rows=logs.map(l=>{
    const dt=new Date(l.ts);
    const est=dt.toLocaleString('en-US',{timeZone:'America/New_York',month:'numeric',day:'numeric',
      hour:'numeric',minute:'2-digit',hour12:true});
    const lvl=l.level||'info';
    const src=l.source||'?';
    const icon=SOURCE_ICONS[src]||'•';
    let detail='';
    if(src==='email'){
      detail=`to: ${escH(l.to||'')} | subj: ${escH((l.subject||'').slice(0,40))} | ${l.ok?'✓ sent':'✗ failed'}`;
    } else if(src==='cache'){
      detail=`store ${escH(l.store_id||'?')} | ${l.hit?'● hit':'○ miss'} | ${escH(l.endpoint||'')}`;
    } else if(src==='api'){
      detail=`${escH(l.method||'?')} ${escH(l.path||'')} → ${l.status||'?'} | ${escH((l.message||'').slice(0,80))}`;
    } else if(src==='api' && (l.action||'').startsWith('inbound-')){
      const parts=[];
      if(l.action) parts.push(`<strong>${escH(l.action)}</strong>`);
      if(l.sender) parts.push(`from: ${escH(l.sender)}`);
      if(l.user)   parts.push(`user: ${escH(l.user)}`);
      if(l.message) parts.push(escH(l.message.slice(0,100)));
      if(l.items_found!==undefined) parts.push(`items: ${l.items_found}`);
      if(l.added!==undefined) parts.push(`added: ${l.added}`);
      detail=parts.join(' · ');
    } else {
      const msg=(l.message||'')+(l.stack?' │ '+l.stack.split('\n')[0]:'');
      detail=escH(msg.slice(0,200));
      if(l.url) detail+=` <span style="color:var(--ink-soft);font-size:10px">[${escH(l.url.slice(0,60))}]</span>`;
    }
    return `<div class="app-log-row lv-${escH(lvl)}">
      <span class="alts">${est}</span>
      <span class="alsrc">${icon} ${escH(src)}</span>
      <span class="almsg">${detail}</span>
    </div>`;
  }).join('');
  el.innerHTML=rows;
}

// ── Cache stats widget ────────────────────────────────────────────────────────
async function adminLoadCacheStats(){
  const el=document.getElementById('cache-stats-wrap');
  el.innerHTML='<div style="color:var(--ink-soft);font-size:13px">Loading…</div>';
  try{
    const res=await fetch(API+'/admin/app-logs?limit=500',{headers:adminHdrs()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Failed');
    const cacheLogs=(data.logs||[]).filter(l=>l.source==='cache');
    if(!cacheLogs.length){
      el.innerHTML='<div style="color:var(--ink-soft);font-size:13px">No cache events recorded yet.</div>';
      return;
    }
    // Group by store
    const byStore={};
    for(const l of cacheLogs){
      const s=l.store_id||'unknown';
      if(!byStore[s]) byStore[s]={hits:0,misses:0,store:s};
      if(l.hit) byStore[s].hits++; else byStore[s].misses++;
    }
    const totalHits=cacheLogs.filter(l=>l.hit).length;
    const totalMiss=cacheLogs.length-totalHits;
    const hitPct=cacheLogs.length?Math.round(totalHits/cacheLogs.length*100):0;
    const rows=Object.values(byStore).sort((a,b)=>(b.hits+b.misses)-(a.hits+a.misses)).map(s=>{
      const total=s.hits+s.misses;
      const pct=total?Math.round(s.hits/total*100):0;
      return `<tr>
        <td style="font-family:var(--mono);font-size:12px">#${escH(s.store)}</td>
        <td style="font-size:12px;color:var(--green)">${s.hits}</td>
        <td style="font-size:12px;color:var(--red)">${s.misses}</td>
        <td style="font-size:12px">${pct}%</td>
        <td style="min-width:100px"><div style="height:6px;background:var(--border);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${pct}%;background:var(--green);border-radius:3px"></div></div></td>
      </tr>`;
    }).join('');
    el.innerHTML=`
      <div class="stats-grid" style="margin-bottom:16px">
        <div class="stat-card"><div class="stat-val">${totalHits+totalMiss}</div><div class="stat-lbl">Total Requests</div></div>
        <div class="stat-card"><div class="stat-val" style="color:var(--green)">${totalHits}</div><div class="stat-lbl">Cache Hits</div></div>
        <div class="stat-card"><div class="stat-val" style="color:var(--amber)">${totalMiss}</div><div class="stat-lbl">Cache Misses</div></div>
        <div class="stat-card"><div class="stat-val">${hitPct}%</div><div class="stat-lbl">Hit Rate</div></div>
      </div>
      <table class="admin-tbl" style="font-size:13px">
        <thead><tr><th>Store</th><th>Hits</th><th>Misses</th><th>Rate</th><th style="min-width:100px"></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }catch(e){
    el.innerHTML=`<div style="color:var(--red);font-size:13px">Error: ${escH(e.message)}</div>`;
  }
}

// ── Frontend error reporting ───────────────────────────────────────────────────
window.onerror = function(msg, src, line, col, err){
  try{fetch(API+'/log/error',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+(token||'')},
    body:JSON.stringify({level:'error',message:String(msg),stack:err&&err.stack||'',url:src+'#L'+line+':'+col})});}catch(_){}
};
window.onunhandledrejection = function(e){
  try{fetch(API+'/log/error',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+(token||'')},
    body:JSON.stringify({level:'error',message:'Unhandled rejection: '+String(e.reason),stack:e.reason&&e.reason.stack||'',url:window.location.href})});}catch(_){}
};

// ═══════════════════════════════════════════════════════════════════
// WELCOME MODAL
// ═══════════════════════════════════════════════════════════════════
let _wlcStep = 0;
const WLC_STEPS = 3;

function wlcShow(){
  _wlcStep = 0;
  _wlcRender();
  document.getElementById('wlc-overlay').classList.add('vis');
}

function _wlcRender(){
  // Show correct step
  for(let i=0;i<WLC_STEPS;i++){
    document.getElementById('wlc-step-'+i).classList.toggle('active', i===_wlcStep);
    document.getElementById('wlc-dot-'+i).classList.toggle('active', i===_wlcStep);
  }
  // Update button label
  const btn = document.getElementById('wlc-next-btn');
  if(_wlcStep < WLC_STEPS-1){
    btn.textContent = 'Next →';
  } else {
    btn.textContent = "Let’s go →";
    btn.style.background = 'var(--green)';
  }
}

function wlcNext(){
  if(_wlcStep < WLC_STEPS-1){
    _wlcStep++;
    _wlcRender();
  } else {
    wlcDismiss();
  }
}

function wlcDismiss(){
  document.getElementById('wlc-overlay').classList.remove('vis');
  // Mark this user as welcomed so we never show again
  if(userEmail) localStorage.setItem('pdc_welcomed_'+userEmail, '1');
  // Ensure we're on the store panel after dismissal
  showPanel('store');
}

// ═══════════════════════════════════════════════════════════════════
// UTILS
// ═══════════════════════════════════════════════════════════════════
function decodeEntities(s){
  if(!s) return '';
  // Use the browser's own HTML parser — handles every named entity (&euml; &rsquo; &ndash; etc.)
  // without maintaining a lookup table. The textarea trick is safe: no script execution.
  const ta=document.createElement('textarea');
  ta.innerHTML=String(s);
  return ta.value.replace(/[\r\n]+/g,' ').trim();
}
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function closeOv(id){document.getElementById(id).classList.remove('vis');}

// ═══════════════════════════════════════════════════════════════════
// AUTO-LOGIN
// ═══════════════════════════════════════════════════════════════════
(async function init(){
  if(!token) return;
  try{
    const res=await fetch(API+'/user/prefs',{headers:{'Authorization':'Bearer '+token}});
    if(!res.ok){localStorage.removeItem('pdc_token');localStorage.removeItem('pdc_email');return;}
    const data=await res.json();
    prefs=data.prefs;userEmail=data.email;
    enterApp({isFirstLogin: !localStorage.getItem('pdc_welcomed_'+data.email) && !(prefs && prefs.store_id)});
  }catch(_){}
})();

document.querySelectorAll('.overlay').forEach(o=>{
  o.addEventListener('click',e=>{if(e.target===o) o.classList.remove('vis');});
});

// ═══════════════════════════════════════════════════════════════════
// AUTOCOMPLETE
// ═══════════════════════════════════════════════════════════════════
let _acIdx = -1;

function acGetTitles() {
  const seen = new Set();
  const titles = [];
  // Merge current-week deal titles with persistent corpus
  const allSources = [
    ..._allDeals.map(d => d.title || ''),
    ..._corpusTitles,
  ];
  // Exclude items already on the list
  const alreadyAdded = new Set(itemNames().map(n => n.toLowerCase()));
  for (const t of allSources) {
    const trimmed = t.trim();
    if (trimmed && !seen.has(trimmed.toLowerCase()) && !alreadyAdded.has(trimmed.toLowerCase())) {
      seen.add(trimmed.toLowerCase());
      titles.push(trimmed);
    }
  }
  return titles;
}

function acInput() {
  const q = (document.getElementById('new-item').value || '').trim();
  const drop = document.getElementById('ac-drop');
  if (!q) { drop.style.display = 'none'; return; }

  const qLow = q.toLowerCase();
  const all = acGetTitles();
  const words = qLow.split(/\s+/).filter(Boolean);
  const matches = all.filter(t => words.some(w => t.toLowerCase().includes(w)));

  matches.sort((a, b) => {
    const aStart = a.toLowerCase().startsWith(qLow) ? 0 : 1;
    const bStart = b.toLowerCase().startsWith(qLow) ? 0 : 1;
    return aStart - bStart || a.localeCompare(b);
  });

  const suggestions = matches.slice(0, 8);
  _acIdx = -1;

  drop.innerHTML = [
    `<div class="ac-item ac-item-free" data-val="${escH(q)}" onmousedown="acSelect(this.dataset.val)">${escH(q)}</div>`,
    ...suggestions.map(s =>
      `<div class="ac-item ac-item-deal" data-val="${escH(s)}" onmousedown="acSelect(this.dataset.val)">${escH(s)}</div>`
    )
  ].join('');

  drop.style.display = q ? '' : 'none';
}

function acKeydown(e) {
  const drop = document.getElementById('ac-drop');
  const items = drop.querySelectorAll('.ac-item');
  if (drop.style.display === 'none' || !items.length) {
    if (e.key === 'Enter') addItem();
    return;
  }
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    _acIdx = Math.min(_acIdx + 1, items.length - 1);
    items.forEach((el, i) => el.classList.toggle('ac-sel', i === _acIdx));
    if (_acIdx >= 0) document.getElementById('new-item').value = items[_acIdx].dataset.val || items[_acIdx].textContent.trim();
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    _acIdx = Math.max(_acIdx - 1, 0);
    items.forEach((el, i) => el.classList.toggle('ac-sel', i === _acIdx));
    if (_acIdx >= 0) document.getElementById('new-item').value = items[_acIdx].dataset.val || items[_acIdx].textContent.trim();
  } else if (e.key === 'Enter') {
    e.preventDefault();
    if (_acIdx >= 0 && items[_acIdx]) {
      acSelect(items[_acIdx].dataset.val || items[_acIdx].textContent.trim());
    } else {
      addItem();
    }
  } else if (e.key === 'Escape') {
    acHide();
    closeDealModal();
  }
}

function acSelect(val) {
  document.getElementById('new-item').value = val;
  acHide();
  addItem();
}

function acHide() {
  const drop = document.getElementById('ac-drop');
  if (drop) drop.style.display = 'none';
  _acIdx = -1;
}
document.addEventListener('DOMContentLoaded', () => { initPinInputs('.auth-pin'); initPinInputs('.ac-pin'); });
