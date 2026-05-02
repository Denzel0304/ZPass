/* ═══════════════════════════════════════════════
   ZPassVault — app.js
   namespace : zPV_
   ═══════════════════════════════════════════════ */

// ── CONFIG ───────────────────────────────────────
const zPV_SUPABASE_URL  = 'https://zkkhzsgaryoraytvsqbf.supabase.co';
const zPV_SUPABASE_ANON = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inpra2h6c2dhcnlvcmF5dHZzcWJmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Mzc5ODM5OTcsImV4cCI6MjA1MzU1OTk5N30.UJtqcka35dVssnZRuUk6zukfjF9UNX392Shd841GSQk';

const zPV_TABLE      = 'zPassWord';
const zPV_USER_TABLE = 'zPassWordUser';
const zPV_LOCAL_KEY  = 'zPV_vault_cache_v1';
const zPV_QUEUE_KEY  = 'zPV_sync_queue_v1';
const zPV_SESS_KEY   = 'zPV_auth_session_v1';

// ── SUPABASE CLIENT ──────────────────────────────
const { createClient } = supabase;
const zPV_sb = createClient(zPV_SUPABASE_URL, zPV_SUPABASE_ANON, {
  auth: {
    storageKey:         zPV_SESS_KEY,
    autoRefreshToken:   true,
    persistSession:     true,
    detectSessionInUrl: false
  }
});

// ── STATE ────────────────────────────────────────
let S = {
  user: null, masterPw: '', salt: null,
  items: [], filteredItems: [],
  currentView: 'home',
  editingId: null, detailItem: null,
  pwVisible: false,
  isOnline: navigator.onLine,
  modalStack: [],
  logoutInProgress: false
};

// ── CRYPTO ───────────────────────────────────────
const zPV_crypto = {
  E: new TextEncoder(), D: new TextDecoder(),

  // salt는 항상 S.salt 사용 (Supabase에서 가져온 것)
  _getSalt() {
    if (!S.salt) throw new Error('salt not loaded');
    return Uint8Array.from(atob(S.salt), c => c.charCodeAt(0));
  },

  _genSalt() {
    return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  },

  async _key(pw, salt) {
    const km = await crypto.subtle.importKey('raw', this.E.encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  },

  async enc(text, pw) {
    const salt = this._getSalt(), key = await this._key(pw, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, this.E.encode(text));
    const b = new Uint8Array(12 + ct.byteLength);
    b.set(iv); b.set(new Uint8Array(ct), 12);
    return btoa(String.fromCharCode(...b));
  },

  async dec(b64, pw) {
    const salt = this._getSalt(), key = await this._key(pw, salt);
    const b = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, key, b.slice(12));
    return this.D.decode(pt);
  }
};

// ── SALT 관리 (Supabase 저장/로드) ───────────────
async function zPV_loadOrCreateSalt() {
  // 서버에서 salt 조회
  const { data, error } = await zPV_sb
    .from(zPV_USER_TABLE)
    .select('salt')
    .eq('user_id', S.user.id)
    .maybeSingle();

  if (!error && data?.salt) {
    // 기존 salt 사용 (멀티기기 핵심)
    S.salt = data.salt;
    return;
  }

  // 없으면 새로 생성 후 저장 (최초 기기)
  const newSalt = zPV_crypto._genSalt();
  await zPV_sb.from(zPV_USER_TABLE).upsert(
    { user_id: S.user.id, salt: newSalt },
    { onConflict: 'user_id' }
  );
  S.salt = newSalt;
}

// ── FIELDS ───────────────────────────────────────
const zPV_FIELDS = ['site_name', 'site_url', 'login_id', 'password', 'memo'];

async function zPV_encItem(raw) {
  const e = { id: raw.id, user_id: raw.user_id, created_at: raw.created_at };
  for (const f of zPV_FIELDS) e[f] = raw[f] ? await zPV_crypto.enc(raw[f], S.masterPw) : '';
  return e;
}

async function zPV_decItem(enc) {
  const d = { id: enc.id, user_id: enc.user_id, created_at: enc.created_at };
  for (const f of zPV_FIELDS) {
    try { d[f] = enc[f] ? await zPV_crypto.dec(enc[f], S.masterPw) : ''; }
    catch { d[f] = ''; }
  }
  return d;
}

// ── HELPERS ──────────────────────────────────────
function zPV_esc(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function zPV_toast(msg, dur = 2000) {
  const t = document.getElementById('vault_toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), dur);
}

function zPV_setSyncStatus(st) {
  const dot = document.getElementById('vault_sync_dot');
  const txt = document.getElementById('vault_sync_text');
  dot.className = 'vault_sync_dot';
  if (st === 'synced')  { txt.textContent = '동기화됨'; }
  if (st === 'pending') { dot.classList.add('pending'); txt.textContent = '동기화 대기 중...'; }
  if (st === 'syncing') { dot.classList.add('pending'); txt.textContent = '동기화 중...'; }
  if (st === 'offline') { dot.classList.add('offline'); txt.textContent = '오프라인 모드'; }
}

function zPV_sort(arr) {
  return [...arr].sort((a, b) => {
    const na = (a.site_name || '').trim(), nb = (b.site_name || '').trim();
    const ak = /^[가-힣]/.test(na), bk = /^[가-힣]/.test(nb);
    if (ak !== bk) return ak ? 1 : -1;
    return na.localeCompare(nb, ak ? 'ko' : 'en', { sensitivity: 'base' });
  });
}

function zPV_genPw(upper, num, sym) {
  const lo = 'abcdefghijklmnopqrstuvwxyz', up = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const nu = '0123456789', sy = '!@#$%^&*';
  let pool = lo, req = [lo[Math.random() * lo.length | 0]];
  if (upper) { pool += up; req.push(up[Math.random() * up.length | 0]); }
  if (num)   { pool += nu; req.push(nu[Math.random() * nu.length | 0]); }
  if (sym)   { pool += sy; req.push(sy[Math.random() * sy.length | 0]); }
  const arr = new Uint32Array(16); crypto.getRandomValues(arr);
  let pw = req.join('');
  for (let i = pw.length; i < 16; i++) pw += pool[arr[i] % pool.length];
  const ch = pw.split('');
  for (let i = ch.length - 1; i > 0; i--) {
    const j = Math.random() * (i + 1) | 0; [ch[i], ch[j]] = [ch[j], ch[i]];
  }
  return ch.join('');
}

async function zPV_copy(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) { btn.classList.add('copied'); setTimeout(() => btn.classList.remove('copied'), 1500); }
    zPV_toast('복사됨');
  } catch { zPV_toast('복사 실패'); }
}

// ── LOCAL CACHE ──────────────────────────────────
function zPV_saveLocal(items) { localStorage.setItem(zPV_LOCAL_KEY, JSON.stringify(items)); }
function zPV_loadLocal()      { try { return JSON.parse(localStorage.getItem(zPV_LOCAL_KEY) || '[]'); } catch { return []; } }

// ── OFFLINE QUEUE ────────────────────────────────
function zPV_queueOp(op) {
  const q = JSON.parse(localStorage.getItem(zPV_QUEUE_KEY) || '[]');
  q.push({ ...op, ts: Date.now() });
  localStorage.setItem(zPV_QUEUE_KEY, JSON.stringify(q));
  zPV_setSyncStatus('pending');
}

async function zPV_flushQueue() {
  const q = JSON.parse(localStorage.getItem(zPV_QUEUE_KEY) || '[]');
  if (!q.length || !S.isOnline) return;
  zPV_setSyncStatus('syncing');
  const rem = [];
  for (const op of q) {
    try {
      if (op.type === 'upsert') await zPV_sb.from(zPV_TABLE).upsert(op.data, { onConflict: 'id' });
      else if (op.type === 'delete') await zPV_sb.from(zPV_TABLE).delete().eq('id', op.id);
    } catch { rem.push(op); }
  }
  localStorage.setItem(zPV_QUEUE_KEY, JSON.stringify(rem));
  zPV_setSyncStatus(rem.length ? 'pending' : 'synced');
}

// ── LOAD ITEMS ───────────────────────────────────
async function zPV_loadItems(fromServer = true) {
  if (fromServer && S.isOnline) {
    try {
      const { data, error } = await zPV_sb.from(zPV_TABLE).select('*').eq('user_id', S.user.id);
      if (!error && data) {
        zPV_saveLocal(data);
        const dec = await Promise.all(data.map(zPV_decItem));
        S.items = zPV_sort(dec); S.filteredItems = S.items;
        zPV_updateUI(); return;
      }
    } catch (e) { console.warn('server load failed', e); }
  }
  const dec = await Promise.all(zPV_loadLocal().map(zPV_decItem));
  S.items = zPV_sort(dec); S.filteredItems = S.items;
  zPV_updateUI();
}

// ── UI ───────────────────────────────────────────
function zPV_updateUI() {
  const n = S.items.length;
  document.getElementById('vault_count_badge').textContent = n;
  document.getElementById('vault_home_sub').textContent =
    n ? `${n}개의 비밀번호가 저장됨` : '탭하여 비밀번호 추가';
  document.getElementById('vault_list_count').textContent = `${S.filteredItems.length}개`;
  zPV_renderList();
}

function zPV_renderList() {
  const el = document.getElementById('vault_items_container');
  const items = S.filteredItems;
  if (!items.length) {
    const q = document.getElementById('vault_search_input').value.trim();
    el.innerHTML = q
      ? '<div class="vault_no_results">검색 결과가 없습니다</div>'
      : '<div class="vault_empty"><svg width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round"><rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="12" cy="12" r="4"/></svg><p>+ 버튼으로 항목을 추가하세요</p></div>';
    return;
  }
  el.innerHTML = items.map(it => `
    <div class="vault_item_card" data-id="${it.id}">
      <div class="vault_item_icon">${(it.site_name || '?')[0].toUpperCase()}</div>
      <div class="vault_item_info">
        <div class="vault_item_name">${zPV_esc(it.site_name)}</div>
        <div class="vault_item_id">${zPV_esc(it.login_id)}</div>
      </div>
      <svg class="vault_item_arrow" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m9 18 6-6-6-6"/></svg>
    </div>`).join('');
  el.querySelectorAll('.vault_item_card').forEach(card => {
    card.addEventListener('click', () => {
      const it = S.items.find(i => i.id === card.dataset.id);
      if (it) zPV_openDetail(it);
    });
  });
}

// ── VIEWS ────────────────────────────────────────
function zPV_showHome() {
  S.currentView = 'home';
  document.getElementById('vault_home_view').style.display = 'flex';
  document.getElementById('vault_list_view').style.display = 'none';
}

function zPV_showList() {
  S.currentView = 'list';
  document.getElementById('vault_home_view').style.display = 'none';
  document.getElementById('vault_list_view').style.display = 'block';
  zPV_renderList();
  history.pushState({ zPV: 'list' }, '');
}

// ── BACK HANDLER ─────────────────────────────────
function zPV_setupBack() {
  window.addEventListener('popstate', () => {
    const top = S.modalStack[S.modalStack.length - 1];
    if (top === 'confirm') { zPV_closeConfirm(false); history.pushState({ zPV: 'c' }, ''); return; }
    if (top === 'form')    { zPV_closeForm();   return; }
    if (top === 'detail')  { zPV_closeDetail(); return; }
    if (S.currentView === 'list') { zPV_showHome(); history.pushState({ zPV: 'home' }, ''); return; }
  });
}

// ── MODALS ───────────────────────────────────────
const zPV_open  = id => document.getElementById(id).classList.add('open');
const zPV_close = id => document.getElementById(id).classList.remove('open');

function zPV_openDetail(it) {
  S.detailItem = it; S.pwVisible = false;
  document.getElementById('vault_detail_title').textContent = it.site_name || '상세 정보';
  document.getElementById('vault_d_site_name').textContent  = it.site_name || '-';
  document.getElementById('vault_d_login_id').textContent   = it.login_id  || '-';
  document.getElementById('vault_d_password').textContent   = '••••••••';
  document.getElementById('vault_d_password').classList.add('vault_pw_dots');
  document.getElementById('vault_d_memo').textContent       = it.memo || '';
  const urlEl  = document.getElementById('vault_d_url');
  const urlFld = document.getElementById('vault_d_url_field');
  if (it.site_url) {
    urlEl.textContent = it.site_url;
    urlEl.href = it.site_url.startsWith('http') ? it.site_url : 'https://' + it.site_url;
    urlFld.style.display = 'block';
  } else { urlFld.style.display = 'none'; }
  document.getElementById('vault_d_memo_field').style.display = it.memo ? 'block' : 'none';
  zPV_open('vault_detail_modal');
  S.modalStack.push('detail');
  history.pushState({ zPV: 'detail' }, '');
}

function zPV_closeDetail() {
  zPV_close('vault_detail_modal');
  S.modalStack = S.modalStack.filter(m => m !== 'detail');
}

function zPV_openForm(it = null) {
  S.editingId = it ? it.id : null;
  document.getElementById('vault_form_title').textContent  = it ? '항목 수정' : '새 항목 추가';
  document.getElementById('vault_f_site_name').value = it ? (it.site_name || '') : '';
  document.getElementById('vault_f_url').value        = it ? (it.site_url  || '') : '';
  document.getElementById('vault_f_login_id').value   = it ? (it.login_id  || '') : '';
  document.getElementById('vault_f_password').value   = it ? (it.password  || '') : '';
  document.getElementById('vault_f_password').type    = 'password';
  document.getElementById('vault_f_memo').value       = it ? (it.memo      || '') : '';
  document.getElementById('vault_gen_options').style.display = 'none';
  zPV_open('vault_form_modal');
  S.modalStack.push('form');
  history.pushState({ zPV: 'form' }, '');
  setTimeout(() => document.getElementById('vault_f_site_name').focus(), 350);
}

function zPV_closeForm() {
  zPV_close('vault_form_modal');
  S.modalStack = S.modalStack.filter(m => m !== 'form');
}

// ── CONFIRM ──────────────────────────────────────
let zPV_confirmCb = null;

function zPV_openConfirm(title, msg, okLabel = '확인', isDanger = false) {
  return new Promise(res => {
    zPV_confirmCb = res;
    document.getElementById('vault_confirm_title').textContent = title;
    document.getElementById('vault_confirm_msg').textContent   = msg;
    const ok = document.getElementById('vault_confirm_ok');
    ok.textContent = okLabel;
    ok.className   = 'vault_confirm_ok' + (isDanger ? ' is-danger' : '');
    document.getElementById('vault_confirm_overlay').classList.add('open');
    S.modalStack.push('confirm');
    history.pushState({ zPV: 'confirm' }, '');
  });
}

function zPV_closeConfirm(result = false) {
  document.getElementById('vault_confirm_overlay').classList.remove('open');
  S.modalStack = S.modalStack.filter(m => m !== 'confirm');
  if (zPV_confirmCb) { zPV_confirmCb(result); zPV_confirmCb = null; }
}

// ── SEARCH ───────────────────────────────────────
function zPV_applySearch(q) {
  if (!q.trim()) { S.filteredItems = S.items; }
  else {
    const lq = q.toLowerCase();
    S.filteredItems = S.items.filter(i =>
      (i.site_name || '').toLowerCase().includes(lq) ||
      (i.login_id  || '').toLowerCase().includes(lq) ||
      (i.site_url  || '').toLowerCase().includes(lq)
    );
  }
  document.getElementById('vault_list_count').textContent = `${S.filteredItems.length}개`;
  if (q.trim() && S.currentView === 'home') zPV_showList();
  zPV_renderList();
}

// ── SAVE ITEM ────────────────────────────────────
async function zPV_saveItem() {
  const sn = document.getElementById('vault_f_site_name').value.trim();
  const li = document.getElementById('vault_f_login_id').value.trim();
  const pw = document.getElementById('vault_f_password').value;
  if (!sn || !li || !pw) { zPV_toast('필수 항목을 모두 입력해주세요'); return; }

  const btn = document.getElementById('vault_form_save_btn');
  btn.disabled = true; btn.textContent = '저장 중...';

  const raw = {
    id:         S.editingId || crypto.randomUUID(),
    user_id:    S.user.id,
    site_name:  sn,
    site_url:   document.getElementById('vault_f_url').value.trim(),
    login_id:   li,
    password:   pw,
    memo:       document.getElementById('vault_f_memo').value.trim(),
    created_at: S.editingId
      ? (S.items.find(i => i.id === S.editingId)?.created_at || new Date().toISOString())
      : new Date().toISOString()
  };

  if (S.editingId) {
    const idx = S.items.findIndex(i => i.id === S.editingId);
    if (idx !== -1) S.items[idx] = raw; else S.items.push(raw);
  } else { S.items.push(raw); }
  S.items = zPV_sort(S.items);
  zPV_applySearch(document.getElementById('vault_search_input').value);

  const enc   = await zPV_encItem(raw);
  const local = zPV_loadLocal();
  const lIdx  = local.findIndex(i => i.id === raw.id);
  if (lIdx !== -1) local[lIdx] = enc; else local.push(enc);
  zPV_saveLocal(local);

  if (S.isOnline) {
    try {
      const { error } = await zPV_sb.from(zPV_TABLE).upsert(enc, { onConflict: 'id' });
      if (error) throw error;
      zPV_setSyncStatus('synced');
    } catch { zPV_queueOp({ type: 'upsert', data: enc }); }
  } else { zPV_queueOp({ type: 'upsert', data: enc }); }

  zPV_updateUI();
  zPV_closeForm();
  btn.disabled = false; btn.textContent = '저장';
  zPV_toast(S.editingId ? '수정되었습니다' : '추가되었습니다');
}

// ── DELETE ITEM ──────────────────────────────────
async function zPV_deleteItem(id) {
  const name = S.items.find(i => i.id === id)?.site_name || '';
  const ok = await zPV_openConfirm(
    '항목 삭제', `"${name}"을(를) 삭제할까요?\n삭제 후 복구할 수 없습니다.`, '삭제', true
  );
  if (!ok) return;

  S.items = S.items.filter(i => i.id !== id);
  zPV_applySearch(document.getElementById('vault_search_input').value);
  zPV_saveLocal(zPV_loadLocal().filter(i => i.id !== id));

  if (S.isOnline) {
    try { await zPV_sb.from(zPV_TABLE).delete().eq('id', id); zPV_setSyncStatus('synced'); }
    catch { zPV_queueOp({ type: 'delete', id }); }
  } else { zPV_queueOp({ type: 'delete', id }); }

  zPV_closeDetail();
  zPV_updateUI();
  zPV_toast('삭제되었습니다');
}

// ── MASTER PW STORAGE KEY ────────────────────────
const zPV_LS_PW = 'zPV_mpw_v1';

// ── LOGIN ────────────────────────────────────────
async function zPV_login() {
  const email = document.getElementById('vault_email_input').value.trim();
  const pw    = document.getElementById('vault_pw_input').value;
  const errEl = document.getElementById('vault_auth_error');
  const btn   = document.getElementById('vault_login_btn');

  errEl.style.display = 'none';
  if (!email || !pw) { errEl.textContent = '이메일과 비밀번호를 입력해주세요'; errEl.style.display = 'block'; return; }

  btn.textContent = '인증 중...'; btn.disabled = true;

  const { data, error } = await zPV_sb.auth.signInWithPassword({ email, password: pw });
  if (error) {
    errEl.textContent = '이메일 또는 비밀번호가 올바르지 않습니다';
    errEl.style.display = 'block';
    btn.textContent = '금고 열기'; btn.disabled = false;
    return;
  }

  S.user     = data.user;
  S.masterPw = pw;

  // 새로고침 복원용 (탭 닫으면 자동 삭제)
  localStorage.setItem(zPV_LS_PW, pw);

  // salt 로드 (멀티기기 핵심)
  btn.textContent = '금고 여는 중...';
  try {
    await zPV_loadOrCreateSalt();
  } catch (e) {
    errEl.textContent = '보안 키 로드 실패. 네트워크를 확인해주세요.';
    errEl.style.display = 'block';
    btn.textContent = '금고 열기'; btn.disabled = false;
    await zPV_sb.auth.signOut();
    localStorage.removeItem(zPV_LS_PW);
    return;
  }

  await zPV_initApp();
}

// ── LOGOUT ───────────────────────────────────────
async function zPV_logout() {
  if (S.logoutInProgress) return;
  const ok = await zPV_openConfirm('로그아웃', '로그아웃 하시겠습니까?', '로그아웃', false);
  if (!ok) return;

  S.logoutInProgress = true;
  document.getElementById('vault_confirm_overlay').classList.remove('open');
  S.modalStack = S.modalStack.filter(m => m !== 'confirm');

  await zPV_sb.auth.signOut();

  localStorage.removeItem(zPV_LOCAL_KEY);
  localStorage.removeItem(zPV_QUEUE_KEY);
  localStorage.removeItem(zPV_LS_PW);

  S = {
    user: null, masterPw: '', salt: null,
    items: [], filteredItems: [],
    currentView: 'home', editingId: null, detailItem: null,
    pwVisible: false, isOnline: navigator.onLine,
    modalStack: [], logoutInProgress: false
  };

  document.getElementById('vault_email_input').value    = '';
  document.getElementById('vault_pw_input').value       = '';
  document.getElementById('vault_auth_error').style.display = 'none';
  document.getElementById('vault_login_btn').textContent = '금고 열기';
  document.getElementById('vault_login_btn').disabled   = false;
  document.getElementById('vault_search_input').value   = '';

  document.getElementById('vault_app_screen').style.display  = 'none';
  document.getElementById('vault_auth_screen').style.display = 'flex';
}

// ── INIT APP ─────────────────────────────────────
async function zPV_initApp() {
  document.getElementById('vault_auth_screen').style.display = 'none';
  document.getElementById('vault_app_screen').style.display  = 'flex';
  zPV_showHome();
  zPV_setSyncStatus(S.isOnline ? 'synced' : 'offline');

  // 로컬 캐시 먼저 표시 (즉각 반응)
  const cached = zPV_loadLocal();
  if (cached.length) {
    const dec = await Promise.all(cached.map(zPV_decItem));
    S.items = zPV_sort(dec); S.filteredItems = S.items;
    zPV_updateUI();
  }

  // 서버에서 최신 데이터 가져오기
  await zPV_loadItems(true);
  await zPV_flushQueue();
  history.replaceState({ zPV: 'home' }, '');
}

// ── ONLINE / OFFLINE ─────────────────────────────
window.addEventListener('online', async () => {
  S.isOnline = true;
  if (S.user) { zPV_setSyncStatus('syncing'); await zPV_flushQueue(); await zPV_loadItems(true); }
});
window.addEventListener('offline', () => {
  S.isOnline = false; zPV_setSyncStatus('offline');
});

// ── TOKEN REFRESH ────────────────────────────────
zPV_sb.auth.onAuthStateChange((event, session) => {
  if (event === 'TOKEN_REFRESHED' && session) S.user = session.user;
});

// ── STARTUP ──────────────────────────────────────
async function zPV_startup() {
  const { data: { session } } = await zPV_sb.auth.getSession();
  const savedPw = localStorage.getItem(zPV_LS_PW);

  // 세션 + 비밀번호 둘 다 있으면 자동으로 금고 열기 (새로고침 복원)
  if (session && savedPw) {
    S.user     = session.user;
    S.masterPw = savedPw;
    try {
      await zPV_loadOrCreateSalt();
      await zPV_initApp();
      return;
    } catch (e) {
      // 복원 실패 시 로그인 화면으로
      localStorage.removeItem(zPV_LS_PW);
    }
  }

  document.getElementById('vault_auth_screen').style.display = 'flex';
}

// ── EVENT BINDING ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  zPV_setupBack();
  zPV_startup();

  // Auth
  document.getElementById('vault_login_btn').addEventListener('click', zPV_login);
  document.getElementById('vault_pw_input').addEventListener('keydown', e => { if (e.key === 'Enter') zPV_login(); });
  document.getElementById('vault_email_input').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('vault_pw_input').focus(); });
  document.getElementById('vault_auth_eye').addEventListener('click', () => {
    const i = document.getElementById('vault_pw_input');
    i.type = i.type === 'password' ? 'text' : 'password';
  });
  document.getElementById('vault_logout_btn').addEventListener('click', zPV_logout);

  // Nav
  document.getElementById('vault_nav_safe_btn').addEventListener('click', () => {
    if (S.currentView === 'home') zPV_showList();
    else { zPV_showHome(); history.pushState({ zPV: 'home' }, ''); }
  });
  document.getElementById('vault_safe_icon_btn').addEventListener('click', zPV_showList);
  document.getElementById('vault_list_back_btn').addEventListener('click', () => {
    zPV_showHome(); history.pushState({ zPV: 'home' }, '');
  });

  // Search
  document.getElementById('vault_search_input').addEventListener('input', e => zPV_applySearch(e.target.value));

  // FAB
  document.getElementById('vault_add_fab').addEventListener('click', () => zPV_openForm());

  // Detail modal
  document.getElementById('vault_detail_close').addEventListener('click', () => {
    zPV_closeDetail(); history.pushState({ zPV: S.currentView }, '');
  });
  document.getElementById('vault_detail_modal').addEventListener('click', e => {
    if (e.target === document.getElementById('vault_detail_modal')) {
      zPV_closeDetail(); history.pushState({ zPV: S.currentView }, '');
    }
  });
  document.getElementById('vault_d_pw_eye').addEventListener('click', () => {
    const el = document.getElementById('vault_d_password');
    S.pwVisible = !S.pwVisible;
    el.textContent = S.pwVisible ? (S.detailItem?.password || '') : '••••••••';
    el.classList.toggle('vault_pw_dots', !S.pwVisible);
  });
  document.getElementById('vault_d_id_copy').addEventListener('click',  e => zPV_copy(S.detailItem?.login_id  || '', e.currentTarget));
  document.getElementById('vault_d_pw_copy').addEventListener('click',  e => zPV_copy(S.detailItem?.password  || '', e.currentTarget));
  document.getElementById('vault_d_url_copy').addEventListener('click', e => zPV_copy(S.detailItem?.site_url  || '', e.currentTarget));
  document.getElementById('vault_detail_edit_btn').addEventListener('click',   () => zPV_openForm(S.detailItem));
  document.getElementById('vault_detail_delete_btn').addEventListener('click', () => zPV_deleteItem(S.detailItem.id));

  // Form modal
  document.getElementById('vault_form_close').addEventListener('click', () => {
    zPV_closeForm(); history.pushState({ zPV: S.currentView }, '');
  });
  document.getElementById('vault_form_modal').addEventListener('click', e => {
    if (e.target === document.getElementById('vault_form_modal')) {
      zPV_closeForm(); history.pushState({ zPV: S.currentView }, '');
    }
  });
  document.getElementById('vault_f_pw_eye').addEventListener('click', () => {
    const i = document.getElementById('vault_f_password');
    i.type = i.type === 'password' ? 'text' : 'password';
  });
  document.getElementById('vault_f_pw_copy').addEventListener('click', e => zPV_copy(document.getElementById('vault_f_password').value, e.currentTarget));
  document.getElementById('vault_f_id_copy').addEventListener('click', e => zPV_copy(document.getElementById('vault_f_login_id').value, e.currentTarget));
  document.getElementById('vault_gen_pw_btn').addEventListener('click', () => {
    const o = document.getElementById('vault_gen_options');
    o.style.display = o.style.display === 'none' ? 'block' : 'none';
  });
  document.getElementById('vault_do_gen_btn').addEventListener('click', () => {
    const pw = zPV_genPw(
      document.getElementById('vault_opt_upper').checked,
      document.getElementById('vault_opt_num').checked,
      document.getElementById('vault_opt_sym').checked
    );
    const i = document.getElementById('vault_f_password');
    i.value = pw; i.type = 'text';
    document.getElementById('vault_gen_options').style.display = 'none';
    zPV_toast('비밀번호가 생성되었습니다');
  });
  document.getElementById('vault_form_save_btn').addEventListener('click', zPV_saveItem);

  // Confirm
  document.getElementById('vault_confirm_cancel').addEventListener('click', () => zPV_closeConfirm(false));
  document.getElementById('vault_confirm_ok').addEventListener('click',     () => zPV_closeConfirm(true));

  // 주기적 queue flush (30초)
  setInterval(async () => { if (S.user && S.isOnline) await zPV_flushQueue(); }, 30000);
});
