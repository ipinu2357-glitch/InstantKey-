const enc = new TextEncoder();
const dec = new TextDecoder();

/* ===== MULTI USER STORAGE ===== */
const INDEX_KEY = "vault_index_v1";
const STORAGE_PREFIX = "vault_user_v1:";

let currentVaultName = null;
let unlockedKey = null;
let vaultData = { items: [] };

/* ===== Auto-lock ===== */
let lockDeadline = null;
let idleTimer = null;
let countdownTimer = null;

function $(id){ return document.getElementById(id); }

function b64(bytes){ return btoa(String.fromCharCode.apply(null, bytes)); }
function unb64(str){ return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, m => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[m]));
}

function setStatus(msg){ $("status").textContent = msg; }
function setWarn(msg){ $("warn").textContent = msg || ""; }

function storageKeyFor(name){
  return STORAGE_PREFIX + String(name || "").trim().toLowerCase();
}

/* ===== INDEX ===== */
function loadIndex(){
  const raw = localStorage.getItem(INDEX_KEY);
  if (!raw) return [];
  try{
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  }catch{
    return [];
  }
}
function saveIndex(list){
  localStorage.setItem(INDEX_KEY, JSON.stringify(list));
}
function ensureIndexHasDefault(){
  let idx = loadIndex();
  if (!idx.length){
    idx = ["Default"];
    saveIndex(idx);
  }
  return idx;
}

function refreshVaultSelect(preferName){
  const sel = $("vaultSelect");
  const idx = ensureIndexHasDefault();
  sel.innerHTML = "";

  idx.forEach(name => {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    sel.appendChild(opt);
  });

  const pick = (preferName && idx.includes(preferName)) ? preferName : idx[0];
  sel.value = pick;
  currentVaultName = pick;
  onVaultChanged();
}

/* ===== Envelope ===== */
function loadEnvelope(){
  if (!currentVaultName) return null;
  const raw = localStorage.getItem(storageKeyFor(currentVaultName));
  return raw ? JSON.parse(raw) : null;
}
function saveEnvelope(env){
  localStorage.setItem(storageKeyFor(currentVaultName), JSON.stringify(env));
}

/* ===== Crypto ===== */
async function deriveKey(masterPassword, secondKeyValue, salt, iterations){
  const iters = iterations || 210000;
  const combined = masterPassword + "::" + secondKeyValue;

  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(combined),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations: iters, hash:"SHA-256" },
    baseKey,
    { name:"AES-GCM", length:256 },
    false,
    ["encrypt","decrypt"]
  );
}

async function encryptJson(key, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify(obj));
  const ctBuf = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, plaintext);
  return { iv: b64(iv), ct: b64(new Uint8Array(ctBuf)) };
}

async function decryptJson(key, payload){
  const iv = unb64(payload.iv);
  const ct = unb64(payload.ct);
  const ptBuf = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, ct);
  return JSON.parse(dec.decode(ptBuf));
}

async function saveVault(){
  if (!unlockedKey) throw new Error("Not unlocked");
  const env = loadEnvelope();
  if (!env) throw new Error("No envelope");
  env.payload = await encryptJson(unlockedKey, vaultData);
  env.version = 1;
  saveEnvelope(env);
}

/* ===== UI enable/disable ===== */
function setUiUnlocked(isUnlocked){
  $("addBtn").disabled = !isUnlocked;
  $("lockBtn").disabled = !isUnlocked;
  $("exportBtn").disabled = !isUnlocked;
  $("importBtn").disabled = !isUnlocked;
  $("unlockBtn").disabled = isUnlocked;

  $("master").disabled = isUnlocked;
  $("k2Value").disabled = isUnlocked;
}

/* ===== Password gen ===== */
function randomPassword(len=22){
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = "";
  for (let i=0;i<len;i++) out += chars[bytes[i] % chars.length];
  return out;
}

/* ===== Table (default masked) ===== */
function filteredItems(){
  const q = $("search").value.trim().toLowerCase();
  if (!q) return vaultData.items;
  return vaultData.items.filter(it => ((it.label||"")+" "+(it.site||"")+" "+(it.username||"")).toLowerCase().includes(q));
}
function maskAny(s){
  s = s || "";
  if (!s) return "";
  return "•".repeat(Math.min(10, Math.max(4, s.length)));
}

function renderTable(){
  const tbody = $("tbody");
  tbody.innerHTML = "";
  const items = filteredItems();

  items.forEach(it => {
    const idx = vaultData.items.indexOf(it);
    const tr = document.createElement("tr");

    // helper: cell with masked code + eye + copy(optional)
    const makeMaskedCell = (value, kind, withCopy) => {
      const td = document.createElement("td");
      const code = document.createElement("code");
      code.setAttribute("data-kind", kind);
      code.setAttribute("data-idx", String(idx));
      code.textContent = maskAny(value);
      code.title = "Tersembunyi";
      td.appendChild(code);

      const eye = document.createElement("button");
      eye.className = "icon-btn mini-eye";
      eye.type = "button";
      eye.textContent = "👁";
      eye.title = "Reveal";
      eye.setAttribute("data-eye", "1");
      eye.setAttribute("data-kind", kind);
      eye.setAttribute("data-idx", String(idx));
      td.appendChild(document.createTextNode(" "));
      td.appendChild(eye);

      if (withCopy){
        const copyBtn = document.createElement("button");
        copyBtn.className = "btn";
        copyBtn.type = "button";
        copyBtn.textContent = "Copy";
        copyBtn.setAttribute("data-copy", kind);
        copyBtn.setAttribute("data-idx", String(idx));
        td.appendChild(document.createTextNode(" "));
        td.appendChild(copyBtn);
      }

      return td;
    };

    tr.appendChild(makeMaskedCell(it.label || "", "label", false));

    // website: tetap link saat reveal saja → default masked (bukan <a>)
    tr.appendChild(makeMaskedCell(it.site || "", "site", false));

    tr.appendChild(makeMaskedCell(it.username || "", "user", true));
    tr.appendChild(makeMaskedCell(it.password || "", "pass", true));

    const tdAksi = document.createElement("td");
    const delBtn = document.createElement("button");
    delBtn.className = "btn";
    delBtn.textContent = "Hapus";
    delBtn.type = "button";
    delBtn.setAttribute("data-del","1");
    delBtn.setAttribute("data-idx", String(idx));
    tdAksi.appendChild(delBtn);
    tr.appendChild(tdAksi);

    tbody.appendChild(tr);
  });
}

/* ===== Reveal once (2.5s) for each field in table ===== */
function getValueByKind(idx, kind){
  const it = vaultData.items[idx] || {};
  if (kind === "label") return it.label || "";
  if (kind === "site") return it.site || "";
  if (kind === "user") return it.username || "";
  if (kind === "pass") return it.password || "";
  return "";
}

function revealCellOnce(idx, kind){
  const code = document.querySelector(`code[data-idx="${idx}"][data-kind="${kind}"]`);
  if (!code) return;

  const originalMasked = code.textContent;
  const value = getValueByKind(idx, kind);

  // kalau website, saat reveal tampil sebagai teks (bukan link) biar simpel
  code.textContent = value;

  setTimeout(() => {
    code.textContent = originalMasked;
  }, 2500);

  resetDeadline();
}

/* ===== Timer ===== */
function updateTimerUI(){
  const pill = $("autolockTimer");
  const text = $("timerText");
  if (!pill || !text) return;

  if (!unlockedKey || !lockDeadline){
    pill.classList.add("hidden");
    pill.classList.remove("warning");
    text.textContent = "--:--";
    return;
  }

  const remaining = lockDeadline - Date.now();
  if (remaining <= 0){
    pill.classList.add("hidden");
    pill.classList.remove("warning");
    return;
  }

  const m = Math.floor(remaining / 60000);
  const s = Math.floor((remaining % 60000) / 1000);
  text.textContent = String(m).padStart(2,"0") + ":" + String(s).padStart(2,"0");

  pill.classList.remove("hidden");
  if (remaining < 30000) pill.classList.add("warning");
  else pill.classList.remove("warning");
}

function resetDeadline(){
  if (!unlockedKey) return;
  const mins = Math.max(1, Number($("idleMinutes").value) || 5);
  lockDeadline = Date.now() + mins*60*1000;
  updateTimerUI();
}

function disarmIdleLock(){
  if (idleTimer) clearInterval(idleTimer);
  if (countdownTimer) clearInterval(countdownTimer);
  idleTimer = null;
  countdownTimer = null;
  lockDeadline = null;
  updateTimerUI();
}

function armIdleLock(){
  disarmIdleLock();
  resetDeadline();

  countdownTimer = setInterval(updateTimerUI, 250);
  idleTimer = setInterval(() => {
    if (!unlockedKey || !lockDeadline) return;
    if (Date.now() >= lockDeadline){
      const mins = Math.max(1, Number($("idleMinutes").value) || 5);
      lock("Auto-lock setelah idle " + mins + " menit.");
    }
  }, 250);
}

/* ===== 2nd key label UI ===== */
function updateSecondKeyUiFromEnvelope(){
  const env = loadEnvelope();
  const k2LabelWrap = $("k2LabelWrap");
  const k2Label = $("k2Label");
  const k2ValueLabel = $("k2ValueLabel");

  if (!env){
    k2LabelWrap.style.display = "";
    k2Label.disabled = false;
    k2ValueLabel.textContent = "Kunci Kedua";
    return;
  }

  if (env.kdf_version === 2){
    k2LabelWrap.style.display = "";
    k2Label.disabled = true;
    k2Label.value = env.k2_label || "Kunci Kedua";
    k2ValueLabel.textContent = env.k2_label ? ("Kunci Kedua (" + env.k2_label + ")") : "Kunci Kedua";
  }else{
    k2LabelWrap.style.display = "none";
    k2Label.value = "";
    k2ValueLabel.textContent = "Kunci Kedua (tidak dipakai di vault lama)";
  }
}

/* ===== Vault change ===== */
function onVaultChanged(){
  lock("Terkunci.");
  setWarn("");
  updateSecondKeyUiFromEnvelope();

  const env = loadEnvelope();
  if (!env) setStatus("Belum ada vault untuk akun ini. Isi master + kunci kedua lalu klik Unlock/Create.");
  else setStatus("Masukkan kunci untuk unlock.");

  setUiUnlocked(false);
}

/* ===== Create / Unlock ===== */
async function unlockOrCreate(){
  setWarn("");
  if (!currentVaultName){
    refreshVaultSelect("Default");
  }

  const master = $("master").value;
  const k2Value = $("k2Value").value;
  const k2Label = ($("k2Label").value || "").trim();

  if (!master) return setWarn("Master password wajib diisi.");

  const env = loadEnvelope();

  // CREATE
  if (!env){
    if (!k2Label) return setWarn("Nama kunci kedua wajib diisi.");
    if (!k2Value) return setWarn("Kunci kedua wajib diisi.");

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iterations = 210000;

    unlockedKey = await deriveKey(master, k2Value, salt, iterations);
    vaultData = { items: [] };

    const payload = await encryptJson(unlockedKey, vaultData);

    saveEnvelope({
      version: 1,
      kdf_version: 2,
      k2_label: k2Label,
      salt_b64: b64(salt),
      iterations,
      payload
    });

    setUiUnlocked(true);
    setStatus("Vault dibuat & dibuka untuk akun: " + currentVaultName);
    renderTable();
    armIdleLock();
    $("k2Value").value = "";
    updateSecondKeyUiFromEnvelope();
    return;
  }

  // UNLOCK
  try{
    const salt = unb64(env.salt_b64);
    const iters = env.iterations || 210000;

    if (env.kdf_version === 2){
      if (!k2Value) return setWarn("Vault ini butuh kunci kedua.");
      unlockedKey = await deriveKey(master, k2Value, salt, iters);
    }else{
      unlockedKey = await deriveKey(master, "", salt, iters);
    }

    vaultData = await decryptJson(unlockedKey, env.payload);

    setUiUnlocked(true);
    setStatus("Vault dibuka untuk akun: " + currentVaultName);
    renderTable();
    armIdleLock();
    $("k2Value").value = "";
    updateSecondKeyUiFromEnvelope();
  }catch{
    unlockedKey = null;
    vaultData = { items: [] };
    setUiUnlocked(false);
    setStatus("Terkunci.");
    setWarn("Gagal unlock. Kunci salah atau data corrupt.");
    renderTable();
    disarmIdleLock();
    updateSecondKeyUiFromEnvelope();
  }
}

function lock(reason){
  unlockedKey = null;
  vaultData = { items: [] };
  $("master").value = "";
  $("k2Value").value = "";
  setStatus(reason || "Terkunci.");
  renderTable();
  disarmIdleLock();
  setUiUnlocked(false);
}

/* ===== CRUD ===== */
async function addItem(){
  setWarn("");
  if (!unlockedKey) return setWarn("Unlock dulu.");

  const item = {
    label: $("label").value.trim(),
    site: $("site").value.trim(),
    username: $("user").value.trim(),
    password: $("pass").value
  };

  if (!item.label || !item.site || !item.username || !item.password) return setWarn("Semua field wajib diisi.");

  vaultData.items.push(item);
  await saveVault();

  // reset field (tetap hidden)
  $("label").value = "";
  $("site").value = "";
  $("user").value = "";
  $("pass").value = "";

  setStatus("Item ditambahkan (terenkripsi).");
  renderTable();
  resetDeadline();
}

async function delItem(idx){
  if (!unlockedKey) return;
  vaultData.items.splice(idx, 1);
  await saveVault();
  setStatus("Item dihapus.");
  renderTable();
  resetDeadline();
}

async function copyText(text){
  await navigator.clipboard.writeText(text || "");
  setStatus("Tersalin ke clipboard.");
  resetDeadline();
}

async function exportVault(){
  if (!unlockedKey) return;
  const data = localStorage.getItem(storageKeyFor(currentVaultName));
  const blob = new Blob([data], { type:"application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "vault-export-" + currentVaultName + ".json";
  a.click();
  URL.revokeObjectURL(url);
  setStatus("Export selesai (masih terenkripsi).");
  resetDeadline();
}

async function importVault(){
  if (!unlockedKey) return;

  const input = document.createElement("input");
  input.type = "file";
  input.accept = "application/json";
  input.onchange = async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    const text = await file.text();
    try{
      const obj = JSON.parse(text);
      if (!obj || !obj.payload || !obj.payload.iv || !obj.payload.ct || !obj.salt_b64) throw new Error("format");
      saveEnvelope(obj);
      lock("Import selesai. Silakan unlock lagi.");
    }catch{
      setWarn("File import tidak valid.");
    }
  };
  input.click();
  resetDeadline();
}

/* ===== reveal/hide for INPUT fields (default hidden) ===== */
function toggleType(inputId, btnId){
  const inp = $(inputId);
  const btn = $(btnId);
  if (!inp || !btn) return;
  btn.addEventListener("click", () => {
    inp.type = (inp.type === "password") ? "text" : "password";
    resetDeadline();
  });
}

/* ===== Wire UI ===== */
$("unlockBtn").addEventListener("click", unlockOrCreate);
$("lockBtn").addEventListener("click", () => lock("Terkunci."));
$("addBtn").addEventListener("click", addItem);
$("genBtn").addEventListener("click", () => { $("pass").value = randomPassword(22); resetDeadline(); });
$("exportBtn").addEventListener("click", exportVault);
$("importBtn").addEventListener("click", importVault);
$("search").addEventListener("input", renderTable);

$("idleMinutes").addEventListener("change", () => { if (unlockedKey) resetDeadline(); });

$("vaultSelect").addEventListener("change", (e) => {
  currentVaultName = e.target.value;
  onVaultChanged();
});

$("newVaultBtn").addEventListener("click", () => {
  const name = prompt("Nama akun vault baru? (mis: Andi / Budi / Kerja / Pribadi)");
  if (!name) return;
  const n = String(name).trim();
  if (!n) return;

  const idx = ensureIndexHasDefault();
  if (!idx.includes(n)){
    idx.push(n);
    saveIndex(idx);
  }
  refreshVaultSelect(n);
});

/* table buttons: eye/copy/delete */
$("tbody").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;

  const idx = Number(btn.getAttribute("data-idx"));

  if (btn.hasAttribute("data-del")) return delItem(idx);

  if (btn.hasAttribute("data-eye")){
    const kind = btn.getAttribute("data-kind");
    return revealCellOnce(idx, kind);
  }

  const copyType = btn.getAttribute("data-copy");
  if (copyType === "user") return copyText(vaultData.items[idx]?.username || "");
  if (copyType === "pass") return copyText(vaultData.items[idx]?.password || "");
});

/* aktivitas -> reset deadline */
const appRoot = $("appRoot");
appRoot.addEventListener("click", () => { if (unlockedKey) resetDeadline(); }, true);
appRoot.addEventListener("keydown", () => { if (unlockedKey) resetDeadline(); }, true);
appRoot.addEventListener("input", () => { if (unlockedKey) resetDeadline(); }, true);

/* toggles */
toggleType("master", "toggleMaster");
toggleType("k2Value", "toggleK2");
toggleType("label", "toggleLabel");
toggleType("site", "toggleSite");
toggleType("user", "toggleUser");
toggleType("pass", "togglePass");

/* ===== INIT ===== */
refreshVaultSelect("Default");
setUiUnlocked(false);
renderTable();
updateSecondKeyUiFromEnvelope();
updateTimerUI();
