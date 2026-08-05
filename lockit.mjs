// Lockit — livello "cassaforte" sul nucleo verificato (pbw-core.mjs).
// Versione MVP SENZA KIT (solo password, modello CryptPad: nessun recupero).
// Superficie pubblica ridotta alle sole porte sicure. Chiusure del 4o giro:
//  - API low-level NON esportate (niente sessione operativa da master non
//    autenticato): si esce solo da createVault o unlockBlobWithPassword, che
//    verificano MAC e nome fisico (N11/N12).
//  - flag session.verified: protectBytes rifiuta una sessione non verificata e
//    rivalida session.master (N16).
//  - unlockBlobWithPassword verifica nome+tetto PRIMA della KDF (fail-fast, N15).
//  - azzeramento a OWNERSHIP esplicita: i buffer non "consegnati" col return
//    riuscito vengono azzerati anche se una derivazione lancia (R03/F17).
//  - peekName: allowlist stretta dei tag del primo record (R04).
// Togliendo il Kit spariscono per costruzione: downgrade del Kit, race e
// semantica non retroattiva dell'aggiunta (N11 parte, N13, N14, R01, N03).
// LIMITI DICHIARATI (file sacrificabili): niente recupero password; rollback
// integrale dello stato cartella (manifest nel prodotto vero); incapsulamento
// forte della sessione (verified/_flags sono difesa in profondita', non assoluta);
// azzeramento memoria best-effort (limite JS). F07 = orchestratore (Passo 3b).

import * as C from "./pbw-core.mjs";

const MAGIC = "LKT1";
const OPS = 3, MEM = 64 * 1024 * 1024;
const LEN = { salt: 16, nonce: 24, wrap32: 48, ss: 24, mac: 32 };
const BLOB_MAX = C.MVP_FILE_MAX + 8 * 1024 * 1024;
const te = s => new TextEncoder().encode(s);

function adMaster(vaultId) { return C.jcs({ d: "lockit/ad/master/v1", v: 1, vault_id: vaultId }); }
function adObjKey(vaultId, objId) { return C.jcs({ d: "lockit/ad/objkey/v1", v: 1, vault_id: vaultId, obj_id: objId }); }
function deriveKHdr(vaultKey) { return C.hkdfSha256(vaultKey, C.FORMAT_HKDF_SALT, te("lockit/hdr/v1")); }
export function opaqueNameOf(blob) { return C.b32OfDigest(C.blake32(blob)).slice(0, 32) + ".lockit"; }

function chkKeys(obj, expected, dove) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) throw new Error("schema " + dove + ": non e un oggetto");
  if (Object.keys(obj).sort().join(",") !== expected.slice().sort().join(",")) throw new Error("schema " + dove + ": campi inattesi o mancanti");
}
function b64len(s, n, dove) { if (typeof s !== "string") throw new Error(dove + " non stringa"); const b = C.b64uDec(s); if (b.length !== n) throw new Error("lunghezza non valida: " + dove); return b; }
function noUnpairedSurrogates(str, dove) {
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) { const d = str.charCodeAt(i + 1); if (!(d >= 0xdc00 && d <= 0xdfff)) throw new Error(dove + ": surrogate non appaiata"); i++; }
    else if (c >= 0xdc00 && c <= 0xdfff) throw new Error(dove + ": surrogate non appaiata");
  }
}

// master = { vault_id, pw } (nessun Kit nell'MVP)
function validateMasterShape(m) {
  chkKeys(m, ["vault_id", "pw"], "master");
  if (typeof m.vault_id !== "string") throw new Error("master.vault_id non valido");
  C.b32Dec16(m.vault_id);
  chkKeys(m.pw, ["alg", "salt", "ops", "mem", "nonce", "ct"], "master.pw");
  if (m.pw.alg !== "ARGON2ID13") throw new Error("algoritmo password non supportato");
  b64len(m.pw.salt, LEN.salt, "master.pw.salt");
  b64len(m.pw.nonce, LEN.nonce, "master.pw.nonce");
  b64len(m.pw.ct, LEN.wrap32, "master.pw.ct");
  C.validateKdf({ alg: m.pw.alg, ops: m.pw.ops, mem: m.pw.mem });
}
function passwordIsTentabile(m) { return C.validateKdf({ alg: m.pw.alg, ops: m.pw.ops, mem: m.pw.mem }); }

function validateHeaderShape(h) {
  chkKeys(h, ["v", "vault_id", "obj_id", "master", "obj_key_wrap", "ss_header", "mac"], "header");
  if (h.v !== 1) throw new Error("versione header non supportata");
  if (typeof h.vault_id !== "string" || typeof h.obj_id !== "string") throw new Error("id non validi");
  C.b32Dec16(h.vault_id); C.b32Dec16(h.obj_id);
  chkKeys(h.obj_key_wrap, ["nonce", "ct"], "obj_key_wrap");
  b64len(h.obj_key_wrap.nonce, LEN.nonce, "obj_key_wrap.nonce");
  b64len(h.obj_key_wrap.ct, LEN.wrap32, "obj_key_wrap.ct");
  b64len(h.ss_header, LEN.ss, "ss_header");
  b64len(h.mac, LEN.mac, "mac");
  validateMasterShape(h.master);
  if (h.vault_id !== h.master.vault_id) throw new Error("vault_id incoerente tra header e master");
}
const RESERVED = new Set(["CON","PRN","AUX","NUL",
  "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9","COM\u00b9","COM\u00b2","COM\u00b3",
  "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9","LPT\u00b9","LPT\u00b2","LPT\u00b3"]);
function validateName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 255) throw new Error("nome file non valido");
  noUnpairedSurrogates(name, "nome file");
  if (/[<>:"/\\|?*\u0000-\u001f]/.test(name)) throw new Error("nome file con caratteri non ammessi");
  if (/[ .]$/.test(name)) throw new Error("il nome file non puo finire con spazio o punto");
  if (RESERVED.has(name.split(".")[0].toUpperCase())) throw new Error("nome file riservato dal sistema");
}
function validateMeta(m) {
  chkKeys(m, ["name", "size", "blake2b"], "metadati");
  if (!Number.isInteger(m.size) || m.size < 0 || m.size > C.MVP_FILE_MAX) throw new Error("dimensione dichiarata non valida");
  b64len(m.blake2b, 32, "impronta metadati");
  validateName(m.name);
}

export function destroySession(session) {
  const sodium = C.sodium;
  for (const k of ["vaultKey", "kObj", "kHdr"]) { if (session && session[k]) { sodium.memzero(session[k]); session[k] = null; } }
  if (session) session.verified = false;
}

export async function createVault(passwordStr) {
  const sodium = C.sodium;
  const pwBytes = C.passwordBytes(passwordStr);
  let kekPw = null, vaultKey = null, kObj = null, kHdr = null, committed = false;
  try {
    C.checkBlocklist(passwordStr, C.BLOCKLIST_V1);
    vaultKey = C.randomBytes(32);
    const vaultId = C.newId16();
    const pwSalt = C.randomBytes(16);
    kekPw = C.kekFromPassword(pwBytes, pwSalt, OPS, MEM);
    const noncePw = C.randomBytes(24);
    const wrapPw = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(vaultKey, adMaster(vaultId), null, noncePw, kekPw);
    const master = { vault_id: vaultId,
      pw: { alg: "ARGON2ID13", salt: C.b64u(pwSalt), ops: OPS, mem: MEM, nonce: C.b64u(noncePw), ct: C.b64u(wrapPw) } };
    const sub = await C.deriveSubkeys(vaultKey); sodium.memzero(sub.kCred); kObj = sub.kObj;
    kHdr = await deriveKHdr(vaultKey);
    const session = { vaultKey, kObj, kHdr, vaultId, master, verified: true }; // vault appena creato = autorevole
    committed = true;
    return { session };
  } finally {
    if (kekPw) sodium.memzero(kekPw); sodium.memzero(pwBytes);
    if (!committed) { if (vaultKey) sodium.memzero(vaultKey); if (kObj) sodium.memzero(kObj); if (kHdr) sodium.memzero(kHdr); }
  }
}

// INTERNA: non esportata. Restituisce una sessione NON verificata (verified:false).
async function unlockVaultInternal(master, passwordStr) {
  const sodium = C.sodium;
  validateMasterShape(master);
  if (!passwordIsTentabile(master)) throw new Error("parametri di protezione oltre il limite tentabile su questo dispositivo");
  const pwBytes = C.passwordBytesForUnlock(passwordStr);
  let kekPw = null, vaultKey = null, kObj = null, kHdr = null, committed = false;
  try {
    kekPw = C.kekFromPassword(pwBytes, C.b64uDec(master.pw.salt), master.pw.ops, master.pw.mem);
    try {
      vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, C.b64uDec(master.pw.ct), adMaster(master.vault_id), C.b64uDec(master.pw.nonce), kekPw);
    } catch { throw new Error("password errata oppure file danneggiato"); }
    const sub = await C.deriveSubkeys(vaultKey); sodium.memzero(sub.kCred); kObj = sub.kObj;
    kHdr = await deriveKHdr(vaultKey);
    const session = { vaultKey, kObj, kHdr, vaultId: master.vault_id, master, verified: false };
    committed = true;
    return session;
  } finally {
    if (kekPw) sodium.memzero(kekPw); sodium.memzero(pwBytes);
    if (!committed) { if (vaultKey) sodium.memzero(vaultKey); if (kObj) sodium.memzero(kObj); if (kHdr) sodium.memzero(kHdr); }
  }
}
function masterFromBlob(blob) { const [h] = C.parseFile(blob, MAGIC); validateHeaderShape(h); return h.master; }

export function isLockitBlob(bytes) {
  try { const [h] = C.parseFile(bytes, MAGIC); validateHeaderShape(h); return true; } catch { return false; }
}

function validatePhysicalBinding(blob, physicalName) {
  if (typeof physicalName !== "string" || physicalName.length === 0) throw new Error("nome fisico del file obbligatorio");
  if (blob.length > BLOB_MAX) throw new Error("file oltre il tetto fisico");
  if (opaqueNameOf(blob) !== physicalName) throw new Error("il file e stato sostituito o rinominato");
}

async function verifyAndParse(session, blob, physicalName) {
  validatePhysicalBinding(blob, physicalName);
  const [h, body] = C.parseFile(blob, MAGIC);
  validateHeaderShape(h);
  if (h.vault_id !== session.vaultId || h.master.vault_id !== session.vaultId)
    throw new Error("il file appartiene a un'altra cassaforte");
  const { mac, ...hNoMac } = h;
  const atteso = await C.credAuth(session.kHdr, C.jcs(hNoMac));
  if (!C.eq(atteso, C.b64uDec(mac))) throw new Error("intestazione del file manomessa");
  return [h, body];
}

// UNICA porta di sblocco da file: nome+tetto PRIMA della KDF, MAC prima della sessione.
export async function unlockBlobWithPassword(blob, physicalName, passwordStr) {
  validatePhysicalBinding(blob, physicalName);            // N15: fail-fast prima di Argon2
  const session = await unlockVaultInternal(masterFromBlob(blob), passwordStr);
  try { await verifyAndParse(session, blob, physicalName); }
  catch (e) { destroySession(session); throw e; }
  session.verified = true;
  return session;
}

export async function protectBytes(session, name, content) {
  const sodium = C.sodium;
  if (!session || session.verified !== true) throw new Error("sessione non verificata");  // N16
  validateMasterShape(session.master);                                                    // N16
  validateName(name);
  if (content.length > C.MVP_FILE_MAX) throw new Error("file troppo grande per l'MVP (limite 100 MB)");
  const objId = C.newId16();
  const objKey = C.randomBytes(32);
  try {
    const nonce = C.randomBytes(24);
    const TAG_MSG = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    const TAG_FIN = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    const meta = { name, size: content.length, blake2b: C.b64u(C.blake32(content)) };
    const records = [];
    if (content.length === 0) records.push([C.jcs(meta), TAG_FIN]);
    else {
      records.push([C.jcs(meta), TAG_MSG]);
      for (let i = 0; i < content.length; i += C.CHUNK) {
        const chunk = content.subarray(i, Math.min(i + C.CHUNK, content.length));
        records.push([chunk, i + C.CHUNK >= content.length ? TAG_FIN : TAG_MSG]);
      }
    }
    const { ssHeader, body } = C.ssEncrypt(objKey, records);
    const objWrap = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      objKey, adObjKey(session.vaultId, objId), null, nonce, session.kObj);
    const hNoMac = { v: 1, vault_id: session.vaultId, obj_id: objId, master: session.master,
      obj_key_wrap: { nonce: C.b64u(nonce), ct: C.b64u(objWrap) }, ss_header: C.b64u(ssHeader) };
    const mac = await C.credAuth(session.kHdr, C.jcs(hNoMac));
    const blobBytes = C.buildFile(MAGIC, { ...hNoMac, mac: C.b64u(mac) }, body);
    return { blobBytes, opaqueName: opaqueNameOf(blobBytes) };
  } finally { sodium.memzero(objKey); }
}

export async function peekName(session, blob, physicalName) {
  const sodium = C.sodium;
  const [h, body] = await verifyAndParse(session, blob, physicalName);
  const objKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, C.b64uDec(h.obj_key_wrap.ct), adObjKey(h.vault_id, h.obj_id), C.b64uDec(h.obj_key_wrap.nonce), session.kObj);
  try {
    const TAG_MSG = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    const TAG_FIN = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    const fr = C.frames(body);
    const st = sodium.crypto_secretstream_xchacha20poly1305_init_pull(C.b64uDec(h.ss_header), objKey);
    const r = sodium.crypto_secretstream_xchacha20poly1305_pull(st, fr[0], null);
    if (!r) throw new Error("file protetto non leggibile");
    const ok = (fr.length === 1) ? (r.tag === TAG_FIN) : (r.tag === TAG_MSG); // R04: allowlist stretta
    if (!ok) throw new Error("sequenza dei record non conforme");
    const meta = C.parseStrictJson(r.message);
    validateMeta(meta);
    return { name: meta.name, contentVerified: false };
  } finally { sodium.memzero(objKey); }
}

export async function unprotectBlob(session, blob, physicalName) {
  const sodium = C.sodium;
  const [h, body] = await verifyAndParse(session, blob, physicalName);
  const objKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, C.b64uDec(h.obj_key_wrap.ct), adObjKey(h.vault_id, h.obj_id), C.b64uDec(h.obj_key_wrap.nonce), session.kObj);
  try {
    const recs = C.ssDecrypt(objKey, C.b64uDec(h.ss_header), body);
    const TAG_MSG = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    const TAG_FIN = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    for (let i = 0; i < recs.length; i++) {
      const atteso = (i === recs.length - 1) ? TAG_FIN : TAG_MSG;
      if (recs[i][1] !== atteso) throw new Error("sequenza dei record non conforme al formato");
    }
    const meta = C.parseStrictJson(recs[0][0]);
    validateMeta(meta);
    const content = recs.length > 1 ? C.concat(...recs.slice(1).map(r => r[0])) : new Uint8Array(0);
    if (content.length !== meta.size) throw new Error("controllo dimensione fallito");
    if (C.b64u(C.blake32(content)) !== meta.blake2b) throw new Error("controllo impronta fallito");
    return { name: meta.name, contentBytes: content };
  } finally { sodium.memzero(objKey); }
}

export { MAGIC };
