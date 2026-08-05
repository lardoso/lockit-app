import * as DefaultCrypto from "./lockit.mjs";

const te = new TextEncoder();
const SESSION_ACCESS = Symbol("lockit.session.internal");
const td = new TextDecoder("utf-8", { fatal: true });

export const INTERNAL_PREFIX = "_lockit-";
export const TEMP_RE = /^_lockit-tmp-([0-9a-f]{32})\.bin$/;
export const MANIFEST_RE = /^_lockit-txn-([0-9a-f]{32})\.json$/;
export const STAMP_RE = /^_lockit-txn-([0-9a-f]{32})\.p(10|20|30|40|50|90)$/;
export const OPAQUE_RE = /^[0-9a-z]{32}\.lockit$/;
export const MAX_CLEAR_BYTES = 100 * 1024 * 1024;
export const DEFAULT_AUTO_LOCK_MS = 10 * 60 * 1000;

export const CHECKPOINTS = Object.freeze({
  protect: Object.freeze([
    "protect.after_source_stable",
    "protect.after_blob_built",
    "protect.after_prepared",
    "protect.after_temp_closed",
    "protect.after_temp_verified",
    "protect.after_p20",
    "protect.after_collision_check",
    "protect.after_dest_published",
    "protect.after_p30",
    "protect.after_dest_verified",
    "protect.after_p40",
    "protect.after_source_revalidated",
    "protect.after_source_removed",
    "protect.after_p50",
    "protect.after_temp_cleanup",
  ]),
  unlock: Object.freeze([
    "unlock.after_cipher_stable",
    "unlock.after_cipher_verified",
    "unlock.after_collision_check",
    "unlock.after_prepared",
    "unlock.after_temp_closed",
    "unlock.after_temp_verified",
    "unlock.after_p20",
    "unlock.after_cipher_revalidated",
    "unlock.after_dest_published",
    "unlock.after_p30",
    "unlock.after_dest_verified",
    "unlock.after_p40",
    "unlock.after_cipher_revalidated_final",
    "unlock.after_source_removed",
    "unlock.after_p50",
    "unlock.after_temp_cleanup",
  ]),
});

export class OrchestratorError extends Error {
  constructor(code, message, details = undefined, cause = undefined) {
    super(message);
    this.name = "OrchestratorError";
    this.code = code;
    this.details = details;
    this.cause = cause;
  }
}

function isCrash(error) {
  return error?.code === "CRASH" || error?.name === "InjectedCrash";
}

function classifyError(error) {
  if (error instanceof OrchestratorError) return error;
  const code = error?.code;
  if (code) return new OrchestratorError(code, error.message || code, undefined, error);
  const name = error?.name;
  const mapped = {
    NotAllowedError: "PERMISSION_REQUIRED",
    SecurityError: "PERMISSION_REQUIRED",
    QuotaExceededError: "NO_SPACE",
    NoModificationAllowedError: "LOCKED_OR_READONLY",
    NotFoundError: "NOT_FOUND",
    AbortError: "INTERNAL_BROWSER_BLOCK",
  }[name] ?? "OPERATION_FAILED";
  return new OrchestratorError(mapped, error?.message || mapped, undefined, error);
}

function randomOpId() {
  const bytes = new Uint8Array(16);
  if (!globalThis.crypto?.getRandomValues) throw new Error("crypto.getRandomValues non disponibile");
  globalThis.crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes) {
  if (!globalThis.crypto?.subtle) throw new Error("crypto.subtle non disponibile");
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}

async function sha256Hex(bytes) {
  return [...await sha256(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function equalBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function zeroBytes(...values) {
  for (const value of values) {
    if (value instanceof Uint8Array) value.fill(0);
  }
}

function canonicalName(name) {
  return String(name).normalize("NFC").toLocaleLowerCase("en-US");
}

function validateUserFileName(name) {
  if (typeof name !== "string" || name.length === 0 || name === "." || name === "..") {
    throw new OrchestratorError("UNSUPPORTED_NAME", "nome file non valido");
  }
  if (name.startsWith(INTERNAL_PREFIX)) {
    throw new OrchestratorError("UNSUPPORTED_NAME", "il prefisso _lockit- è riservato");
  }
  if (name.includes("/") || name.includes("\\")) {
    throw new OrchestratorError("UNSUPPORTED_NAME", "il nome deve essere una singola componente");
  }
}

function validateProtectSourceName(name) {
  validateUserFileName(name);
  if (OPAQUE_RE.test(name)) {
    throw new OrchestratorError("UNSUPPORTED_NAME", "il nome coincide con il namespace dei file protetti");
  }
}

function tempName(opId) {
  return `_lockit-tmp-${opId}.bin`;
}

function manifestName(opId) {
  return `_lockit-txn-${opId}.json`;
}

function stampName(opId, phase) {
  return `_lockit-txn-${opId}.p${String(phase).padStart(2, "0")}`;
}

function encodeJson(value) {
  return te.encode(`${JSON.stringify(value)}\n`);
}

function decodeJson(bytes) {
  return JSON.parse(td.decode(bytes));
}

function sanitizeDetails(details) {
  if (!details || typeof details !== "object") return details;
  const safe = {};
  for (const [key, value] of Object.entries(details)) {
    if (/session|password|key|contentBytes|clearBytes|blobBytes/i.test(key)) continue;
    if (value instanceof Uint8Array) safe[key] = `[${value.length} bytes]`;
    else safe[key] = value;
  }
  return safe;
}

function buildManifest({ opId, direction, tempName: tmp, sourceOpaqueName = null, expectedOpaqueName = null, candidateCipherSize, candidateCipherSha256, now }) {
  return Object.freeze({
    format: "lockit-txn",
    version: 1,
    opId,
    direction,
    tempName: tmp,
    sourceOpaqueName,
    expectedOpaqueName,
    candidateCipherSize,
    candidateCipherSha256,
    createdAt: new Date(now()).toISOString(),
  });
}

function validateManifest(value, expectedOpId = undefined) {
  const expectedKeys = [
    "candidateCipherSha256", "candidateCipherSize", "createdAt", "direction",
    "expectedOpaqueName", "format", "opId", "sourceOpaqueName", "tempName", "version",
  ].sort();
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("manifesto non oggetto");
  if (Object.keys(value).sort().join(",") !== expectedKeys.join(",")) throw new Error("schema manifesto non valido");
  if (value.format !== "lockit-txn" || value.version !== 1) throw new Error("versione manifesto non valida");
  if (!/^[0-9a-f]{32}$/.test(value.opId) || (expectedOpId && value.opId !== expectedOpId)) throw new Error("opId manifesto non valido");
  if (value.direction !== "PROTECT" && value.direction !== "UNLOCK") throw new Error("direzione manifesto non valida");
  if (value.tempName !== tempName(value.opId)) throw new Error("tempName manifesto non valido");
  if (value.direction === "PROTECT") {
    if (value.sourceOpaqueName !== null) throw new Error("sourceOpaqueName inatteso");
    if (!OPAQUE_RE.test(value.expectedOpaqueName)) throw new Error("expectedOpaqueName non valido");
  } else {
    if (!OPAQUE_RE.test(value.sourceOpaqueName)) throw new Error("sourceOpaqueName non valido");
    if (value.expectedOpaqueName !== null) throw new Error("expectedOpaqueName inatteso");
  }
  if (!Number.isInteger(value.candidateCipherSize) || value.candidateCipherSize < 0) throw new Error("dimensione candidata non valida");
  if (!/^[0-9a-f]{64}$/.test(value.candidateCipherSha256)) throw new Error("hash candidato non valido");
  return value;
}

export class SessionManager {
  #crypto;
  #session = null;
  #lastActivity = 0;
  #timeoutMs;
  #now;

  constructor({ crypto = DefaultCrypto, timeoutMs = DEFAULT_AUTO_LOCK_MS, now = () => Date.now() } = {}) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError("timeoutMs deve essere un numero positivo finito");
    }
    this.#crypto = crypto;
    this.#timeoutMs = timeoutMs;
    this.#now = now;
  }

  async create(password) {
    this.lock();
    const { session } = await this.#crypto.createVault(password);
    this.#session = session;
    this.#lastActivity = this.#now();
  }

  async unlock(blobBytes, physicalName, password) {
    this.lock();
    this.#session = await this.#crypto.unlockBlobWithPassword(blobBytes, physicalName, password);
    this.#lastActivity = this.#now();
  }

  isUnlocked() {
    this.#expireIfNeeded();
    return this.#session !== null;
  }

  touch() {
    this.#expireIfNeeded();
    if (this.#session) this.#lastActivity = this.#now();
  }

  lock() {
    if (this.#session) this.#crypto.destroySession(this.#session);
    this.#session = null;
    this.#lastActivity = 0;
  }

  #expireIfNeeded() {
    if (this.#session && this.#now() - this.#lastActivity >= this.#timeoutMs) this.lock();
  }

  async [SESSION_ACCESS](internalCallback) {
    this.#expireIfNeeded();
    if (!this.#session) throw new OrchestratorError("SESSION_LOCKED", "sessione bloccata");
    this.#lastActivity = this.#now();
    try {
      return await internalCallback(this.#session);
    } finally {
      if (this.#session) this.#lastActivity = this.#now();
    }
  }
}

export class LockitOrchestrator {
  #fs;
  #crypto;
  #sessions;
  #now;
  #opIdFactory;
  #logger;

  constructor({
    fs,
    crypto = DefaultCrypto,
    sessionManager,
    sessionTimeoutMs = DEFAULT_AUTO_LOCK_MS,
    now = () => Date.now(),
    opIdFactory = randomOpId,
    logger = null,
  }) {
    if (!fs) throw new TypeError("FsAdapter obbligatorio");
    this.#fs = fs;
    this.#crypto = crypto;
    this.#sessions = sessionManager ?? new SessionManager({ crypto, timeoutMs: sessionTimeoutMs, now });
    this.#now = now;
    this.#opIdFactory = opIdFactory;
    this.#logger = logger;
  }

  get sessionManager() {
    return this.#sessions;
  }

  #log(event, details = undefined) {
    if (typeof this.#logger === "function") this.#logger(event, sanitizeDetails(details));
  }

  async #checkpoint(label, details = undefined) {
    await this.#fs.checkpoint?.(label, sanitizeDetails(details));
  }

  async #readStable(dir, name, maxBytes, checkpointPrefix) {
    const firstHandle = await this.#fs.getFileHandle(dir, name);
    const firstStat = await this.#fs.statFile(firstHandle);
    if (firstStat.size > maxBytes) throw new OrchestratorError("FILE_TOO_LARGE", `file oltre il limite: ${name}`);
    const firstBytes = await this.#fs.readFile(firstHandle);
    if (firstBytes.length !== firstStat.size) throw new OrchestratorError("CONCURRENT_MODIFICATION", "dimensione cambiata durante la lettura");
    const firstFp = await sha256Hex(firstBytes);
    await this.#checkpoint(`${checkpointPrefix}.between_reads`, { name, size: firstBytes.length });
    const secondHandle = await this.#fs.getFileHandle(dir, name);
    if (typeof this.#fs.sameEntry === "function" && !(await this.#fs.sameEntry(firstHandle, dir, name))) {
      throw new OrchestratorError("CONCURRENT_MODIFICATION", "file cancellato e ricreato durante la lettura");
    }
    const secondStat = await this.#fs.statFile(secondHandle);
    const secondBytes = await this.#fs.readFile(secondHandle);
    const secondFp = await sha256Hex(secondBytes);
    if (secondStat.size !== firstStat.size || secondBytes.length !== firstBytes.length || secondFp !== firstFp) {
      throw new OrchestratorError("CONCURRENT_MODIFICATION", "file modificato fra le due letture");
    }
    zeroBytes(firstBytes);
    return { bytes: secondBytes, sha256: secondFp, size: secondBytes.length, handle: secondHandle };
  }

  async #revalidateByName(dir, name, expectedSha256, expectedSize, expectedClear = undefined) {
    const handle = await this.#fs.getFileHandle(dir, name);
    const bytes = await this.#fs.readFile(handle);
    const fp = await sha256Hex(bytes);
    const ok = bytes.length === expectedSize && fp === expectedSha256 && (!expectedClear || equalBytes(bytes, expectedClear));
    if (!ok) {
      zeroBytes(bytes);
      throw new OrchestratorError("CONCURRENT_MODIFICATION", `sorgente modificata prima del commit: ${name}`);
    }
    return bytes;
  }

  async #assertNameAbsentConservatively(dir, wantedName) {
    const wanted = canonicalName(wantedName);
    const entries = await this.#fs.listDir(dir);
    for (const entry of entries) {
      if (canonicalName(entry.name) === wanted) {
        throw new OrchestratorError("NAME_COLLISION", `destinazione già esistente o equivalente: ${wantedName}`, { existingName: entry.name });
      }
    }
    if (await this.#fs.exists(dir, wantedName)) {
      throw new OrchestratorError("NAME_COLLISION", `destinazione già esistente: ${wantedName}`);
    }
  }

  async #writeAndReadBack(dir, name, bytes, role) {
    await this.#fs.createFileExclusive(dir, name, bytes, { role });
    const handle = await this.#fs.getFileHandle(dir, name);
    const readBack = await this.#fs.readFile(handle);
    if (!equalBytes(bytes, readBack)) {
      zeroBytes(readBack);
      throw new OrchestratorError("WRITE_VERIFY_FAILED", `rilettura diversa dopo la scrittura: ${name}`);
    }
    zeroBytes(readBack);
  }

  async #writeManifest(dir, manifest) {
    const bytes = encodeJson(manifest);
    await this.#writeAndReadBack(dir, manifestName(manifest.opId), bytes, "manifest");
    const readBack = decodeJson(await this.#fs.readFile(await this.#fs.getFileHandle(dir, manifestName(manifest.opId))));
    validateManifest(readBack, manifest.opId);
  }

  async #stamp(dir, opId, phase, extra = undefined) {
    const bytes = encodeJson({ format: "lockit-phase", version: 1, opId, phase, at: new Date(this.#now()).toISOString(), ...(extra ? { errorClass: extra } : {}) });
    const name = stampName(opId, phase);
    if (await this.#fs.exists(dir, name)) return;
    await this.#writeAndReadBack(dir, name, bytes, "stamp");
  }

  async #bestEffortErrorStamp(dir, opId, code) {
    if (!opId) return;
    try { await this.#stamp(dir, opId, 90, code); } catch {}
  }

  async #verifyProtectedBytes(session, bytes, { expectedOpaqueName, expectedCipherSha256, expectedCipherSize, expectedOriginalName = undefined, expectedClearSha256 = undefined, expectedClearSize = undefined, physicalName }) {
    if (bytes.length !== expectedCipherSize) throw new OrchestratorError("VERIFY_FAILED", "dimensione cifrata inattesa");
    const cipherFp = await sha256Hex(bytes);
    if (cipherFp !== expectedCipherSha256) throw new OrchestratorError("VERIFY_FAILED", "impronta cifrata inattesa");
    const computedOpaque = this.#crypto.opaqueNameOf(bytes);
    if (computedOpaque !== expectedOpaqueName) throw new OrchestratorError("CORRUPT_OR_RENAMED_BLOB", "nome opaco non coerente con i byte");
    const verified = await this.#crypto.unprotectBlob(session, bytes, physicalName);
    if (expectedOriginalName !== undefined && verified.name !== expectedOriginalName) {
      zeroBytes(verified.contentBytes);
      throw new OrchestratorError("VERIFY_FAILED", "nome originale verificato inatteso");
    }
    if (expectedClearSize !== undefined && verified.contentBytes.length !== expectedClearSize) {
      zeroBytes(verified.contentBytes);
      throw new OrchestratorError("VERIFY_FAILED", "dimensione chiara inattesa");
    }
    if (expectedClearSha256 !== undefined && await sha256Hex(verified.contentBytes) !== expectedClearSha256) {
      zeroBytes(verified.contentBytes);
      throw new OrchestratorError("VERIFY_FAILED", "impronta chiara inattesa");
    }
    return verified;
  }

  async #verifyProtectedEntry(session, dir, name, expectations, { temp = false } = {}) {
    const bytes = await this.#fs.readFile(await this.#fs.getFileHandle(dir, name));
    // Correzione autorevole della specifica: per un temporaneo si passa il nome
    // fisico che il blob DEVE avere, non il nome _lockit-tmp-* sul disco.
    const physicalName = temp ? this.#crypto.opaqueNameOf(bytes) : name;
    try {
      const verified = await this.#verifyProtectedBytes(session, bytes, { ...expectations, physicalName });
      return { bytes, ...verified };
    } catch (error) {
      zeroBytes(bytes);
      throw error;
    }
  }

  async #verifyClearEntry(dir, name, expectedSha256, expectedSize) {
    const bytes = await this.#fs.readFile(await this.#fs.getFileHandle(dir, name));
    const fp = await sha256Hex(bytes);
    if (bytes.length !== expectedSize || fp !== expectedSha256) {
      zeroBytes(bytes);
      throw new OrchestratorError("VERIFY_FAILED", `verifica integrale del chiaro fallita: ${name}`);
    }
    return bytes;
  }

  #supportsPredictablePublication() {
    return this.#fs.capabilities?.atomicNoReplaceMove === true
      || this.#fs.capabilities?.exclusiveCreate === true
      || this.#fs.capabilities?.bestEffortPredictableCreate === true;
  }

  #assertPredictablePublicationSupported(name) {
    if (this.#supportsPredictablePublication()) return;
    throw new OrchestratorError(
      "UNSAFE_PREDICTABLE_DESTINATION",
      `impossibile pubblicare senza rischio di sovrascrittura in corsa: ${name}`,
      {
        destinationName: name,
        atomicNoReplaceMove: this.#fs.capabilities?.atomicNoReplaceMove === true,
        exclusiveCreate: this.#fs.capabilities?.exclusiveCreate === true,
        bestEffortPredictableCreate: this.#fs.capabilities?.bestEffortPredictableCreate === true,
      },
    );
  }

  async #publishWithoutOverwrite(dir, fromName, toName, { predictableDestination = false } = {}) {
    await this.#assertNameAbsentConservatively(dir, toName);
    if (predictableDestination) this.#assertPredictablePublicationSupported(toName);
    if (this.#fs.capabilities?.atomicNoReplaceMove === true) {
      await this.#fs.moveOrRenameNoReplace(dir, fromName, toName, { role: "final" });
      return { moved: true };
    }
    const source = await this.#fs.readFile(await this.#fs.getFileHandle(dir, fromName));
    try {
      await this.#assertNameAbsentConservatively(dir, toName);
      if (predictableDestination) this.#assertPredictablePublicationSupported(toName);
      await this.#fs.createFileExclusive(dir, toName, source, { role: "final", predictableDestination });
    } finally {
      zeroBytes(source);
    }
    return { moved: false };
  }

  async #cleanupTransaction(dir, opId, tmpName) {
    if (tmpName && await this.#fs.exists(dir, tmpName)) await this.#fs.deleteFile(dir, tmpName, { role: "temp" });
    const entries = await this.#fs.listDir(dir);
    for (const entry of entries) {
      if (entry.kind !== "file") continue;
      if (entry.name === manifestName(opId) || entry.name.startsWith(`_lockit-txn-${opId}.p`)) {
        await this.#fs.deleteFile(dir, entry.name, { role: "journal" });
      }
    }
  }

  async protectOne(dir, sourceName) {
    validateProtectSourceName(sourceName);
    const opId = this.#opIdFactory();
    const tmpName = tempName(opId);
    let journaled = false;
    let clearBytes;
    let blobBytes;
    let sourceNow;
    try {
      await this.#fs.ensureReadWrite(dir);
      const stable = await this.#readStable(dir, sourceName, MAX_CLEAR_BYTES, "protect.source");
      clearBytes = stable.bytes;
      await this.#checkpoint("protect.after_source_stable", { sourceName, opId, size: stable.size });

      return await this.#sessions[SESSION_ACCESS](async (session) => {
        const protectedResult = await this.#crypto.protectBytes(session, sourceName, clearBytes);
        blobBytes = protectedResult.blobBytes;
        const opaqueName = protectedResult.opaqueName;
        if (opaqueName !== this.#crypto.opaqueNameOf(blobBytes)) {
          throw new OrchestratorError("CRYPTO_CONTRACT_BROKEN", "opaqueName incoerente con opaqueNameOf");
        }
        const blobFp = await sha256Hex(blobBytes);
        await this.#checkpoint("protect.after_blob_built", { sourceName, opId, opaqueName, size: blobBytes.length });

        const manifest = buildManifest({
          opId,
          direction: "PROTECT",
          tempName: tmpName,
          expectedOpaqueName: opaqueName,
          candidateCipherSize: blobBytes.length,
          candidateCipherSha256: blobFp,
          now: this.#now,
        });
        await this.#writeManifest(dir, manifest);
        await this.#stamp(dir, opId, 10);
        journaled = true;
        await this.#checkpoint("protect.after_prepared", { sourceName, opId, opaqueName });

        await this.#fs.createFileExclusive(dir, tmpName, blobBytes, { role: "temp" });
        await this.#checkpoint("protect.after_temp_closed", { opId, tmpName });
        const tempVerified = await this.#verifyProtectedEntry(session, dir, tmpName, {
          expectedOpaqueName: opaqueName,
          expectedCipherSha256: blobFp,
          expectedCipherSize: blobBytes.length,
          expectedOriginalName: sourceName,
          expectedClearSha256: stable.sha256,
          expectedClearSize: stable.size,
        }, { temp: true });
        zeroBytes(tempVerified.bytes, tempVerified.contentBytes);
        await this.#checkpoint("protect.after_temp_verified", { opId, tmpName });
        await this.#stamp(dir, opId, 20);
        await this.#checkpoint("protect.after_p20", { opId });

        await this.#assertNameAbsentConservatively(dir, opaqueName);
        await this.#checkpoint("protect.after_collision_check", { opId, opaqueName });
        const publication = await this.#publishWithoutOverwrite(dir, tmpName, opaqueName);
        await this.#checkpoint("protect.after_dest_published", { opId, opaqueName });
        await this.#stamp(dir, opId, 30);
        await this.#checkpoint("protect.after_p30", { opId });

        const finalVerified = await this.#verifyProtectedEntry(session, dir, opaqueName, {
          expectedOpaqueName: opaqueName,
          expectedCipherSha256: blobFp,
          expectedCipherSize: blobBytes.length,
          expectedOriginalName: sourceName,
          expectedClearSha256: stable.sha256,
          expectedClearSize: stable.size,
        });
        zeroBytes(finalVerified.bytes, finalVerified.contentBytes);
        await this.#checkpoint("protect.after_dest_verified", { opId, opaqueName });
        await this.#stamp(dir, opId, 40);
        await this.#checkpoint("protect.after_p40", { opId });

        sourceNow = await this.#revalidateByName(dir, sourceName, stable.sha256, stable.size, clearBytes);
        await this.#checkpoint("protect.after_source_revalidated", { opId, sourceName });
        await this.#fs.deleteFile(dir, sourceName, { role: "source" });
        if (await this.#fs.exists(dir, sourceName)) throw new OrchestratorError("DELETE_VERIFY_FAILED", "sorgente ancora presente dopo remove");
        await this.#checkpoint("protect.after_source_removed", { opId, sourceName });
        await this.#stamp(dir, opId, 50);
        await this.#checkpoint("protect.after_p50", { opId });

        if (!publication.moved && await this.#fs.exists(dir, tmpName)) await this.#fs.deleteFile(dir, tmpName, { role: "temp" });
        await this.#checkpoint("protect.after_temp_cleanup", { opId });
        await this.#cleanupTransaction(dir, opId, null);
        this.#log("protect.success", { sourceName, opaqueName, opId });
        return { status: "SUCCESS", direction: "PROTECT", sourceName, destinationName: opaqueName, opId };
      });
    } catch (error) {
      if (isCrash(error)) throw error;
      const normalized = classifyError(error);
      if (journaled) await this.#bestEffortErrorStamp(dir, opId, normalized.code);
      this.#log("protect.error", { sourceName, opId, code: normalized.code });
      throw normalized;
    } finally {
      zeroBytes(clearBytes, blobBytes, sourceNow);
    }
  }

  async unlockOne(dir, opaquePhysicalName) {
    if (!OPAQUE_RE.test(opaquePhysicalName)) throw new OrchestratorError("CORRUPT_OR_RENAMED_BLOB", "nome fisico .lockit non conforme");
    const opId = this.#opIdFactory();
    const tmpName = tempName(opId);
    let journaled = false;
    let cipherBytes;
    let clearBytes;
    let cipherNow;
    try {
      await this.#fs.ensureReadWrite(dir);
      const stable = await this.#readStable(dir, opaquePhysicalName, MAX_CLEAR_BYTES + 8 * 1024 * 1024, "unlock.cipher");
      cipherBytes = stable.bytes;
      if (this.#crypto.opaqueNameOf(cipherBytes) !== opaquePhysicalName) {
        throw new OrchestratorError("CORRUPT_OR_RENAMED_BLOB", "il nome fisico non corrisponde ai byte cifrati");
      }
      await this.#checkpoint("unlock.after_cipher_stable", { opaquePhysicalName, opId, size: stable.size });

      return await this.#sessions[SESSION_ACCESS](async (session) => {
        const unprotected = await this.#crypto.unprotectBlob(session, cipherBytes, opaquePhysicalName);
        const originalName = unprotected.name;
        clearBytes = unprotected.contentBytes;
        validateUserFileName(originalName);
        const clearFp = await sha256Hex(clearBytes);
        await this.#checkpoint("unlock.after_cipher_verified", { opaquePhysicalName, originalName, opId, size: clearBytes.length });

        await this.#assertNameAbsentConservatively(dir, originalName);
        this.#assertPredictablePublicationSupported(originalName);
        await this.#checkpoint("unlock.after_collision_check", { originalName, opId });

        const manifest = buildManifest({
          opId,
          direction: "UNLOCK",
          tempName: tmpName,
          sourceOpaqueName: opaquePhysicalName,
          candidateCipherSize: cipherBytes.length,
          candidateCipherSha256: stable.sha256,
          now: this.#now,
        });
        await this.#writeManifest(dir, manifest);
        await this.#stamp(dir, opId, 10);
        journaled = true;
        await this.#checkpoint("unlock.after_prepared", { opId, opaquePhysicalName });

        await this.#fs.createFileExclusive(dir, tmpName, clearBytes, { role: "temp" });
        await this.#checkpoint("unlock.after_temp_closed", { opId, tmpName });
        const tempBytes = await this.#verifyClearEntry(dir, tmpName, clearFp, clearBytes.length);
        zeroBytes(tempBytes);
        await this.#checkpoint("unlock.after_temp_verified", { opId });
        await this.#stamp(dir, opId, 20);
        await this.#checkpoint("unlock.after_p20", { opId });

        const rechecked = await this.#verifyProtectedEntry(session, dir, opaquePhysicalName, {
          expectedOpaqueName: opaquePhysicalName,
          expectedCipherSha256: stable.sha256,
          expectedCipherSize: stable.size,
          expectedOriginalName: originalName,
          expectedClearSha256: clearFp,
          expectedClearSize: clearBytes.length,
        });
        zeroBytes(rechecked.bytes, rechecked.contentBytes);
        await this.#checkpoint("unlock.after_cipher_revalidated", { opId, opaquePhysicalName });

        await this.#assertNameAbsentConservatively(dir, originalName);
        const publication = await this.#publishWithoutOverwrite(dir, tmpName, originalName, { predictableDestination: true });
        await this.#checkpoint("unlock.after_dest_published", { opId, originalName });
        await this.#stamp(dir, opId, 30);
        await this.#checkpoint("unlock.after_p30", { opId });

        const finalClear = await this.#verifyClearEntry(dir, originalName, clearFp, clearBytes.length);
        zeroBytes(finalClear);
        await this.#checkpoint("unlock.after_dest_verified", { opId, originalName });
        await this.#stamp(dir, opId, 40);
        await this.#checkpoint("unlock.after_p40", { opId });

        const finalCipherCheck = await this.#verifyProtectedEntry(session, dir, opaquePhysicalName, {
          expectedOpaqueName: opaquePhysicalName,
          expectedCipherSha256: stable.sha256,
          expectedCipherSize: stable.size,
          expectedOriginalName: originalName,
          expectedClearSha256: clearFp,
          expectedClearSize: clearBytes.length,
        });
        cipherNow = finalCipherCheck.bytes;
        zeroBytes(finalCipherCheck.contentBytes);
        await this.#checkpoint("unlock.after_cipher_revalidated_final", { opId, opaquePhysicalName });

        await this.#fs.deleteFile(dir, opaquePhysicalName, { role: "source" });
        if (await this.#fs.exists(dir, opaquePhysicalName)) throw new OrchestratorError("DELETE_VERIFY_FAILED", "cifrato ancora presente dopo remove");
        await this.#checkpoint("unlock.after_source_removed", { opId, opaquePhysicalName });
        await this.#stamp(dir, opId, 50);
        await this.#checkpoint("unlock.after_p50", { opId });

        if (!publication.moved && await this.#fs.exists(dir, tmpName)) await this.#fs.deleteFile(dir, tmpName, { role: "temp" });
        await this.#checkpoint("unlock.after_temp_cleanup", { opId });
        await this.#cleanupTransaction(dir, opId, null);
        this.#log("unlock.success", { opaquePhysicalName, originalName, opId });
        return { status: "SUCCESS", direction: "UNLOCK", sourceName: opaquePhysicalName, destinationName: originalName, opId };
      });
    } catch (error) {
      if (isCrash(error)) throw error;
      const normalized = classifyError(error);
      if (journaled) await this.#bestEffortErrorStamp(dir, opId, normalized.code);
      this.#log("unlock.error", { opaquePhysicalName, opId, code: normalized.code });
      throw normalized;
    } finally {
      zeroBytes(cipherBytes, clearBytes, cipherNow);
    }
  }

  async #readManifest(dir, entryName) {
    const match = MANIFEST_RE.exec(entryName);
    if (!match) throw new Error("nome manifesto non valido");
    const bytes = await this.#fs.readFile(await this.#fs.getFileHandle(dir, entryName));
    return validateManifest(decodeJson(bytes), match[1]);
  }

  async #highestPhase(dir, opId) {
    let phase = 0;
    for (const entry of await this.#fs.listDir(dir)) {
      const match = STAMP_RE.exec(entry.name);
      if (match && match[1] === opId && match[2] !== "90") phase = Math.max(phase, Number(match[2]));
    }
    return phase;
  }

  async #tryVerifyProtectedCandidate(session, dir, name, manifest, { temp = false } = {}) {
    if (!(await this.#fs.exists(dir, name))) return { exists: false, valid: false };
    try {
      const verified = await this.#verifyProtectedEntry(session, dir, name, {
        expectedOpaqueName: manifest.expectedOpaqueName ?? manifest.sourceOpaqueName,
        expectedCipherSha256: manifest.candidateCipherSha256,
        expectedCipherSize: manifest.candidateCipherSize,
      }, { temp });
      return { exists: true, valid: true, ...verified };
    } catch (error) {
      return { exists: true, valid: false, error: classifyError(error) };
    }
  }

  async #tryVerifyClearCandidate(dir, name, expectedBytes) {
    if (!(await this.#fs.exists(dir, name))) return { exists: false, valid: false };
    try {
      const bytes = await this.#fs.readFile(await this.#fs.getFileHandle(dir, name));
      return { exists: true, valid: equalBytes(bytes, expectedBytes), bytes };
    } catch (error) {
      return { exists: true, valid: false, error: classifyError(error) };
    }
  }

  async #recoverProtect(dir, manifest, session, phase) {
    const opId = manifest.opId;
    const finalName = manifest.expectedOpaqueName;
    const temp = await this.#tryVerifyProtectedCandidate(session, dir, manifest.tempName, manifest, { temp: true });
    const final = await this.#tryVerifyProtectedCandidate(session, dir, finalName, manifest);

    try {
      if (final.exists && !final.valid) {
        return { status: "AMBIGUOUS_RECOVERY", direction: "PROTECT", opId, reason: "FINAL_INVALID", sourcePreserved: true };
      }

      const candidate = final.valid ? final : temp.valid ? temp : null;
      if (!candidate) {
        // Prima di p20 nessuna cancellazione della sorgente era consentita.
        // Da p20 in poi un candidato era già stato verificato: se ora manca o è
        // diverso, si conserva tutto come evidenza e non si deduce nulla dai marker.
        if (phase >= 20) {
          return { status: "AMBIGUOUS_RECOVERY", direction: "PROTECT", opId, reason: "VERIFIED_CANDIDATE_MISSING_OR_CHANGED" };
        }
        if (temp.exists) await this.#fs.deleteFile(dir, manifest.tempName, { role: "temp" });
        await this.#cleanupTransaction(dir, opId, null);
        return { status: "ABORTED_SAFE", direction: "PROTECT", opId };
      }

      const originalName = candidate.name;
      validateProtectSourceName(originalName);
      const clearBytes = candidate.contentBytes;
      const clearFp = await sha256Hex(clearBytes);
      const sourceExists = await this.#fs.exists(dir, originalName);

      if (final.valid) {
        if (sourceExists) {
          const source = await this.#revalidateByName(dir, originalName, clearFp, clearBytes.length, clearBytes);
          zeroBytes(source);
          await this.#fs.deleteFile(dir, originalName, { role: "source" });
          await this.#stamp(dir, opId, 50);
        }
        if (temp.exists && temp.valid && await this.#fs.exists(dir, manifest.tempName)) {
          await this.#fs.deleteFile(dir, manifest.tempName, { role: "temp" });
        }
        await this.#cleanupTransaction(dir, opId, null);
        zeroBytes(clearBytes);
        return { status: "RECOVERED", direction: "PROTECT", opId, destinationName: finalName };
      }

      if (sourceExists) {
        const source = await this.#revalidateByName(dir, originalName, clearFp, clearBytes.length, clearBytes);
        zeroBytes(source);
      }
      await this.#assertNameAbsentConservatively(dir, finalName);
      const publication = await this.#publishWithoutOverwrite(dir, manifest.tempName, finalName);
      const finalVerified = await this.#verifyProtectedEntry(session, dir, finalName, {
        expectedOpaqueName: finalName,
        expectedCipherSha256: manifest.candidateCipherSha256,
        expectedCipherSize: manifest.candidateCipherSize,
        expectedOriginalName: originalName,
        expectedClearSha256: clearFp,
        expectedClearSize: clearBytes.length,
      });
      zeroBytes(finalVerified.bytes, finalVerified.contentBytes);
      await this.#stamp(dir, opId, 40);
      if (sourceExists) {
        const source = await this.#revalidateByName(dir, originalName, clearFp, clearBytes.length, clearBytes);
        zeroBytes(source);
        await this.#fs.deleteFile(dir, originalName, { role: "source" });
      }
      await this.#stamp(dir, opId, 50);
      if (!publication.moved && await this.#fs.exists(dir, manifest.tempName)) {
        await this.#fs.deleteFile(dir, manifest.tempName, { role: "temp" });
      }
      await this.#cleanupTransaction(dir, opId, null);
      zeroBytes(clearBytes);
      return { status: "RECOVERED", direction: "PROTECT", opId, destinationName: finalName };
    } finally {
      zeroBytes(temp.bytes, temp.contentBytes, final.bytes, final.contentBytes);
    }
  }

  async #findExactUserMatches(dir, expectedBytes, excludedNames = []) {
    const excluded = new Set(excludedNames.map(canonicalName));
    const matches = [];
    for (const entry of await this.#fs.listDir(dir)) {
      if (entry.kind !== "file" || entry.name.startsWith(INTERNAL_PREFIX) || excluded.has(canonicalName(entry.name))) continue;
      const bytes = await this.#fs.readFile(entry.handle);
      const equal = equalBytes(bytes, expectedBytes);
      zeroBytes(bytes);
      if (equal) matches.push(entry.name);
    }
    return matches;
  }

  async #recoverUnlock(dir, manifest, session, phase) {
    const opId = manifest.opId;
    const cipherName = manifest.sourceOpaqueName;
    const cipher = await this.#tryVerifyProtectedCandidate(session, dir, cipherName, manifest);

    if (cipher.exists && !cipher.valid) {
      return { status: "AMBIGUOUS_RECOVERY", direction: "UNLOCK", opId, reason: "CIPHER_INVALID" };
    }

    if (cipher.valid) {
      const originalName = cipher.name;
      validateUserFileName(originalName);
      const clearBytes = cipher.contentBytes;
      const temp = await this.#tryVerifyClearCandidate(dir, manifest.tempName, clearBytes);
      const final = await this.#tryVerifyClearCandidate(dir, originalName, clearBytes);
      try {
        if (!this.#supportsPredictablePublication()) {
          return {
            status: "UNSAFE_PREDICTABLE_DESTINATION",
            direction: "UNLOCK",
            opId,
            destinationName: originalName,
            reason: final.exists ? "DESTINATION_PRESENT_ON_UNSAFE_ADAPTER" : "NO_ATOMIC_NO_REPLACE_PRIMITIVE",
          };
        }
        if (final.exists && !final.valid) {
          return { status: "NAME_COLLISION", direction: "UNLOCK", opId, destinationName: originalName };
        }
        if (final.valid) {
          const rechecked = await this.#tryVerifyProtectedCandidate(session, dir, cipherName, manifest);
          if (!rechecked.valid) return { status: "AMBIGUOUS_RECOVERY", direction: "UNLOCK", opId, reason: "CIPHER_CHANGED" };
          zeroBytes(rechecked.bytes, rechecked.contentBytes);
          await this.#fs.deleteFile(dir, cipherName, { role: "source" });
          await this.#stamp(dir, opId, 50);
          if (temp.exists && temp.valid && await this.#fs.exists(dir, manifest.tempName)) {
            await this.#fs.deleteFile(dir, manifest.tempName, { role: "temp" });
          }
          await this.#cleanupTransaction(dir, opId, null);
          return { status: "RECOVERED", direction: "UNLOCK", opId, destinationName: originalName };
        }
        if (temp.valid) {
          await this.#assertNameAbsentConservatively(dir, originalName);
          const publication = await this.#publishWithoutOverwrite(dir, manifest.tempName, originalName, { predictableDestination: true });
          const finalBytes = await this.#verifyClearEntry(dir, originalName, await sha256Hex(clearBytes), clearBytes.length);
          zeroBytes(finalBytes);
          await this.#stamp(dir, opId, 40);
          const rechecked = await this.#tryVerifyProtectedCandidate(session, dir, cipherName, manifest);
          if (!rechecked.valid) return { status: "AMBIGUOUS_RECOVERY", direction: "UNLOCK", opId, reason: "CIPHER_CHANGED_AFTER_PUBLISH" };
          zeroBytes(rechecked.bytes, rechecked.contentBytes);
          await this.#fs.deleteFile(dir, cipherName, { role: "source" });
          await this.#stamp(dir, opId, 50);
          if (!publication.moved && await this.#fs.exists(dir, manifest.tempName)) {
            await this.#fs.deleteFile(dir, manifest.tempName, { role: "temp" });
          }
          await this.#cleanupTransaction(dir, opId, null);
          return { status: "RECOVERED", direction: "UNLOCK", opId, destinationName: originalName };
        }
        if (temp.exists && !temp.valid) await this.#fs.deleteFile(dir, manifest.tempName, { role: "temp" });
        await this.#cleanupTransaction(dir, opId, null);
        return { status: "ABORTED_SAFE", direction: "UNLOCK", opId, sourceName: cipherName };
      } finally {
        zeroBytes(clearBytes, temp.bytes, final.bytes);
      }
    }

    // Su un adattatore privo di no-replace atomico non è dimostrabile che una
    // destinazione prevedibile già pubblicata non abbia sovrascritto una race.
    // Il recupero resta quindi fail-closed e non dichiara successo né pulisce.
    if (!this.#supportsPredictablePublication()) {
      return { status: "AMBIGUOUS_RECOVERY", direction: "UNLOCK", opId, reason: "UNSAFE_PREDICTABLE_DESTINATION_SOURCE_MISSING" };
    }

    // Il protocollo sicuro elimina il cifrato solo dopo p40. Se il cifrato manca,
    // non sono consentite ulteriori cancellazioni di dati utente.
    const tempExists = await this.#fs.exists(dir, manifest.tempName);
    if (tempExists) {
      const tempBytes = await this.#fs.readFile(await this.#fs.getFileHandle(dir, manifest.tempName));
      const matches = await this.#findExactUserMatches(dir, tempBytes, [cipherName]);
      zeroBytes(tempBytes);
      if (matches.length === 1 && phase >= 40) {
        await this.#fs.deleteFile(dir, manifest.tempName, { role: "temp" });
        await this.#cleanupTransaction(dir, opId, null);
        return { status: "RECOVERED", direction: "UNLOCK", opId, destinationName: matches[0] };
      }
      return { status: "AMBIGUOUS_RECOVERY", direction: "UNLOCK", opId, reason: "SOURCE_MISSING_WITH_TEMP" };
    }
    if (phase >= 40) {
      await this.#cleanupTransaction(dir, opId, null);
      return { status: "RECOVERED_CLEANUP_ONLY", direction: "UNLOCK", opId };
    }
    return { status: "AMBIGUOUS_RECOVERY", direction: "UNLOCK", opId, reason: "SOURCE_AND_TEMP_MISSING" };
  }

  async recoverDirectory(dir) {
    await this.#fs.ensureReadWrite(dir);
    const entries = await this.#fs.listDir(dir);
    const manifests = entries.filter((entry) => entry.kind === "file" && MANIFEST_RE.test(entry.name));
    const results = [];
    for (const entry of manifests) {
      let manifest;
      try {
        manifest = await this.#readManifest(dir, entry.name);
      } catch (error) {
        results.push({ status: "AMBIGUOUS_RECOVERY", reason: "INVALID_MANIFEST", manifestName: entry.name });
        continue;
      }
      const phase = await this.#highestPhase(dir, manifest.opId);
      if (!this.#sessions.isUnlocked()) {
        results.push({ status: "PENDING_UNLOCK", direction: manifest.direction, opId: manifest.opId, phase });
        continue;
      }
      try {
        const result = await this.#sessions[SESSION_ACCESS]((session) => manifest.direction === "PROTECT"
          ? this.#recoverProtect(dir, manifest, session, phase)
          : this.#recoverUnlock(dir, manifest, session, phase));
        results.push({ ...result, phase });
      } catch (error) {
        if (isCrash(error)) throw error;
        const normalized = classifyError(error);
        await this.#bestEffortErrorStamp(dir, manifest.opId, normalized.code);
        results.push({ status: "RECOVERY_ERROR", direction: manifest.direction, opId: manifest.opId, phase, error: normalized.code });
      }
    }
    return results;
  }

  async recoverTree(rootDir) {
    const results = [];
    const visit = async (dir, path) => {
      results.push(...(await this.recoverDirectory(dir)).map((result) => ({ path, ...result })));
      for (const entry of await this.#fs.listDir(dir)) {
        if (entry.kind === "dir") await visit(entry.handle, `${path}/${entry.name}`);
      }
    };
    await visit(rootDir, "");
    return results;
  }

  async #expandSelections(selections, mode) {
    const planned = [];
    const seen = new Set();
    const visitDir = async (dir, path) => {
      for (const entry of await this.#fs.listDir(dir)) {
        const childPath = `${path}/${entry.name}`;
        if (entry.kind === "dir") {
          await visitDir(entry.handle, childPath);
          continue;
        }
        if (entry.name.startsWith(INTERNAL_PREFIX)) continue;
        const wanted = mode === "PROTECT" ? !OPAQUE_RE.test(entry.name) : OPAQUE_RE.test(entry.name);
        if (!wanted) continue;
        const identity = await this.#fs.identityOf(dir, entry.name);
        if (!seen.has(identity)) {
          seen.add(identity);
          planned.push({ dir, name: entry.name, path: childPath });
        }
      }
    };

    for (const selection of selections) {
      if (selection.kind === "dir") {
        await visitDir(selection.handle, selection.path ?? "");
      } else {
        const identity = await this.#fs.identityOf(selection.dir, selection.name);
        if (!seen.has(identity)) {
          seen.add(identity);
          planned.push({ dir: selection.dir, name: selection.name, path: selection.path ?? selection.name });
        }
      }
    }
    return planned;
  }

  async runBatch(selections, direction) {
    if (direction !== "PROTECT" && direction !== "UNLOCK") throw new TypeError("direzione batch non valida");
    const plan = await this.#expandSelections(selections, direction);
    const results = [];
    for (const item of plan) {
      try {
        const result = direction === "PROTECT"
          ? await this.protectOne(item.dir, item.name)
          : await this.unlockOne(item.dir, item.name);
        results.push({ path: item.path, ok: true, ...result });
      } catch (error) {
        if (isCrash(error)) throw error;
        const normalized = classifyError(error);
        results.push({ path: item.path, ok: false, status: "ERROR", error: normalized.code, message: normalized.message });
      }
    }
    return results;
  }

  async scanTree(rootDir, { visiblePaths = new Set(), includeHiddenProtectedNames = false } = {}) {
    const visit = async (dir, path) => {
      const nodes = [];
      for (const entry of await this.#fs.listDir(dir)) {
        const childPath = path ? `${path}/${entry.name}` : entry.name;
        if (entry.name.startsWith(INTERNAL_PREFIX)) {
          nodes.push({ kind: "internal", physicalName: entry.name, path: childPath });
          continue;
        }
        if (entry.kind === "dir") {
          nodes.push({ kind: "dir", name: entry.name, path: childPath, children: await visit(entry.handle, childPath) });
          continue;
        }
        if (!entry.name.endsWith(".lockit")) {
          nodes.push({ kind: "clear", name: entry.name, physicalName: entry.name, path: childPath });
          continue;
        }
        let classification = OPAQUE_RE.test(entry.name) ? "protected-candidate" : "renamed-or-invalid";
        let displayName = includeHiddenProtectedNames ? entry.name : undefined;
        if (classification === "protected-candidate" && visiblePaths.has(childPath) && this.#sessions.isUnlocked()) {
          try {
            const bytes = await this.#fs.readFile(entry.handle);
            if (this.#crypto.opaqueNameOf(bytes) !== entry.name) throw new Error("nome fisico non coerente");
            const peeked = await this.#sessions[SESSION_ACCESS]((session) => this.#crypto.peekName(session, bytes, entry.name));
            displayName = peeked.name;
            classification = "protected";
            zeroBytes(bytes);
          } catch {
            classification = "corrupt-or-different-vault";
          }
        }
        nodes.push({ kind: classification, name: displayName, physicalName: entry.name, path: childPath });
      }
      return nodes;
    };
    return visit(rootDir, "");
  }
}
