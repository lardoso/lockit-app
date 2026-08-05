/**
 * FsAdapter reale per Chrome/File System Access API.
 * Non promette atomicità, O_EXCL o fsync. Per l'MVP dichiara esplicitamente
 * l'opt-in best-effort per i nomi prevedibili, con rischio residuo accettato.
 */

export class BrowserFsAdapterError extends Error {
  constructor(code, message, cause = undefined) {
    super(message);
    this.name = "BrowserFsAdapterError";
    this.code = code;
    this.cause = cause;
  }
}

function classifyDomError(error) {
  const name = error?.name;
  if (name === "NotAllowedError" || name === "SecurityError") return "PERMISSION_REQUIRED";
  if (name === "QuotaExceededError") return "NO_SPACE";
  if (name === "NoModificationAllowedError" || name === "InvalidModificationError") return "LOCKED_OR_READONLY";
  if (name === "NotFoundError") return "NOT_FOUND";
  if (name === "AbortError") return "INTERNAL_BROWSER_BLOCK";
  return "FS_ERROR";
}

async function notFound(handle, name) {
  try {
    await handle.getFileHandle(name, { create: false });
    return false;
  } catch (error) {
    if (error?.name === "NotFoundError") return true;
    throw error;
  }
}

export class BrowserFsAdapter {
  constructor({ bestEffortPredictableCreate = true } = {}) {
    this.capabilities = Object.freeze({
      atomicNoReplaceMove: false,
      durableFlush: false,
      exclusiveCreate: false,
      bestEffortPredictableCreate: bestEffortPredictableCreate === true,
      caseInsensitiveNames: true,
    });
  }

  async checkpoint() {}

  async requestReadWritePermission(dirHandle) {
    const result = await dirHandle.requestPermission({ mode: "readwrite" });
    if (result !== "granted") throw new BrowserFsAdapterError("PERMISSION_REQUIRED", "permesso readwrite non concesso");
    return result;
  }

  async ensureReadWrite(dirHandle) {
    try {
      const result = await dirHandle.queryPermission({ mode: "readwrite" });
      if (result !== "granted") throw new BrowserFsAdapterError("PERMISSION_REQUIRED", "serve un gesto utente per concedere il permesso readwrite");
    } catch (error) {
      if (error instanceof BrowserFsAdapterError) throw error;
      throw new BrowserFsAdapterError(classifyDomError(error), "verifica permessi fallita", error);
    }
  }

  async listDir(dirHandle) {
    const result = [];
    try {
      for await (const [name, handle] of dirHandle.entries()) {
        result.push({ name, kind: handle.kind === "directory" ? "dir" : "file", handle });
      }
      return result.sort((a, b) => a.name.localeCompare(b.name));
    } catch (error) {
      throw new BrowserFsAdapterError(classifyDomError(error), "enumerazione cartella fallita", error);
    }
  }

  async getFileHandle(dirHandle, name) {
    try {
      return await dirHandle.getFileHandle(name, { create: false });
    } catch (error) {
      throw new BrowserFsAdapterError(classifyDomError(error), `apertura file fallita: ${name}`, error);
    }
  }

  async getDirectoryHandle(dirHandle, name) {
    try {
      return await dirHandle.getDirectoryHandle(name, { create: false });
    } catch (error) {
      throw new BrowserFsAdapterError(classifyDomError(error), `apertura cartella fallita: ${name}`, error);
    }
  }

  async readFile(fileHandle) {
    try {
      const file = await fileHandle.getFile();
      return new Uint8Array(await file.arrayBuffer());
    } catch (error) {
      throw new BrowserFsAdapterError(classifyDomError(error), "lettura file fallita", error);
    }
  }

  async statFile(fileHandle) {
    try {
      const file = await fileHandle.getFile();
      return { size: file.size, version: `${file.lastModified}:${file.size}`, name: file.name };
    } catch (error) {
      throw new BrowserFsAdapterError(classifyDomError(error), "stat file fallita", error);
    }
  }

  async sameEntry(fileHandle, dirHandle, name) {
    try {
      const current = await dirHandle.getFileHandle(name, { create: false });
      if (typeof fileHandle.isSameEntry === "function") return await fileHandle.isSameEntry(current);
      return true;
    } catch (error) {
      if (error?.name === "NotFoundError") return false;
      throw new BrowserFsAdapterError(classifyDomError(error), "confronto handle fallito", error);
    }
  }

  async exists(dirHandle, name) {
    try {
      return !(await notFound(dirHandle, name));
    } catch (error) {
      throw new BrowserFsAdapterError(classifyDomError(error), `controllo esistenza fallito: ${name}`, error);
    }
  }

  async createFileExclusive(dirHandle, name, bytes, { predictableDestination = false } = {}) {
    let writable;
    try {
      // Safe by default: la pubblicazione prevedibile è consentita soltanto
      // quando l'adattatore dichiara esplicitamente l'opt-in best-effort.
      if (predictableDestination && this.capabilities.bestEffortPredictableCreate !== true) {
        throw new BrowserFsAdapterError(
          "UNSAFE_PREDICTABLE_DESTINATION",
          `modalità best-effort non abilitata per: ${name}`,
        );
      }
      // Preflight anti-collisione obbligatorio. Rimane una finestra di race tra
      // questo controllo e getFileHandle({create:true}), non eliminabile sul web.
      if (!(await notFound(dirHandle, name))) {
        throw new BrowserFsAdapterError("NAME_COLLISION", `destinazione già esistente: ${name}`);
      }
      const handle = await dirHandle.getFileHandle(name, { create: true });
      writable = await handle.createWritable({ keepExistingData: false });
      await writable.write(bytes);
      await writable.close();
      return handle;
    } catch (error) {
      try { await writable?.abort?.(); } catch {}
      if (error instanceof BrowserFsAdapterError) throw error;
      throw new BrowserFsAdapterError(classifyDomError(error), `scrittura file fallita: ${name}`, error);
    }
  }

  async deleteFile(dirHandle, name) {
    try {
      await dirHandle.removeEntry(name);
    } catch (error) {
      throw new BrowserFsAdapterError(classifyDomError(error), `cancellazione file fallita: ${name}`, error);
    }
  }

  async moveOrRenameNoReplace(dirHandle, fromName, toName) {
    try {
      if (!(await notFound(dirHandle, toName))) {
        throw new BrowserFsAdapterError("NAME_COLLISION", `destinazione già esistente: ${toName}`);
      }
      const source = await dirHandle.getFileHandle(fromName, { create: false });
      if (typeof source.move !== "function") {
        throw new BrowserFsAdapterError("MOVE_UNSUPPORTED", "move non disponibile per questo handle");
      }
      await source.move(toName);
    } catch (error) {
      if (error instanceof BrowserFsAdapterError) throw error;
      throw new BrowserFsAdapterError(classifyDomError(error), `move fallito: ${fromName} -> ${toName}`, error);
    }
  }

  async identityOf(dirHandle, name) {
    // Identità solo per la durata della pianificazione. Non è un path persistente.
    if (!this._dirIds) {
      this._dirIds = new WeakMap();
      this._nextDirId = 1;
    }
    if (!this._dirIds.has(dirHandle)) this._dirIds.set(dirHandle, this._nextDirId++);
    return `${this._dirIds.get(dirHandle)}:${name.normalize("NFC").toLocaleLowerCase("en-US")}`;
  }
}
