// Lockit · aggregato.mjs — l'INGRESSO AGGREGATO del prodotto (piano v0.4)
// Due classi (Q1), budget 32, dominanza, formula del tetto (Q2),
// pianificazione dei gruppi KDF (C1) e coordinatore delle derivazioni (H2).
import * as C from "./pbw-core.mjs";
import sodium from "libsodium-wrappers-sumo";
import { parseStructural, HDR_BUDGET } from "./servizio.mjs";
const te = (s) => new TextEncoder().encode(s);
export const RE_OPACO = /^[0123456789abcdefghjkmnpqrstvwxyz]{32}\.lockit$/;
export const CANONICO = "_lockit-cassaforte";          // sez.4: nome canonico
const RE_SCHEMI_INTERNI = /^_lockit-(tmp-|txn-)/;      // temporanei e manifesti
export function isCandidato(path, bytes) {               // la CLASSE (b) vera (N5, G3, Q1)
  const base = path.split("/").pop();
  const inRadice = !path.includes("/");
  const prefissato = inRadice && base.startsWith("_lockit-") &&
                     !RE_SCHEMI_INTERNI.test(base) && base !== "_lockit-quarantena";
  const nomeUtente = !base.startsWith("_lockit-") && !RE_OPACO.test(base);
  const sniffLKT1 = bytes && bytes.length >= 4 &&
    bytes[0] === 0x4c && bytes[1] === 0x4b && bytes[2] === 0x54 && bytes[3] === 0x31;
  return prefissato || (nomeUtente && sniffLKT1);
}

// -------- coordinatore delle derivazioni: qui vive il passo 13 (H2) --------
export async function derivaKek({ salt, ops, mem }, password) {
  if (!(ops >= C.OPS_MIN && ops <= C.OPS_MAX_TENTABILE) ||
      !(mem >= C.MEM_MIN && mem <= C.MEM_MAX_TENTABILE)) {
    return { errore: "ERRORE_RISORSE_KDF", rule: 13 };
  }
  await C.init();
  const pw = new TextEncoder().encode(password);
  try { return { kek: C.kekFromPassword(pw, salt, ops, mem) }; }
  catch (e) { return { errore: "ERRORE_RISORSE_KDF", rule: 13, causa: String(e && e.message || e) }; }
}

const cmpBytes = (A, B) => { const L = Math.min(A.length, B.length);
  for (let i = 0; i < L; i++) if (A[i] !== B[i]) return A[i] - B[i];
  return A.length - B.length; };
const inp = (bytes) => ({ prefisso: bytes.subarray(0, Math.min(bytes.length, HDR_BUDGET)),
                          dimensioneTotale: bytes.length });

// -------- censimento, sniff, prelettura, dominanza, tetto (Q1, Q2, C5) -----
export function censisci(files) {
  // C5: la scansione RACCOGLIE gli errori e prosegue; qui i "files" sono
  // già letti (path+bytes); gli errori di lettura arrivano come voce
  // {path, erroreAccesso:true} e vengono accumulati, mai fatali.
  const errori = [];
  const leggibili = files.filter(f => { if (f.erroreAccesso) { errori.push(f.path); return false; } return true; });
  const ord = leggibili.slice().sort((a, b) => cmpBytes(te(a.path), te(b.path)));
  // sniff dei 6 byte su TUTTI, fuori da ogni budget (livello contenitore)
  for (const f of ord) {
    const b = f.bytes;
    if (b.length >= 6 && new TextDecoder().decode(b.subarray(0, 4)) === "LKT1" &&
        ((b[4] << 8) | b[5]) > 1)
      return { riga: 2, motivo: "versione futura del contenitore", dove: [f.path], errori };
  }
  const anomali = ord.filter(f => isCandidato(f.path, f.bytes));
  let preletti = 0; const vFuturi = [];
  for (const f of anomali) {
    if (preletti >= 32) return { riga: "1e-rigida", motivo: "budget di prelettura superato", errori };
    preletti++;
    const r = parseStructural(inp(f.bytes), { soloPrelettura: true });
    if (r.errore === "VERSIONE_FUTURA_NON_AUTENTICATA") vFuturi.push(f.path);
  }
  if (vFuturi.length) return { riga: 2, motivo: "v futuro nell'intestazione", dove: vFuturi, errori };
  if (anomali.length > 8) return { riga: "1e", motivo: "perimetro anomalo oltre gli 8", errori };
  return { riga: 6, ordine: ord.map(x => x.path), candidati: anomali, errori };
}

// -------- pianificazione dei gruppi (C1) e ordine normativo (G2) -----------
export function pianificaGruppi(strutture) {
  const gruppi = new Map();
  for (const s of strutture) {
    const chiave = "ARGON2ID13|" + [...s.struct.saltB].map(x => x.toString(16).padStart(2, "0")).join("") +
                   "|" + s.struct.ops + "|" + s.struct.mem;
    if (!gruppi.has(chiave)) gruppi.set(chiave, { tupla: { salt: s.struct.saltB, ops: s.struct.ops, mem: s.struct.mem }, membri: [] });
    gruppi.get(chiave).membri.push(s);
  }
  if (gruppi.size > 3) return { oltreIGruppi: true };
  const arr = [...gruppi.values()];
  const dig = (m) => m.map(x => x.digestHex).sort()[0] ?? "";
  arr.sort((a, b) => {
    const ca = a.membri.some(m => m.path.split("/").pop() === CANONICO) ? 0 : 1;
    const cb = b.membri.some(m => m.path.split("/").pop() === CANONICO) ? 0 : 1;
    if (ca !== cb) return ca - cb;                       // 1: il gruppo del canonico
    if (a.membri.length !== b.membri.length) return b.membri.length - a.membri.length; // 2: più candidati
    return dig(a.membri) < dig(b.membri) ? -1 : 1;       // 3: ordine dei digest
  });
  return { gruppi: arr };
}

export async function digestHex(bytes) {
  await C.init();
  const d = sodium.crypto_generichash(32, bytes);
  return [...d].map(x => x.toString(16).padStart(2, "0")).join("");
}
export const spareggio = (dA, dB) => (dA < dB ? "A" : "B");   // memcmp sugli hex
