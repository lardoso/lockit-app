// Lockit · app-core.mjs — la pipeline PURA dell'apertura (T4), senza DOM.
// preflight strutturale -> fase 1 (password accettata al primo autentico,
// ordine normativo dei gruppi) -> fase 2 (tutti i gruppi) -> quadro -> stati.
import { parseStructural, autentica, HDR_BUDGET } from "./servizio.mjs";
import { censisci, pianificaGruppi, derivaKek, digestHex, CANONICO, RE_OPACO } from "./aggregato.mjs";
import { decidi } from "./stati.mjs";

const inp = (b) => ({ prefisso: b.subarray(0, Math.min(b.length, HDR_BUDGET)), dimensioneTotale: b.length });
const base = (p) => p.split("/").pop();

export async function apriCassaforte(ambiente, password, spia = () => {}) {
  // ---- PREFLIGHT strutturale (senza password) ----
  const files = await ambiente.elencaELeggi();      // [{path, bytes} | {path, erroreAccesso}]
  const cens = censisci(files);
  spia({ fase: "preflight", cens });
  const quadro = { classificazioneCompleta: false };
  if (cens.errori?.length) quadro.erroriAccesso = cens.errori;
  if (cens.riga === 2) { quadro.versioneFutura = cens.dove; quadro.classificazioneCompleta = true; return { esito: decidi(quadro), quadro }; }
  if (cens.riga === "1e-rigida") { quadro.budgetPrelettureSuperato = true; quadro.classificazioneCompleta = true; return { esito: decidi(quadro), quadro }; }
  if (cens.riga === "1e") { quadro.oltreGli8 = true; quadro.classificazioneCompleta = true; return { esito: decidi(quadro), quadro }; }
  if (cens.riga === 1 || quadro.erroriAccesso) { quadro.classificazioneCompleta = true; return { esito: decidi(quadro), quadro }; }
  // ---- strutture dei candidati ----
  const strutture = []; const malformati = [];
  for (const f of cens.candidati) {
    const st = parseStructural(inp(f.bytes));
    if (st.errore) malformati.push({ path: f.path, ...st });
    else strutture.push({ path: f.path, struct: st, bytes: f.bytes, digestHex: await digestHex(f.bytes) });
  }
  const piano = pianificaGruppi(strutture);
  if (piano.oltreIGruppi) { quadro.oltreIGruppi = true; quadro.classificazioneCompleta = true; return { esito: decidi(quadro), quadro }; }
  // ---- FASE 1: derivazioni nell'ordine normativo, stop al primo autentico ----
  const autentici = []; const nonAutentici = [];
  let passwordAccettata = false; let risorseKdf = false;
  for (const g of piano.gruppi ?? []) {
    const der = await derivaKek(g.tupla, password);
    if (der.errore) { risorseKdf = true; continue; }
    for (const m of g.membri) {
      const a = await autentica(m.struct, der.kek);
      if (a.esito === "AUTENTICO") { autentici.push({ ...m, epoch: a.epoch, vaultKey: a.vaultKey });
        if (!passwordAccettata) { passwordAccettata = true; spia({ fase: "fase1", passwordAccettata: true }); } }
      else nonAutentici.push(m);
    }
  }
  spia({ fase: "fase2" });
  // ---- QUADRO ----
  if (risorseKdf && !autentici.length) quadro.erroriRisorseKdf = true;
  const opachi = files.filter(f => !f.erroreAccesso && RE_OPACO.test(base(f.path)));
  const canonicoFile = files.find(f => !f.erroreAccesso && f.path === CANONICO);
  const canonicoAut = autentici.find(a => a.path === CANONICO);
  quadro.servizioRadiceAutentico = !!canonicoAut;
  quadro.serviziAnnidatiAutentici = autentici.filter(a => a.path !== CANONICO && a.path.includes("/")).length;
  quadro.blobAutenticati = 0;   // T4: l'identità dell'accesso passa dal servizio
  quadro.materialeAutenticabile = strutture.length > 0 || opachi.length > 0;
  const vaultIds = new Set(autentici.map(a => a.struct.vaultId));
  if (vaultIds.size > 1) quadro.mescolanza = true;
  const chiavi = new Set(autentici.map(a => [...a.vaultKey].join(",")));
  if (vaultIds.size === 1 && chiavi.size > 1) quadro.corruzioneGrave = true;
  const plausibili = nonAutentici.map(m => m.path);
  if (canonicoFile && !canonicoAut) {
    const st = strutture.find(s => s.path === CANONICO);
    quadro.canonicoOccupatoDa = { tipo: st ? "plausibile" : "malformato" };
  } else if (plausibili.length) quadro.plausibili = plausibili;
  if (!strutture.length && !malformati.length && !opachi.length) quadro.percorsoSenzaTracce = true;
  quadro.servizioAssente = !canonicoFile && (quadro.blobAutenticati > 0);
  quadro.classificazioneCompleta = true;
  return { esito: decidi(quadro), quadro, passwordAccettata, autentici: autentici.map(a => a.path) };
}
