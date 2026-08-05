// Lockit · stati.mjs — la PRECEDENZA AGGREGATA della sez.6 (v0.3.17)
// dagli esiti al {stato, riga, messaggio, dettagli, azioni[]}.
import { insieme } from "./azioni.mjs";

export function decidi(q) {
  const det = {};
  if (q.erroriAccesso?.length) det.illeggibili = q.erroriAccesso;
  if (q.vociNonRegolari?.length) det.vociNonRegolari = q.vociNonRegolari;
  const fine = (r) => {
    // Cancello della fase 2 (G2/C8): nessun comando finché la
    // classificazione non è completa.
    if (!q.classificazioneCompleta) r.azioni = [];
    r.azioni = insieme(...r.azioni);
    r.dettagli = { ...det, ...(r.dettagli ?? {}) };
    return r;
  };
  // R8-1 + Q4: la VERSIONE_FUTURA domina TUTTO, errore d'accesso compreso.
  if (q.versioneFutura?.length) return fine({
    stato: "BLOCCO_RIGIDO", riga: 2,
    messaggio: "serve una versione più recente di Lockit",
    dettagli: { futuri: q.versioneFutura },
    azioni: ["esporta"] });                       // R6-3: sola esportazione
  if (q.erroriAccesso?.length) return fine({
    stato: "NESSUNA_MUTAZIONE", riga: 1,
    messaggio: "lettura incompleta: riprovare quando la cartella è accessibile",
    azioni: ["riprova"] });
  if (q.budgetPrelettureSuperato) return fine({   // 1e(b): come se il futuro ci fosse
    stato: "BLOCCO_RIGIDO", riga: "1e-rigida",
    messaggio: "troppi materiali da esaminare: rientrare manualmente, poi nuova scansione",
    azioni: ["elenco"] });                        // le deroghe NON si applicano
  if (q.erroriRisorseKdf) return fine({
    stato: "BLOCCO_OPERATIVO", riga: "1b",
    messaggio: "memoria insufficiente per verificare la password: chiudere altre attività o usare un dispositivo con più memoria",
    azioni: ["quarantena", "elenco"],             // R6-2: senza autenticazione
    dettagli: { senzaAutenticazione: true } });
  if (q.canonicoOccupatoDa) {                     // 1c
    const voce = q.canonicoOccupatoDa.tipo === "voce_non_regolare";
    const nessunAutenticabile = !q.blobAutenticati && !q.servizioRadiceAutentico &&
                                !q.serviziAnnidatiAutentici && !q.materialeAutenticabile;
    const az = [];
    if (voce) { if (q.canonicoOccupatoDa.spostamentoAtomico) az.push("quarantena_voce"); }
    else {
      az.push("quarantena");
      if (!nessunAutenticabile) az.push("elimina");   // R9-1: eliminare senza
    }                                                 // autenticazione MAI
    if (q.blobAutenticati || q.servizioRadiceAutentico) az.push("esporta");
    return fine({
      stato: "BLOCCO_OPERATIVO", riga: "1c",
      messaggio: voce && !q.canonicoOccupatoDa.spostamentoAtomico
        ? "il nome canonico è occupato da una voce non spostabile: intervenire in Esplora risorse"
        : "il nome canonico è occupato: risolvere prima di procedere",
      azioni: az,
      dettagli: { derogaR9_1: nessunAutenticabile || undefined,
                  avvertenzaPlausibile: (nessunAutenticabile && q.canonicoOccupatoDa.tipo === "plausibile") || undefined } });
  }
  if (q.oltreIGruppi) return fine({               // 1d
    stato: "BLOCCO_OPERATIVO", riga: "1d",
    messaggio: "troppi gruppi di parametri: mettere da parte materiali fino a rientrare",
    azioni: ["quarantena", "elenco"], dettagli: { senzaAutenticazione: true } });
  if (q.oltreGli8) return fine({                  // 1e(a)
    stato: "BLOCCO_OPERATIVO", riga: "1e",
    messaggio: "troppi materiali da verificare: mettere da parte fino a rientrare",
    azioni: ["quarantena", "elenco"], dettagli: { senzaAutenticazione: true } });
  if (q.mescolanza) return fine({
    stato: "BLOCCO_OPERATIVO", riga: 3,
    messaggio: "materiali di casseforti diverse nella stessa cartella",
    azioni: ["quarantena", "elimina", "esporta"] });
  if (q.corruzioneGrave) return fine({
    stato: "BLOCCO_OPERATIVO", riga: 4,
    messaggio: "copie in conflitto con chiavi diverse: possibile corruzione",
    azioni: ["quarantena", "elimina", "esporta"] });
  if (q.plausibili?.length) return fine({
    stato: "BLOCCO_OPERATIVO", riga: 5,
    messaggio: "materiali riconosciuti ma non verificati con questa password",
    azioni: ["quarantena", "elimina", "esporta"],
    dettagli: { avvertenzaPlausibile: true, plausibili: q.plausibili } });
  const radiceOk = q.blobAutenticati > 0 || q.servizioRadiceAutentico;
  if (!radiceOk && q.serviziAnnidatiAutentici > 0) return fine({  // D13-1
    stato: "BLOCCO_OPERATIVO", riga: "D13-1",
    messaggio: "password verificata, ma il file di servizio vive solo in una sottocartella",
    azioni: ["installa_in_radice", "esporta"] });
  if (radiceOk) return fine({
    stato: "OPERATIVITA_PIENA", riga: 6,
    messaggio: "cassaforte aperta",
    azioni: ["proteggi", "sproteggi", "esporta"],
    dettagli: { rigenerazionePrimoAtto: q.servizioAssente || undefined } });
  return fine({
    stato: "NESSUNA_IDENTITA", riga: 7,
    messaggio: q.percorsoSenzaTracce ? "cartella senza tracce di Lockit"
                                     : "password non verificabile in questa cartella",
    azioni: [] });
}
