// Lockit · azioni.mjs — la TABELLA DELLE AZIONI (dati normativi, C3/G3/G4)
// Gli esecutori arrivano in T4/T5; qui vivono gli insiemi e i prerequisiti.
export const TABELLA = {
  quarantena:        { lock: true, autenticazione: "derogabile",  // R9-1; R6-2/R8-2/C2
                       digest: "file", scansione: true },
  quarantena_voce:   { lock: true, autenticazione: "derogabile",
                       digest: "nome_e_tipo", scansione: true },  // R8-3: mai digest
  elimina:           { lock: true, autenticazione: "sempre",      // MAI per voci non regolari
                       digest: "file", scansione: true },
  installa_in_radice:{ lock: true, autenticazione: "sempre",      // D13-1/D14-1, transazionale
                       digest: "file", scansione: true },
  esporta:           { lock: true, autenticazione: "gia_avvenuta",// solo materiali autenticati
                       digest: "nessuno", scansione: false },     // lettura, mai mutazione
  elenco:            { lock: false, autenticazione: "no", digest: "nessuno", scansione: false },
  riprova:           { lock: false, autenticazione: "no", digest: "nessuno", scansione: true },
  proteggi:          { lock: true, autenticazione: "sessione", digest: "nessuno", scansione: false },
  sproteggi:         { lock: true, autenticazione: "sessione", digest: "file", scansione: false },
};
export const insieme = (...ids) => ids.slice().sort();
