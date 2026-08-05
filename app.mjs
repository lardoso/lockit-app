// Lockit · app.mjs — colla DOM (C6: un'unica applicazione, viste commutate).
// REGIA DEI PANNELLI (T4-1): niente cervello demo delle tele; e' app.mjs a
// decidere quale pannello mostrare e ad agganciare i comandi.
import { apriCassaforte } from "./app-core.mjs";
import { ambienteBrowser } from "./ambiente-browser.mjs";
const $ = (sel, root = document) => root.querySelector(sel);
const viste = {}; let ambiente = null;

async function caricaVista(nome) {
  if (viste[nome]) return viste[nome];
  const html = await (await fetch(`bozzetto-${nome}.html`)).text();
  const doc = new DOMParser().parseFromString(html, "text/html");
  const host = document.createElement("div");
  host.id = "vista-" + nome; host.hidden = true;
  const sh = host.attachShadow({ mode: "open" });
  for (const st of doc.querySelectorAll("style")) sh.appendChild(st.cloneNode(true));
  // <defs> SVG (gradienti, simboli) servono al rendering: li copio.
  for (const svg of doc.querySelectorAll("svg")) if (svg.querySelector("defs")) sh.appendChild(svg.cloneNode(true));
  const corpo = document.createElement("div");
  // Copio header/main/footer/finestre MA NON i <script> (il cervello demo muore qui).
  for (const el of doc.body.children) if (el.tagName !== "SCRIPT") corpo.appendChild(el.cloneNode(true));
  sh.appendChild(corpo);
  document.body.appendChild(host);
  viste[nome] = { host, sh };
  return viste[nome];
}
function mostraSoloVista(nome) {
  for (const figlio of [...document.body.children])
    if (!figlio.id?.startsWith("vista-")) figlio.style.display = "none";
  for (const [k, v] of Object.entries(viste)) v.host.hidden = (k !== nome);
}

// --- REGIA della tela accesso: sceglie il pannello e aggancia i comandi ---
function mostraPannello(sh, quale) {           // "cartella" | "password2" | "ricordata"
  const map = { ricordata: "stato-password", cartella: "stato-cartella", password2: "stato-password-2" };
  for (const id of Object.values(map)) { const el = sh.getElementById(id); if (el) el.hidden = true; }
  const on = sh.getElementById(map[quale]); if (on) on.hidden = false;
  // artifici demo sempre spenti
  const avviso = sh.getElementById("avviso"); if (avviso) avviso.style.display = "none";
  const demo = sh.getElementById("demo-toggle"); if (demo) demo.closest("p").style.display = "none";
}
// Messaggi UMANI del cantiere (T4-3): titolo chiaro + cosa fare.
// Testi provvisori: quelli definitivi si ratificano in T6.
const UMANI = {
  6:        { t: "Cassaforte aperta", s: "Tutto in ordine: la password è giusta e i tuoi file sono qui.", verde: true },
  7:        { t: "Qui non trovo la tua cassaforte",
              s: "In questa cartella non c'è nessuna cassaforte che risponda a questa password. Controlla di aver scelto la cartella giusta. Se hai appena estratto uno ZIP, può darsi che dentro ci sia un'altra cartella con lo stesso nome: entra e scegli quella più interna." },
  "7bis":   { t: "Questa cartella non è una cassaforte", s: "Non ci sono tracce di Lockit qui dentro. Scegli la cartella della tua cassaforte." },
  2:        { t: "Serve una versione più recente di Lockit", s: "Qui c'è materiale creato da un Lockit più nuovo. Per sicurezza non tocco nulla: aggiorna Lockit, oppure sposta via quel file con Esplora risorse." },
  1:        { t: "Non riesco a leggere tutta la cartella", s: "Alcuni file non si lasciano leggere (forse un altro programma li tiene occupati). Chiudi gli altri programmi e riprova." },
  "1b":     { t: "Memoria insufficiente per la verifica", s: "Il computer non ha abbastanza memoria libera per controllare la password. Chiudi altre attività o prova da un dispositivo con più memoria." },
  "1c":     { t: "C'è un intruso al posto del file di servizio", s: "Il nome riservato della cassaforte è occupato da qualcosa che non riconosco. Va messo da parte prima di continuare." },
  "1d":     { t: "Troppi materiali diversi in questa cartella", s: "Ci sono troppe famiglie di file da verificare. Metti da parte quelli che non c'entrano e riprova." },
  "1e":     { t: "Troppi file da verificare", s: "Ci sono troppi materiali da controllare in una volta. Mettine da parte qualcuno e riprova." },
  "1e-rigida": { t: "Troppi file da esaminare", s: "Per sicurezza non tocco nulla finché non rientri: sposta via qualche materiale con Esplora risorse e rifai la scansione." },
  3:        { t: "Qui ci sono due casseforti mescolate", s: "Ho trovato materiali di casseforti diverse nella stessa cartella. Vanno separati prima di continuare." },
  4:        { t: "Copie in conflitto tra loro", s: "Due copie del file di servizio non coincidono: possibile corruzione. Serve una risoluzione manuale." },
  5:        { t: "Materiale riconosciuto ma non verificato", s: "C'è materiale di Lockit che questa password non apre. Potrebbe essere di un'altra cassaforte: riprova con la password giusta." },
  "D13-1":  { t: "La cassaforte è in una sottocartella", s: "La password è giusta, ma il file di servizio vive solo in una sottocartella: va installato nella cartella principale." },
};
function schermataStato(sh, esito, filesVisti) {
  let box = sh.getElementById("app-stato");
  if (!box) { box = document.createElement("div"); box.id = "app-stato";
    sh.querySelector("main")?.appendChild(box); }
  const chiave = (esito.riga === 7 && !esito.messaggio.includes("password")) ? "7bis" : esito.riga;
  const u = UMANI[chiave] ?? { t: "Qualcosa non torna", s: esito.messaggio };
  box.style.cssText = "margin:16px auto;max-width:560px;padding:18px 20px;border:2px solid " + (u.verde ? "#1a7f4e" : "#b98a1f") + ";border-radius:14px;background:" + (u.verde ? "#f2fbf6" : "#fdf8ec") + ";font-family:inherit;text-align:center";
  const az = esito.azioni.map(a => `<button data-azione="${a}" style="margin:4px;padding:8px 12px">${a.replaceAll("_", " ")}</button>`).join("");
  box.innerHTML = `<strong style="font-size:17px;display:block;margin-bottom:6px">${u.t}</strong>` +
    `<span style="display:block;margin:0 0 10px;line-height:1.45">${u.s}</span>` + az +
    `<span style="display:block;margin-top:12px;font-size:11px;color:#8a8f96">codice per l'assistenza: ${esito.stato} · riga ${esito.riga}</span>` +
    (!u.verde && filesVisti?.length ? `<details style="margin-top:8px;text-align:left;font-size:11px;color:#8a8f96"><summary style="cursor:pointer">cosa ho visto in questa cartella (${filesVisti.length} voci)</summary><div style="margin-top:6px;white-space:pre-wrap">${filesVisti.join("\n")}</div></details>` : "");
}

function tornaAllaHome() {
  for (const figlio of [...document.body.children])
    if (!figlio.id?.startsWith("vista-")) figlio.style.display = "";
  for (const v of Object.values(viste)) v.host.hidden = true;
  window.scrollTo(0, 0);
}

async function avvia() {
  const v = await caricaVista("accesso-4");   // preparata, ma NASCOSTA:
  const sh = v.sh;                            // si parte dalla HOME (T4-2)
  mostraPannello(sh, "cartella");
  ambiente = ambienteBrowser();
  let cartellaScelta = false;

  // Home -> Accedi commuta alla vista accesso (il bottone della tela e' libero)
  document.getElementById("btn-accedi")?.addEventListener("click", () => {
    mostraSoloVista("accesso-4");
    mostraPannello(sh, cartellaScelta ? "password2" : "cartella");
    window.scrollTo(0, 0);
  });
  // "Creala dalla pagina iniziale" (scialuppa) riporta alla home
  sh.querySelector("#stato-cartella .scialuppa a")?.addEventListener("click", (ev) => {
    ev.preventDefault(); tornaAllaHome();
  });

  const scegli = sh.getElementById("scegli");
  scegli?.addEventListener("click", async () => {
    try {
      const nome = await ambiente.richiediCartella();
      cartellaScelta = true;
      mostraPannello(sh, "password2");
      const h1 = sh.getElementById("nome-cassaforte-2"); if (h1) h1.textContent = nome;
      const dove = sh.querySelector("#stato-password-2 .dove"); if (dove) dove.textContent = "Cartella indicata: " + nome;
    } catch { /* annullato dall'utente */ }
  });

  const apri2 = sh.getElementById("apri-2");
  apri2?.addEventListener("click", async () => {
    if (!cartellaScelta) return;
    const pw = sh.getElementById("password-2").value;
    const err = sh.getElementById("msg-errore-2");
    if (!pw) { if (err) err.style.display = "block"; return; }
    if (err) err.style.display = "none";
    apri2.textContent = "Password accettata, completo la verifica…";
    apri2.disabled = true;
    const spia = (e) => { if (e.passwordAccettata) apri2.textContent = "Password accettata, completo la verifica…"; };
    try {
      const r = await apriCassaforte(ambiente, pw, spia);
      schermataStato(sh, r.esito, r.filesVisti);
      apri2.textContent = "Apri la cassaforte"; apri2.disabled = false;
    } catch (e) {
      schermataStato(sh, { stato: "ERRORE", riga: "-", messaggio: "Errore imprevisto: " + (e?.message || e), azioni: [] });
      apri2.textContent = "Apri la cassaforte"; apri2.disabled = false;
    }
  });

  const torna = sh.getElementById("torna-2");
  torna?.addEventListener("click", (ev) => { ev.preventDefault(); cartellaScelta = false; mostraPannello(sh, "cartella"); });
  const mostra2 = sh.getElementById("mostra-2");
  mostra2?.addEventListener("click", () => { const i = sh.getElementById("password-2"); if (i) i.type = i.type === "password" ? "text" : "password"; });
}
document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", avvia) : avvia();
