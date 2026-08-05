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
function schermataStato(sh, esito) {
  let box = sh.getElementById("app-stato");
  if (!box) { box = document.createElement("div"); box.id = "app-stato";
    box.style.cssText = "margin:16px auto;max-width:520px;padding:16px;border:2px solid #1a7f4e;border-radius:14px;background:#f2fbf6;font-family:inherit;text-align:center";
    sh.querySelector("main")?.appendChild(box); }
  const az = esito.azioni.map(a => `<button data-azione="${a}" style="margin:4px;padding:8px 12px">${a.replaceAll("_", " ")}</button>`).join("");
  box.innerHTML = `<strong style="font-size:15px">${esito.stato}</strong> <span style="opacity:.7">(riga ${esito.riga})</span><br><span style="display:block;margin:8px 0">${esito.messaggio}</span>${az}`;
}

async function avvia() {
  const v = await caricaVista("accesso-4");
  const sh = v.sh;
  mostraSoloVista("accesso-4");
  mostraPannello(sh, "cartella");              // il flusso reale parte da "scegli la cartella"
  ambiente = ambienteBrowser();
  let cartellaScelta = false;

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
      schermataStato(sh, r.esito);
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
