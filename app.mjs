// Lockit · app.mjs — colla DOM (C6: un'unica applicazione, viste commutate)
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
  const corpo = document.createElement("div");
  corpo.append(...[...doc.body.childNodes].map(n => n.cloneNode(true)));
  sh.appendChild(corpo);
  document.body.appendChild(host);
  viste[nome] = { host, sh };
  return viste[nome];
}
function commuta(nome) {
  for (const figlio of [...document.body.children]) if (!figlio.id?.startsWith("vista-")) figlio.style.display = nome ? "none" : "";
  for (const [k, v] of Object.entries(viste)) v.host.hidden = (k !== nome);
}
function schermataStato(sh, esito) {
  let box = sh.querySelector("#app-stato");
  if (!box) { box = document.createElement("div"); box.id = "app-stato";
    box.style.cssText = "margin:16px auto;max-width:640px;padding:16px;border:2px solid #1a7f4e;border-radius:12px;background:#f2fbf6;font-family:inherit";
    sh.appendChild(box); }
  const az = esito.azioni.map(a => `<button data-azione="${a}" style="margin:4px">${a.replaceAll("_", " ")}</button>`).join("");
  box.innerHTML = `<strong>${esito.stato}</strong> (riga ${esito.riga})<br>${esito.messaggio}<br>${az}`;
}
async function avvia() {
  await caricaVista("accesso-4");
  const acc = viste["accesso-4"].sh;
  ambiente = ambienteBrowser();
  $("#btn-accedi")?.addEventListener("click", async () => { await 0; commuta("accesso-4"); });
  $("#btn-crea")?.addEventListener("click", async () => { commuta("accesso-4"); });
  acc.querySelector("#scegli")?.addEventListener("click", async () => {
    try { const nome = await ambiente.richiediCartella();
      acc.querySelector("#stato-cartella").textContent = "Cartella scelta: " + nome; }
    catch { /* annullato */ }
  });
  acc.querySelector("#apri")?.addEventListener("click", async () => {
    const pw = acc.querySelector("#password").value;
    const spia = (e) => { if (e.passwordAccettata) acc.querySelector("#stato-password").textContent = "Password accettata, completo la verifica…"; };
    const r = await apriCassaforte(ambiente, pw, spia);
    schermataStato(acc, r.esito);
  });
}
document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", avvia) : avvia();
