// Adattatore d'ambiente per il browser (File System Access API)
export function ambienteBrowser() {
  let dirHandle = null;
  return {
    async richiediCartella() { dirHandle = await window.showDirectoryPicker({ mode: "readwrite" }); return dirHandle.name; },
    async elencaELeggi() {
      const out = [];
      async function giro(h, prefisso) {
        for await (const [nome, voce] of h.entries()) {
          const p = prefisso ? prefisso + "/" + nome : nome;
          if (voce.kind === "directory" && nome === ".~lockit-quarantena") continue; // G3
          if (voce.kind === "directory") await giro(voce, p);
          else {
            try { const f = await voce.getFile(); out.push({ path: p, bytes: new Uint8Array(await f.arrayBuffer()) }); }
            catch { out.push({ path: p, erroreAccesso: true }); }
          }
        }
      }
      await giro(dirHandle, "");
      return out;
    },
  };
}
