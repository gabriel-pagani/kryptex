(function () {
  const FOLDER_STATE_KEY = "kryptex.folderState.v1";

  function isSearchMode() {
    const q = new URLSearchParams(window.location.search).get("q");
    return !!(q && q.trim());
  }

  function loadFolderState() {
    try {
      const raw = localStorage.getItem(FOLDER_STATE_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch {
      return {};
    }
  }

  function saveFolderState(state) {
    try {
      localStorage.setItem(FOLDER_STATE_KEY, JSON.stringify(state || {}));
    } catch {
      // ignora
    }
  }

  function getFolderRows() {
    return Array.from(document.querySelectorAll(".js-folder"));
  }

  function getFolderGroupId(folderRow) {
    return folderRow.getAttribute("data-group");
  }

  function setExpanded(folderRow, expanded) {
    folderRow.setAttribute("aria-expanded", String(!!expanded));
    syncFolderUI(folderRow);
  }

  async function fetchPassword(id) {
    try {
      const resp = await fetch(`/api/password/${id}/`);
      if (!resp.ok) throw new Error("Erro");
      const data = await resp.json();
      return data.password;
    } catch (e) {
      console.error(e);
      return null;
    }
  }

  // Função genérica de copy
  async function copyText(text) {
    if (!text) return false;
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      return false;
    }
  }

  // Ícone de feedback visual
  function setTempIcon(btn, ok) {
    if (!btn.dataset.originalHtml) {
      btn.dataset.originalHtml = btn.innerHTML;
    }
    if (btn.dataset.restoreTimerId) {
      clearTimeout(Number(btn.dataset.restoreTimerId));
    }
    btn.innerHTML = ok
      ? '<i class="fa-solid fa-check"></i>'
      : '<i class="fa-solid fa-xmark"></i>';
    
    const id = setTimeout(() => {
      btn.innerHTML = btn.dataset.originalHtml;
      btn.dataset.restoreTimerId = "";
    }, 1000);
    btn.dataset.restoreTimerId = String(id);
  }

  // Lógica do botão "Olho"
  async function toggleSecret(toggleBtn) {
    const wrap = toggleBtn.closest(".cellActions");
    const displayEl = wrap.querySelector(".js-secret-display");
    const id = wrap.dataset.id;
    
    const isPressed = toggleBtn.getAttribute("aria-pressed") === "true";
    
    if (isPressed) {
      // Ocultar
      displayEl.textContent = "••••••••";
      toggleBtn.setAttribute("aria-pressed", "false");
      toggleBtn.innerHTML = '<i class="fa-regular fa-eye"></i>';
    } else {
      // Exibir - Busca no servidor
      toggleBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>'; // Loading
      const password = await fetchPassword(id);
      
      if (password) {
        displayEl.textContent = password;
        toggleBtn.setAttribute("aria-pressed", "true");
        toggleBtn.innerHTML = '<i class="fa-regular fa-eye-slash"></i>';
      } else {
        setTempIcon(toggleBtn, false); // Erro
        toggleBtn.innerHTML = '<i class="fa-regular fa-eye"></i>';
      }
    }
  }

  // Lógica do botão "Copiar Senha"
  async function copyPasswordHandler(btn) {
    const wrap = btn.closest(".cellActions");
    const id = wrap.dataset.id;
    const displayEl = wrap.querySelector(".js-secret-display");
    
    // Se já estiver visível na tela, copia direto do texto
    let password = displayEl.textContent;
    if (password === "••••••••") {
       // Se estiver oculto, busca no servidor pra copiar
       btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
       password = await fetchPassword(id);
       btn.innerHTML = '<i class="fa-regular fa-copy"></i>'; // Restaura ícone
    }

    const ok = await copyText(password);
    setTempIcon(btn, ok);

    if (ok) {
      setTimeout(async () => {
        try {
          const currentText = await navigator.clipboard.readText();
          if (currentText === password) {
            await navigator.clipboard.writeText("");
          }
        } catch (e) {
          navigator.clipboard.writeText("").catch(() => {}); 
        }
      }, 15000); // 15s
    }
  }

  function syncFolderUI(folderRow) {
    const group = folderRow.getAttribute("data-group");
    if (group == null) return;

    const expanded = folderRow.getAttribute("aria-expanded") === "true";

    const iconWrap = folderRow.querySelector(".folderRow__icon");
    if (iconWrap) {
      iconWrap.innerHTML = expanded
        ? '<i class="fa-solid fa-chevron-down"></i>'
        : '<i class="fa-solid fa-chevron-right"></i>';
    }

    document
      .querySelectorAll(`.js-login-row[data-group="${group}"]`)
      .forEach((tr) => tr.classList.toggle("is-hidden", !expanded));
  }

  const searching = isSearchMode();

  function toggleFolder(folderRow) {
    const group = getFolderGroupId(folderRow);
    if (group == null) return;

    const expanded = folderRow.getAttribute("aria-expanded") === "true";
    const nextExpanded = !expanded;

    setExpanded(folderRow, nextExpanded);

    // Só persiste fora do modo de busca (para "voltar ao estado anterior")
    if (!searching) {
      const state = loadFolderState();
      state[group] = nextExpanded;
      saveFolderState(state);
    }
  }

  if (searching) {
    getFolderRows().forEach((row) => setExpanded(row, true));
  } else {
    const state = loadFolderState();
    getFolderRows().forEach((row) => {
      const group = getFolderGroupId(row);
      const expanded = group != null ? !!state[group] : false;
      setExpanded(row, expanded);
    });
  }

  // garante ícone/linhas consistentes no carregamento
  document.querySelectorAll(".js-folder").forEach((row) => syncFolderUI(row));

  document.addEventListener("click", async (ev) => {
    const folder = ev.target.closest(".js-folder");
    if (folder) {
      toggleFolder(folder);
      return;
    }

    const toggleBtn = ev.target.closest(".js-toggle-secret");
    if (toggleBtn) {
      toggleSecret(toggleBtn);
      return;
    }

    const copyLoginBtn = ev.target.closest(".js-copy");
    if (copyLoginBtn) {
      const text = copyLoginBtn.dataset.copy || "";
      const ok = await copyText(text);
      setTempIcon(copyLoginBtn, ok);
      return;
    }

    const copyPassBtn = ev.target.closest(".js-copy-password");
    if (copyPassBtn) {
      copyPasswordHandler(copyPassBtn);
      return;
    }
  });
})();