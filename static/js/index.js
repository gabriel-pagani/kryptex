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

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      return false;
    }
  }

  function setTempIcon(btn, ok) {
    // salva o HTML original uma única vez
    if (!btn.dataset.originalHtml) {
      btn.dataset.originalHtml = btn.innerHTML;
    }

    // se já houver um timer rodando, cancela
    if (btn.dataset.restoreTimerId) {
      clearTimeout(Number(btn.dataset.restoreTimerId));
      btn.dataset.restoreTimerId = "";
    }

    // troca pelo ícone de sucesso/erro
    btn.innerHTML = ok
      ? '<i class="fa-solid fa-check"></i>'
      : '<i class="fa-solid fa-xmark"></i>';

    // restaura depois de um tempo
    const id = setTimeout(() => {
      btn.innerHTML = btn.dataset.originalHtml;
      btn.dataset.restoreTimerId = "";
    }, 900);

    btn.dataset.restoreTimerId = String(id);
  }

  function toggleSecret(toggleBtn) {
    const wrap = toggleBtn.closest(".cellActions");
    if (!wrap) return;

    const secretEl = wrap.querySelector(".js-secret");
    if (!secretEl) return;

    const secret = secretEl.getAttribute("data-secret") || "";
    const masked = secretEl.getAttribute("data-masked") || "••••••••";

    // se não houver segredo, mantém mascarado
    if (!secret) {
      secretEl.textContent = masked;
      toggleBtn.setAttribute("aria-pressed", "false");
      toggleBtn.innerHTML = '<i class="fa-regular fa-eye"></i>';
      return;
    }

    const isPressed = toggleBtn.getAttribute("aria-pressed") === "true";
    const nextPressed = !isPressed;

    toggleBtn.setAttribute("aria-pressed", String(nextPressed));
    secretEl.textContent = nextPressed ? secret : masked;
    toggleBtn.innerHTML = nextPressed
      ? '<i class="fa-regular fa-eye-slash"></i>'
      : '<i class="fa-regular fa-eye"></i>';
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

    const btn = ev.target.closest(".js-copy");
    if (!btn) return;

    const value = btn.getAttribute("data-copy") || "";
    if (!value) return;

    const ok = await copyText(value);
    setTempIcon(btn, ok);
  });
})();