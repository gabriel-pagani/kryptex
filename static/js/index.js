(function () {
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

  document.addEventListener("click", async (ev) => {
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