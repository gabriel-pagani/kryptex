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

  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest(".js-copy");
    if (!btn) return;

    const value = btn.getAttribute("data-copy") || "";
    if (!value) return;

    const ok = await copyText(value);
    setTempIcon(btn, ok);
  });
})();