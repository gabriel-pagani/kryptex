(function () {
  const FOLDER_STATE_KEY = "kryptex.folderState.v1";
  const SALT = "QrzzRcLpktICK_Gizrts1Y6CyuQ9pHBBweB7DpkLQ6Y";
  const PBKDF2_ITERATIONS = 600000;

  let masterKeyCache = null;

  // --- CRYPTO CORE ---

  async function getMasterKey(password) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: enc.encode(SALT),
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptData(plainText, key) {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      enc.encode(plainText)
    );

    return JSON.stringify({
      iv: btoa(String.fromCharCode(...iv)),
      data: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    });
  }

  async function decryptData(encryptedJsonStr, key) {
    try {
      const dataObj = JSON.parse(encryptedJsonStr);
      const iv = Uint8Array.from(atob(dataObj.iv), (c) => c.charCodeAt(0));
      const ciphertext = Uint8Array.from(atob(dataObj.data), (c) =>
        c.charCodeAt(0)
      );

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ciphertext
      );
      return new TextDecoder().decode(decryptedBuffer);
    } catch (e) {
      console.error(e);
      return null;
    }
  }

  // --- UI: MODAL DE SENHA MESTRA ---

  function askPasswordViaModal() {
    return new Promise((resolve) => {
      const modal = document.getElementById("masterPasswordModal");
      const form = document.getElementById("masterPasswordForm");
      const input = document.getElementById("masterPassInput");

      // Limpa input anterior
      input.value = "";

      // Exibe Modal
      modal.showModal();

      // Handler único para o submit
      const submitHandler = (e) => {
        e.preventDefault();
        const pwd = input.value;
        modal.close();
        form.removeEventListener("submit", submitHandler); // Limpa listener para não duplicar
        resolve(pwd); // Retorna a senha digitada
      };

      form.addEventListener("submit", submitHandler);

      // Se o usuário cancelar (ESC), resolve como null
      const closeHandler = () => {
        if (modal.returnValue === "close") resolve(null); // Só se não foi pelo submit
        form.removeEventListener("submit", submitHandler);
      };
      modal.addEventListener("close", closeHandler, { once: true });
    });
  }

  async function requestMasterPassword() {
    if (masterKeyCache) return masterKeyCache;

    const password = await askPasswordViaModal();

    if (!password || password.trim().length === 0) return null;

    const key = await getMasterKey(password);

    masterKeyCache = key;
    return masterKeyCache;
  }

  // --- UI HELPERS ---

  function generateStrongPassword(length = 50) {
    const charset =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&()_+~|}{[]:;?><,./-=";
    const values = new Uint32Array(length);
    window.crypto.getRandomValues(values);
    let password = "";
    for (let i = 0; i < length; i++) {
      password += charset[values[i] % charset.length];
    }
    return password;
  }

  function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== "") {
      const cookies = document.cookie.split(";");
      for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.substring(0, name.length + 1) === name + "=") {
          cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
          break;
        }
      }
    }
    return cookieValue;
  }

  async function copyText(text) {
    if (!text) return false;
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      return false;
    }
  }

  function setTempIcon(btn, ok) {
    if (!btn.dataset.originalHtml) {
      btn.dataset.originalHtml = btn.innerHTML;
    }
    if (btn.dataset.restoreTimerId)
      clearTimeout(Number(btn.dataset.restoreTimerId));

    btn.innerHTML = ok
      ? '<i class="fa-solid fa-check"></i>'
      : '<i class="fa-solid fa-xmark"></i>';

    const id = setTimeout(() => {
      btn.innerHTML = btn.dataset.originalHtml;
    }, 1000);
    btn.dataset.restoreTimerId = String(id);
  }

  // --- PARTIAL REFRESH (sem recarregar a página / sem perder a chave mestra) ---
  async function refreshLoginTableFromServer() {
    // Busca o HTML da página atual e troca somente a parte da tabela/contadores.
    const resp = await fetch(window.location.href, {
      method: "GET",
      headers: {
        "X-Requested-With": "XMLHttpRequest",
      },
      cache: "no-store",
    });

    if (!resp.ok) throw new Error("Falha ao atualizar lista");

    const html = await resp.text();
    const doc = new DOMParser().parseFromString(html, "text/html");

    const newTbody = doc.querySelector(".table tbody");
    const oldTbody = document.querySelector(".table tbody");
    if (newTbody && oldTbody) oldTbody.replaceWith(newTbody);

    const newCount = doc.querySelector(".card__header .muted");
    const oldCount = document.querySelector(".card__header .muted");
    if (newCount && oldCount) oldCount.textContent = newCount.textContent;

    // Reaplica o estado das pastas (folders) no DOM novo
    applyFolderStateToCurrentDom();
  }

  // --- ACTIONS ---

  async function fetchEncryptedData(id) {
    const resp = await fetch(`/api/password/${id}/`, {
      method: "POST",
      headers: { "X-CSRFToken": getCookie("csrftoken") },
    });
    if (!resp.ok) throw new Error("Erro de rede");
    const data = await resp.json();
    return data.password;
  }

  async function toggleSecret(toggleBtn) {
    const wrap = toggleBtn.closest(".cellActions");
    const displayEl = wrap.querySelector(".js-secret-display");
    const id = wrap.dataset.id;
    const isPressed = toggleBtn.getAttribute("aria-pressed") === "true";

    if (isPressed) {
      displayEl.textContent = "••••••••";
      toggleBtn.setAttribute("aria-pressed", "false");
      toggleBtn.innerHTML = '<i class="fa-regular fa-eye"></i>';
    } else {
      const key = await requestMasterPassword();
      if (!key) return;

      toggleBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';

      try {
        const encryptedStr = await fetchEncryptedData(id);
        const plainText = await decryptData(encryptedStr, key);

        if (plainText) {
          displayEl.textContent = plainText;
          toggleBtn.setAttribute("aria-pressed", "true");
          toggleBtn.innerHTML = '<i class="fa-regular fa-eye-slash"></i>';
        } else {
          masterKeyCache = null;
          alert("Falha na descriptografia. A chave salva será redefinida.");

          toggleBtn.innerHTML = '<i class="fa-regular fa-eye"></i>';
        }
      } catch (e) {
        setTempIcon(toggleBtn, false);
        toggleBtn.innerHTML = '<i class="fa-regular fa-eye"></i>';
      }
    }
  }

  async function copyPasswordHandler(btn) {
    const wrap = btn.closest(".cellActions");
    const id = wrap.dataset.id;
    const displayEl = wrap.querySelector(".js-secret-display");

    let password = displayEl.textContent;
    if (password === "••••••••") {
      const key = await requestMasterPassword();
      if (!key) return;

      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
      try {
        const encryptedStr = await fetchEncryptedData(id);
        password = await decryptData(encryptedStr, key);
        if (!password) throw new Error("Decryption fail");
        btn.innerHTML = '<i class="fa-regular fa-copy"></i>';
      } catch {
        setTempIcon(btn, false);
        btn.innerHTML = '<i class="fa-regular fa-copy"></i>';
        return;
      }
    }

    const ok = await copyText(password);
    setTempIcon(btn, ok);
    if (ok) {
      setTimeout(() => {
        navigator.clipboard.writeText("").catch(() => {});
      }, 15000);
    }
  }

  // --- MODAL CADASTRO ---

  const addModal = document.getElementById("addLoginModal");
  const addForm = document.getElementById("addLoginForm");

  function setupAddModal() {
    if (!addModal) return;

    const openBtn = document.querySelector(".js-open-modal");

    if (openBtn) {
      openBtn.addEventListener("click", async () => {
        const key = await requestMasterPassword();
        if (!key) return;

        addModal.showModal();
      });
    }

    document.querySelectorAll(".js-close-modal").forEach((btn) => {
      btn.addEventListener("click", () => addModal.close());
    });

    addForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitBtn = addForm.querySelector("button[type='submit']");
      const originalText = submitBtn.innerText;

      const key = await requestMasterPassword();
      if (!key) return;

      submitBtn.disabled = true;
      submitBtn.innerText = "Processando...";

      try {
        const formData = new FormData(addForm);

        let password = formData.get("password");
        if (!password) {
          password = generateStrongPassword();
        }

        const encryptedPass = await encryptData(password, key);

        const payload = {
          service: formData.get("service"),
          type_id: formData.get("type_id"),
          login: formData.get("login"),
          password: encryptedPass,
          notes: formData.get("notes"),
        };

        const resp = await fetch("/api/login/create/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken"),
          },
          body: JSON.stringify(payload),
        });

        if (resp.ok) {
          addModal.close();
          addForm.reset();
          await refreshLoginTableFromServer();
        } else {
          alert("Erro ao salvar.");
        }
      } catch (err) {
        console.error(err);
        alert("Erro no processamento.");
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerText = originalText;
      }
    });
  }

  // --- MODAL DE EDIÇÃO ---

  const editModal = document.getElementById("editLoginModal");
  const editForm = document.getElementById("editLoginForm");

  function setupEditModal() {
    if (!editModal) return;

    // Fechar modal
    editModal.querySelectorAll(".js-close-modal").forEach((btn) => {
      btn.addEventListener("click", () => editModal.close());
    });

    // Toggle de visibilidade da senha dentro do modal
    const toggleVisBtn = editForm.querySelector(".js-toggle-pass-visibility");
    if (toggleVisBtn) {
      toggleVisBtn.addEventListener("click", () => {
        const input = editForm.querySelector("input[name='password']");
        if (input.type === "password") {
          input.type = "text";
          toggleVisBtn.innerHTML = '<i class="fa-regular fa-eye-slash"></i>';
        } else {
          input.type = "password";
          toggleVisBtn.innerHTML = '<i class="fa-regular fa-eye"></i>';
        }
      });
    }

    // --- LÓGICA DE EXCLUSÃO (NOVO) ---
    const deleteBtn = editForm.querySelector(".js-delete-login");
    if (deleteBtn) {
      deleteBtn.addEventListener("click", async () => {
        const loginId = editForm.querySelector("[name='login_id']").value;
        if (!loginId) return;

        // Confirmação simples do navegador
        if (
          !confirm(
            "Tem certeza que deseja EXCLUIR este login? Esta ação não pode ser desfeita."
          )
        ) {
          return;
        }

        const originalText = deleteBtn.innerHTML;
        deleteBtn.disabled = true;
        deleteBtn.innerText = "Excluindo...";

        try {
          const resp = await fetch(`/api/login/${loginId}/delete/`, {
            method: "POST",
            headers: {
              "X-CSRFToken": getCookie("csrftoken"),
            },
          });

          if (resp.ok) {
            editModal.close();
            await refreshLoginTableFromServer();
          } else {
            alert("Erro ao excluir login.");
            deleteBtn.disabled = false;
            deleteBtn.innerHTML = originalText;
          }
        } catch (e) {
          console.error(e);
          alert("Erro de conexão.");
          deleteBtn.disabled = false;
          deleteBtn.innerHTML = originalText;
        }
      });
    }

    // Submit do Formulário de Edição
    editForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitBtn = editForm.querySelector("button[type='submit']");
      const originalText = submitBtn.innerText;

      const key = await requestMasterPassword();
      if (!key) return;

      submitBtn.disabled = true;
      submitBtn.innerText = "Salvando...";

      try {
        const formData = new FormData(editForm);
        const loginId = formData.get("login_id");

        let password = formData.get("password");
        if (!password) {
          password = generateStrongPassword();
        }

        const encryptedPass = await encryptData(password, key);

        const payload = {
          service: formData.get("service"),
          type_id: formData.get("type_id"),
          login: formData.get("login"),
          password: encryptedPass,
          notes: formData.get("notes"),
        };

        const resp = await fetch(`/api/login/${loginId}/update/`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken"),
          },
          body: JSON.stringify(payload),
        });

        if (resp.ok) {
          editModal.close();
          await refreshLoginTableFromServer();
        } else {
          alert("Erro ao atualizar login.");
        }
      } catch (err) {
        console.error(err);
        alert("Erro ao processar atualização.");
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerText = originalText;
      }
    });
  }

  // Função chamada ao clicar no botão de lápis
  async function openEditLogin(btn) {
    const wrap = btn.closest(".cellActions");
    const id = wrap.dataset.id; // Pega o ID da linha

    // 1. Solicita a chave mestra antes de tudo
    const key = await requestMasterPassword();
    if (!key) return;

    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';

    try {
      // 2. Busca os dados completos no backend
      const resp = await fetch(`/api/login/${id}/details/`);
      if (!resp.ok) throw new Error("Erro ao buscar dados");
      const data = await resp.json();

      // 3. Descriptografa a senha para preencher o formulário
      const encryptedStr = await fetchEncryptedData(id);
      const plainPassword = await decryptData(encryptedStr, key);
      if (plainPassword === null) {
        alert(
          "Erro: Não foi possível descriptografar a senha com a chave atual."
        );
        btn.innerHTML = '<i class="fa-regular fa-pen-to-square"></i>';
        return;
      }

      // 4. Preenche o formulário
      editForm.querySelector("[name='login_id']").value = data.id;
      editForm.querySelector("[name='service']").value = data.service;
      editForm.querySelector("[name='login']").value = data.login;
      editForm.querySelector("[name='type_id']").value = data.type_id;
      editForm.querySelector("[name='notes']").value = data.notes;
      editForm.querySelector("[name='password']").value = plainPassword;

      // 5. Abre o modal
      editModal.showModal();
    } catch (e) {
      alert("Erro ao carregar dados do login.");
    } finally {
      btn.innerHTML = '<i class="fa-regular fa-pen-to-square"></i>';
    }
  }

  // --- FOLDER LOGIC ---
  function loadFolderState() {
    try {
      return JSON.parse(localStorage.getItem(FOLDER_STATE_KEY) || "{}");
    } catch {
      return {};
    }
  }
  function saveFolderState(state) {
    try {
      localStorage.setItem(FOLDER_STATE_KEY, JSON.stringify(state || {}));
    } catch {}
  }
  function setExpanded(folderRow, expanded) {
    folderRow.setAttribute("aria-expanded", String(!!expanded));
    const group = folderRow.dataset.group;
    if (group == null) return;
    const icon = folderRow.querySelector(".folderRow__icon");
    if (icon)
      icon.innerHTML = expanded
        ? '<i class="fa-solid fa-chevron-down"></i>'
        : '<i class="fa-solid fa-chevron-right"></i>';
    document
      .querySelectorAll(`.js-login-row[data-group="${group}"]`)
      .forEach((tr) => tr.classList.toggle("is-hidden", !expanded));
  }
  function toggleFolder(folderRow) {
    const group = folderRow.dataset.group;
    const expanded = folderRow.getAttribute("aria-expanded") === "true";
    const next = !expanded;
    setExpanded(folderRow, next);
    if (!new URLSearchParams(window.location.search).get("q")) {
      const state = loadFolderState();
      state[group] = next;
      saveFolderState(state);
    }
  }

  function applyFolderStateToCurrentDom() {
    const isSearchNow = !!new URLSearchParams(window.location.search).get("q");
    if (isSearchNow) {
      document
        .querySelectorAll(".js-folder")
        .forEach((r) => setExpanded(r, true));
    } else {
      const state = loadFolderState();
      document.querySelectorAll(".js-folder").forEach((r) => {
        const g = r.dataset.group;
        setExpanded(r, !!state[g]);
      });
    }
  }

  // --- INIT ---

  const isSearch = !!new URLSearchParams(window.location.search).get("q");
  if (isSearch) {
    document
      .querySelectorAll(".js-folder")
      .forEach((r) => setExpanded(r, true));
  } else {
    const state = loadFolderState();
    document.querySelectorAll(".js-folder").forEach((r) => {
      const g = r.dataset.group;
      setExpanded(r, !!state[g]);
    });
  }

  applyFolderStateToCurrentDom();

  setupAddModal();
  setupEditModal();

  document.addEventListener("click", async (ev) => {
    if (ev.target.closest(".js-folder")) {
      toggleFolder(ev.target.closest(".js-folder"));
      return;
    }

    const favBtn = ev.target.closest(".js-toggle-favorite");
    if (favBtn) {
      const wrap = favBtn.closest(".cellActions");
      const id = wrap.dataset.id;
      const icon = favBtn.querySelector("i");

      // Determina novo estado baseado na classe atual
      const isCurrentlyFav = icon.classList.contains("fa-solid");
      const newStatus = !isCurrentlyFav;

      // Atualização Otimista da UI
      if (newStatus) {
        icon.classList.remove("fa-regular");
        icon.classList.add("fa-solid");
        icon.style.color = "#fbbf24"; // Amarelo
      } else {
        icon.classList.remove("fa-solid");
        icon.classList.add("fa-regular");
        icon.style.color = "";
      }

      try {
        // Envia apenas o campo is_fav
        const resp = await fetch(`/api/login/${id}/update/`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken"),
          },
          body: JSON.stringify({ is_fav: newStatus }),
        });

        if (!resp.ok) {
          // Reverte em caso de erro
          throw new Error("Falha ao favoritar");
        }

        await refreshLoginTableFromServer();
      } catch (e) {
        console.error(e);
        alert("Erro ao favoritar. Recarregue a página.");
      }
      return;
    }

    const toggleBtn = ev.target.closest(".js-toggle-secret");
    if (toggleBtn) {
      toggleSecret(toggleBtn);
      return;
    }

    const copyLoginBtn = ev.target.closest(".js-copy");
    if (copyLoginBtn) {
      const ok = await copyText(copyLoginBtn.dataset.copy || "");
      setTempIcon(copyLoginBtn, ok);
      return;
    }

    const copyPassBtn = ev.target.closest(".js-copy-password");
    if (copyPassBtn) {
      copyPasswordHandler(copyPassBtn);
      return;
    }

    const editBtn = ev.target.closest(".js-edit-login");
    if (editBtn) {
      openEditLogin(editBtn);
      return;
    }
  });
})();
