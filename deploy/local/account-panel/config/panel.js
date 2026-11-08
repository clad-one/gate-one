(() => {
  const api = window.__cladoneAuth;
  const toggle = document.getElementById("account-toggle");
  const panel = document.getElementById("account-panel");
  const close = document.getElementById("account-close");
  const anonymous = document.getElementById("account-anonymous");
  const signed = document.getElementById("account-signed");
  const error = document.getElementById("account-error");
  const nameEl = document.getElementById("account-name");
  const emailEl = document.getElementById("account-email");
  const rolesEl = document.getElementById("account-roles");
  const scopesEl = document.getElementById("account-scopes");
  const loginButton = document.getElementById("account-login");
  const logoutButton = document.getElementById("account-logout");

  function setOpen(open) {
    panel.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    if (open) refresh();
  }

  function showError(message) {
    error.textContent = message;
    error.hidden = false;
  }

  function render(session) {
    error.hidden = true;

    if (!session) {
      anonymous.hidden = false;
      signed.hidden = true;
      return;
    }

    const claims = session.claims || {};
    anonymous.hidden = true;
    signed.hidden = false;
    nameEl.textContent = claims.preferred_username || claims.email || "Account";
    emailEl.textContent = claims.email || "—";
    rolesEl.textContent = (session.roles || []).join(", ") || "—";
    scopesEl.textContent = (session.scopes || []).join(", ") || "—";
  }

  async function refresh() {
    if (!api) {
      showError("Gate One guard is not available on this route.");
      return;
    }

    try {
      // With no userBadge and no data-gtw-* markup, the guard does not
      // probe on its own. refresh() forces the probe before session().
      await api.refresh({ quiet: true });
      render(await api.session());
    } catch (e) {
      showError("Unable to read the Gate One session.");
    }
  }

  toggle.addEventListener("click", () => setOpen(panel.hidden));
  close.addEventListener("click", () => setOpen(false));

  loginButton.addEventListener("click", async () => {
    if (!api) return;
    const ok = await api.login();
    if (ok) refresh();
  });

  logoutButton.addEventListener("click", () => {
    if (api) api.logout();
  });

  // The route may already be authenticated when the page loads.
  refresh();
})();
