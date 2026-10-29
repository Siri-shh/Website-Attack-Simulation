"use strict";

document.querySelectorAll(".record-form").forEach((form) => {
  const fileInput = form.querySelector('input[name="image"]');
  if (!fileInput) return;

  fileInput.addEventListener("change", () => {
    if (!fileInput.files?.length) return;
    const replaceAction = form.querySelector('input[name="image_action"][value="replace"]');
    if (replaceAction) replaceAction.checked = true;
  });
});

document.querySelectorAll("details[data-ciphertext-url]").forEach((control) => {
  control.addEventListener("toggle", async () => {
    if (!control.open || control.dataset.loaded === "true" || control.dataset.loading === "true") {
      return;
    }

    const output = control.querySelector("[data-ciphertext-output]");
    const error = control.querySelector("[data-ciphertext-error]");
    const status = control.querySelector("[data-ciphertext-status]");
    if (!output || !error || !status) return;

    control.dataset.loading = "true";
    error.hidden = true;
    status.textContent = "Loading encrypted image evidence…";
    try {
      const response = await fetch(control.dataset.ciphertextUrl, {
        credentials: "same-origin",
        headers: { Accept: "text/plain" },
      });
      if (!response.ok || !response.headers.get("Content-Type")?.startsWith("text/plain")) {
        throw new Error("Ciphertext request failed");
      }
      output.textContent = await response.text();
      control.dataset.loaded = "true";
      status.textContent = "Encrypted image evidence loaded.";
    } catch {
      error.textContent = "Ciphertext could not be loaded. Close and reopen this section to try again.";
      error.hidden = false;
      status.textContent = "Encrypted image evidence could not be loaded.";
    } finally {
      delete control.dataset.loading;
    }
  });
});
