"use strict";

const form = document.querySelector("#login-form");
const button = document.querySelector("#login-button");
const errorBox = document.querySelector("#login-error");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.textContent = "";
  button.disabled = true;
  button.textContent = "正在验证…";

  try {
    const response = await fetch("api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        username: document.querySelector("#username").value,
        password: document.querySelector("#password").value,
      }),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.ok !== true) {
      throw new Error(result.message || "登录失败，请稍后再试");
    }
    location.reload();
  } catch (error) {
    errorBox.textContent = error instanceof Error ? error.message : "登录失败，请稍后再试";
    button.disabled = false;
    button.textContent = "进入控制台";
  }
});
