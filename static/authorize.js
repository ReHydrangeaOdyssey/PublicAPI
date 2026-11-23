"use strict";
const form = document.querySelector("#login");
const status = document.querySelector("#status");
const encoder = new TextEncoder();
const query = new URLSearchParams(location.search);
const encode64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const decode64 = text => Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0));
const csrf = encode64(crypto.getRandomValues(new Uint8Array(32)));
document.cookie = "__Host-CsrfToken=" + csrf + "; Secure; SameSite=Strict; Path=/";
function varint(n) {
    const out = [];
    do { const byte = n & 127; n = Math.floor(n / 128); out.push(byte | (n ? 128 : 0)); } while (n);
    return out;
}
function message(fields) {
    return new Uint8Array(fields.flatMap(([tag, value]) => {
        const bytes = typeof value === "string" ? encoder.encode(value) : value;
        return [...varint(tag * 8 + 2), ...varint(bytes.length), ...bytes];
    }));
}
function fieldOne(body) {
    let offset = 0;
    function read() {
        let n = 0, multiplier = 1;
        for (let i = 0; i < 10; i++) {
            if (offset === body.length) throw Error("応答を読み取れませんでした");
            const b = body[offset++]; n += (b & 127) * multiplier;
            if (!(b & 128)) return n;
            multiplier *= 128;
        }
        throw Error("応答を読み取れませんでした");
    }
    if (read() !== 10) throw Error("応答を読み取れませんでした");
    const length = read();
    if (length !== 32 || offset + length > body.length) throw Error("応答を読み取れませんでした");
    return body.slice(offset, offset + length);
}
async function rpc(method, fields) {
    const response = await fetch("/v1/public/" + method, {method: "POST", credentials: "same-origin",
        headers: {"Content-Type": "application/x-protobuf", "X-CSRF-Token": csrf}, body: message(fields), cache: "no-store"});
    if (!response.ok) throw Error("処理できませんでした（" + response.status + "）");
    return new Uint8Array(await response.arrayBuffer());
}
async function finish() {
    if (!query.has("redirect_uri")) { status.textContent = "ログインしました。"; return; }
    if (query.get("redirect_uri") !== settings.callback || query.get("code_challenge_method") !== "S256"
        || !/^[A-Za-z0-9_-]{43}$/.test(query.get("code_challenge") || "")
        || !/^[A-Za-z0-9_-]{16,256}$/.test(query.get("state") || "")) throw Error("認証要求が不正です");
    const code = fieldOne(await rpc("IssueAuthorizationCode", [[1, settings.callback], [2, decode64(query.get("code_challenge"))]]));
    const callback = new URL(settings.callback);
    callback.searchParams.set("code", encode64(code)); callback.searchParams.set("state", query.get("state"));
    location.replace(callback.href);
}
function fields(create) {
    const data = new FormData(form);
    return [[1, data.get("login_id")], [2, data.get("password")], [3, create ? data.get("user_name") : settings.version],
        [4, data.get("discord_token")], [6, data.get("provider")]];
}
async function execute(action) {
    const buttons = [...form.querySelectorAll("button")];
    buttons.forEach(b => b.disabled = true);
    try { await action(); } catch (error) { status.textContent = error.message; }
    finally { buttons.forEach(b => b.disabled = false); }
}
form.addEventListener("submit", event => { event.preventDefault(); execute(async () => { await rpc("Login", fields(false)); await finish(); }); });
document.querySelector("#create").addEventListener("click", () => execute(async () => {
    await rpc("CreateAccount", fields(true)); status.textContent = "登録しました。ログインしてください。";
}));
document.querySelector("#resume").addEventListener("click", () => execute(async () => { await rpc("RefreshAccessToken", []); await finish(); }));
document.querySelector("#logout").addEventListener("click", () => execute(async () => { await rpc("Logout", []); status.textContent = "ログアウトしました。"; }));
for (const provider of settings.providers) {
    const option = document.createElement("option"); option.value = provider; option.textContent = provider;
    form.elements.provider.append(option);
}
