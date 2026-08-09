/* Thin fetch wrapper: same-origin cookies, JSON in/out, throws Error(detail) on failure. */
const API = {
  async _req(method, path, body) {
    const opts = {
      method,
      credentials: "include",
      headers: {},
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { /* no body */ }
    if (!res.ok) {
      if (res.status === 401 && path !== "/api/auth/login") {
        window.dispatchEvent(new Event("nxc:unauthorized"));
      }
      const detail = (data && data.detail) ? data.detail : `HTTP ${res.status}`;
      throw new Error(detail);
    }
    return data;
  },
  get(path) { return this._req("GET", path); },
  post(path, body) { return this._req("POST", path, body ?? {}); },
  patch(path, body) { return this._req("PATCH", path, body ?? {}); },
  del(path) { return this._req("DELETE", path); },
};
