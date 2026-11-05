/* Enca's SGEN — lógica del navegador. Sin dependencias externas.
 *
 * Las claves y CSR generados se guardan ÚNICAMENTE en el localStorage de
 * este navegador. El servidor no conserva nada.
 */
(function () {
  "use strict";

  var STORE_KEY = "opensslweb.requests";
  var THEME_KEY = "opensslweb.theme";
  var FORMAT_KEY = "opensslweb.format";

  var KEY_LABELS = {
    rsa2048: "RSA 2048", rsa3072: "RSA 3072", rsa4096: "RSA 4096",
    ecp256: "ECDSA P-256", ecp384: "ECDSA P-384", ecp521: "ECDSA P-521"
  };
  var DIGEST_LABELS = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
  var CIPHER_LABELS = { none: "Sin cifrar", aes128: "AES-128", aes192: "AES-192", aes256: "AES-256" };

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) return;
        if (k === "text") node.textContent = v;
        else if (k === "className") node.className = v;
        else if (k.slice(0, 2) === "on") node.addEventListener(k.slice(2), v);
        else node.setAttribute(k, v === true ? "" : v);
      });
    }
    if (children !== null && children !== undefined && !Array.isArray(children)) children = [children];
    (children || []).forEach(function (c) {
      if (c === null || c === undefined) return;
      node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return node;
  }

  /* ------------------------------------------------------------------ */
  /* Almacenamiento local                                               */
  /* ------------------------------------------------------------------ */
  function safeGet(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }
  function safeSet(key, value) {
    try { window.localStorage.setItem(key, value); return true; } catch (e) { return false; }
  }
  function loadEntries() {
    try {
      var list = JSON.parse(safeGet(STORE_KEY) || "[]");
      return Array.isArray(list) ? list : [];
    } catch (e) { return []; }
  }
  function saveEntries(list) {
    return safeSet(STORE_KEY, JSON.stringify(list));
  }
  function newId() {
    var a = new Uint8Array(8);
    (window.crypto || window.msCrypto).getRandomValues(a);
    return Array.prototype.map.call(a, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }

  /* ------------------------------------------------------------------ */
  /* Tema día / noche                                                   */
  /* ------------------------------------------------------------------ */
  function systemDark() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  }
  function applyTheme(theme) {
    if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);
    else document.documentElement.removeAttribute("data-theme");
  }
  applyTheme(safeGet(THEME_KEY));

  /* ------------------------------------------------------------------ */
  /* Utilidades UI                                                      */
  /* ------------------------------------------------------------------ */
  var toastTimer = null;
  function toast(text) {
    var t = $("#toast");
    t.textContent = text;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.classList.remove("show"); }, 2200);
  }

  function setMsg(node, text, kind) {
    node.textContent = text || "";
    node.className = "msg" + (kind ? " " + kind : "");
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () { toast("Copiado al portapapeles"); });
    }
    var ta = el("textarea", { className: "offscreen" });
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); toast("Copiado al portapapeles"); } catch (e) { toast("No se pudo copiar"); }
    document.body.removeChild(ta);
    return Promise.resolve();
  }

  /* ------------------------------------------------------------------ */
  /* Cifrado de las comunicaciones (protocolo sgen1)                    */
  /*   1. GET /api/key  -> clave pública ECDH P-256 efímera del servidor */
  /*   2. Par ECDH efímero del navegador + HKDF-SHA256 -> 2 claves AES   */
  /*   3. Petición y respuesta cifradas con AES-256-GCM                 */
  /* El servidor destruye su clave privada tras cada petición.          */
  /* ------------------------------------------------------------------ */
  var E2E_INFO = "encas-sgen e2e v1";

  function cryptoAvailable() {
    return !!(window.crypto && window.crypto.subtle && window.isSecureContext !== false);
  }

  function b64encode(bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i += 0x8000) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(out);
  }

  function b64decode(text) {
    var bin = atob(text);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function utf8(text) { return new TextEncoder().encode(text); }

  function jsonFetch(path, opts) {
    return fetch(path, opts).then(function (res) {
      var ctype = res.headers.get("Content-Type") || "";
      if (ctype.indexOf("application/json") !== 0) throw new Error("Error " + res.status);
      return res.json().then(function (j) { return { status: res.status, ok: res.ok, body: j }; });
    });
  }

  function api(path, body) {
    if (!cryptoAvailable()) {
      return Promise.reject(new Error("El cifrado de las comunicaciones requiere acceder a la web por HTTPS."));
    }
    var subtle = window.crypto.subtle;
    var server, clientKeys, kid, resKey;
    return jsonFetch("/api/key", { method: "GET", cache: "no-store", credentials: "same-origin" })
      .then(function (r) {
        if (!r.ok || r.body.v !== 1) throw new Error((r.body && r.body.error) || "No se pudo iniciar el cifrado");
        server = r.body;
        kid = b64decode(server.kid);
        return Promise.all([
          subtle.importKey("raw", b64decode(server.publicKey), { name: "ECDH", namedCurve: "P-256" }, false, []),
          subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
        ]);
      })
      .then(function (keys) {
        clientKeys = keys[1];
        return subtle.deriveBits({ name: "ECDH", public: keys[0] }, clientKeys.privateKey, 256);
      })
      .then(function (shared) {
        return subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
      })
      .then(function (hkdfKey) {
        return subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: kid, info: utf8(E2E_INFO) }, hkdfKey, 512);
      })
      .then(function (okm) {
        okm = new Uint8Array(okm);
        return Promise.all([
          subtle.importKey("raw", okm.slice(0, 32), "AES-GCM", false, ["encrypt"]),
          subtle.importKey("raw", okm.slice(32), "AES-GCM", false, ["decrypt"]),
          subtle.exportKey("raw", clientKeys.publicKey)
        ]);
      })
      .then(function (k) {
        resKey = k[1];
        var iv = window.crypto.getRandomValues(new Uint8Array(12));
        var epk = new Uint8Array(k[2]);
        return subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: utf8("sgen1|req|" + path) },
          k[0], utf8(JSON.stringify(body))).then(function (ct) {
          return JSON.stringify({ v: 1, kid: server.kid, epk: b64encode(epk), iv: b64encode(iv),
            ct: b64encode(new Uint8Array(ct)) });
        });
      })
      .then(function (envelope) {
        body = null; // no conservamos el texto en claro más de lo necesario
        return jsonFetch(path, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: envelope,
          cache: "no-store",
          credentials: "same-origin"
        });
      })
      .then(function (r) {
        if (!r.body || r.body.v !== 1 || !r.body.ct) {
          throw new Error((r.body && r.body.error) || "Error " + r.status);
        }
        return subtle.decrypt({ name: "AES-GCM", iv: b64decode(r.body.iv), additionalData: utf8("sgen1|res|" + path) },
          resKey, b64decode(r.body.ct)).then(function (plain) {
          var obj = JSON.parse(new TextDecoder().decode(plain));
          if (obj && obj.error) throw new Error(obj.error);
          return obj;
        });
      });
  }

  function saveBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = el("a", { href: url, download: filename, className: "offscreen" });
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); document.body.removeChild(a); }, 1000);
  }

  function fileName(base, kind, fmt) {
    return fmt === "txt" ? base + "-" + kind + ".txt" : base + "." + kind;
  }

  function downloadOne(entry, kind, fmt) {
    var content = (kind === "csr" ? entry.csr : entry.key).trim() + "\n";
    var mime = fmt === "txt" ? "text/plain" : (kind === "csr" ? "application/pkcs10" : "application/x-pem-file");
    saveBlob(new Blob([content], { type: mime + ";charset=utf-8" }), fileName(entry.name, kind, fmt));
  }

  function downloadZip(entry, fmt, button) {
    if (button) button.disabled = true;
    // El servidor comprime en memoria y no conserva nada.
    return api("/api/zip", { name: entry.name, format: fmt, csr: entry.csr, key: entry.key })
      .then(function (res) {
        saveBlob(new Blob([b64decode(res.zip)], { type: "application/zip" }), res.filename || entry.name + ".zip");
      })
      .catch(function (err) { toast(err.message); })
      .then(function () { if (button) button.disabled = false; });
  }

  function currentFormat() { return safeGet(FORMAT_KEY) === "txt" ? "txt" : "pem"; }
  function setFormat(fmt) {
    safeSet(FORMAT_KEY, fmt);
    $all('input[type="radio"][data-format]').forEach(function (r) { r.checked = r.value === fmt; });
  }

  var fmtCounter = 0;
  function formatSelector() {
    var name = "fmt-" + (++fmtCounter);
    var fmt = currentFormat();
    function radio(value, label) {
      var input = el("input", { type: "radio", name: name, value: value, "data-format": "1" });
      input.checked = fmt === value;
      input.addEventListener("change", function () { if (input.checked) setFormat(value); });
      return el("label", { className: "check" }, [input, " " + label]);
    }
    return el("div", { className: "format-row" }, [
      el("span", { text: "Formato:" }), radio("pem", ".csr / .key"), radio("txt", ".txt")
    ]);
  }

  function downloadButtons(entry) {
    var zipBtn = el("button", { type: "button", className: "btn small primary", text: "Descargar ambos (.zip)" });
    zipBtn.addEventListener("click", function () { downloadZip(entry, currentFormat(), zipBtn); });
    return [
      el("button", { type: "button", className: "btn small", text: "Descargar KEY",
        onclick: function () { downloadOne(entry, "key", currentFormat()); } }),
      el("button", { type: "button", className: "btn small", text: "Descargar CSR",
        onclick: function () { downloadOne(entry, "csr", currentFormat()); } }),
      zipBtn
    ];
  }

  /* ------------------------------------------------------------------ */
  /* Pestañas                                                           */
  /* ------------------------------------------------------------------ */
  function showTab(name) {
    $all(".tab").forEach(function (t) { t.setAttribute("aria-selected", String(t.dataset.tab === name)); });
    $all(".panel").forEach(function (p) { p.hidden = p.id !== "tab-" + name; });
    if (name === "saved") renderSaved();
    if (history.replaceState) history.replaceState(null, "", "#" + name);
  }

  /* ------------------------------------------------------------------ */
  /* SAN                                                                */
  /* ------------------------------------------------------------------ */
  function guessSanType(v) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (v.indexOf(":") > -1 && /^[0-9a-f:.]+$/i.test(v))) return "IP";
    if (v.indexOf("@") > -1 && v.indexOf("://") === -1) return "email";
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return "URI";
    return "DNS";
  }

  function addSanRow(type, value, focus) {
    var frag = $("#tpl-san").content.cloneNode(true);
    var row = $(".san-row", frag);
    var sel = $(".san-type", row);
    var input = $(".san-value", row);
    sel.value = type || "DNS";
    input.value = value || "";
    $(".san-del", row).addEventListener("click", function () { row.parentNode.removeChild(row); });
    input.addEventListener("paste", function (ev) {
      var text = (ev.clipboardData || window.clipboardData).getData("text");
      var parts = text.split(/[\s,;]+/).filter(Boolean);
      if (parts.length > 1) {
        ev.preventDefault();
        input.value = parts[0];
        sel.value = guessSanType(parts[0]);
        var after = row;
        parts.slice(1).forEach(function (p) { after = addSanRow(guessSanType(p), p, false, after); });
      }
    });
    input.addEventListener("blur", function () {
      if (input.value && sel.value === "DNS") sel.value = guessSanType(input.value.trim());
    });
    var list = $("#san-list");
    var insertAfter = arguments[3];
    if (insertAfter && insertAfter.nextSibling) list.insertBefore(row, insertAfter.nextSibling);
    else list.appendChild(row);
    if (focus) input.focus();
    return row;
  }

  function collectSans() {
    return $all(".san-row").map(function (row) {
      return { type: $(".san-type", row).value, value: $(".san-value", row).value.trim() };
    }).filter(function (s) { return s.value; });
  }

  /* ------------------------------------------------------------------ */
  /* Generación                                                         */
  /* ------------------------------------------------------------------ */
  var lastEntry = null;

  function updatePassVisibility() {
    var form = $("#gen-form");
    $("#pass-row").hidden = form.cipher.value === "none";
  }

  function updateKeyUsageForKeyType() {
    var form = $("#gen-form");
    var isEc = form.keyType.value.indexOf("ec") === 0;
    var ke = $('input[name="ku"][value="keyEncipherment"]');
    ke.disabled = isEc;
    if (isEc) ke.checked = false;
    else if (!ke.dataset.touched) ke.checked = true;
  }

  function onGenerate(ev) {
    ev.preventDefault();
    var form = ev.target;
    var msg = $("#gen-msg");
    $all("input.invalid", form).forEach(function (i) { i.classList.remove("invalid"); });

    var cn = form.CN.value.trim();
    if (!cn) {
      form.CN.classList.add("invalid");
      form.CN.focus();
      setMsg(msg, "El Common Name (CN) es obligatorio.", "error");
      return;
    }
    var country = form.C.value.trim().toUpperCase();
    if (country && !/^[A-Z]{2}$/.test(country)) {
      form.C.classList.add("invalid");
      setMsg(msg, "País (C): usa el código ISO de 2 letras, p. ej. ES.", "error");
      return;
    }
    if (form.cipher.value !== "none") {
      if (form.passphrase.value.length < 4) {
        form.passphrase.classList.add("invalid");
        setMsg(msg, "La contraseña debe tener al menos 4 caracteres.", "error");
        return;
      }
      if (form.passphrase.value !== form.passphrase2.value) {
        form.passphrase2.classList.add("invalid");
        setMsg(msg, "Las contraseñas no coinciden.", "error");
        return;
      }
    }

    var payload = {
      keyType: form.keyType.value,
      digest: form.digest.value,
      cipher: form.cipher.value,
      keyFormat: form.keyFormat.value,
      passphrase: form.cipher.value === "none" ? "" : form.passphrase.value,
      subject: {
        CN: cn, O: form.O.value, OU: form.OU.value, L: form.L.value,
        ST: form.ST.value, C: country, emailAddress: form.emailAddress.value
      },
      cnInSan: form.cnInSan.checked,
      sans: collectSans(),
      keyUsage: $all('input[name="ku"]:checked', form).map(function (i) { return i.value; }),
      keyUsageCritical: form.kuCritical.checked,
      extKeyUsage: $all('input[name="eku"]:checked', form).map(function (i) { return i.value; }),
      mustStaple: form.mustStaple.checked
    };

    var btn = $("#gen-btn");
    btn.disabled = true;
    setMsg(msg, form.keyType.value === "rsa4096" ? "Generando clave RSA 4096 (puede tardar unos segundos)…" : "Generando…", "busy");

    api("/api/generate", payload).then(function (res) {
      // Borramos la contraseña del formulario en cuanto deja de ser necesaria.
      form.passphrase.value = "";
      form.passphrase2.value = "";
      payload.passphrase = "";
      var entry = {
        id: newId(),
        name: res.name,
        cn: cn,
        created: new Date().toISOString(),
        keyType: payload.keyType,
        digest: payload.digest,
        cipher: payload.cipher,
        keyFormat: payload.keyFormat,
        csr: res.csr,
        key: res.key
      };
      var list = loadEntries();
      list.unshift(entry);
      var stored = saveEntries(list);
      lastEntry = entry;
      showResult(entry, stored);
      updateSavedCount();
      setMsg(msg, "");
    }).catch(function (err) {
      setMsg(msg, err.message, "error");
    }).then(function () {
      btn.disabled = false;
    });
  }

  function showResult(entry, stored) {
    var box = $("#gen-result");
    $("#res-name").textContent = entry.name;
    $("#res-csr").value = entry.csr;
    $("#res-key").value = entry.key;
    var pill = $(".pill", box);
    pill.className = "pill " + (stored ? "ok" : "warn");
    pill.textContent = stored ? "Guardado solo en este navegador" : "No se pudo guardar en el navegador: descárgalo ahora";
    var bar = $("#res-downloads");
    bar.textContent = "";
    bar.appendChild(formatSelector());
    downloadButtons(entry).forEach(function (b) { bar.appendChild(b); });
    box.hidden = false;
    box.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  /* ------------------------------------------------------------------ */
  /* Decodificación                                                     */
  /* ------------------------------------------------------------------ */
  function normalizePem(text) {
    var m = /-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----([\s\S]*?)-----END (?:NEW )?CERTIFICATE REQUEST-----/.exec(text || "");
    return m ? m[1].replace(/\s+/g, "") : null;
  }

  function onDecode() {
    var input = $("#dec-input");
    var msg = $("#dec-msg");
    var out = $("#dec-result");
    var text = input.value;
    if (/PRIVATE KEY-----/.test(text)) {
      setMsg(msg, "Has pegado una clave privada. Por seguridad no se envía: pega solo el CSR.", "error");
      return;
    }
    if (!normalizePem(text)) {
      setMsg(msg, "No se encuentra un bloque -----BEGIN CERTIFICATE REQUEST-----.", "error");
      return;
    }
    var btn = $("#dec-btn");
    btn.disabled = true;
    setMsg(msg, "Analizando…", "busy");
    api("/api/decode", { csr: text }).then(function (info) {
      setMsg(msg, "");
      renderDecoded(out, info);
      out.hidden = false;
    }).catch(function (err) {
      out.hidden = true;
      setMsg(msg, err.message, "error");
    }).then(function () { btn.disabled = false; });
  }

  function kvTable(rows) {
    return el("table", { className: "kv" }, [el("tbody", null, rows.map(function (r) {
      return el("tr", null, [el("th", null, r[0]), el("td", null, Array.isArray(r[1]) ? r[1] : [r[1]])]);
    }))]);
  }

  function renderDecoded(out, info) {
    out.textContent = "";

    var errors = info.checks.filter(function (c) { return c.level === "error"; }).length;
    var warns = info.checks.filter(function (c) { return c.level === "warn"; }).length;
    var status = errors ? ["error", "No válido"] : warns ? ["warn", "Válido con advertencias"] : ["ok", "Válido"];

    var summary = el("div", { className: "card" }, [
      el("div", { className: "result-head" }, [
        el("h2", { text: info.subjectString || "(sin sujeto)" }),
        el("span", { className: "pill " + status[0], text: status[1] })
      ]),
      el("ul", { className: "checks" }, info.checks.map(function (c) {
        return el("li", { className: c.level, text: c.message });
      }))
    ]);
    var match = findSavedMatch(info.pem);
    if (match) {
      summary.appendChild(el("p", { className: "hint match" }, [
        "Este CSR corresponde a la petición guardada en este navegador «" + match.name + "» (" +
        new Date(match.created).toLocaleString() + ")."
      ]));
    }
    out.appendChild(summary);

    var subjRows = info.subject.map(function (s) {
      return [[s.label + " ", el("code", { text: "(" + s.short + ")" })], s.value];
    });
    if (!subjRows.length) subjRows.push(["—", "Sin sujeto"]);
    out.appendChild(el("div", { className: "card" }, [el("h2", { text: "Sujeto" }), kvTable(subjRows)]));

    var pk = info.publicKey;
    var keyRows = [
      ["Algoritmo", pk.algorithm],
      ["Tamaño", pk.bits ? pk.bits + " bits" : "—"]
    ];
    if (pk.detail) keyRows.push(["Detalle", pk.detail]);
    if (pk.modulus) {
      keyRows.push(["Módulo", el("details", null, [
        el("summary", { text: pk.modulus.slice(0, 16) + "… (mostrar)" }),
        el("span", { className: "mono", text: pk.modulus.replace(/(.{2})(?!$)/g, "$1:") })
      ])]);
    }
    keyRows.push(["Algoritmo de firma", info.signatureAlgorithm]);
    keyRows.push(["Hash de firma", info.signatureHash]);
    keyRows.push(["Firma", info.signatureValid ? "Válida" : "NO válida"]);
    keyRows.push(["Versión", String(info.version)]);
    out.appendChild(el("div", { className: "card" }, [el("h2", { text: "Clave pública y firma" }), kvTable(keyRows)]));

    var sanBody = info.sans.length
      ? el("div", { className: "tag-list" }, info.sans.map(function (s) {
        return el("span", { className: "tag" }, [el("b", { text: s.type }), " " + s.value]);
      }))
      : el("p", { className: "hint", text: "El CSR no incluye Subject Alternative Names." });
    out.appendChild(el("div", { className: "card" }, [
      el("h2", { text: "Subject Alternative Names (" + info.sans.length + ")" }), sanBody
    ]));

    var extRows = info.extensions.filter(function (e) { return e.oid !== "2.5.29.17"; }).map(function (e) {
      return [[e.name + " ", e.critical ? el("span", { className: "pill warn", text: "crítica" }) : null],
        el("div", { className: "tag-list" }, e.values.map(function (v) { return el("span", { className: "tag", text: v }); }))];
    });
    info.attributes.forEach(function (a) { extRows.push([a.name, a.value || "—"]); });
    if (extRows.length) {
      out.appendChild(el("div", { className: "card" }, [el("h2", { text: "Extensiones y atributos" }), kvTable(extRows)]));
    }

    if (info.opensslText) {
      out.appendChild(el("details", { className: "card" }, [
        el("summary", null, [el("h2", { text: "Salida completa de openssl" })]),
        el("pre", { className: "raw", text: info.opensslText })
      ]));
    }
  }

  function findSavedMatch(pem) {
    var body = normalizePem(pem);
    if (!body) return null;
    var list = loadEntries();
    for (var i = 0; i < list.length; i++) {
      if (normalizePem(list[i].csr) === body) return list[i];
    }
    return null;
  }

  /* ------------------------------------------------------------------ */
  /* Guardados                                                          */
  /* ------------------------------------------------------------------ */
  function updateSavedCount() {
    $("#saved-count").textContent = String(loadEntries().length);
  }

  function renderSaved() {
    var list = loadEntries();
    var box = $("#saved-list");
    box.textContent = "";
    $("#saved-empty").hidden = list.length > 0;
    $("#saved-clear").hidden = list.length === 0;
    $all('input[name="fmt-saved"]').forEach(function (r) { r.checked = r.value === currentFormat(); });

    list.forEach(function (entry) {
      var item = el("div", { className: "saved-item" });
      var meta = [KEY_LABELS[entry.keyType] || entry.keyType, DIGEST_LABELS[entry.digest] || entry.digest,
        CIPHER_LABELS[entry.cipher] || entry.cipher, new Date(entry.created).toLocaleString()].join(" · ");
      item.appendChild(el("div", { className: "saved-top" }, [
        el("span", { className: "saved-name", text: entry.cn }),
        el("span", { className: "saved-meta", text: meta })
      ]));
      var viewer = el("div", { hidden: true });
      var actions = el("div", { className: "saved-actions" }, downloadButtons(entry).concat([
        el("button", { type: "button", className: "btn small ghost", text: "Ver",
          onclick: function () {
            if (!viewer.childNodes.length) {
              var csr = el("textarea", { className: "pem", readonly: true, spellcheck: "false" });
              var key = el("textarea", { className: "pem", readonly: true, spellcheck: "false" });
              csr.value = entry.csr;
              key.value = entry.key;
              viewer.appendChild(el("div", { className: "grid two" }, [csr, key]));
            }
            viewer.hidden = !viewer.hidden;
          } }),
        el("button", { type: "button", className: "btn small ghost", text: "Desglosar CSR",
          onclick: function () { $("#dec-input").value = entry.csr; showTab("decode"); onDecode(); } }),
        el("button", { type: "button", className: "btn small danger", text: "Eliminar",
          onclick: function () {
            if (!confirm("¿Eliminar «" + entry.cn + "» de este navegador? Si no la has descargado, la clave privada se perderá.")) return;
            saveEntries(loadEntries().filter(function (e) { return e.id !== entry.id; }));
            renderSaved();
            updateSavedCount();
          } })
      ]));
      item.appendChild(actions);
      item.appendChild(viewer);
      box.appendChild(item);
    });
  }

  /* ------------------------------------------------------------------ */
  /* Inicio                                                             */
  /* ------------------------------------------------------------------ */
  function init() {
    $("#theme-toggle").addEventListener("click", function () {
      var current = document.documentElement.getAttribute("data-theme") || (systemDark() ? "dark" : "light");
      var next = current === "dark" ? "light" : "dark";
      applyTheme(next);
      safeSet(THEME_KEY, next);
    });

    $all(".tab").forEach(function (t) {
      t.addEventListener("click", function () { showTab(t.dataset.tab); });
    });

    var form = $("#gen-form");
    form.addEventListener("submit", onGenerate);
    form.cipher.addEventListener("change", updatePassVisibility);
    form.keyType.addEventListener("change", updateKeyUsageForKeyType);
    $('input[name="ku"][value="keyEncipherment"]').addEventListener("change", function (e) {
      e.target.dataset.touched = "1";
    });
    form.addEventListener("reset", function () {
      setTimeout(function () {
        $("#san-list").textContent = "";
        addSanRow("DNS", "");
        updatePassVisibility();
        updateKeyUsageForKeyType();
        setMsg($("#gen-msg"), "");
      }, 0);
    });
    form.C.addEventListener("input", function () { form.C.value = form.C.value.toUpperCase(); });
    $("#san-add").addEventListener("click", function () { addSanRow("DNS", "", true); });
    addSanRow("DNS", "");
    updatePassVisibility();
    updateKeyUsageForKeyType();

    $all("[data-copy]").forEach(function (b) {
      b.addEventListener("click", function () { copyText($("#" + b.dataset.copy).value); });
    });
    $("#res-decode").addEventListener("click", function () {
      if (!lastEntry) return;
      $("#dec-input").value = lastEntry.csr;
      showTab("decode");
      onDecode();
    });

    $("#dec-btn").addEventListener("click", onDecode);
    $("#dec-clear").addEventListener("click", function () {
      $("#dec-input").value = "";
      $("#dec-result").hidden = true;
      setMsg($("#dec-msg"), "");
    });
    $("#dec-file").addEventListener("change", function (ev) {
      var f = ev.target.files && ev.target.files[0];
      if (!f) return;
      if (f.size > 65536) { setMsg($("#dec-msg"), "Archivo demasiado grande.", "error"); return; }
      var reader = new FileReader();
      reader.onload = function () { $("#dec-input").value = String(reader.result); ev.target.value = ""; onDecode(); };
      reader.readAsText(f);
    });

    $all('input[name="fmt-saved"]').forEach(function (r) {
      r.addEventListener("change", function () { if (r.checked) setFormat(r.value); });
    });
    $("#saved-clear").addEventListener("click", function () {
      if (!confirm("¿Borrar TODAS las peticiones guardadas en este navegador? Las claves privadas no descargadas se perderán.")) return;
      saveEntries([]);
      renderSaved();
      updateSavedCount();
    });

    window.addEventListener("storage", function (e) {
      if (e.key === STORE_KEY) { updateSavedCount(); if (!$("#tab-saved").hidden) renderSaved(); }
    });

    updateSavedCount();
    if (!cryptoAvailable()) $("#e2e-warning").hidden = false;
    $all("[data-goto]").forEach(function (a) {
      a.addEventListener("click", function (ev) {
        ev.preventDefault();
        showTab(a.dataset.goto);
        window.scrollTo(0, 0);
      });
    });
    var hash = (location.hash || "").slice(1);
    if (hash === "decode" || hash === "saved" || hash === "info") showTab(hash);
    else if (hash.indexOf("info-") === 0 && document.getElementById(hash)) {
      showTab("info");
      history.replaceState(null, "", "#" + hash);
      document.getElementById(hash).scrollIntoView();
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
