/* Enca's SGEN — lógica del navegador. Sin dependencias externas.
 *
 * Las claves y CSR generados (y, si el usuario lo pide, el certificado y la
 * cadena) se guardan ÚNICAMENTE en el localStorage de este navegador. Los PFX
 * y sus contraseñas no se guardan en ningún sitio. El servidor no conserva nada.
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

  function downloadCert(entry, fmt) {
    var content = (entry.cert || "").trim() + "\n" + (entry.chain ? entry.chain.trim() + "\n" : "");
    var filename = fmt === "txt" ? entry.name + "-crt.txt" : entry.name + ".crt";
    saveBlob(new Blob([content], { type: (fmt === "txt" ? "text/plain" : "application/x-pem-file") + ";charset=utf-8" }), filename);
  }

  function downloadButtons(entry) {
    var zipBtn = el("button", { type: "button", className: "btn small primary", text: "Descargar ambos (.zip)" });
    zipBtn.addEventListener("click", function () { downloadZip(entry, currentFormat(), zipBtn); });
    var extra = entry.cert ? [el("button", { type: "button", className: "btn small", text: "Descargar CRT",
      title: "Certificado y cadena guardados (PEM)",
      onclick: function () { downloadCert(entry, currentFormat()); } })] : [];
    return extra.concat([
      el("button", { type: "button", className: "btn small", text: "Descargar KEY",
        onclick: function () { downloadOne(entry, "key", currentFormat()); } }),
      el("button", { type: "button", className: "btn small", text: "Descargar CSR",
        onclick: function () { downloadOne(entry, "csr", currentFormat()); } }),
      zipBtn
    ]);
  }

  /* ------------------------------------------------------------------ */
  /* Pestañas                                                           */
  /* ------------------------------------------------------------------ */
  function showTab(name) {
    $all(".tab").forEach(function (t) { t.setAttribute("aria-selected", String(t.dataset.tab === name)); });
    $all(".panel").forEach(function (p) { p.hidden = p.id !== "tab-" + name; });
    if (name === "saved") renderSaved();
    if (name === "pfx") refreshPfxEntries();
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
  /* Crear PFX                                                          */
  /*   Los ficheros se leen en el navegador. Clave, certificados y       */
  /*   contraseñas viajan cifrados (sgen1) a /api/pfx y el PFX vuelve    */
  /*   cifrado. Ni el PFX ni las contraseñas se guardan.                 */
  /* ------------------------------------------------------------------ */
  var MAX_UPLOAD = 96 * 1024;
  var lastPfx = null; // { bytes, filename } solo en memoria, para «Descargar de nuevo»

  function pemWrap(label, bytes) {
    var b64 = b64encode(bytes);
    return "-----BEGIN " + label + "-----\n" + b64.replace(/(.{64})/g, "$1\n").replace(/\n$/, "") +
      "\n-----END " + label + "-----\n";
  }

  // Lector DER mínimo: devuelve { tag, start (contenido), end } o null.
  function derItem(b, pos) {
    if (pos + 2 > b.length) return null;
    var tag = b[pos], len = b[pos + 1], hdr = 2;
    if (len & 0x80) {
      var n = len & 0x7f;
      if (n < 1 || n > 4 || pos + 2 + n > b.length) return null;
      len = 0;
      for (var i = 0; i < n; i++) len = len * 256 + b[pos + 2 + i];
      hdr += n;
    }
    return { tag: tag, start: pos + hdr, end: pos + hdr + len };
  }

  function containsBytes(b, needle, limit) {
    outer: for (var i = 0; i < Math.min(b.length, limit) - needle.length; i++) {
      for (var j = 0; j < needle.length; j++) if (b[i + j] !== needle[j]) continue outer;
      return true;
    }
    return false;
  }

  // Identifica un fichero DER por su estructura: "PFX", "PKCS7", "CERTIFICATE", "PRIVATE KEY",
  // "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY" o null.
  var OID_SIGNED_DATA = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
  function sniffDer(b) {
    var outer = derItem(b, 0);
    if (!outer || outer.tag !== 0x30) return null;
    var first = derItem(b, outer.start);
    if (!first) return null;
    if (first.tag === 0x02) { // versión: PKCS#12 (3), PKCS#8 o clave tradicional (0/1)
      var version = b[first.start];
      var second = derItem(b, first.end);
      if (!second) return null;
      if (version === 3 && second.tag === 0x30) return "PFX";
      if (second.tag === 0x30) return "PRIVATE KEY";
      if (second.tag === 0x02) return "RSA PRIVATE KEY";
      if (second.tag === 0x04) return "EC PRIVATE KEY";
      return null;
    }
    if (first.tag === 0x06) return containsBytes(b, OID_SIGNED_DATA, 24) ? "PKCS7" : null;
    if (first.tag === 0x30) { // AlgorithmIdentifier (PKCS#8 cifrada) o TBSCertificate
      var inner = derItem(b, first.start);
      return inner && inner.tag === 0x06 ? "ENCRYPTED PRIVATE KEY" : "CERTIFICATE";
    }
    return null;
  }

  // Lee un fichero en el navegador y lo devuelve como texto PEM (sin subirlo a ningún sitio).
  function readCryptoFile(file, kind) {
    return new Promise(function (resolve, reject) {
      if (file.size > MAX_UPLOAD) { reject(new Error("«" + file.name + "» es demasiado grande.")); return; }
      var reader = new FileReader();
      reader.onerror = function () { reject(new Error("No se pudo leer «" + file.name + "».")); };
      reader.onload = function () {
        var bytes = new Uint8Array(reader.result);
        var text = new TextDecoder("utf-8").decode(bytes);
        if (/-----BEGIN [A-Z0-9 ]+-----/.test(text)) { resolve(text.trim() + "\n"); return; }
        if (/^[A-Za-z0-9+\/=\s]+$/.test(text) && text.trim().length > 40) {
          // Base64 sin cabeceras: se intenta identificar.
          try { bytes = b64decode(text.replace(/\s+/g, "")); } catch (e) { /* se queda como binario */ }
        }
        var label = sniffDer(bytes);
        if (label === "PFX") {
          reject(new Error("«" + file.name + "» ya es un PFX/PKCS#12. Aquí van la clave y el certificado por separado."));
          return;
        }
        if (!label) { reject(new Error("«" + file.name + "» no parece " + (kind === "key" ? "una clave privada" : "un certificado") + " en PEM o DER.")); return; }
        if (kind === "key" && label.indexOf("PRIVATE KEY") === -1) { reject(new Error("«" + file.name + "» no es una clave privada.")); return; }
        if (kind !== "key" && label.indexOf("PRIVATE KEY") > -1) { reject(new Error("«" + file.name + "» es una clave privada: súbela en el paso 1.")); return; }
        resolve(pemWrap(label, bytes));
      };
      reader.readAsArrayBuffer(file);
    });
  }

  function pfxEntries() {
    return loadEntries().filter(function (e) { return e && e.key && e.csr; });
  }

  function selectedPfxEntry() {
    var id = $("#pfx-entry").value;
    var list = pfxEntries();
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return null;
  }

  function keySource() {
    var r = $('#pfx-form input[name="keySource"]:checked');
    return r ? r.value : "saved";
  }

  function setKeySource(value) {
    $all('#pfx-form input[name="keySource"]').forEach(function (r) { r.checked = r.value === value; });
    updatePfxForm();
  }

  function keyIsEncrypted() {
    if (keySource() === "saved") {
      var entry = selectedPfxEntry();
      return !!(entry && entry.cipher && entry.cipher !== "none");
    }
    var text = $("#pfx-key").value;
    return /ENCRYPTED/.test(text);
  }

  function fillCertFromEntry(entry) {
    var cert = $("#pfx-cert"), chain = $("#pfx-chain");
    // Solo se sustituye lo que se rellenó automáticamente o lo que está vacío.
    if (!cert.value.trim() || cert.dataset.auto === "1") {
      cert.value = (entry && entry.cert) || "";
      cert.dataset.auto = entry && entry.cert ? "1" : "";
    }
    if (!chain.value.trim() || chain.dataset.auto === "1") {
      chain.value = (entry && entry.chain) || "";
      chain.dataset.auto = entry && entry.chain ? "1" : "";
    }
  }

  function updatePfxForm() {
    var src = keySource();
    var list = pfxEntries();
    $("#pfx-saved-box").hidden = src !== "saved";
    $("#pfx-own-box").hidden = src !== "own";
    $("#pfx-no-saved").hidden = list.length > 0;
    $("#pfx-entry").parentNode.hidden = list.length === 0;
    $("#pfx-remember-row").hidden = src !== "saved" || list.length === 0;
    var entry = src === "saved" ? selectedPfxEntry() : null;
    var info = $("#pfx-entry-info");
    info.textContent = entry
      ? (KEY_LABELS[entry.keyType] || entry.keyType) + " · " + (CIPHER_LABELS[entry.cipher] || entry.cipher) +
        " · creada el " + new Date(entry.created).toLocaleString() +
        (entry.cert ? " · certificado guardado" : " · aún sin certificado: pega el que te envió la CA")
      : "";
    if (src === "saved") fillCertFromEntry(entry);
    else {
      // Lo rellenado desde una petición guardada no debe mezclarse con una clave propia.
      [$("#pfx-cert"), $("#pfx-chain")].forEach(function (area) {
        if (area.dataset.auto === "1") { area.value = ""; area.dataset.auto = ""; }
      });
    }
    var encrypted = keyIsEncrypted();
    var ownUnknown = src === "own" && $("#pfx-key").value.trim() && !/-----BEGIN/.test($("#pfx-key").value);
    $("#pfx-keypass-row").hidden = !(encrypted || ownUnknown);
    $("#pfx-keypass-hint").textContent = encrypted
      ? "Esta clave está cifrada: indica la contraseña con la que la protegiste. Solo se usa para abrirla."
      : "Si la clave está cifrada, indica su contraseña. Si no lo está, deja el campo vacío.";
    var friendly = $("#pfx-friendly");
    friendly.placeholder = entry ? entry.cn : "Por defecto, el CN del certificado";
  }

  function refreshPfxEntries(selectId) {
    var sel = $("#pfx-entry");
    var current = selectId || sel.value;
    var list = pfxEntries();
    sel.textContent = "";
    list.forEach(function (e) {
      var label = e.cn + " · " + (KEY_LABELS[e.keyType] || e.keyType) + " · " + new Date(e.created).toLocaleDateString() +
        (e.cert ? " · con certificado" : "");
      sel.appendChild(el("option", { value: e.id, text: label }));
    });
    if (current && list.some(function (e) { return e.id === current; })) sel.value = current;
    if (!list.length && keySource() === "saved" && !selectId) {
      $all('#pfx-form input[name="keySource"]').forEach(function (r) { r.checked = r.value === "own"; });
    }
    updatePfxForm();
  }

  function openPfxFor(id) {
    setKeySource("saved");
    var cert = $("#pfx-cert"), chain = $("#pfx-chain");
    if (cert.dataset.auto === "1") cert.value = "";
    if (chain.dataset.auto === "1") chain.value = "";
    showTab("pfx");
    refreshPfxEntries(id);
    window.scrollTo(0, 0);
    var entry = selectedPfxEntry();
    (entry && entry.cert ? $("#pfx-pass") : $("#pfx-cert")).focus();
  }

  function randomPassword(length) {
    var chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!@#%+=";
    var out = "";
    var buf = new Uint32Array(length * 2);
    window.crypto.getRandomValues(buf);
    var limit = Math.floor(4294967296 / chars.length) * chars.length; // sin sesgo
    for (var i = 0; i < buf.length && out.length < length; i++) {
      if (buf[i] < limit) out += chars.charAt(buf[i] % chars.length);
    }
    return out.length === length ? out : randomPassword(length);
  }

  function clearPfxSecrets() {
    $("#pfx-pass").value = "";
    $("#pfx-pass2").value = "";
    $("#pfx-keypass").value = "";
  }

  function onCreatePfx(ev) {
    ev.preventDefault();
    var msg = $("#pfx-msg");
    var form = $("#pfx-form");
    $all(".invalid", form).forEach(function (i) { i.classList.remove("invalid"); });
    function fail(node, text) {
      if (node) { node.classList.add("invalid"); node.focus(); }
      setMsg(msg, text, "error");
    }

    var src = keySource();
    var entry = src === "saved" ? selectedPfxEntry() : null;
    var key = src === "saved" ? (entry && entry.key) : $("#pfx-key").value.trim();
    if (src === "saved" && !entry) return fail(null, "Elige una petición guardada o sube tu propia clave.");
    if (!key) return fail($("#pfx-key"), "Pega o sube la clave privada.");
    if (src === "own" && /CERTIFICATE/.test(key) && !/PRIVATE KEY/.test(key)) {
      return fail($("#pfx-key"), "En el campo de la clave has puesto un certificado.");
    }
    var certNode = $("#pfx-cert");
    var cert = certNode.value.trim();
    if (!cert) return fail(certNode, "Pega o sube el certificado que te emitió la CA.");
    if (/CERTIFICATE REQUEST/.test(cert)) return fail(certNode, "Has puesto el CSR: aquí va el certificado que te devolvió la CA a partir de él.");
    if (/PRIVATE KEY/.test(cert) || /PRIVATE KEY/.test($("#pfx-chain").value)) {
      return fail(certNode, "Hay una clave privada en el certificado o la cadena: ponla solo en el paso 1.");
    }
    if (keyIsEncrypted() && !$("#pfx-keypass").value) {
      return fail($("#pfx-keypass"), "La clave está cifrada: indica su contraseña.");
    }
    var pass = $("#pfx-pass"), pass2 = $("#pfx-pass2");
    if (pass.value.length < 4) return fail(pass, "La contraseña del PFX debe tener al menos 4 caracteres.");
    if (pass.value !== pass2.value) return fail(pass2, "Las contraseñas del PFX no coinciden.");

    var ext = $('#pfx-form input[name="pfxExt"]:checked').value;
    var payload = {
      key: key,
      keyPassword: $("#pfx-keypass").value,
      cert: cert,
      chain: $("#pfx-chain").value.trim() ? [$("#pfx-chain").value] : [],
      includeChain: $("#pfx-include-chain").checked,
      password: pass.value,
      profile: $("#pfx-profile").value,
      friendlyName: $("#pfx-friendly").value.trim(),
      extension: ext,
      name: entry ? entry.name : ""
    };
    var btn = $("#pfx-btn");
    btn.disabled = true;
    setMsg(msg, "Creando el PFX…", "busy");
    api("/api/pfx", payload).then(function (res) {
      payload = null;
      clearPfxSecrets();
      var bytes = b64decode(res.pfx);
      res.pfx = null;
      lastPfx = { bytes: bytes, filename: res.filename };
      savePfxBlob();
      var remembered = false;
      if (entry && $("#pfx-remember").checked) remembered = rememberCertificate(entry.id, res);
      renderPfxResult(res, remembered);
      setMsg(msg, "");
    }).catch(function (err) {
      setMsg(msg, err.message, "error");
    }).then(function () { btn.disabled = false; });
  }

  function savePfxBlob() {
    if (!lastPfx) return;
    saveBlob(new Blob([lastPfx.bytes], { type: "application/x-pkcs12" }), lastPfx.filename);
  }

  function rememberCertificate(id, res) {
    var list = loadEntries();
    var changed = false;
    list.forEach(function (e) {
      if (e.id === id) {
        e.cert = res.leafPem;
        e.chain = res.chainPem || "";
        e.certNotAfter = res.leaf.notAfter;
        changed = true;
      }
    });
    var ok = changed && saveEntries(list);
    if (ok) {
      updateSavedCount();
      var cert = $("#pfx-cert"), chain = $("#pfx-chain");
      cert.dataset.auto = "1";
      chain.dataset.auto = res.chainPem ? "1" : "";
    }
    return ok;
  }

  function renderPfxResult(res, remembered) {
    var out = $("#pfx-result");
    out.textContent = "";
    var errors = res.checks.filter(function (c) { return c.level === "error"; }).length;
    var warns = res.checks.filter(function (c) { return c.level === "warn"; }).length;
    var status = errors ? ["error", "Creado con errores"] : warns ? ["warn", "Creado con advertencias"] : ["ok", "Creado correctamente"];
    var again = el("button", { type: "button", className: "btn small primary", text: "Descargar " + res.filename, onclick: savePfxBlob });
    var forget = el("button", { type: "button", className: "btn small ghost", text: "Olvidar el PFX de la memoria",
      onclick: function () { lastPfx = null; out.hidden = true; out.textContent = ""; toast("PFX eliminado de la memoria de esta página"); } });

    var leaf = res.leaf;
    var validity = new Date(leaf.notBefore).toLocaleDateString() + " → " + new Date(leaf.notAfter).toLocaleDateString() +
      (leaf.expired ? " (caducado)" : leaf.notYetValid ? " (aún no válido)" : " (" + leaf.daysLeft + " días restantes)");
    var rows = [
      ["Fichero", res.filename + " (" + res.size + " bytes)"],
      ["Nombre descriptivo", res.friendlyName],
      ["Cifrado del PFX", res.profileLabel],
      ["Sujeto", leaf.subject],
      ["Emisor", leaf.issuer],
      ["Validez", validity],
      ["Clave", leaf.key],
      ["Número de serie", el("span", { className: "mono", text: leaf.serial })],
      ["Huella SHA-256", el("span", { className: "mono", text: leaf.sha256 })]
    ];
    if (leaf.sans.length) {
      rows.push(["SAN", el("div", { className: "tag-list" }, leaf.sans.map(function (v) { return el("span", { className: "tag", text: v }); }))]);
    }
    rows.push(["Cadena incluida", res.chain.length
      ? el("ol", { className: "chain" }, res.chain.map(function (c) {
        return el("li", null, [el("b", { text: c.cn }), " · emitido por " + c.issuerCn + " · hasta " +
          new Date(c.notAfter).toLocaleDateString() + (c.selfSigned ? " · raíz" : "")]);
      }))
      : "Ninguna"]);

    out.appendChild(el("div", { className: "card result" }, [
      el("div", { className: "result-head" }, [
        el("h2", { text: "PFX: " + res.filename }),
        el("span", { className: "pill " + status[0], text: status[1] })
      ]),
      el("div", { className: "download-bar" }, [again, forget,
        el("span", { className: "hint", text: "El PFX no se guarda: si cierras la página tendrás que crearlo de nuevo." })]),
      el("ul", { className: "checks" }, res.checks.map(function (c) { return el("li", { className: c.level, text: c.message }); })),
      remembered ? el("p", { className: "hint match", text: "El certificado y la cadena se han guardado junto a la petición en este navegador." }) : null,
      el("h3", { className: "sub", text: "Contenido del PFX" }),
      kvTable(rows)
    ]));
    out.hidden = false;
    out.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function attachFileInput(input, target, kind, append) {
    input.addEventListener("change", function () {
      var files = Array.prototype.slice.call(input.files || []);
      input.value = "";
      if (!files.length) return;
      Promise.all(files.map(function (f) { return readCryptoFile(f, kind); })).then(function (texts) {
        var area = $(target);
        var joined = texts.join("");
        area.value = append && area.value.trim() ? area.value.trim() + "\n" + joined : joined;
        area.dataset.auto = "";
        setMsg($("#pfx-msg"), "");
        updatePfxForm();
      }).catch(function (err) { setMsg($("#pfx-msg"), err.message, "error"); });
    });
  }

  function initPfx() {
    var form = $("#pfx-form");
    form.addEventListener("submit", onCreatePfx);
    $all('#pfx-form input[name="keySource"]').forEach(function (r) { r.addEventListener("change", updatePfxForm); });
    $("#pfx-entry").addEventListener("change", updatePfxForm);
    $("#pfx-key").addEventListener("input", updatePfxForm);
    ["#pfx-cert", "#pfx-chain"].forEach(function (sel) {
      $(sel).addEventListener("input", function () { $(sel).dataset.auto = ""; });
    });
    attachFileInput($("#pfx-key-file"), "#pfx-key", "key", false);
    attachFileInput($("#pfx-cert-file"), "#pfx-cert", "cert", false);
    attachFileInput($("#pfx-chain-file"), "#pfx-chain", "cert", true);
    $("#pfx-showpass").addEventListener("change", function (e) {
      ["#pfx-pass", "#pfx-pass2", "#pfx-keypass"].forEach(function (sel) { $(sel).type = e.target.checked ? "text" : "password"; });
    });
    $("#pfx-genpass").addEventListener("click", function () {
      var pw = randomPassword(20);
      $("#pfx-pass").value = pw;
      $("#pfx-pass2").value = pw;
      $("#pfx-showpass").checked = true;
      ["#pfx-pass", "#pfx-pass2", "#pfx-keypass"].forEach(function (sel) { $(sel).type = "text"; });
      toast("Contraseña generada en tu navegador: cópiala y guárdala antes de crear el PFX");
    });
    $("#pfx-copypass").addEventListener("click", function () {
      if (!$("#pfx-pass").value) { toast("No hay contraseña que copiar"); return; }
      copyText($("#pfx-pass").value);
    });
    $("#pfx-reset").addEventListener("click", function () {
      clearPfxSecrets();
      ["#pfx-key", "#pfx-cert", "#pfx-chain", "#pfx-friendly"].forEach(function (sel) { $(sel).value = ""; $(sel).dataset.auto = ""; });
      $("#pfx-result").hidden = true;
      $("#pfx-result").textContent = "";
      lastPfx = null;
      setMsg($("#pfx-msg"), "");
      updatePfxForm();
    });
    refreshPfxEntries();
  }

  /* ------------------------------------------------------------------ */
  /* Guardados                                                          */
  /* ------------------------------------------------------------------ */
  function updateSavedCount() {
    $("#saved-count").textContent = String(loadEntries().length);
    if ($("#pfx-entry")) refreshPfxEntries();
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
        el("span", { className: "saved-name" }, [entry.cn + " ",
          entry.cert ? el("span", { className: "pill ok", text: "Con certificado" }) : el("span", { className: "pill neutral", text: "Pendiente de certificado" })]),
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
        el("button", { type: "button", className: "btn small ghost", text: "Crear PFX",
          onclick: function () { openPfxFor(entry.id); } }),
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
    $("#res-pfx").addEventListener("click", function () { if (lastEntry) openPfxFor(lastEntry.id); });
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
      if (e.key === STORE_KEY) {
        updateSavedCount();
        if (!$("#tab-saved").hidden) renderSaved();
        refreshPfxEntries();
      }
    });

    initPfx();
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
    if (hash === "decode" || hash === "pfx" || hash === "saved" || hash === "info") showTab(hash);
    else if (hash.indexOf("info-") === 0 && document.getElementById(hash)) {
      showTab("info");
      history.replaceState(null, "", "#" + hash);
      document.getElementById(hash).scrollIntoView();
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
