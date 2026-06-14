// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors
//
// Documentation version switcher. scripts/pages/build-site.sh injects a <script>
// tag pointing here into every page of every published version (so even tags
// whose sources predate this file get it) and copies this file to the Pages
// root. At runtime it reads versions.json, renders a <select>, and on change
// navigates to the same page within the chosen version (a missing page lands on
// that version's 404, which links home). It mounts into mdBook's top bar when
// present, else as a floating control, and stays hidden unless >1 version exists.
(function () {
  "use strict";

  var script =
    document.currentScript || document.querySelector("script[data-rsk-base]");
  var base = (script && script.getAttribute("data-rsk-base")) || "/";

  function relPath() {
    return location.pathname.indexOf(base) === 0
      ? location.pathname.slice(base.length)
      : location.pathname.replace(/^\/+/, "");
  }

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  fetch(base + "versions.json", { cache: "no-cache" })
    .then(function (r) {
      return r.ok ? r.json() : null;
    })
    .then(function (data) {
      if (data && data.versions && data.versions.length > 1) {
        ready(function () {
          mount(data.versions);
        });
      }
    })
    .catch(function () {});

  // The version whose path prefixes the current URL; main (root) is the fallback.
  function currentVersion(versions) {
    var path = relPath();
    var match = null;
    versions.forEach(function (v) {
      if (!v.path) return;
      var vp = v.path.replace(/\/+$/, "");
      if (path === vp || path.indexOf(vp + "/") === 0) {
        if (!match || vp.length > match.path.length) match = v;
      }
    });
    return match || versions[0];
  }

  function styles() {
    if (document.getElementById("rsk-version-style")) return;
    var s = document.createElement("style");
    s.id = "rsk-version-style";
    s.textContent =
      ".rsk-version{display:flex;align-items:center;margin:0 .4rem}" +
      ".rsk-version select{font:inherit;color:inherit;background:transparent;" +
      "border:1px solid currentColor;border-radius:4px;padding:2px 6px;cursor:pointer;opacity:.85}" +
      ".rsk-version select:hover{opacity:1}" +
      ".rsk-version-floating{position:fixed;bottom:1rem;left:1rem;z-index:1000;padding:6px 8px;" +
      "border-radius:6px;background:var(--bg,#fff);color:var(--fg,#000);box-shadow:0 1px 6px rgba(0,0,0,.35)}";
    document.head.appendChild(s);
  }

  function mount(versions) {
    var cur = currentVersion(versions);
    var vp = cur.path.replace(/\/+$/, "");
    var inVersion = vp
      ? relPath().slice(vp.length).replace(/^\/+/, "")
      : relPath();

    var sel = document.createElement("select");
    sel.setAttribute("aria-label", "Documentation version");
    versions.forEach(function (v) {
      var o = document.createElement("option");
      o.value = base + v.path + inVersion; // same page in the chosen version
      o.textContent = v.name;
      if (v === cur) o.selected = true;
      sel.appendChild(o);
    });
    sel.addEventListener("change", function () {
      location.href = sel.value;
    });

    styles();
    var bar = document.querySelector(".menu-bar .right-buttons");
    var box = document.createElement("div");
    box.className = bar ? "rsk-version" : "rsk-version rsk-version-floating";
    box.appendChild(sel);
    if (bar) {
      bar.insertBefore(box, bar.firstChild);
    } else {
      document.body.appendChild(box);
    }
  }
})();
