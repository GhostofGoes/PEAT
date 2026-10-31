// PEAT HTML report: progressive enhancement (sortable and filterable tables,
// expand/collapse all, expanded sections when printing). ASCII only (it's
// hashed for the CSP). The report is complete without it. Reads the page
// only through the DOM (textContent), never by parsing HTML strings.
(function () {
  "use strict";
  var doc = document;

  function each(list, fn) { Array.prototype.forEach.call(list, fn); }

  function cellKey(row, idx) {
    var cell = row.cells[idx];
    if (!cell) { return ""; }
    var v = cell.getAttribute("data-sort");
    return v !== null ? v : cell.textContent.trim().toLowerCase();
  }

  function compare(a, b) {
    var na = Number(a), nb = Number(b);
    if (a !== "" && b !== "" && !isNaN(na) && !isNaN(nb)) { return na - nb; }
    return a < b ? -1 : (a > b ? 1 : 0);
  }

  function makeSortable(table) {
    var head = table.tHead;
    if (!head || !table.tBodies.length) { return; }
    var headers = head.rows[0].cells;
    each(headers, function (th, idx) {
      if (th.hasAttribute("data-nosort")) { return; }
      var btn = doc.createElement("button");
      btn.type = "button";
      btn.className = "sort";
      while (th.firstChild) { btn.appendChild(th.firstChild); }
      var icon = doc.createElement("span");
      icon.setAttribute("aria-hidden", "true");
      icon.className = "sort-icon";
      btn.appendChild(icon);
      th.appendChild(btn);
      btn.addEventListener("click", function () {
        var asc = th.getAttribute("aria-sort") !== "ascending";
        each(headers, function (o) { o.removeAttribute("aria-sort"); });
        th.setAttribute("aria-sort", asc ? "ascending" : "descending");
        var body = table.tBodies[0];
        var rows = Array.prototype.slice.call(body.rows);
        rows.sort(function (r1, r2) {
          var c = compare(cellKey(r1, idx), cellKey(r2, idx));
          return asc ? c : -c;
        });
        rows.forEach(function (r) { body.appendChild(r); });
      });
    });
  }

  function makeFilterable(table) {
    var body = table.tBodies[0];
    if (!body || body.rows.length < 6) { return; }
    var wrap = doc.createElement("div");
    wrap.className = "table-filter no-print";
    var label = doc.createElement("label");
    var input = doc.createElement("input");
    input.type = "search";
    label.textContent = "Filter rows";
    label.appendChild(input);
    var status = doc.createElement("span");
    status.className = "filter-status";
    status.setAttribute("aria-live", "polite");
    wrap.appendChild(label);
    wrap.appendChild(status);
    table.parentNode.insertBefore(wrap, table);
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase(), shown = 0;
      each(body.rows, function (r) {
        var hit = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
        r.hidden = !hit;
        if (hit) { shown++; }
      });
      status.textContent = q ? "Showing " + shown + " of " + body.rows.length + " rows" : "";
    });
  }

  function setAllDetails(open) {
    each(doc.querySelectorAll("details"), function (d) { d.open = open; });
  }

  function openTarget() {
    var id = window.location.hash.slice(1);
    var el = id ? doc.getElementById(id) : null;
    while (el) {
      if (el.tagName === "DETAILS") { el.open = true; }
      el = el.parentElement;
    }
  }

  doc.addEventListener("DOMContentLoaded", function () {
    each(doc.querySelectorAll("table.sortable"), makeSortable);
    each(doc.querySelectorAll("table.filterable"), makeFilterable);
    each(doc.querySelectorAll("[data-details]"), function (btn) {
      btn.hidden = false;
      btn.addEventListener("click", function () {
        setAllDetails(btn.getAttribute("data-details") === "open");
      });
    });
    openTarget();
  });
  window.addEventListener("hashchange", openTarget);

  var saved = null;
  window.addEventListener("beforeprint", function () {
    saved = Array.prototype.map.call(doc.querySelectorAll("details"), function (d) { return d.open; });
    setAllDetails(true);
  });
  window.addEventListener("afterprint", function () {
    if (!saved) { return; }
    each(doc.querySelectorAll("details"), function (d, i) { d.open = saved[i]; });
    saved = null;
  });
}());
