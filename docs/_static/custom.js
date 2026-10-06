/*
 * PEAT documentation: small accessibility fixes for things the Furo theme's templates
 * don't expose as options. Checked by scripts/docs_a11y.py (axe-core).
 */
(function () {
  "use strict";

  /* Furo renders two <aside> (complementary) landmarks; each needs a unique name. */
  function labelLandmarks() {
    var sidebar = document.querySelector("aside.sidebar-drawer");
    if (sidebar && !sidebar.hasAttribute("aria-label")) {
      sidebar.setAttribute("aria-label", "Site navigation");
    }
    var toc = document.querySelector("aside.toc-drawer");
    if (toc && !toc.hasAttribute("aria-label")) {
      toc.setAttribute("aria-label", "Page contents");
    }
    /* The "view/edit this page" links sit outside of every landmark. */
    var actions = document.querySelector("div.content-icon-container");
    if (actions && !actions.hasAttribute("role")) {
      actions.setAttribute("role", "navigation");
      actions.setAttribute("aria-label", "Page actions");
    }
  }

  /* Code blocks that overflow scroll horizontally, so they must be keyboard focusable. */
  function makeScrollableCodeFocusable() {
    document.querySelectorAll("div.highlight pre, pre.literal-block").forEach(function (pre) {
      if (pre.scrollWidth > pre.clientWidth) {
        pre.setAttribute("tabindex", "0");
      } else if (pre.getAttribute("tabindex") === "0") {
        pre.removeAttribute("tabindex");
      }
    });
  }

  function run() {
    labelLandmarks();
    makeScrollableCodeFocusable();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run);
  } else {
    run();
  }

  var resizeTimer;
  window.addEventListener("resize", function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(makeScrollableCodeFocusable, 150);
  });
})();
