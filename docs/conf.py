# Configuration file for the Sphinx documentation builder.
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------
import importlib.metadata
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

docs_dir = Path(__file__).resolve().parent  # docs/
pardir = docs_dir.parent  # repository root
sys.path.insert(0, str(pardir))
sys.path.insert(0, str(docs_dir / "_ext"))  # local Sphinx extensions (peat_docs)
sys.setrecursionlimit(1500)


def _clean_read(pth: Path) -> list:
    return [x.strip() for x in pth.read_text().splitlines() if x]


def get_git_version() -> str:
    """
    Determine the version string shown in the docs (e.g. "v2026.9.2").

    The release workflow stamps the version into the environment variable
    ``PDM_BUILD_SCM_VERSION`` (the same variable pdm-backend uses to override
    the SCM-derived package version) because it builds the docs *before* the
    release tag exists. Otherwise, fall back to the latest reachable git tag,
    then to the version of the installed PEAT package (e.g. when building from
    a source distribution without Git history).

    This string is only used by Sphinx for display (|version| and |release|),
    it is not validated against PEP 440, so the final "dev" fallback is safe.
    """
    version = os.environ.get("PDM_BUILD_SCM_VERSION", "").strip()
    if not version:
        try:
            # Run the git command to get the latest tag
            version = subprocess.check_output(
                args=["git", "describe", "--tags", "--abbrev=0"],
                encoding="utf-8",
                stderr=subprocess.DEVNULL,
            ).strip()
        except Exception:
            # Git is not available or no tags exist
            version = ""
    if not version:
        try:
            version = importlib.metadata.version("PEAT").split(".dev")[0]
        except Exception:
            return "dev"  # PEAT isn't installed either
    # Tags are "vYYYY.M.D"; ensure the prefix is present regardless of source
    return version if version.startswith("v") else f"v{version}"


# -- Extensions --------------------------------------------------------------
# autodoc-pydantic 1.x is required because PEAT pins pydantic 1.x, but it still imports
# "stringify" from sphinx.util.typing, an alias that was removed in Sphinx 8.0
# (renamed to "stringify_annotation" in Sphinx 6.1). Restore the alias so the extension
# imports under current Sphinx versions. Remove once PEAT moves to pydantic 2 and
# autodoc-pydantic 2.x.
import sphinx.util.typing as _sphinx_typing  # noqa: E402

if not hasattr(_sphinx_typing, "stringify"):
    _sphinx_typing.stringify = _sphinx_typing.stringify_annotation

extensions = [
    "sphinx.ext.napoleon",  # Google-style docstrings (built-in)
    "sphinx.ext.viewcode",  # Links to source code (built-in)
    "sphinx.ext.autodoc",  # Auto-generated source code API docs (built-in)
    "sphinx.ext.todo",  # Blocks of TODOs for use in module documentation
    "sphinx.ext.intersphinx",  # External code documentation linkages
    # NOTE: sphinx.ext.napoleon MUST be loaded before sphinx_autodoc_typehints
    "sphinx_autodoc_typehints",  # Use Python type annotations for types in docs
    "sphinx_automodapi.automodapi",  # NOTE: requires Graphviz
    "sphinx_copybutton",  # Adds a copy to clipboard button to code blocks
    "sphinx_argparse_cli",  # Document CLI arguments
    "sphinxcontrib.autodoc_pydantic",  # Document the Pydantic data models
    "sphinx_design",  # Tabs, cards, grids, and dropdowns
    "sphinx_reredirects",  # Redirects from old page locations to new ones
    "peat_docs",  # PEAT-specific directives (docs/_ext/peat_docs.py)
]

autodoc_pydantic_model_show_config_summary = False
autodoc_pydantic_model_show_config_member = False
autodoc_pydantic_model_signature_prefix = " "
autodoc_pydantic_field_show_default = False
autodoc_pydantic_field_signature_prefix = " "
autodoc_pydantic_model_show_json = True
# NOTE (cegoes, 06/03/2022 and 06/16/2023)
# autodoc_pydantic >= 1.7.0 errors out when "bysource" is used for list order
# Should be fixed in 1.9.0: https://github.com/mansenfranzen/autodoc_pydantic/issues/137
# autodoc_pydantic_model_summary_list_order = "bysource"


# -- Project metadata --------------------------------------------------------
project = "PEAT"
language = "en"
date = datetime.now().strftime("%m/%d/%Y")
copyright = f"2016 - {datetime.now().year}, Sandia National Laboratories"
author = "Sandia National Laboratories"
authors = sorted(_clean_read(Path(pardir, "AUTHORS")))
version = get_git_version()
release = version


# -- General configuration ---------------------------------------------------
source_suffix = [".rst"]
source_encoding = "utf-8"
needs_sphinx = "7.0.0"

# Add any paths that contain templates here, relative to this directory
templates_path = ["_templates"]

# The “master” document, contains the root toctree directive
master_doc = "index"
exclude_patterns = [
    "_build",
    "_built_docs",
    "_ext",
    "_static",
    "_templates",
    ".doctrees",
    "Thumbs.db",
    ".DS_Store",
    ".vscode",
    ".idea",
    ".vagrant",
    # Generated by "pdm run dep-doc" and pulled in with ".. include::",
    # it is not a standalone page
    "developer/dependencies_table.rst",
]
todo_include_todos = False

# Code styles: https://pygments.org/docs/styles/
# NOTE: Furo sets accessible, high-contrast Pygments styles for light and dark
# mode ("a11y-light" and "a11y-dark"), so this is only used by non-HTML builders.
# Both styles come from the "accessible-pygments" package and meet WCAG AA contrast on
# their own backgrounds. (Styles that set per-token backgrounds, such as "colorful", break
# in Furo's dark mode: the light background stays while the dark text colors apply.)
pygments_style = "a11y-light"
pygments_dark_style = "a11y-dark"

# Treat these as warnings (and therefore as errors in CI, which builds with -W)
nitpicky = False

# Intersphinx mapping for external documentation
intersphinx_mapping = {
    # Latest version of the mapping can be pulled from python.org:
    # https://docs.python.org/3/objects.inv
    "python": ("https://docs.python.org/3", "python3-docs-inventory.inv")
}


# Make :manpage directive work on HTML output
# https://www.sphinx-doc.org/en/master/usage/configuration.html?#confval-manpages_url
manpages_url = "https://manpages.debian.org/{path}"


# Napoleon settings (lets us use Google-style docstrings)
# https://www.sphinx-doc.org/en/master/usage/extensions/napoleon.html
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_attr_annotations = True


# sphinx-autodoc-typehints settings
# https://github.com/agronholm/sphinx-autodoc-typehints
always_document_param_types = False


# autodoc
# https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html
autodoc_default_options = {
    "member-order": "bysource",
    "undoc-members": True,
    # Include docs from members even if they're not included in '__all__'
    "ignore-module-all": True,
}
add_module_names = False


# automodapi
# https://sphinx-automodapi.readthedocs.io/en/latest/
automodapi_toctreedirnm = "automodapi_tmp"

smartquotes_action = "qe"

# sphinx-copybutton: don't copy the prompts or output lines from console examples
# https://sphinx-copybutton.readthedocs.io/en/latest/use.html
copybutton_prompt_text = r">>> |\.\.\. |\$ |PS> |# "
copybutton_prompt_is_regexp = True
copybutton_line_continuation_character = "\\"


# -- Redirects from old page locations ----------------------------------------
# The documentation was reorganized into sections (getting_started/, user_guide/,
# reference/, developer/, design/, contributing/). These client-side redirects keep
# links to the old flat page URLs working (e.g. README links and bookmarks).
# https://documatt.com/sphinx-reredirects/
redirects = {
    "introduction": "getting_started/introduction.html",
    "system_requirements": "getting_started/requirements.html",
    "install": "getting_started/install.html",
    "configure": "user_guide/configure.html",
    "operate": "user_guide/index.html",
    "reference_documents": "reference/index.html",
    "module_documents": "reference/index.html",
    "database_schema": "reference/database_schema.html",
    "sel": "reference/devices/sel.html",
    "siemens": "reference/devices/siemens.html",
    "openplc": "reference/devices/openplc.html",
    "mysql": "reference/devices/mysql.html",
    "design_documents": "design/index.html",
    "developer_reference": "developer/index.html",
    "module_developer_guide": "developer/module_developer_guide.html",
    "data_model": "developer/data_model.html",
    "peat_api": "developer/peat_api.html",
    "device_api": "developer/device_api.html",
    "device_modules": "developer/device_modules.html",
    "general_apis": "developer/general_apis.html",
    "heat_api": "developer/heat_api.html",
    "elastic_implementation": "developer/elastic_implementation.html",
    "python_examples": "developer/python_examples.html",
    "dependencies": "developer/dependencies.html",
    "contributing": "contributing/index.html",
    "development_infrastructure": "contributing/building.html",
}


# -- Link checking (sphinx-build -b linkcheck) --------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-the-linkcheck-builder
linkcheck_timeout = 30
linkcheck_retries = 2
linkcheck_workers = 8
linkcheck_anchors = False  # Many sites render anchors with JavaScript
linkcheck_ignore = [
    # Links to PEAT's own published documentation (CONTRIBUTING.rst, README): pages added
    # by a pull request don't exist on the live site until it is merged and deployed, and
    # Sphinx already checks the internal references.
    r"https://sandialabs\.github\.io/PEAT/.*",
    # Placeholder URLs in examples
    r"https?://localhost.*",
    r"https?://127\.0\.0\.1.*",
    r"https?://.*user:pass.*",
    r"https?://hostname-or-ip.*",
    r"https?://example\.com.*",
    r"https?://heat-elastic.*",
    r"https?://results-elastic.*",
    # These sites reject automated requests (HTTP 403) but work in a browser
    r"https://stackoverflow\.com/.*",
    r"https://askubuntu\.com/.*",
    r"https://superuser\.com/.*",
    r"https://serverfault\.com/.*",
    r"https://dev\.mysql\.com/.*",
    r"https://realpython\.com/.*",
    r"https://(www\.)?cisco\.com/.*",
    r"https://access\.redhat\.com/.*",
    r"https://docs\.redhat\.com/.*",
    r"https://(www\.)?rockwellautomation\.com/.*",
    r"https://literature\.rockwellautomation\.com/.*",
    r"https://(www\.)?se\.com/.*",
    r"https://selinc\.com/.*",
    r"https://(www\.)?siemens\.com/.*",
    r"https://(www\.)?gevernova\.com/.*",
    r"https://support\.woodward\.com/.*",
    r"https://(www\.)?linkedin\.com/.*",
]
# GitHub returns 403 for the default python-requests user agent in some networks
linkcheck_request_headers = {
    "https://github.com/": {
        "User-Agent": "Mozilla/5.0 (compatible; PEAT-docs-linkcheck; +https://sandialabs.github.io/PEAT/)",
        "Accept": "text/html,application/xhtml+xml",
    },
    "*": {
        "User-Agent": "Mozilla/5.0 (compatible; PEAT-docs-linkcheck; +https://sandialabs.github.io/PEAT/)",
    },
}
# Redirects that are expected and should not be reported
linkcheck_allowed_redirects = {
    r"https://docs\.python\.org/3/.*": r"https://docs\.python\.org/3/.*",
    r"https://www\.elastic\.co/guide/.*": r"https://www\.elastic\.co/docs/.*",
    r"https://pdm-project\.org.*": r"https://pdm-project\.org/.*",
    r"https://towncrier\.readthedocs\.io/": r"https://towncrier\.readthedocs\.io/en/stable/",
    r"https://pyinstaller\.org/en/stable/.*": r"https://pyinstaller\.org/en/.*",
    r"https://code\.visualstudio\.com/docs/.*": r"https://code\.visualstudio\.com/docs/.*",
    r"https://docs\.docker\.com/.*": r"https://docs\.docker\.com/.*",
    r"https://learn\.microsoft\.com/.*": r"https://learn\.microsoft\.com/.*",
    r"https://(www\.)?wireshark\.org/.*": r"https://(www\.)?wireshark\.org/.*",
    r"https://github\.com/.*": r"https://github\.com/.*",
}


# -- Output configurations  -------------------------------------------------

# Configuration for HTML output
#   https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output
# HTML theme: Furo (https://pradyunsg.me/furo/)
html_theme = "furo"
html_title = "PEAT Documentation"
html_short_title = "PEAT"
html_favicon = "favicon.ico"
html_logo = "PEAT_Logo.png"
html_last_updated_fmt = ""
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_js_files = ["custom.js"]  # Small accessibility fixes, see the file
html_copy_source = False  # Don't ship the .rst sources (the "view" button links to GitHub)
html_show_sourcelink = False

# PEAT brand colors derived from the logo. The light-mode teal is darkened so that
# link text has at least a 4.5:1 contrast ratio against white (WCAG 2.1 AA), and the
# dark-mode cyan is lightened for the same reason against Furo's dark backgrounds.
html_theme_options = {
    "top_of_page_buttons": ["view", "edit"],
    "source_repository": "https://github.com/sandialabs/PEAT/",
    "source_branch": "main",
    "source_directory": "docs/",
    "light_css_variables": {
        "color-brand-primary": "#0b7285",
        "color-brand-content": "#0b7285",
        "color-brand-visited": "#6a3fa0",
        "color-sidebar-brand-text": "#0b7285",
    },
    "dark_css_variables": {
        "color-brand-primary": "#4cc9e8",
        "color-brand-content": "#4cc9e8",
        "color-brand-visited": "#c49bf2",
        "color-sidebar-brand-text": "#4cc9e8",
    },
    "footer_icons": [
        {
            "name": "GitHub",
            "url": "https://github.com/sandialabs/PEAT",
            "html": """
                <svg stroke="currentColor" fill="currentColor" stroke-width="0" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
                    <path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path>
                </svg>
            """,
            "class": "",
        },
    ],
}


# Build command line interface (CLI) manpage (e.g. "man peat.1")
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-manual-page-output
# The man builder inlines every page in the document's toctree, so the man page
# contains the entire User guide (CLI basics, each command, output, containers, ...).
man_pages = [
    (
        "user_guide/index",  # docs/user_guide/index.rst
        "peat",
        "Process Extraction and Analysis Tool",
        authors,
        1,
    ),
]
man_show_urls = True


# TODO: build PDF using rinohtype (https://github.com/brechtm/rinohtype)
# https://www.mos6581.org/rinohtype/master/sphinx.html#sphinx-builder
# rinoh_documents = [{
#     "doc": "index",
#     "target": "peat",  # PDF filename
#     # TODO: add logo in PDF
# }]
