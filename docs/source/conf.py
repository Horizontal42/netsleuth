"""Sphinx documentation configuration for Netsleuth."""

import sys
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Project information
project = "Netsleuth"
copyright = "2024, netsleuth contributors"
author = "netsleuth contributors"
release = "0.1.0"

# General configuration
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.coverage",
    "sphinx_autodoc_typehints",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# HTML theme
html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

# Autodoc configuration
autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
    "special-members": "__init__",
}

autodoc_member_order = "bysource"

# Napoleon configuration
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True

# Intersphinx configuration
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "typer": ("https://typer.tiangolo.com", None),
    "rich": ("https://rich.readthedocs.io/en/latest", None),
    "httpx": ("https://www.python-httpx.org", None),
    "pydantic": ("https://docs.pydantic.dev/latest", None),
}

# Typehints configuration
set_type_checking_flag = True
typehints_fully_qualified = False
always_document_param_types = True

# Coverage configuration
coverage_write_headline = False
