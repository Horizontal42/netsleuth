.. Netsleuth documentation master file, created by
   sphinx-quickstart on Tue Aug 12 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Netsleuth Documentation
========================

**Cross-platform CLI for deep network diagnostics**

Netsleuth is a powerful command-line tool for comprehensive network analysis,
providing insights into ISP/VPN/ASN identity, latency, routing paths, and bandwidth.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   api/modules

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Quick Start
-----------

Install Netsleuth::

   pip install netsleuth

Basic usage::

   netsleuth diagnose example.com
   netsleuth trace google.com
   netsleuth speedtest

For more information, see the :doc:`API Reference <api/modules>`.

License
-------

This project is licensed under the PolyForm Noncommercial License 1.0.0.
