"""ScanMind AI - a security scanner that finds the vulnerabilities AI website
builders most commonly ship: leaked API keys, weak forms, missing security
headers and accidentally deployed files.

Two scan modes:

* ``scanmind scan https://example.com``  - crawl and audit a live site
* ``scanmind scan ./generated-site``     - static audit of files an AI site
  generator produced, before they get deployed

Only scan websites you own or are explicitly authorized to test.
"""

__version__ = "0.1.0"
