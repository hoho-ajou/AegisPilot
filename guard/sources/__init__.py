"""
AegisPilot - where scanned code comes from, one module per source.

A source only gets files onto disk without running anything; what is done with them (rules, verdict) is the same for
every source (scan_engine.scan_files). PyPI, the original source, still lives in scan_engine.

  npm        registry.npmjs.org packages (tarball) and their lifecycle scripts
  repo       a git repository (GitHub archive, or a shallow sparse clone) - plugins
  bundle     a folder already on disk (a skill, a plugin from a local marketplace, a hook script)
"""
