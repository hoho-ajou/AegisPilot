# Bundled third-party code

| Package | Version | Source | License |
| --- | --- | --- | --- |
| packaging | 24.2 | `packaging-24.2-py3-none-any.whl` from PyPI, SHA-256 `09abb1bccd265c01f4a3aa3f7a7db064b36514d2cba19a2f694fe6150451a759` | Apache-2.0 or BSD-2-Clause (`packaging/LICENSE*`) |

The files are unchanged from the wheel. AegisPilot imports them as `_vendor.packaging` so that version ranges and
environment markers are evaluated the same way whatever Python packages are installed.
