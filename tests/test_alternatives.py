"""One exact version instead of a held one (guard/alternatives.py) and the next-step text built from it (output/render.py)."""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "guard"))

import alternatives as A  # noqa: E402
from output import render as M  # noqa: E402

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def release(hours_ago, yanked=False):
    return [{"upload_time_iso_8601": (NOW - timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z"), "yanked": yanked}]


META = {"releases": {
    "2.31.0": release(9000), "2.32.3": release(4000), "2.32.4": release(3000, yanked=True), "2.33.0": release(2000),
    "2.33.1": release(500), "2.34.0rc1": release(100), "2.34.0": release(3)}}


class PickPyPI(unittest.TestCase):
    def pick(self, current, fix, dirty=()):
        seen = {}

        def clean(eco, name, versions):
            seen["asked"] = list(versions)
            return [v for v in versions if v not in dirty]
        with mock.patch.object(A, "_osv_clean", side_effect=clean):
            return A.pypi("requests", META, current, fix, 24, now=NOW), seen.get("asked")

    def test_fix_is_the_newest_clean_version_from_the_fixed_one_up(self):
        got, asked = self.pick("2.31.0", "2.32.4")
        self.assertEqual(got, "2.33.1")
        self.assertEqual(asked, ["2.33.1", "2.33.0"])         # 2.32.4 yanked, no pre-release, nothing under a day old (2.34.0)

    def test_a_candidate_with_an_osv_record_is_skipped(self):
        self.assertEqual(self.pick("2.31.0", "2.32.4", dirty={"2.33.1"})[0], "2.33.0")
        self.assertIsNone(self.pick("2.31.0", "2.32.4", dirty={"2.33.0", "2.33.1"})[0])

    def test_without_a_fix_the_newest_earlier_version(self):
        got, asked = self.pick("2.34.0", None)              # a release under a day old, or a hijacked one
        self.assertEqual(got, "2.33.1")
        self.assertEqual(asked[:3], ["2.33.1", "2.33.0", "2.32.3"])

    def test_osv_unreachable_names_nothing(self):
        with mock.patch.object(A, "_osv_clean", side_effect=OSError("down")):
            self.assertIsNone(A.pypi("requests", META, "2.31.0", "2.32.4", 24, now=NOW))


class PickNpm(unittest.TestCase):
    def test_npm_uses_publish_times_and_skips_deprecated(self):
        meta = {"versions": {"1.0.0": {}, "1.1.0": {"deprecated": "bad"}, "1.2.0": {}, "2.0.0": {}}}
        times = {"1.0.0": "2025-01-01T00:00:00Z", "1.1.0": "2025-02-01T00:00:00Z", "1.2.0": "2025-03-01T00:00:00Z",
                 "2.0.0": (NOW - timedelta(hours=2)).isoformat()}
        with mock.patch.object(A, "_osv_clean", side_effect=lambda e, n, vs: list(vs)):
            self.assertEqual(A.npm("x", meta, times, "1.0.0", "1.1.0", 24, now=NOW), "1.2.0")
            self.assertEqual(A.npm("x", meta, times, "2.0.0", None, 24, now=NOW), "1.2.0")
            self.assertIsNone(A.npm("x", meta, None, "2.0.0", None, 24, now=NOW))


def rec(name, version, verdict, **adv):
    r = {"package": name, "version": version, "verdict": verdict, "evidence": [], "advice": adv}
    return r


class NextStep(unittest.TestCase):
    HELD = [rec("ctx", "0.2.2", "BLOCK"), rec("requests", "2.32.3", "NEEDS_HUMAN_REVIEW", ids=["GHSA-x"], fix_version="2.33.0",
                                              safe_version="2.33.0")]
    ALL = HELD + [rec("rich", "13.9.4", "ALLOW"), rec("click", "8.1.7", "ALLOW"), {**rec("idna", "3.10", "ALLOW"), "via": "requests → idna"}]

    def test_every_held_package_gets_one_change_and_the_passed_ones_are_named(self):
        text = M.next_step(self.HELD, self.ALL)
        self.assertIn("- ctx 0.2.2: leave it out", text)
        self.assertIn("- requests 2.32.3: use `requests==2.33.0` instead", text)
        self.assertIn("Passed: rich 13.9.4, click 8.1.7", text)
        self.assertNotIn("idna", text)                          # dependencies are not listed as passed

    def test_user_question_covers_every_held_package(self):
        q = M.user_question(self.HELD)
        self.assertIn("without ctx", q)
        self.assertIn("requests==2.33.0 instead of requests 2.32.3", q)

    def test_user_mode_block_asks_about_all_of_them(self):
        r = M.claude_reason("report", [("requests", "requests>=2.33.0")], ["known_malicious"], self.HELD, self.ALL)
        self.assertIn("without ctx", r)
        self.assertIn("Passed: rich 13.9.4", r)

    def test_review_without_another_version_is_left_to_decide(self):
        ml = rec("pkg", "1.0", "NEEDS_HUMAN_REVIEW")
        self.assertEqual(M._change(ml)[0], "decide")
        typo = rec("reqeusts", "1.0", "NEEDS_HUMAN_REVIEW", typosquat_of="requests")
        kind, text = M._change(typo)
        self.assertEqual(kind, "decide")
        self.assertIn("`requests`", text)

    def test_a_dependency_is_pinned_in_the_same_install(self):
        dep = {**rec("urllib3", "2.6.3", "NEEDS_HUMAN_REVIEW", ids=["G"], fix_version="2.8.0", safe_version="2.8.0"), "via": "requests → urllib3"}
        kind, text = M._change(dep)
        self.assertEqual(kind, "add")
        self.assertIn("add `urllib3==2.8.0` to the same install", text)

    def test_the_person_notice_lists_what_passed(self):
        n = M.person_notice("BLOCK", self.HELD, None, self.ALL)
        self.assertIn("Passed: rich 13.9.4, click 8.1.7", n)


if __name__ == "__main__":
    unittest.main()
