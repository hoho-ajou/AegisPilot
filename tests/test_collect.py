"""Offline tests for the collection helpers."""
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "guard"))
import collect as C


class CollectTests(unittest.TestCase):
    def test_markers_and_extras_filtered(self):
        got = C.parse_requires(["urllib3<3,>=1.21.1", "PySocks>=1.5.6; extra == 'socks'", "colorama; sys_platform=='win32'",
                                "Idna>=2.5", "typing_extensions>=4; python_version<'3.8'"])
        self.assertEqual([d["name"] for d in got], ["idna", "urllib3"])

    def test_names_normalized_and_deduplicated(self):
        got = C.parse_requires(["Foo_Bar>=1", "foo-bar<2"])
        self.assertEqual([d["name"] for d in got], ["foo-bar"])

    def test_unparsable_entry_kept_by_name(self):
        self.assertEqual([d["name"] for d in C.parse_requires(["weird name ((("])], ["weird"])

    def test_none_is_empty(self):
        self.assertEqual(C.parse_requires(None), [])

    def test_reputation(self):
        meta = {"info": {"author": "a", "description": "d"},
                "releases": {"1": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}], "2": [{"upload_time_iso_8601": "2026-02-01T00:00:00Z"}]}}
        r = C.reputation_signals(meta, datetime(2026, 1, 31, tzinfo=timezone.utc))
        self.assertEqual((r["maintainer_count"], r["has_description"], round(r["age_days"])), (1, True, 30))

    def test_latest_requires_read_from_meta_without_network(self):
        meta = {"info": {"version": "2", "requires_dist": ["idna"]}}
        self.assertEqual(C.fetch_requires("x", "2", meta), [{"name": "idna", "spec": ""}])


if __name__ == "__main__":
    unittest.main()
