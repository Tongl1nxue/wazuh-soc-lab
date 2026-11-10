"""Unit-only synthetic metadata; these fixtures are not experiment evidence."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('analysis',Path(__file__).with_name('analyze-alerts.py'))
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)


class CountingTests(unittest.TestCase):
    def test_archive_source_id_collision_keeps_distinct_documents(self):
        hits=[{'_index':'test','_id':'a','_source':{'id':'same'}},
              {'_index':'test','_id':'b','_source':{'id':'same'}}]
        self.assertEqual(len(a.unique_hits(hits)),2)

    def test_duplicate_document_counted_once(self):
        event={'_index':'test','_id':'a','_source':{'id':'same'}}
        self.assertEqual(len(a.unique_hits([event,event])),1)

    def test_spreadsheet_formula_is_text(self):
        self.assertEqual(a.csv_cell('=1+1'),"'=1+1")
        self.assertEqual(a.csv_cell('1794126908.218582'),'1794126908.218582')

    def test_url_secret_query_excluded(self):
        self.assertEqual(a.public_url('/index.html?token=UNIT_ONLY&soc_run=soc-detect-123456abcdef'),
                         '/index.html?soc_run=soc-detect-123456abcdef')

    def test_timed_out_query_rejected(self):
        with self.assertRaises(ValueError):
            a.analyze({'web_archives':{'timed_out':True}})


if __name__=='__main__':unittest.main()
