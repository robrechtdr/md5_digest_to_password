import hashlib
import multiprocessing
import sys
import StringIO
import unittest

import md5_digest_to_password as mtp


table_printout = """\
user    pass    

john    qwer    
eva     asdf    
allan   zxcv    
"""


class CSVTableTestCase(unittest.TestCase):
    def setUp(self):
        # This assumes the csv file is never modified!
        # In a project that doesn't have a spec that will never expand beyond
        # it's initial description (everything else but a pure exercise or
        # test) I would create a seperate csv file for testing.
        self.table = mtp.CSVTable("data.csv")
        assert len(self.table) == 3
        assert len(self.table[0]) == 2

    def test_create_column(self):
        self.table.create_column("eye color", "brown")
        self.assertEqual(self.table.columns[-1], "eye color")
        self.assertEqual(self.table[0], {"eye color": "brown",
                                         "user": "john",
                                         "pass": "qwer"})

    def test_delete_column(self):
        self.table.delete_column("pass")
        self.assertEqual(len(self.table.columns), 1)
        self.assertEqual(len(self.table[0]), 1)

    def test_show(self):
        sys.stdout = strio = StringIO.StringIO()
        self.table.show()
        table_show_output = strio.getvalue()
        strio.close()
        self.assertEqual(table_show_output, table_printout)


class Md5DigestToPasswordTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "qwer"
        cls.md5_digest = hashlib.md5("qwer").hexdigest()

    def test_get_password_from_md5_digest(self):
        self.assertEqual(mtp.get_password_from_md5_digest(self.md5_digest),
                         self.password)

    def test_get_password_and_time(self):
        self.assertEqual(len(mtp.get_password_and_time(self.md5_digest)), 2)

    def test_get_optimized_amount_of_processes(self):
        table = [{"user": "john", "pass": "qwer"},
                 {"user": "eva", "pass": "asdf"},
                 {"user": "allan", "pass": "zxcv"}]
        virtual_cores = multiprocessing.cpu_count()
        if len(table) < virtual_cores:
            self.assertEqual(mtp.get_optimized_amount_of_processes(table),
                             len(table))
        else:
            self.assertEqual(mtp.get_optimized_amount_of_processes(table),
                             virtual_cores)


if __name__ == "__main__":
    unittest.main()
