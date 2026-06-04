import os
import unittest
import innounpack

class TestInnoUnpackPythonBindings(unittest.TestCase):
    
    def test_library_loaded(self):
        """Verify that the compiled C-shared library loads successfully."""
        self.assertIsNotNone(innounpack._lib, "Failed to load libinnounpack shared library")

    def test_list_files_missing_file_raises_error(self):
        """Verify that calling list_files on a non-existent installer raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            innounpack.list_files("non_existent_file_path_1234.exe")

    def test_extract_all_missing_file_raises_error(self):
        """Verify that calling extract_all on a non-existent installer raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            innounpack.extract_all("non_existent_file_path_1234.exe", "./out")

    def test_crack_password_missing_file_raises_error(self):
        """Verify that calling crack_password on a non-existent installer raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            innounpack.crack_password("non_existent_file_path_1234.exe")

if __name__ == "__main__":
    unittest.main()
