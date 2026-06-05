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

    def test_decompile_script_missing_file_raises_error(self):
        """Verify that calling decompile_script on a non-existent file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            innounpack.decompile_script("non_existent_file_path_1234.exe")

    def test_decompile_script_invalid_type_raises_error(self):
        """Verify that passing an invalid argument type to decompile_script raises TypeError."""
        with self.assertRaises(TypeError):
            innounpack.decompile_script(12345)

    def test_decompile_script_invalid_bytes_raises_error(self):
        """Verify that passing corrupted byte vectors in-memory raises Exception."""
        corrupted_bytes = b"MZ\x90\x00\x03\x00\x00\x00"
        with self.assertRaises(Exception):
            innounpack.decompile_script(corrupted_bytes)

if __name__ == "__main__":
    unittest.main()
