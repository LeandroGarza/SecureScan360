import unittest
from Fussion.Pentest import handle_scan

class TestMain(unittest.TestCase):
    def test_handle_scan_with_valid_ip(self):
        response = handle_scan('8.8.8.8')
        self.assertEqual(response.status_code, 200)

    def test_handle_scan_with_invalid_ip(self):
        response = handle_scan('999.999.999.999')
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
