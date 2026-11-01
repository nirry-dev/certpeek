import unittest

from certpeek import split_target


class TestSplitTarget(unittest.TestCase):
    def test_bare_host(self):
        self.assertEqual(split_target("example.com"), ("example.com", 443))

    def test_host_port(self):
        self.assertEqual(split_target("example.com:8443"), ("example.com", 8443))

    def test_url(self):
        self.assertEqual(split_target("https://api.example.com/v1/x"), ("api.example.com", 443))
        self.assertEqual(split_target("https://api.example.com:9000/x"), ("api.example.com", 9000))

    def test_ipv6_bracket(self):
        self.assertEqual(split_target("[2001:db8::1]:8443"), ("2001:db8::1", 8443))

    def test_default_port_override(self):
        self.assertEqual(split_target("example.com", 8443), ("example.com", 8443))


if __name__ == "__main__":
    unittest.main()
