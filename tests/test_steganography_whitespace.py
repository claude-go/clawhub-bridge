"""Tests for steganographic detection — whitespace and domain patterns."""

from clawhub_bridge.scanner import scan_content


def _has(result, name):
    return any(f.pattern_name == name for f in result.findings)


class TestTabSpaceAlternation:
    def test_alternating_pattern(self):
        pattern = " \t" * 10  # 20 alternations
        result = scan_content(f"text{pattern}end", source="test")
        assert _has(result, "tab_space_alternation")

    def test_normal_indent(self):
        result = scan_content("    normal indent", source="test")
        assert not _has(result, "tab_space_alternation")


class TestTrailingWhitespace:
    def test_excessive_trailing(self):
        result = scan_content(
            "text" + " " * 25, source="test"
        )
        assert _has(result, "trailing_whitespace_pattern")

    def test_normal_trailing(self):
        result = scan_content("text   ", source="test")
        assert not _has(result, "trailing_whitespace_pattern")


class TestPunycodeDomain:
    def test_punycode_url(self):
        result = scan_content(
            "visit xn--pple-43d.com for info", source="test"
        )
        assert _has(result, "punycode_domain")

    def test_normal_domain(self):
        result = scan_content("visit apple.com", source="test")
        assert not _has(result, "punycode_domain")

    def test_punycode_with_subdomain(self):
        result = scan_content(
            "api.xn--gogle-5qd.com/endpoint", source="test"
        )
        assert _has(result, "punycode_domain")
