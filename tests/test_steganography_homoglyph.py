"""Tests for steganographic detection — homoglyph and mixed-script patterns."""

from clawhub_bridge.scanner import scan_content


def _has(result, name):
    return any(f.pattern_name == name for f in result.findings)


class TestCyrillicHomoglyph:
    def test_cyrillic_a(self):
        # U+0430 Cyrillic small а looks like Latin a
        result = scan_content("run the comm\u0430nd", source="test")
        assert _has(result, "cyrillic_homoglyph")

    def test_cyrillic_o(self):
        result = scan_content("d\u043ewnload the file", source="test")
        assert _has(result, "cyrillic_homoglyph")

    def test_cyrillic_uppercase_A(self):
        result = scan_content("\u0410ccept all cookies", source="test")
        assert _has(result, "cyrillic_homoglyph")

    def test_clean_latin(self):
        result = scan_content("run the command safely", source="test")
        assert not _has(result, "cyrillic_homoglyph")


class TestGreekHomoglyph:
    def test_greek_omicron(self):
        # U+03BF Greek small omicron looks like Latin o
        result = scan_content("d\u03bfwnload payload", source="test")
        assert _has(result, "greek_homoglyph")

    def test_greek_uppercase_A(self):
        result = scan_content("\u0391dmin access", source="test")
        assert _has(result, "greek_homoglyph")

    def test_clean_english(self):
        result = scan_content("download payload safely", source="test")
        assert not _has(result, "greek_homoglyph")


class TestFullwidthLatin:
    def test_fullwidth_sequence(self):
        # U+FF41 = fullwidth 'a', U+FF42 = fullwidth 'b', etc.
        result = scan_content("\uff52\uff55\uff4e this", source="test")
        assert _has(result, "fullwidth_latin")

    def test_single_fullwidth_no_match(self):
        # Single char should not trigger (pattern needs 2+)
        result = scan_content("just \uff41 char", source="test")
        assert not _has(result, "fullwidth_latin")


class TestConfusableUrl:
    def test_cyrillic_in_url(self):
        result = scan_content(
            "fetch https://g\u043eogle.com/api", source="test"
        )
        assert _has(result, "confusable_url")

    def test_clean_url(self):
        result = scan_content(
            "fetch https://google.com/api", source="test"
        )
        assert not _has(result, "confusable_url")
