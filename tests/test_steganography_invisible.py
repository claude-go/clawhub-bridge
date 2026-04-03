"""Tests for steganographic detection — invisible characters."""

from clawhub_bridge.scanner import scan_content


def _has(result, name):
    return any(f.pattern_name == name for f in result.findings)


class TestSingleZeroWidth:
    def test_zwsp(self):
        result = scan_content("run\u200b command", source="test")
        assert _has(result, "single_zero_width")

    def test_zwnj(self):
        result = scan_content("execute\u200c task", source="test")
        assert _has(result, "single_zero_width")

    def test_zwj(self):
        result = scan_content("send\u200d data", source="test")
        assert _has(result, "single_zero_width")

    def test_bom_mid_text(self):
        result = scan_content("download\ufeff file", source="test")
        assert _has(result, "single_zero_width")

    def test_clean_ascii(self):
        result = scan_content("run command safely", source="test")
        assert not _has(result, "single_zero_width")


class TestSoftHyphen:
    def test_soft_hyphen_sequence(self):
        result = scan_content("data\u00ad\u00ad\u00ad hidden", source="test")
        assert _has(result, "soft_hyphen_sequence")

    def test_soft_hyphen_in_words(self):
        result = scan_content(
            "e\u00adx\u00ade\u00adc\u00adu\u00adt\u00ade", source="test"
        )
        assert _has(result, "soft_hyphen_sequence")

    def test_no_soft_hyphens(self):
        result = scan_content("execute command", source="test")
        assert not _has(result, "soft_hyphen_sequence")


class TestWordJoinerAbuse:
    def test_word_joiner_sequence(self):
        result = scan_content(
            "data\u2060\u2060\u2060hidden", source="test"
        )
        assert _has(result, "word_joiner_abuse")

    def test_mixed_invisible(self):
        result = scan_content(
            "x\u2060\u200b\u2060\u200b payload", source="test"
        )
        assert _has(result, "word_joiner_abuse")


class TestInterlinearAnnotation:
    def test_annotation_start(self):
        result = scan_content(
            "normal \ufff9hidden instruction\ufffb text", source="test"
        )
        assert _has(result, "interlinear_annotation")

    def test_clean_text(self):
        result = scan_content("normal text here", source="test")
        assert not _has(result, "interlinear_annotation")


class TestTagCharacters:
    def test_plane14_tags(self):
        result = scan_content(
            "normal \U000e0001\U000e0041\U000e0042 text", source="test"
        )
        assert _has(result, "tag_characters")

    def test_clean_supplementary(self):
        result = scan_content("emoji: \U0001F600", source="test")
        assert not _has(result, "tag_characters")
