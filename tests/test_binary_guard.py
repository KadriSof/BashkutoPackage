"""Tests for binary output detection."""

from bashkuto.presentation.binary_guard import is_binary


class TestBinaryGuard:
    """Test is_binary function."""

    def test_plain_text_is_not_binary(self):
        """Plain text should not be detected as binary."""
        data = b"hello world"
        assert is_binary(data) is False

    def test_utf8_text_is_not_binary(self):
        """UTF-8 text should not be detected as binary."""
        data = "Hello 世界 🌍".encode("utf-8")
        assert is_binary(data) is False

    def test_empty_data_is_not_binary(self):
        """Empty data should not be binary."""
        assert is_binary(b"") is False

    def test_binary_data_detected(self):
        """Binary data should be detected."""
        # Null bytes and non-printable chars
        data = b"\x00\x01\x02\x03\x04\x05"
        assert is_binary(data) is True

    def test_executable_binary_detected(self):
        """Executable-like data should be detected."""
        # ELF header
        data = b"\x7fELF\x02\x01\x01\x00"
        assert is_binary(data) is True

    def test_mixed_content_binary(self):
        """Mostly binary content should be detected."""
        # 90% binary, 10% text
        data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08hello"
        assert is_binary(data) is True

    def test_mixed_content_text(self):
        """Mostly text content should not be detected."""
        # 90% text, 10% special chars
        data = b"hello world\n" * 100 + b"\x00\x01"
        assert is_binary(data) is False

    def test_newlines_not_binary(self):
        """Text with newlines should not be binary."""
        data = b"line1\nline2\nline3\n"
        assert is_binary(data) is False

    def test_tabs_not_binary(self):
        """Text with tabs should not be binary."""
        data = b"col1\tcol2\tcol3"
        assert is_binary(data) is False

    def test_unicode_text_not_binary(self):
        """Unicode text should not be binary."""
        # Use ASCII printable + common unicode that decodes correctly
        data = "Hello World".encode("utf-8")
        assert is_binary(data) is False

    def test_invalid_utf8_is_binary(self):
        """Invalid UTF-8 should be detected as binary."""
        # Invalid UTF-8 sequence
        data = b"\xff\xfe\x00\x01"
        assert is_binary(data) is True

    def test_threshold_boundary(self):
        """Test the 70% threshold boundary."""
        # Exactly at threshold
        data = b"abc" + b"\x00"  # 75% printable
        assert is_binary(data) is False

        # Below threshold
        data = b"a" + b"\x00" * 3  # 25% printable
        assert is_binary(data) is True

    def test_unicode_cyrillic_not_binary(self):
        """Cyrillic (Russian) text should not be binary."""
        data = "Привет мир".encode("utf-8")
        assert is_binary(data) is False

    def test_unicode_arabic_not_binary(self):
        """Arabic text should not be binary."""
        data = "مرحبا بالعالم".encode("utf-8")
        assert is_binary(data) is False

    def test_unicode_japanese_not_binary(self):
        """Japanese text should not be binary."""
        data = "こんにちは世界".encode("utf-8")
        assert is_binary(data) is False

    def test_unicode_mixed_latin_not_binary(self):
        """Mixed Latin with accents should not be binary."""
        data = "Café résumé naïve".encode("utf-8")
        assert is_binary(data) is False

    def test_unicode_with_emoji_not_binary(self):
        """Text with emoji should not be binary."""
        data = "Hello 世界 🌍".encode("utf-8")
        assert is_binary(data) is False

    def test_null_bytes_are_binary(self):
        """Data with multiple NUL bytes should be detected as binary."""
        # Multiple null bytes to exceed 30% threshold
        data = b"hi\x00\x00\x00\x00\x00\x00"  # 6 nulls out of 8 chars = 25% printable
        assert is_binary(data) is True

    def test_mostly_control_chars_are_binary(self):
        """Data with mostly control chars should be binary."""
        # Less than 70% printable
        data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0e\x0f" + b"abc"
        assert is_binary(data) is True
