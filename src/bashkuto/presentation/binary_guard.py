"""Binary output detection."""

# Common whitespace characters that are valid in text but may not be
# considered printable by str.isprintable() in all contexts
ALLOWED_WHITESPACE = frozenset({'\n', '\r', '\t', '\f', '\v'})


def is_binary(data: bytes) -> bool:
    """
    Detect if data is binary based on Unicode-aware printability check.

    Uses str.isprintable() which handles Unicode characters correctly,
    combined with explicit allowance for common whitespace characters.

    Args:
        data: Raw bytes to check

    Returns:
        True if data appears to be binary, False if text
    """
    # Empty data is not binary
    if not data:
        return False

    try:
        text = data.decode("utf-8")
    except Exception:
        return True

    # Empty text is not binary
    if not text:
        return False

    # Count characters that are either printable (Unicode-aware) or
    # common whitespace characters
    def is_printable_or_whitespace(c: str) -> bool:
        return c.isprintable() or c in ALLOWED_WHITESPACE

    ratio = sum(1 for c in text if is_printable_or_whitespace(c)) / len(text)

    # Consider binary if less than 70% printable/whitespace characters
    return ratio < 0.7