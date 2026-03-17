"""Binary output detection."""

import string


PRINTABLE = set(string.printable)


def is_binary(data: bytes) -> bool:
    """
    Detect if data is binary based on printable character ratio.

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

    ratio = sum(c in PRINTABLE for c in text) / max(len(text), 1)

    return ratio < 0.7