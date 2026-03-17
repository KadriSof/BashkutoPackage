import string


PRINTABLE = set(string.printable)


def is_binary(data: bytes) -> bool:

    try:
        text = data.decode("utf-8")
    except Exception:
        return True

    ratio = sum(c in PRINTABLE for c in text) / max(len(text), 1)

    return ratio < 0.7