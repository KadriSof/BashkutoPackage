from pathlib import Path
import uuid


def truncate_output(text, max_chars, overflow_dir):

    if len(text) <= max_chars:
        return text, False, None

    Path(overflow_dir).mkdir(exist_ok=True)

    filename = f"cmd_{uuid.uuid4().hex}.txt"
    path = Path(overflow_dir) / filename

    path.write_text(text)

    truncated = text[:max_chars]

    truncated += "\n\n--- output truncated ---"
    truncated += f"\nFull output: {path}"

    return truncated, True, str(path)