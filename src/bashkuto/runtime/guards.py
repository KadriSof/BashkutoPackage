BLOCKED_DEFAULT = [
    "rm -rf",
    "shutdown",
    "reboot",
    ":(){ :|:& };:"
]


def check_command(command: str, blocked):

    for pattern in blocked:
        if pattern in command:
            raise RuntimeError(f"Blocked command detected: {pattern}")