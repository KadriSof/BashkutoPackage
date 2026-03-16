from .executor import execute
from .result import CommandResult
from .guards import check_command, BLOCKED_DEFAULT
from ..presentation.truncation import truncate_output
from ..presentation.binary_guard import is_binary


class BashRuntime:

    def __init__(
        self,
        shell="/bin/bash",
        max_output_chars=8000,
        blocked_commands=None,
        overflow_dir=".bashkuto_overflow"
    ):

        self.shell = shell
        self.max_output_chars = max_output_chars
        self.blocked = blocked_commands or BLOCKED_DEFAULT
        self.overflow_dir = overflow_dir

    def run(self, command: str) -> CommandResult:

        check_command(command, self.blocked)

        stdout, stderr, code, duration = execute(command, self.shell)

        if is_binary(stdout):
            return CommandResult(
                output="[binary output suppressed]",
                stderr="",
                exit_code=code,
                duration_ms=duration
            )

        text_out = stdout.decode("utf-8", errors="replace")
        text_err = stderr.decode("utf-8", errors="replace")

        text_out, truncated, overflow_file = truncate_output(
            text_out,
            self.max_output_chars,
            self.overflow_dir
        )

        return CommandResult(
            output=text_out,
            stderr=text_err,
            exit_code=code,
            duration_ms=duration,
            truncated=truncated,
            overflow_file=overflow_file
        )