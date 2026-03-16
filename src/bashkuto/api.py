from .runtime.runtime import BashRuntime

_default_runtime = BashRuntime()


def run(command: str) -> str:

    result = _default_runtime.run(command)

    return result.to_agent_string()