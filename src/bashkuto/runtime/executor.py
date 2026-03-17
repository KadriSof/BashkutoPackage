import subprocess
import time


def execute(command, shell):

    start = time.time()

    process = subprocess.Popen(
        command,
        shell=True,
        executable=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    stdout, stderr = process.communicate()

    duration = int((time.time() - start) * 1000)

    return stdout, stderr, process.returncode, duration