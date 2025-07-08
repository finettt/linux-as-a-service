import shlex
import subprocess


def execute_command(cmdline, cwd):
    completed = subprocess.run(
        shlex.split(cmdline),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        shell=False,
        cwd=cwd,
    )

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()

    if completed.returncode != 0:
        raise RuntimeError(stderr or "Unknown error")

    return stdout or "(no output)"