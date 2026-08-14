#!/usr/bin/env python3
"""Run one command in a PTY and answer one exact observed prompt."""

from __future__ import annotations

import argparse
import errno
import os
import pty
import select
import signal
import sys
import time
from pathlib import Path


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--prompt", required=True)
    value.add_argument("--input-file", type=Path, required=True)
    value.add_argument("--timeout", type=int, required=True)
    value.add_argument("command", nargs=argparse.REMAINDER)
    return value


def terminate(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        waited, _status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return
        time.sleep(0.05)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)


def main() -> int:
    args = parser().parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise SystemExit("pty_prompt: command is required after --")
    if args.timeout <= 0:
        raise SystemExit("pty_prompt: timeout must be positive")
    try:
        prompt = args.prompt.encode("ascii")
        response = args.input_file.read_bytes()
        response.decode("ascii")
    except (OSError, UnicodeError) as error:
        raise SystemExit(f"pty_prompt: cannot read canonical ASCII input: {error}") from None
    if not prompt or b"\r" in response or b"\x00" in response:
        raise SystemExit("pty_prompt: prompt or input is not canonical")
    if not response.endswith(b"\n") or response.endswith(b"\n\n"):
        raise SystemExit("pty_prompt: input must contain one LF-terminated line")
    if b"\n" in response[:-1]:
        raise SystemExit("pty_prompt: input must contain exactly one line")

    pid, descriptor = pty.fork()
    if pid == 0:
        os.execvp(command[0], command)

    deadline = time.monotonic() + args.timeout
    observed = bytearray()
    answered = False
    child_status: int | None = None
    eof = False
    try:
        while child_status is None or not eof:
            if time.monotonic() >= deadline:
                terminate(pid)
                child_status = 0
                print("pty_prompt: command timed out", file=sys.stderr)
                return 124
            ready, _writable, _exceptional = select.select(
                [descriptor], [], [], min(0.1, deadline - time.monotonic())
            )
            if ready:
                try:
                    chunk = os.read(descriptor, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    chunk = b""
                if chunk:
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                    observed.extend(chunk)
                    if len(observed) > 16384:
                        del observed[:-16384]
                    if not answered and prompt in observed:
                        # Ansible displays the prompt before flushing pending tty
                        # input, so wait until its read setup has completed.
                        time.sleep(0.25)
                        os.write(descriptor, response)
                        answered = True
                else:
                    eof = True
            if child_status is None:
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    child_status = status
        if not answered:
            print("pty_prompt: expected prompt was not observed", file=sys.stderr)
            return 2
        assert child_status is not None
        return os.waitstatus_to_exitcode(child_status)
    finally:
        os.close(descriptor)
        if child_status is None:
            terminate(pid)


if __name__ == "__main__":
    raise SystemExit(main())
