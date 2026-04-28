"""
tests/test_tailer.py — Integration-level tests for FileTailer.
"""

import os
import threading
import time
import pytest

from detector.tailer import FileTailer


def collect_lines(tailer, count, timeout=5.0):
    """
    Run tailer in a thread, collect exactly `count` lines, then return.
    Returns whatever lines were collected within timeout — may be fewer than count.
    """
    lines = []
    error = []

    def run():
        try:
            for line in tailer.tail():
                lines.append(line)
                if len(lines) >= count:
                    break
        except Exception as exc:
            error.append(exc)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)

    if error:
        raise error[0]
    return lines


class TestFileTailer:

    def test_reads_new_lines(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")

        tailer = FileTailer(str(log), poll_interval=0.05)

        def write_lines():
            time.sleep(0.1)
            with open(str(log), "a") as f:
                f.write('{"line": 1}\n')
                f.write('{"line": 2}\n')
                f.write('{"line": 3}\n')

        writer = threading.Thread(target=write_lines)
        writer.start()

        lines = collect_lines(tailer, 3)
        writer.join()

        assert len(lines) == 3
        assert '{"line": 1}' in lines[0]

    def test_handles_rotation_by_rename(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")

        tailer = FileTailer(str(log), poll_interval=0.05, reopen_delay=0.1)
        collected = []
        done = threading.Event()

        def run():
            for line in tailer.tail():
                collected.append(line)
                # Stop after we see the post-rotation line
                if "post_rotation" in line:
                    done.set()
                    break

        t = threading.Thread(target=run, daemon=True)
        t.start()

        # Write pre-rotation line
        time.sleep(0.1)
        with open(str(log), "a") as f:
            f.write('{"pre_rotation": true}\n')

        time.sleep(0.2)

        # Rotate: rename old file, create new file
        rotated = tmp_path / "test.log.1"
        os.rename(str(log), str(rotated))
        time.sleep(0.05)

        # Write to the new file
        with open(str(log), "w") as f:
            f.write('{"post_rotation": true}\n')

        # Wait up to 3s for the tailer to detect rotation and read the new line
        done.wait(timeout=3.0)
        t.join(timeout=1.0)

        assert any("post_rotation" in line for line in collected), (
            f"Expected post-rotation line not found. Collected: {collected}"
        )

    def test_handles_partial_write(self, tmp_path):
        """Partial lines must not be emitted until the newline arrives."""
        log = tmp_path / "test.log"
        log.write_text("")

        tailer = FileTailer(str(log), poll_interval=0.05)

        def write_partial_then_complete():
            time.sleep(0.1)
            with open(str(log), "a") as f:
                f.write('{"partial"')
                f.flush()
            time.sleep(0.2)
            with open(str(log), "a") as f:
                f.write(': true}\n')
                f.flush()

        writer = threading.Thread(target=write_partial_then_complete)
        writer.start()

        lines = collect_lines(tailer, 1, timeout=3)
        writer.join()

        assert len(lines) == 1
        assert lines[0] == '{"partial": true}'

    def test_waits_for_file_creation(self, tmp_path):
        log = tmp_path / "not_yet.log"
        # File does NOT exist yet

        tailer = FileTailer(
            str(log), poll_interval=0.05, reopen_delay=0.05, max_reopen_attempts=30
        )
        got_line = threading.Event()
        result = []

        def run():
            for line in tailer.tail():
                result.append(line)
                got_line.set()
                break

        t = threading.Thread(target=run, daemon=True)
        t.start()

        # Create the file after a short delay
        time.sleep(0.3)
        with open(str(log), "w") as f:
            f.write('{"created": true}\n')

        got_line.wait(timeout=5.0)
        t.join(timeout=1.0)

        assert len(result) == 1
        assert "created" in result[0]

    def test_raises_after_max_reopen_attempts(self, tmp_path):
        log = tmp_path / "missing.log"

        tailer = FileTailer(
            str(log), poll_interval=0.01, reopen_delay=0.01, max_reopen_attempts=3
        )

        with pytest.raises(RuntimeError, match="Could not open"):
            for _ in tailer.tail():
                pass
