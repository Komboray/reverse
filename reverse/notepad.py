import ctypes
import os
import sys


def run_as_admin(executable, params=""):
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",  # The "runas" verb to request elevation
            executable,
            params,
            None,
            1  # Show the window
        )
    except Exception as e:
        print(f"Failed to run as administrator: {e}")


if __name__ == "__main__":
    # Path to the notepad executable
    notepad_path = os.path.join(os.environ['SYSTEMROOT'], 'system32', 'notepad.exe')

    # Path to the file you want to open with Notepad
    file_to_open = "C:\\Windows\\System32\\drivers\\etc\\hosts"

    # Run Notepad as administrator and open the specified file
    run_as_admin(notepad_path, file_to_open)
