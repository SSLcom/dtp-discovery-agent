"""Deterministic zip, for the Windows archives.

Python's zipfile rather than the `zip` binary because this script has to behave
identically on a laptop and on a CI runner, and `zip` is not installed
everywhere. Entries are sorted and every timestamp is fixed, so two builds of
one commit produce identical bytes — see the note in build-release.sh.
"""

import os
import sys
import zipfile

FIXED_DATE = (1980, 1, 1, 0, 0, 0)  # The earliest a zip entry can claim.


def main(out_path: str, root: str) -> None:
    paths = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            paths.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
    paths.sort()

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for arcname, full in paths:
            info = zipfile.ZipInfo(arcname, date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            # Preserve the executable bit; the rest of the mode is fixed so the
            # archive does not vary with the builder's umask.
            mode = 0o755 if os.access(full, os.X_OK) else 0o644
            info.external_attr = (mode & 0xFFFF) << 16
            with open(full, "rb") as handle:
                archive.writestr(info, handle.read())


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
