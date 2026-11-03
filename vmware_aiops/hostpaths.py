"""Confine host-side file paths to one dedicated directory.

Guest upload/download, OVA import and deploy-spec loading take a path on the
machine running this server. The server runs as root, so without a guard a
caller could read any host file into a guest (``/root/.vmware-aiops/.env``,
``/etc/shadow``) or write a guest file over any host file (``/etc/cron.d``).

Every such path must resolve, with symlinks followed, to a location strictly
inside ``VMWARE_MCP_FILE_ROOT`` (default ``/var/lib/vmware-aiops/files``).
A relative path is taken relative to that root.

Ported in spirit from upstream v2.3.2 (``vmware_policy.hostpaths``), which is
not a dependency of this line.
"""

from __future__ import annotations

import os
from pathlib import Path

FILE_ROOT_ENV = "VMWARE_MCP_FILE_ROOT"
DEFAULT_FILE_ROOT = "/var/lib/vmware-aiops/files"


class HostPathRefusedError(ValueError):
    """A host path resolves outside the allowed file root."""


def file_root() -> Path:
    """Return the configured file root (not resolved, not created)."""
    return Path(os.environ.get(FILE_ROOT_ENV) or DEFAULT_FILE_ROOT)


# @MX:ANCHOR: [AUTO] Single gate for every host path a tool reads or writes.
# @MX:REASON: Called by guest upload/download, OVA deploy, deploy spec and plan
#             validation; weakening it re-opens root-level file read/write.
def check_host_path(path: str) -> Path:
    """Return the resolved path if it lies strictly inside the file root.

    Raises:
        HostPathRefusedError: the path is empty, is the root itself, or
            resolves (after ``~`` expansion and symlink resolution) outside it.
    """
    root_setting = file_root()
    root = Path(os.path.realpath(root_setting))
    if root == Path(root.anchor):
        raise HostPathRefusedError(
            f"{FILE_ROOT_ENV} resolves to the filesystem root; set it to a dedicated directory."
        )

    if not isinstance(path, str) or not path.strip():
        raise HostPathRefusedError(
            f"Empty host path. Pass a file inside {root_setting} (or a path relative to it)."
        )

    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    # realpath resolves every existing symlink, including directory links,
    # and normalises '..' without requiring the final file to exist.
    resolved = Path(os.path.realpath(candidate))

    if resolved == root or root not in resolved.parents:
        raise HostPathRefusedError(
            f"Host path refused: {path!r} is outside the allowed directory {root_setting}. "
            f"Place the file inside it (or pass a path relative to it); the server does not "
            f"read or write host files anywhere else."
        )
    return resolved
