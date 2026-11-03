"""Guest Operations: execute commands and transfer files inside VMs.

Requires VMware Tools running inside the guest OS.
Uses the GuestOperationsManager API (VIX-like, over SOAP).
"""

from __future__ import annotations

import logging
import os
import stat
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from pyVmomi import vim

from vmware_aiops.hostpaths import check_host_path
from vmware_aiops.ops.inventory import find_vm_by_name
from vmware_aiops.ops.vm_lifecycle import VMNotFoundError

if TYPE_CHECKING:
    from pyVmomi.vim import ServiceInstance

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 2  # seconds
_EXEC_TIMEOUT = 300  # seconds

# Guest OS family constants (vm.guest.guestFamily)
_FAMILY_WINDOWS = "windowsGuest"
_FAMILY_LINUX = "linuxGuest"


class GuestOpsError(Exception):
    """Raised when a guest operation fails."""


def _require_vm_with_tools(
    si: ServiceInstance, vm_name: str
) -> vim.VirtualMachine:
    """Find VM and verify VMware Tools is running."""
    vm = find_vm_by_name(si, vm_name)
    if vm is None:
        raise VMNotFoundError(f"VM '{vm_name}' not found")
    if vm.runtime.powerState != vim.VirtualMachine.PowerState.poweredOn:
        raise GuestOpsError(f"VM '{vm_name}' is not powered on")
    tools_status = vm.guest.toolsRunningStatus if vm.guest else None
    if tools_status != "guestToolsRunning":
        raise GuestOpsError(
            f"VMware Tools not running on '{vm_name}' "
            f"(status: {tools_status}). Guest operations require running Tools."
        )
    return vm


def _detect_shell(vm: vim.VirtualMachine) -> tuple[str, str]:
    """Detect guest OS shell from guestFamily. Returns (program_path, shell_flag)."""
    family = vm.guest.guestFamily if vm.guest else None
    if family == _FAMILY_WINDOWS:
        return ("C:\\Windows\\System32\\cmd.exe", "/c")
    return ("/bin/sh", "-c")


def _guest_auth(username: str, password: str) -> vim.vm.guest.NamePasswordAuthentication:
    """Build guest authentication spec."""
    auth = vim.vm.guest.NamePasswordAuthentication()
    auth.username = username
    auth.password = password
    auth.interactiveSession = False
    return auth


def guest_exec(
    si: ServiceInstance,
    vm_name: str,
    command: str,
    username: str,
    password: str,
    arguments: str = "",
    working_directory: str | None = None,
    timeout: int = _EXEC_TIMEOUT,
) -> dict:
    """Execute a command inside a VM via VMware Tools.

    Args:
        si: vSphere ServiceInstance.
        vm_name: Target VM name.
        command: Full path to the program (e.g. "/bin/bash", "C:\\Windows\\System32\\cmd.exe").
        username: Guest OS username.
        password: Guest OS password.
        arguments: Command arguments (e.g. "-c 'ls -la /tmp'").
        working_directory: Working directory inside the guest (optional).
        timeout: Max wait time in seconds (default 300).

    Returns:
        dict with keys: exit_code, stdout, stderr, timed_out.
    """
    vm = _require_vm_with_tools(si, vm_name)
    content = si.RetrieveContent()
    gom = content.guestOperationsManager
    pm = gom.processManager

    auth = _guest_auth(username, password)

    # Build process spec
    spec = vim.vm.guest.ProcessManager.ProgramSpec()
    spec.programPath = command
    spec.arguments = arguments
    if working_directory:
        spec.workingDirectory = working_directory

    # Start the process
    pid = pm.StartProgramInGuest(vm, auth, spec)
    logger.info("Started process PID %d in VM '%s': %s %s", pid, vm_name, command, arguments)

    # Poll for completion
    start = time.time()
    timed_out = False
    while True:
        elapsed = time.time() - start
        if elapsed > timeout:
            timed_out = True
            break

        processes = pm.ListProcessesInGuest(vm, auth, pids=[pid])
        if not processes:
            break
        proc = processes[0]
        if proc.exitCode is not None:
            # Process finished
            return {
                "exit_code": proc.exitCode,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
                "command": f"{command} {arguments}".strip(),
                "pid": pid,
            }
        time.sleep(_POLL_INTERVAL)

    if timed_out:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Process timed out after {timeout}s",
            "timed_out": True,
            "command": f"{command} {arguments}".strip(),
            "pid": pid,
        }

    return {
        "exit_code": -1,
        "stdout": "",
        "stderr": "Process disappeared unexpectedly",
        "timed_out": False,
        "command": f"{command} {arguments}".strip(),
        "pid": pid,
    }


def guest_exec_with_output(
    si: ServiceInstance,
    vm_name: str,
    command: str,
    username: str,
    password: str,
    timeout: int = _EXEC_TIMEOUT,
) -> dict:
    """Execute a shell command inside a VM and capture stdout + stderr.

    Automatically detects guest OS (Linux/Windows) and uses the appropriate
    shell. Captures output by redirecting to a temp file, downloading it,
    then cleaning up.

    Args:
        si: vSphere ServiceInstance.
        vm_name: Target VM name.
        command: Shell command to run (e.g. "df -h" or "dir C:\\").
        username: Guest OS username.
        password: Guest OS password.
        timeout: Max wait time in seconds (default 300).

    Returns:
        dict with keys: exit_code, stdout, stderr, timed_out, command, os_family.
    """
    vm = _require_vm_with_tools(si, vm_name)
    family = vm.guest.guestFamily if vm.guest else None
    program, flag = _detect_shell(vm)

    # Temp file paths inside the guest
    run_id = uuid.uuid4().hex[:8]
    if family == _FAMILY_WINDOWS:
        tmp_out = f"C:\\Windows\\Temp\\vmops_{run_id}.txt"
        wrapped = f"{command} > {tmp_out} 2>&1"
    else:
        tmp_out = f"/tmp/.vmops_{run_id}.txt"
        wrapped = f"{command} > {tmp_out} 2>&1"

    # Run command with output redirection
    result = guest_exec(
        si, vm_name, program, username, password,
        arguments=f"{flag} \"{wrapped}\"",
        timeout=timeout,
    )
    exit_code = result["exit_code"]
    timed_out = result["timed_out"]

    # Fetch the output file into memory (no host file: the file root does
    # not apply to this internal transfer, and nothing is left on the host).
    stdout = ""
    try:
        stdout = _guest_download_bytes(si, vm_name, tmp_out, username, password).decode(
            "utf-8", errors="replace"
        )
    except Exception as e:
        logger.warning("Could not retrieve output file from guest: %s", e)
    finally:
        # Best-effort cleanup of temp file in guest
        try:
            if family == _FAMILY_WINDOWS:
                guest_exec(si, vm_name, "C:\\Windows\\System32\\cmd.exe",
                           username, password, arguments=f"/c del {tmp_out}")
            else:
                guest_exec(si, vm_name, "/bin/sh", username, password,
                           arguments=f"-c 'rm -f {tmp_out}'")
        except Exception:
            pass

    return {
        "exit_code": exit_code,
        "stdout": stdout.strip(),
        "stderr": "",
        "timed_out": timed_out,
        "command": command,
        "os_family": family or "unknown",
    }


def guest_provision(
    si: "ServiceInstance",
    vm_name: str,
    username: str,
    password: str,
    steps: list[dict],
    timeout: int = 300,
) -> dict:
    """Provision a VM by running a sequence of guest operations.

    Each step is a dict with a ``type`` key:

    - ``{"type": "exec", "command": "apt-get install -y nginx"}``
      Run a shell command (uses guest_exec_with_output).

    - ``{"type": "upload", "local_path": "keys/id_rsa.pub", "guest_path": "/root/.ssh/authorized_keys"}``
      Upload a host file (inside VMWARE_MCP_FILE_ROOT) into the guest.

    - ``{"type": "service", "name": "nginx", "action": "start"}``
      Start/stop/restart/enable a systemd service (Linux only).

    Steps are executed in order. Execution stops on the first failure
    (non-zero exit code or exception).

    Args:
        si: vSphere ServiceInstance.
        vm_name: Target VM name.
        username: Guest OS username.
        password: Guest OS password.
        steps: List of step dicts (see above).
        timeout: Per-step timeout in seconds (default 300).

    Returns:
        dict with keys:
          - success (bool)
          - completed_steps (int)
          - total_steps (int)
          - results (list of per-step dicts)
          - error (str or None)
    """
    # Pre-flight: refuse any upload source outside the file root before the
    # first step runs, so a provision never stops half-way on a path that
    # could never have been used.
    for i, step in enumerate(steps):
        if step.get("type") == "upload":
            try:
                check_host_path(step.get("local_path"))
            except ValueError as exc:
                return {
                    "success": False,
                    "completed_steps": 0,
                    "total_steps": len(steps),
                    "results": [],
                    "error": f"Step {i + 1} (upload) refused before any step ran: {exc}",
                }

    results = []
    for i, step in enumerate(steps):
        step_type = step.get("type")
        step_result: dict = {"step": i + 1, "type": step_type, "success": False}
        try:
            if step_type == "exec":
                command = step["command"]
                step_result["command"] = command
                out = guest_exec_with_output(si, vm_name, command, username, password, timeout=timeout)
                step_result["exit_code"] = out["exit_code"]
                step_result["stdout"] = out["stdout"]
                step_result["timed_out"] = out["timed_out"]
                step_result["success"] = out["exit_code"] == 0 and not out["timed_out"]

            elif step_type == "upload":
                local_path = step["local_path"]
                guest_path = step["guest_path"]
                step_result["local_path"] = local_path
                step_result["guest_path"] = guest_path
                msg = guest_upload(si, vm_name, local_path, guest_path, username, password)
                step_result["message"] = msg
                step_result["success"] = True

            elif step_type == "service":
                name = step["name"]
                action = step.get("action", "start")
                step_result["service"] = name
                step_result["action"] = action
                command = f"systemctl {action} {name}"
                out = guest_exec_with_output(si, vm_name, command, username, password, timeout=timeout)
                step_result["exit_code"] = out["exit_code"]
                step_result["stdout"] = out["stdout"]
                step_result["success"] = out["exit_code"] == 0

            else:
                step_result["error"] = f"Unknown step type: '{step_type}'"
                results.append(step_result)
                return {
                    "success": False,
                    "completed_steps": i,
                    "total_steps": len(steps),
                    "results": results,
                    "error": f"Step {i + 1}: unknown type '{step_type}'",
                }

        except Exception as exc:
            step_result["error"] = str(exc)
            results.append(step_result)
            return {
                "success": False,
                "completed_steps": i,
                "total_steps": len(steps),
                "results": results,
                "error": f"Step {i + 1} ({step_type}) failed: {exc}",
            }

        results.append(step_result)
        if not step_result["success"]:
            return {
                "success": False,
                "completed_steps": i,
                "total_steps": len(steps),
                "results": results,
                "error": f"Step {i + 1} ({step_type}) failed with exit_code={step_result.get('exit_code')}",
            }

    return {
        "success": True,
        "completed_steps": len(steps),
        "total_steps": len(steps),
        "results": results,
        "error": None,
    }


def guest_upload(
    si: ServiceInstance,
    vm_name: str,
    local_path: str,
    guest_path: str,
    username: str,
    password: str,
    overwrite: bool = True,
) -> str:
    """Upload a file from the local machine to a VM via VMware Tools.

    Args:
        si: vSphere ServiceInstance.
        vm_name: Target VM name.
        local_path: Local file path to upload.
        guest_path: Destination path inside the guest.
        username: Guest OS username.
        password: Guest OS password.
        overwrite: Overwrite if file exists (default True).

    Returns:
        Success message string.
    """
    import urllib.request
    import ssl

    # Only files inside VMWARE_MCP_FILE_ROOT, checked before vCenter is touched.
    local = check_host_path(local_path)

    vm = _require_vm_with_tools(si, vm_name)
    content = si.RetrieveContent()
    gom = content.guestOperationsManager
    fm = gom.fileManager

    auth = _guest_auth(username, password)

    file_data = _read_upload_source(local)

    file_size = len(file_data)

    # Create file attributes
    file_attr = vim.vm.guest.FileManager.FileAttributes()

    # Initiate file transfer (get upload URL)
    transfer_url = fm.InitiateFileTransferToGuest(
        vm, auth, guest_path, file_attr, file_size, overwrite
    )

    # Upload via HTTPS PUT
    # The URL returned may use the vCenter/ESXi hostname; we need to handle
    # self-signed certificates for lab environments
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Lab/ESXi self-signed certs  # nosec B501

    req = urllib.request.Request(transfer_url, data=file_data, method="PUT")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("Content-Length", str(file_size))

    urllib.request.urlopen(req, context=ctx)  # nosec B310 — URL from vSphere API

    logger.info(
        "Uploaded %d bytes to '%s:%s'", file_size, vm_name, guest_path
    )
    return f"Uploaded {file_size} bytes to {guest_path} on VM '{vm_name}'"


def guest_download(
    si: ServiceInstance,
    vm_name: str,
    guest_path: str,
    local_path: str,
    username: str,
    password: str,
) -> str:
    """Download a file from a VM to the local machine via VMware Tools.

    Args:
        si: vSphere ServiceInstance.
        vm_name: Target VM name.
        guest_path: File path inside the guest to download.
        local_path: Local destination path.
        username: Guest OS username.
        password: Guest OS password.

    Returns:
        Success message string.
    """
    # Only inside VMWARE_MCP_FILE_ROOT, checked before vCenter is touched.
    check_host_path(local_path)

    file_data = _guest_download_bytes(si, vm_name, guest_path, username, password)

    # The transfer took time: check again, then write without following a link.
    local = check_host_path(local_path)
    local.parent.mkdir(parents=True, exist_ok=True)
    _write_download(local, file_data)

    logger.info(
        "Downloaded %d bytes from '%s:%s' to '%s'",
        len(file_data), vm_name, guest_path, local_path,
    )
    return (
        f"Downloaded {len(file_data)} bytes from {guest_path} "
        f"on VM '{vm_name}' to {local_path}"
    )


def _guest_download_bytes(
    si: ServiceInstance,
    vm_name: str,
    guest_path: str,
    username: str,
    password: str,
) -> bytes:
    """Fetch a guest file into memory via VMware Tools (no host file involved)."""
    import ssl
    import urllib.request

    vm = _require_vm_with_tools(si, vm_name)
    fm = si.RetrieveContent().guestOperationsManager.fileManager
    auth = _guest_auth(username, password)

    transfer_info = fm.InitiateFileTransferFromGuest(vm, auth, guest_path)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Lab/ESXi self-signed certs  # nosec B501

    resp = urllib.request.urlopen(transfer_info.url, context=ctx)  # nosec B310
    return resp.read()


def _read_upload_source(local: Path) -> bytes:
    """Read an upload source without following a link swapped in after the check.

    ``O_NOFOLLOW`` refuses a final symlink, ``O_NONBLOCK`` keeps a FIFO from
    blocking the worker, and anything but a single regular file is refused
    (a hard link shares its inode with another path, possibly a protected one).
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(local, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Local upload source is not a regular file: {local}")
        if st.st_nlink > 1:
            raise ValueError(
                f"Local upload source is a hard link: {local}. Copy the file and upload the copy."
            )
        with os.fdopen(fd, "rb") as f:
            fd = -1
            return f.read()
    finally:
        if fd != -1:
            os.close(fd)


def _write_download(local: Path, data: bytes) -> None:
    """Write a downloaded file without following a link swapped in after the check.

    The destination must end up a single regular file; it is truncated only
    after that is verified on the open descriptor.
    """
    flags = (
        os.O_WRONLY | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(local, flags, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
            raise ValueError(
                "Choose a new local path: the destination is a hard link or not a regular "
                f"file, so writing it would change another file too. Path: {local}"
            )
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
    finally:
        if fd != -1:
            os.close(fd)
