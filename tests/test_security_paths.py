"""Reproduction tests for the host-path and plan-id hardening.

Ported from the intent of upstream v2.3.2 (vmware-skills/VMware-AIops):

* ``plan_id`` must never name a path outside the plans directory.
* Guest upload/download, OVA and deploy-spec paths on the MCP host must stay
  inside a dedicated file root (``VMWARE_MCP_FILE_ROOT``), with symlinks
  resolved before the check.

No test talks to vCenter: the ServiceInstance is a MagicMock, and every
refusal test asserts it was never touched.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from vmware_aiops.ops import guest_ops, planner, vm_deploy

try:  # absent before the fix: every test that needs it must FAIL, not skip
    from vmware_aiops import hostpaths
except ImportError:  # pragma: no cover - only true in the red phase
    hostpaths = SimpleNamespace()  # attribute access raises AttributeError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def plans_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "home" / ".vmware-aiops" / "plans"
    d.mkdir(parents=True)
    monkeypatch.setattr(planner, "_PLANS_DIR", d)
    return d


@pytest.fixture()
def file_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "files"
    root.mkdir()
    monkeypatch.setenv("VMWARE_MCP_FILE_ROOT", str(root))
    return root


@pytest.fixture()
def outside(tmp_path: Path) -> Path:
    """A real file outside the root, standing in for /etc/shadow or a .env."""
    secret = tmp_path / "secret.env"
    secret.write_text("TOKEN=not-for-guests\n")
    return secret


def _untouched_si() -> MagicMock:
    return MagicMock(name="ServiceInstance")


# ---------------------------------------------------------------------------
# plan_id
# ---------------------------------------------------------------------------

BAD_PLAN_IDS = [
    "../../etc/passwd",
    "../outside",
    "plan-20260101-000000-abcd/../../x",
    "plan-../../x",
    "/etc/shadow",
    "plan-20260101-000000-abcd.json",
    "plan-20260101-000000-abcd\x00",
    "",
    "plan-",
    "x" * 300,
]


@pytest.mark.parametrize("bad", BAD_PLAN_IDS)
def test_load_plan_rejects_path_like_id(plans_dir: Path, bad: str) -> None:
    with pytest.raises(ValueError):
        planner.load_plan(bad)


@pytest.mark.parametrize("bad", BAD_PLAN_IDS)
def test_delete_plan_rejects_path_like_id(plans_dir: Path, tmp_path: Path, bad: str) -> None:
    victim = plans_dir.parent / "outside.json"
    victim.write_text("{}")
    with pytest.raises(ValueError):
        planner.delete_plan(bad)
    assert victim.exists()


@pytest.mark.parametrize("bad", BAD_PLAN_IDS)
def test_save_plan_rejects_path_like_id(plans_dir: Path, bad: str) -> None:
    before = {p for p in plans_dir.parent.rglob("*")}
    with pytest.raises(ValueError):
        planner.save_plan({"plan_id": bad, "status": "pending"})
    assert {p for p in plans_dir.parent.rglob("*")} == before


def test_apply_plan_rejects_traversal_id_without_vcenter(plans_dir: Path) -> None:
    from vmware_aiops.ops.plan_executor import apply_plan, rollback_plan

    si = _untouched_si()
    with pytest.raises(ValueError):
        apply_plan(si, "../../etc/passwd")
    with pytest.raises(ValueError):
        rollback_plan(si, "../../etc/passwd")
    assert si.mock_calls == []


def test_load_plan_refuses_file_whose_stored_id_differs(plans_dir: Path) -> None:
    good = planner._generate_plan_id()
    (plans_dir / f"{good}.json").write_text('{"plan_id": "../../evil", "status": "pending"}')
    with pytest.raises(ValueError):
        planner.load_plan(good)


def test_generated_plan_id_round_trips(plans_dir: Path) -> None:
    pid = planner._generate_plan_id()
    planner.save_plan({"plan_id": pid, "status": "pending"})
    assert (plans_dir / f"{pid}.json").is_file()
    assert planner.load_plan(pid) == {"plan_id": pid, "status": "pending"}
    planner.delete_plan(pid)
    assert planner.load_plan(pid) is None


def test_unknown_but_well_formed_plan_id_is_not_found(plans_dir: Path) -> None:
    assert planner.load_plan("plan-20260101-000000-abcd") is None


# ---------------------------------------------------------------------------
# check_host_path
# ---------------------------------------------------------------------------


def test_default_file_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VMWARE_MCP_FILE_ROOT", raising=False)
    assert hostpaths.file_root() == Path("/var/lib/vmware-aiops/files")


@pytest.mark.parametrize(
    "bad",
    [
        "/etc/passwd",
        "/root/.vmware-aiops/.env",
        "~/.vmware-aiops/.env",
        "../secret.env",
        "sub/../../secret.env",
        "",
        ".",
    ],
)
def test_path_outside_root_rejected(file_root: Path, bad: str) -> None:
    with pytest.raises(hostpaths.HostPathRefusedError):
        hostpaths.check_host_path(bad)


def test_root_itself_rejected(file_root: Path) -> None:
    with pytest.raises(hostpaths.HostPathRefusedError):
        hostpaths.check_host_path(str(file_root))


def test_sibling_with_root_prefix_rejected(file_root: Path) -> None:
    sibling = file_root.parent / (file_root.name + "-evil")
    sibling.mkdir()
    with pytest.raises(hostpaths.HostPathRefusedError):
        hostpaths.check_host_path(str(sibling / "x.ova"))


def test_symlink_inside_root_pointing_outside_rejected(file_root: Path, outside: Path) -> None:
    link = file_root / "innocent.ova"
    link.symlink_to(outside)
    with pytest.raises(hostpaths.HostPathRefusedError):
        hostpaths.check_host_path(str(link))


def test_symlinked_directory_inside_root_rejected(file_root: Path, outside: Path) -> None:
    (file_root / "dir").symlink_to(outside.parent)
    with pytest.raises(hostpaths.HostPathRefusedError):
        hostpaths.check_host_path(str(file_root / "dir" / outside.name))


def test_root_set_to_filesystem_root_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VMWARE_MCP_FILE_ROOT", "/")
    with pytest.raises(hostpaths.HostPathRefusedError):
        hostpaths.check_host_path("/etc/passwd")


def test_absolute_path_inside_root_accepted(file_root: Path) -> None:
    target = file_root / "images" / "a.ova"
    assert hostpaths.check_host_path(str(target)) == target.resolve()


def test_relative_path_is_taken_under_root(file_root: Path) -> None:
    assert hostpaths.check_host_path("keys/id.pub") == (file_root / "keys" / "id.pub").resolve()


# ---------------------------------------------------------------------------
# Ops entry points: refused before vCenter is touched
# ---------------------------------------------------------------------------


def test_guest_upload_outside_root_refused(file_root: Path, outside: Path) -> None:
    si = _untouched_si()
    with pytest.raises(hostpaths.HostPathRefusedError):
        guest_ops.guest_upload(si, "vm1", str(outside), "/tmp/x", "u", "p")
    assert si.mock_calls == []


def test_guest_download_outside_root_refused(file_root: Path, tmp_path: Path) -> None:
    si = _untouched_si()
    dest = tmp_path / "cron.d" / "evil"
    with pytest.raises(hostpaths.HostPathRefusedError):
        guest_ops.guest_download(si, "vm1", "/etc/hostname", str(dest), "u", "p")
    assert si.mock_calls == []
    assert not dest.exists()


def test_guest_download_through_symlink_refused(file_root: Path, outside: Path) -> None:
    si = _untouched_si()
    (file_root / "out.txt").symlink_to(outside)
    with pytest.raises(hostpaths.HostPathRefusedError):
        guest_ops.guest_download(si, "vm1", "/etc/hostname", str(file_root / "out.txt"), "u", "p")
    assert si.mock_calls == []
    assert outside.read_text() == "TOKEN=not-for-guests\n"


def test_deploy_ova_outside_root_refused(file_root: Path, outside: Path) -> None:
    si = _untouched_si()
    with pytest.raises(hostpaths.HostPathRefusedError):
        vm_deploy.deploy_ova(si, str(outside), "vm1", "ds1")
    assert si.mock_calls == []


def test_deploy_spec_outside_root_refused(file_root: Path, outside: Path) -> None:
    with pytest.raises(hostpaths.HostPathRefusedError):
        vm_deploy.load_deploy_spec(str(outside))


def test_provision_refuses_bad_upload_before_running_any_step(
    file_root: Path, outside: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        guest_ops, "guest_exec_with_output",
        lambda *a, **k: calls.append("exec") or {"exit_code": 0, "stdout": "", "timed_out": False},
    )
    result = guest_ops.guest_provision(
        _untouched_si(), "vm1", "u", "p",
        steps=[
            {"type": "exec", "command": "touch /tmp/marker"},
            {"type": "upload", "local_path": str(outside), "guest_path": "/root/x"},
        ],
    )
    assert result["success"] is False
    assert calls == []


def test_plan_validation_flags_host_path_outside_root(file_root: Path, outside: Path) -> None:
    errors = planner.validate_operations([
        {"action": "guest_upload", "vm_name": "vm1", "local_path": str(outside),
         "guest_path": "/x", "username": "u", "password": "p"},
        {"action": "guest_download", "vm_name": "vm1", "local_path": "/etc/cron.d/x",
         "guest_path": "/x", "username": "u", "password": "p"},
        {"action": "deploy_ova", "ova_path": "/etc/passwd", "vm_name": "v",
         "datastore_name": "d", "network_name": "n"},
    ])
    assert len(errors) == 3


def test_plan_validation_accepts_path_inside_root(file_root: Path) -> None:
    assert planner.validate_operations([
        {"action": "guest_upload", "vm_name": "vm1", "local_path": "keys/id.pub",
         "guest_path": "/x", "username": "u", "password": "p"},
    ]) == []


# ---------------------------------------------------------------------------
# Ops entry points: valid paths still work (vCenter mocked)
# ---------------------------------------------------------------------------


def _fake_vcenter(monkeypatch: pytest.MonkeyPatch, download_bytes: bytes = b"") -> dict:
    """Mock just enough of the guest-ops call chain; record what is sent."""
    sent: dict = {}
    monkeypatch.setattr(guest_ops, "_require_vm_with_tools", lambda si, name: object())
    monkeypatch.setattr(guest_ops, "_guest_auth", lambda u, p: object())

    import urllib.request

    def fake_urlopen(req, context=None):
        if isinstance(req, urllib.request.Request):
            sent["data"] = req.data
            return SimpleNamespace(read=lambda: b"")
        return SimpleNamespace(read=lambda: download_bytes)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return sent


def _si_with_file_manager() -> MagicMock:
    si = MagicMock(name="ServiceInstance")
    fm = si.RetrieveContent.return_value.guestOperationsManager.fileManager
    fm.InitiateFileTransferToGuest.return_value = "https://esxi/upload"
    fm.InitiateFileTransferFromGuest.return_value = SimpleNamespace(url="https://esxi/download")
    return si


def test_guest_upload_inside_root_accepted(
    file_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = file_root / "id.pub"
    src.write_bytes(b"ssh-ed25519 AAAA test")
    sent = _fake_vcenter(monkeypatch)
    msg = guest_ops.guest_upload(_si_with_file_manager(), "vm1", "id.pub", "/root/k", "u", "p")
    assert sent["data"] == b"ssh-ed25519 AAAA test"
    assert f"Uploaded {len(b'ssh-ed25519 AAAA test')} bytes" in msg


def test_guest_upload_hard_link_refused(
    file_root: Path, outside: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = file_root / "hard.txt"
    os.link(outside, link)
    _fake_vcenter(monkeypatch)
    with pytest.raises(ValueError):
        guest_ops.guest_upload(_si_with_file_manager(), "vm1", str(link), "/x", "u", "p")


def test_guest_download_inside_root_accepted(
    file_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_vcenter(monkeypatch, download_bytes=b"hello")
    guest_ops.guest_download(_si_with_file_manager(), "vm1", "/etc/hostname", "out/h.txt", "u", "p")
    assert (file_root / "out" / "h.txt").read_bytes() == b"hello"


def test_exec_output_capture_does_not_need_the_file_root(
    file_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """guest_exec_with_output fetches its own temp file; the root must not block it."""
    _fake_vcenter(monkeypatch, download_bytes=b"up 3 days\n")
    monkeypatch.setattr(
        guest_ops, "guest_exec",
        lambda *a, **k: {"exit_code": 0, "timed_out": False},
    )
    monkeypatch.setattr(
        guest_ops, "_require_vm_with_tools",
        lambda si, name: SimpleNamespace(guest=SimpleNamespace(guestFamily="linuxGuest")),
    )
    out = guest_ops.guest_exec_with_output(_si_with_file_manager(), "vm1", "uptime", "u", "p")
    assert out["stdout"] == "up 3 days"
    assert out["exit_code"] == 0
