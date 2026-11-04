"""Principal directory validation and file-permission checks (audit finding H3)."""

import json
import os
import sys

import pytest
from secure_support import ISSUER, directory_json, write_private_file

from agentheist.secure import auth
from agentheist.secure.auth import ConfigurationError, PrincipalDirectory

posix_only = pytest.mark.skipif(os.name != "posix", reason="permission checks are POSIX-only")


def load(tmp_path, content: str, mode: int = 0o600) -> PrincipalDirectory:
    return PrincipalDirectory.from_file(write_private_file(tmp_path / "principals.json", content, mode),
                                        trusted_issuer=ISSUER)


def test_valid_directory_loads(tmp_path):
    directory = load(tmp_path, directory_json(("alice", ["customer"]), ("sam", ["staff", "customer"])))
    assert directory.roles_for(ISSUER, "alice") == {"customer"}
    assert directory.roles_for(ISSUER, "sam") == {"staff", "customer"}
    assert directory.roles_for(ISSUER, "nobody") == frozenset()


def test_empty_principal_list_is_allowed_and_denies_everyone(tmp_path):
    assert load(tmp_path, '{"principals": []}').roles_for(ISSUER, "alice") == frozenset()


def test_duplicate_identity_is_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match=r"principals\[1\].*duplicate identity"):
        load(tmp_path, directory_json(("sam", ["staff"]), ("sam", ["customer"])))


@pytest.mark.parametrize("content", [
    '{"principals": [], "principals": []}',
    '{"principals": [{"issuer": "%s", "subject": "a", "subject": "b", "roles": ["customer"]}]}' % ISSUER,
])
def test_duplicate_json_keys_are_rejected(tmp_path, content):
    with pytest.raises(ConfigurationError, match="duplicate JSON keys"):
        load(tmp_path, content)


@pytest.mark.parametrize("document", [
    [],
    {},
    {"principals": {}},
    {"principals": [], "extra": 1},
    {"principals": ["alice"]},
    {"principals": [{"issuer": ISSUER, "subject": "alice"}]},
    {"principals": [{"issuer": ISSUER, "subject": "alice", "roles": ["customer"], "admin": True}]},
    {"principals": [{"issuer": ISSUER, "subject": "alice", "roles": "customer"}]},
    {"principals": [{"issuer": ISSUER, "subject": "alice", "roles": []}]},
    {"principals": [{"issuer": ISSUER, "subject": "alice", "roles": [1]}]},
    {"principals": [{"issuer": ISSUER, "subject": "alice", "roles": ["customer", "customer"]}]},
    {"principals": [{"issuer": ISSUER, "subject": 42, "roles": ["customer"]}]},
    {"principals": [{"issuer": ISSUER, "subject": "", "roles": ["customer"]}]},
    {"principals": [{"issuer": ISSUER, "subject": "a\nb", "roles": ["customer"]}]},
    {"principals": [{"issuer": ISSUER, "subject": "x" * 256, "roles": ["customer"]}]},
])
def test_malformed_records_are_rejected(tmp_path, document):
    with pytest.raises(ConfigurationError):
        load(tmp_path, json.dumps(document))


def test_unknown_role_is_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="unknown roles"):
        load(tmp_path, directory_json(("alice", ["superadmin"])))


def test_issuer_mismatch_is_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="trusted issuer"):
        load(tmp_path, directory_json(("alice", ["customer"]), issuer="https://other-idp.test.invalid"))


@pytest.mark.parametrize("content", ["not json", "\xff\xfe", '{"principals": [}'])
def test_invalid_json_is_rejected(tmp_path, content):
    with pytest.raises(ConfigurationError, match="not valid UTF-8 JSON"):
        PrincipalDirectory.from_file(
            write_private_file(tmp_path / "p.json", content.encode("latin-1")), trusted_issuer=ISSUER)


def test_oversized_file_is_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="larger than"):
        load(tmp_path, " " * (auth.MAX_DIRECTORY_BYTES + 1))


def test_missing_file_is_a_configuration_error(tmp_path):
    with pytest.raises(ConfigurationError, match="cannot read file"):
        PrincipalDirectory.from_file(tmp_path / "missing.json", trusted_issuer=ISSUER)


def test_errors_do_not_echo_file_contents(tmp_path):
    with pytest.raises(ConfigurationError) as excinfo:
        load(tmp_path, directory_json(("alice", ["customer"]), ("alice", ["staff"])))
    assert "alice" not in str(excinfo.value)


@posix_only
@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_group_or_world_writable_file_is_rejected(tmp_path, mode):
    with pytest.raises(ConfigurationError, match="writable"):
        load(tmp_path, directory_json(("alice", ["customer"])), mode=mode)


@posix_only
def test_read_only_for_others_is_accepted(tmp_path):
    assert load(tmp_path, directory_json(("alice", ["customer"])), mode=0o644).roles_for(ISSUER, "alice")


@posix_only
def test_file_owned_by_another_user_is_rejected(tmp_path, monkeypatch):
    path = write_private_file(tmp_path / "p.json", directory_json(("alice", ["customer"])))
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(path).st_uid + 1)  # pretend the server runs as someone else
    if os.stat(path).st_uid == 0:
        pytest.skip("running as root: root-owned files are accepted by design")
    with pytest.raises(ConfigurationError, match="owned by"):
        PrincipalDirectory.from_file(path, trusted_issuer=ISSUER)


@posix_only
def test_world_writable_parent_without_sticky_bit_is_rejected(tmp_path):
    folder = tmp_path / "shared"
    folder.mkdir()
    os.chmod(folder, 0o777)
    path = write_private_file(folder / "p.json", directory_json(("alice", ["customer"])))
    with pytest.raises(ConfigurationError, match="world-writable"):
        PrincipalDirectory.from_file(path, trusted_issuer=ISSUER)
    os.chmod(folder, 0o1777)  # sticky bit: other users cannot replace the file
    assert PrincipalDirectory.from_file(path, trusted_issuer=ISSUER).roles_for(ISSUER, "alice")


@posix_only
def test_non_regular_file_is_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="regular file"):
        PrincipalDirectory.from_file(tmp_path, trusted_issuer=ISSUER)


@posix_only
@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_symlink_to_a_safe_file_is_followed(tmp_path):
    target = write_private_file(tmp_path / "real.json", directory_json(("alice", ["customer"])))
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert PrincipalDirectory.from_file(link, trusted_issuer=ISSUER).roles_for(ISSUER, "alice")


def test_in_memory_directory_enforces_the_same_rules():
    with pytest.raises(ConfigurationError):
        PrincipalDirectory({(ISSUER, "bad\rsubject"): ["customer"]})
    with pytest.raises(ConfigurationError):
        PrincipalDirectory({("https://other.test.invalid", "alice"): ["customer"]}, trusted_issuer=ISSUER)
