import tempfile
from pathlib import Path

import pytest

from dihi_datavault import DataVault

DATAVAULT_SECRET = DataVault.generate_secret()


@pytest.fixture
def stub_secret(monkeypatch):
    def secret():
        return DATAVAULT_SECRET

    monkeypatch.setattr(DataVault, "generate_secret", secret)


@pytest.fixture
def vault():
    path = str(Path(tempfile.mkdtemp()) / "vault")
    vault = DataVault(path)
    vault.create()
    return vault


def test_vault_paths(vault: DataVault):
    assert Path(vault.root_path).exists()
    assert Path(vault.encrypted_path).exists()
    assert Path(vault.vault_manifest_path).exists()
    assert Path(vault.root_path / ".gitignore").exists()


def test_files(vault: DataVault):
    assert vault.files() == []
    assert vault.is_empty()

    # Add a file to the vault
    with open(str(vault.root_path / "test.txt"), "w") as f:
        f.write("test")

    assert vault.files() == ["test.txt"]


def test_encrypt_decrypt(vault: DataVault):
    assert vault.is_empty()

    with open(str(vault.root_path / "test.txt"), "w") as f:
        f.write("test")

    assert vault.files() == ["test.txt"]
    assert vault.encrypted_files() == []
    assert vault.changes()["additions"] == ["test.txt"]

    vault.encrypt(DATAVAULT_SECRET)

    assert vault.files() == ["test.txt"]
    assert vault.encrypted_files() == ["test.txt"]
    assert vault.changes()["additions"] == []
