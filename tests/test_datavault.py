import os
import pytest
from pathlib import Path
import tempfile
from click.testing import CliRunner

from datavault import KEEPFILE, __version__
from datavault import cli
from datavault import DataVault

DATAVAULT_SECRET = DataVault.generate_secret()


@pytest.fixture
def stub_secret(monkeypatch):
    def secret():
        return DATAVAULT_SECRET

    monkeypatch.setattr(DataVault, "generate_secret", secret)


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli.main, "--version")
    assert result.exit_code == 0
    assert result.output.find(__version__) > 0


def test_cli_new(stub_secret):
    path = str(Path(tempfile.mkdtemp()) / "vault")
    runner = CliRunner()
    result = runner.invoke(cli.main, ["new", path], catch_exceptions=False)
    assert result.exit_code == 0
    assert result.output.find(DATAVAULT_SECRET) > 0
    assert DataVault(path).exists()

    # Attempt to create second data vault at same path
    # which should fail
    result = runner.invoke(cli.main, ["new", path])
    assert result.exit_code == 1


def test_cli_secret(stub_secret):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["secret"])
    assert result.exit_code == 0
    assert result.output.find(DATAVAULT_SECRET) > 0


def test_cli_encrypt_decrypt():
    """
    This is a throughout test of CLI and DataVault API.
    """

    #
    # Create a new vault
    #

    path = str(Path(tempfile.mkdtemp()) / "vault")
    runner = CliRunner()
    result = runner.invoke(cli.main, ["new", path])
    assert result.exit_code == 0

    vault = DataVault(path)
    assert vault.exists()

    assert vault.is_decrypted_dir_empty()

    # assert the length of the files in the encrypted directory is 0
    assert len(os.listdir(vault.encrypted_dir)) == 0

    #
    # Add some files to the vault
    #

    with open(Path(vault.decrypted_dir) / "test1.txt", "w") as f:
        f.write("test1")

    with open(Path(vault.decrypted_dir) / "test2.txt", "w") as f:
        f.write("test2")

    assert vault.has_changes()
    changes = vault.changes()
    assert changes["total"] == 2
    assert changes["additions"] == ["test1.txt", "test2.txt"]
    assert changes["deletions"] == []
    assert changes["updates"] == []

    #
    # Encrypt the vault
    #

    result = runner.invoke(
        cli.main, ["encrypt", path], env={"DATAVAULT_SECRET": DATAVAULT_SECRET}
    )
    assert result.exit_code == 0

    # Ensure the files are encrypted
    assert os.path.exists(Path(vault.encrypted_dir) / "test1.txt")
    assert os.path.exists(Path(vault.encrypted_dir) / "test2.txt")

    # Ensure the files are listed in the manifest
    with open(vault.vault_manifest_path, "r") as f:
        manifest = f.read()
        assert manifest.find("test1.txt") > 0
        assert manifest.find("test2.txt") > 0

    # The encrypted file is not the same as the decrypted file
    assert not os.path.samefile(
        Path(vault.encrypted_dir) / "test1.txt", Path(vault.decrypted_dir) / "test1.txt"
    )

    # Delete all files in the decrypted dir
    for f in vault.decrypted_dir.iterdir():
        if not f == KEEPFILE:
            f.unlink()

    # The encrypted directory should be empty even though the keepfile is present
    assert vault.is_decrypted_dir_empty()

    #
    # Decrypt the vault
    #

    result = runner.invoke(
        cli.main, ["decrypt", "-f", path], env={"DATAVAULT_SECRET": DATAVAULT_SECRET}
    )
    assert result.exit_code == 0

    # assert the contents of the decrypted file is the same as the original
    with open(Path(vault.decrypted_dir) / "test1.txt", "r") as f:
        assert f.read() == "test1"

    with open(Path(vault.decrypted_dir) / "test2.txt", "r") as f:
        assert f.read() == "test2"

    #
    # Delete and update a file in the vault
    #

    os.remove(Path(vault.decrypted_dir) / "test1.txt")

    with open(Path(vault.decrypted_dir) / "test2.txt", "w") as f:
        f.write("test2 updated")

    assert vault.has_changes()
    changes = vault.changes()

    assert changes["total"] == 2
    assert changes["additions"] == []
    assert changes["deletions"] == ["test1.txt"]
    assert changes["updates"] == ["test2.txt"]

    #
    # Encrypt the vault again
    #

    result = runner.invoke(
        cli.main, ["encrypt", path], env={"DATAVAULT_SECRET": DATAVAULT_SECRET}
    )
    assert result.exit_code == 0

    # test1.txt should be deleted from the encrypted directory
    assert not os.path.exists(Path(vault.encrypted_dir) / "test1.txt")
    # test2.txt should be updated in the encrypted directory
    assert os.path.exists(Path(vault.encrypted_dir) / "test2.txt")

    # Ensure the files are listed in the manifest
    with open(vault.vault_manifest_path, "r") as f:
        manifest = f.read()
        assert manifest.find("test1.txt") == -1
        assert manifest.find("test2.txt") > 0

    # Delete all decrypted files
    for f in vault.decrypted_dir.iterdir():
        if not f == KEEPFILE:
            f.unlink()

    #
    # Decrypt the vault again and verify its contents
    #

    result = runner.invoke(
        cli.main, ["decrypt", "-f", path], env={"DATAVAULT_SECRET": DATAVAULT_SECRET}
    )
    assert result.exit_code == 0

    # test1.txt should be deleted from the decrypted directory
    assert not os.path.exists(Path(vault.decrypted_dir) / "test1.txt")
    # test2.txt should have the updated text
    with open(Path(vault.decrypted_dir) / "test2.txt", "r") as f:
        assert f.read() == "test2 updated"
