import subprocess
import os
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from dihi_datavault import DataVault, __version__, cli

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
    path = "vault"
    runner = CliRunner()
    with runner.isolated_filesystem() as tempdir:
        result = runner.invoke(cli.main, ["new", path])
        # The command shoul hae succeeded
        assert result.exit_code == 0
        # The secret should have been out output
        assert result.output.find(DATAVAULT_SECRET) > 0

        vault = DataVault(Path(tempdir) / "vault")
        assert vault.verify()

        gitignore = Path(tempdir) / "vault" / ".gitignore"
        assert gitignore.exists()

        result = runner.invoke(cli.main, ["new", path])
        assert result.exit_code == 1


def test_gitignore(stub_secret):
    path = "vault"
    runner = CliRunner()
    with runner.isolated_filesystem() as tempdir:
        result = runner.invoke(cli.main, ["new", path])

        assert result.exit_code == 0

        vault = DataVault(Path(tempdir) / path)

        result = subprocess.run(["cat", "vault/.gitignore"], capture_output=True)
        assert result.returncode == 0

        gitignore_contents = result.stdout.decode("utf-8")

        # Write some data to the vault
        with open(Path(vault.root_path) / "test1.txt", "w") as f:
            f.write("test1")
        with open(Path(vault.root_path) / "test2.txt", "w") as f:
            f.write("test2")
        result = subprocess.run(["git", "init"], cwd=tempdir)
        assert result.returncode == 0
        result = subprocess.run(["git", "add", "."], cwd=tempdir, capture_output=True)
        assert result.returncode == 0
        result = subprocess.run(["git", "status"], cwd=tempdir, capture_output=True)
        assert result.returncode == 0
        message = result.stdout.decode("utf-8")

        # test1.txt and test2.txt should not be in the git status output
        assert "test1.txt" not in message
        assert "test2.txt" not in message
        assert "vault/.encrypted/vault_manifest.json" in message


def test_cli_secret(stub_secret):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["secret"])
    assert result.exit_code == 0
    assert result.output.find(DATAVAULT_SECRET) > 0


def test_cli_encrypt_decrypt():
    """
    This is a throughout test of CLI and DataVault API.
    """
    path = "test_vault"
    runner = CliRunner()

    with runner.isolated_filesystem():
        #
        # Create a new vault
        #
        result = runner.invoke(cli.main, ["new", path])
        assert result.exit_code == 0

        vault = DataVault(path)
        assert vault.verify()
        assert vault.is_empty()

        assert len(os.listdir(vault.encrypted_path)) == 1
        assert DataVault.MANIFEST_FILENAME in os.listdir(vault.encrypted_path)

        #
        # Add some files to the vault
        #

        with open(Path(vault.root_path) / "test1.txt", "w") as f:
            f.write("test1")

        with open(Path(vault.root_path) / "test2.txt", "w") as f:
            f.write("test2")

        assert vault.has_changes()
        changes = vault.changes()
        assert vault.verify()
        assert changes["total"] == 2
        assert list(sorted(changes["additions"])) == ["test1.txt", "test2.txt"]
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
        assert os.path.exists(Path(vault.encrypted_path) / "test1.txt")
        assert os.path.exists(Path(vault.encrypted_path) / "test2.txt")

        # Ensure the files are listed in the manifest
        with open(vault.vault_manifest_path, "r") as f:
            manifest = f.read()
            assert manifest.find("test1.txt") > 0
            assert manifest.find("test2.txt") > 0

        # The encrypted file is not the same as the decrypted file
        assert not os.path.samefile(
            Path(vault.encrypted_path) / "test1.txt",
            Path(vault.root_path) / "test1.txt",
        )

        # Delete all decrypted files
        vault.clear()

        # The encrypted directory should be empty even though the keepfile is present
        assert vault.is_empty()

        #
        # Decrypt the vault
        #

        result = runner.invoke(
            cli.main,
            ["decrypt", "-f", path],
            env={"DATAVAULT_SECRET": DATAVAULT_SECRET},
        )
        assert result.exit_code == 0

        # assert the contents of the decrypted file is the same as the original
        with open(Path(vault.root_path) / "test1.txt", "r") as f:
            assert f.read() == "test1"

        with open(Path(vault.root_path) / "test2.txt", "r") as f:
            assert f.read() == "test2"

        #
        # Delete and update a file in the vault
        #

        os.remove(Path(vault.root_path) / "test1.txt")

        with open(Path(vault.root_path) / "test2.txt", "w") as f:
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
        assert vault.verify()

        # test1.txt should be deleted from the encrypted directory
        assert not os.path.exists(Path(vault.encrypted_path) / "test1.txt")
        # test2.txt should be updated in the encrypted directory
        assert os.path.exists(Path(vault.encrypted_path) / "test2.txt")

        # Ensure the files are listed in the manifest
        with open(vault.vault_manifest_path, "r") as f:
            manifest = f.read()
            assert manifest.find("test1.txt") == -1
            assert manifest.find("test2.txt") > 0

        # Delete all decrypted files
        vault.clear()

        #
        # Decrypt the vault again and verify its contents
        #

        result = runner.invoke(
            cli.main,
            ["decrypt", "-f", path],
            env={"DATAVAULT_SECRET": DATAVAULT_SECRET},
        )
        assert result.exit_code == 0
        assert vault.verify()
        # test1.txt should be deleted from the decrypted directory
        assert not os.path.exists(Path(vault.root_path) / "test1.txt")
        # test2.txt should have the updated text
        with open(Path(vault.root_path) / "test2.txt", "r") as f:
            assert f.read() == "test2 updated"


def test_clearing():

    #
    # Create a new vault
    #

    path = "test_clearing_vault"
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli.main, ["new", path])
        assert result.exit_code == 0

        vault = DataVault(path)
        assert vault.verify()
        assert vault.is_empty()

        assert len(os.listdir(vault.encrypted_path)) == 1
        assert DataVault.MANIFEST_FILENAME in os.listdir(vault.encrypted_path)

        #
        # Add some files to the vault
        #

        with open(Path(vault.root_path) / "test1.txt", "w") as f:
            f.write("test1")

        with open(Path(vault.root_path) / "test2.txt", "w") as f:
            f.write("test2")

        assert vault.has_changes()
        changes = vault.changes()
        assert changes["total"] == 2
        assert list(sorted(changes["additions"])) == ["test1.txt", "test2.txt"]
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
        assert os.path.exists(Path(vault.encrypted_path) / "test1.txt")
        assert os.path.exists(Path(vault.encrypted_path) / "test2.txt")

        result = runner.invoke(
            cli.main,
            ["clear-decrypted", "-f", path],
            env={"DATAVAULT_SECRET": DATAVAULT_SECRET},
        )
        assert result.exit_code == 0
        assert not os.path.exists(Path(vault.root_path) / "test1.txt")
        assert not os.path.exists(Path(vault.root_path) / "test2.txt")

        changes = vault.changes()

        assert changes["total"] == 2
        assert list(sorted(changes["deletions"])) == ["test1.txt", "test2.txt"]

        result = runner.invoke(
            cli.main,
            ["clear-encrypted", path, "--force"],
            env={"DATAVAULT_SECRET": DATAVAULT_SECRET},
        )

        changes = vault.changes()
        assert changes["total"] == 0
        assert changes["deletions"] == []
