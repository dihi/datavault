import hashlib
import json
import os
import struct
import sys
import textwrap
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Union

import cryptography
from cryptography.fernet import Fernet

if sys.version_info < (3, 8):
    TypedDict = dict
else: 
    from typing import TypedDict

__version__ = "1.0.0"

#
# Helpers
#


def md5_hash_for_file(filepath):
    return hashlib.md5(open(filepath, "rb").read()).hexdigest()


def encrypt(key: str, fin: Union[str, Path], fout: Union[str, Path], *, block=1 << 16):
    """
    Encrypts a file in chunks to support large file sizes.

    :param key: The key to use for encryption
    :param fin: The file to encrypt
    :param fout: The encrypted file to write to
    """
    fernet = cryptography.fernet.Fernet(key)
    with open(fin, "rb") as fi, open(fout, "wb") as fo:
        while True:
            chunk = fi.read(block)
            if len(chunk) == 0:
                break
            enc = fernet.encrypt(chunk)
            fo.write(struct.pack("<I", len(enc)))
            fo.write(enc)
            if len(chunk) < block:
                break


def decrypt(key: str, fin: Union[str, Path], fout: Union[str, Path]):
    """
    Decrypts a file in chunks to support large file sizes.

    :param key: The key to use for decryption
    :param fin: The encrypted file to decrypt
    :param fout: The decrypted file to write to
    """
    fernet = cryptography.fernet.Fernet(key)
    with open(fin, "rb") as fi, open(fout, "wb") as fo:
        while True:
            size_data = fi.read(4)
            if len(size_data) == 0:
                break
            chunk = fi.read(struct.unpack("<I", size_data)[0])
            dec = fernet.decrypt(chunk)
            fo.write(dec)

class VaultManifest(TypedDict):
    """
    A VaultManifest is a dictionary of files and their hashes.
    """

    # Used as a notice to indicate the file is machien generated
    _: str
    # The version of the manifest, used for backwards compatibility
    version: str
    # The list of file hashes in the vault
    files: Dict[str, str]


class VaultChangeSet(TypedDict):
    total: int
    additions: List[str]
    deletions: List[str]
    updates: List[str]
    unchanged: List[str]


#
# DataVault
#


class DataVault:
    VERSION = 1
    MANIFEST_FILENAME = "vault_manifest.json"
    ENCRYPTED_NAMESPACE = ".encrypted"

    @staticmethod
    def find_all(path: Union[str, Path]) -> List["DataVault"]:
        """
        Returns a list of all vaults in the given path.
        """
        # Search path for vault manifests
        manifest_paths = [
            path
            for path in Path(path).rglob(
                f"{DataVault.ENCRYPTED_NAMESPACE}/{DataVault.MANIFEST_FILENAME}"
            )
            if DataVault.verify_manifest(path)
        ]
        vault_dirs = [Path(path).parent.parent for path in manifest_paths]
        vaults = [DataVault(path) for path in sorted(vault_dirs)]
        return vaults

    @staticmethod
    def verify_manifest(vault_manifest_path: Union[str, Path]) -> bool:
        """
        Verifies that the vault manifest is valid.
        """
        try:
            with open(vault_manifest_path, "r") as f:
                manifest = json.load(f)
        except Exception as e:
            return False

        if not isinstance(manifest.get("_"), str):
            return False

        if not isinstance(manifest.get("files"), dict):
            return False

        return manifest.get("version") == DataVault.VERSION

    @staticmethod
    def generate_secret() -> str:
        """
        Generates a fresh vault key. Keep this some place safe! If you lose it
        you'll no longer be able to decrypt vaults; if anyone else gains
        access to it, they'll be able to decrypt all of your messages, and
        they'll also be able forge arbitrary messages that will be
        authenticated and decrypted.
        """
        return Fernet.generate_key().decode("utf-8")

    def __init__(self, path: Union[str, Path]):
        self.root_path = Path(path)
        self.encrypted_path = self.root_path / DataVault.ENCRYPTED_NAMESPACE
        self.vault_manifest_path = self.encrypted_path / DataVault.MANIFEST_FILENAME

    def create(self) -> str:
        """
        Creates the file paths for a new vault with an empty manifest.

        This method will not work if there are already files in the
        vaults standard paths.
        """

        # Create vault storage paths
        self.root_path.mkdir(exist_ok=False)
        self.encrypted_path.mkdir(exist_ok=False)
        self.__reset_manifest()
        self.verify()

    def encrypt(self, secret_key: str) -> None:
        """
        Encrypts all decrypted files in the data vault that have changed
        since the last encryption.
        """
        self.verify()

        changes = self.changes()

        for f in changes["additions"]:
            encrypt(secret_key, self.root_path / f, self.encrypted_path / f)

        for f in changes["updates"]:
            os.remove(os.path.join(self.encrypted_path, f))
            encrypt(secret_key, self.root_path / f, self.encrypted_path / f)

        for f in changes["deletions"]:
            os.remove(os.path.join(self.encrypted_path, f))

        # Write the new manifest
        with open(self.vault_manifest_path, "w") as f:
            json.dump(self.__next_manifest(), f, indent=2)

    def decrypt(self, secret_key: str) -> None:
        """
        Decrypts all the encrypted files in the data vault.
        """
        self.verify()

        # Delete all decrypted files
        for f in self.files():
            os.remove(os.path.join(self.root_path, f))

        for f in self.encrypted_files():
            decrypt(secret_key, self.encrypted_path / f, self.root_path / f)

    def exists(self) -> bool:
        """
        Returns True if a valid vault exists for the given path.
        """
        try:
            self.verify()
            return True
        except:
            return False

    def files(self) -> List[str]:
        """
        Returns a list of all files in the vault recursively.
        """
        files = []

        # Enumerate all files skippping the ones in the encrypted
        # directory
        for f in os.listdir(self.root_path):
            # Skip the encrypted directory
            if f == DataVault.ENCRYPTED_NAMESPACE:
                continue
            # Walk all other directories
            elif os.path.isdir(os.path.join(self.root_path, f)):
                for dp, dn, filenames in os.walk("."):
                    for f in filenames:
                        if os.path.splitext(f)[1]:
                            # files.append(os.path.join(dp, f))
                            files.append(
                                f"{Path(os.path.join(dp, f)).relative_to(self.encrypted_path)}"
                            )
            # Append other files
            else:
                files.append(f)

        # Collect gitignore files
        ignore_files = []
        if (Path.home() / ".gitignore").exists():
            with open(Path.home() / ".gitignore", "r") as f:
                ignore_files.append(f.read())

        if (Path.cwd() / ".gitignore").exists():
            with open(Path.cwd() / ".gitignore", "r") as f:
                ignore_files.append(f.read())

        # Filter out ignored files
        return [
            n for n in files if not any(fnmatch(n, ignore) for ignore in ignore_files)
        ]

    def encrypted_files(self):
        """
        Returns a list of all encrypted files in the vault.
        """
        files = []

        for dp, dn, filenames in os.walk(self.encrypted_path):
            for f in filenames:
                if f != DataVault.MANIFEST_FILENAME:
                    if os.path.splitext(f)[1]:
                        files.append(
                            f"{Path(os.path.join(dp, f)).relative_to(self.encrypted_path)}"
                        )
        return files

    def is_empty(self) -> bool:
        """
        Returns True if the vault is empty.
        """
        return len(self.files()) == 0

    def changes(self) -> VaultChangeSet:
        """
        Returns a list of the changes to the vault since the last encryption.
        """

        updates, additions, deletions = (
            self.updates(),
            self.additions(),
            self.deletions(),
        )
        return {
            "total": len(updates) + len(additions) + len(deletions),
            "additions": additions,
            "deletions": deletions,
            "updates": updates,
            "unchanged": [
                f for f in self.files() if f not in set(updates + additions + deletions)
            ],
        }

    def has_changes(self):
        """
        Returns True if there are changes to the data in the vault.
        """
        return self.changes()["total"] > 0

    def additions(self) -> List[str]:
        """
        Returns a list of files that are in the decrypted directory but not
        in the vault manifest.
        """
        manifest_files = set(self.manifest()["files"])
        return [f for f in self.files() if f not in manifest_files]

    def deletions(self) -> List[str]:
        """
        Returns a list of files that are in the vault manifest but not in
        the decrypted directory.
        """
        return [f for f in self.manifest()["files"] if f not in self.files()]

    def updates(self) -> List[str]:
        """
        Returns a list of files that have changed since the last encryption.

        We accomplish this by investigating the hashes of the files in the
        decrypted directory. If the hash of the file in the decrypted directory
        is different than the hash of the file in the vault manifest, we
        consider the file to have changed.
        """
        current_manifest = self.manifest()["files"]
        next_manifest = self.__next_manifest()["files"]

        updates = []

        for file, hash in current_manifest.items():
            if not next_manifest.get(file):
                continue
            if hash == next_manifest[file]:
                continue
            updates.append(file)

        return updates

    def manifest(self) -> VaultManifest:
        """
        Reads the currently persisted vault manifest file.
        """
        with open(self.vault_manifest_path, "r") as f:
            return json.load(f)

    def no_encypted_files(self) -> bool:
        """
        Returns True if the encrypted directory is empty.
        """
        return len(self.encrypted_files()) == 0

    def clear(self) -> None:
        """
        Clears the data vault.
        """
        for f in self.files():
            os.remove(os.path.join(self.root_path, f))

    def clear_encrypted(self) -> None:
        """
        Clears the encrypted directory.
        """
        for f in self.encrypted_files():
            os.remove(os.path.join(self.encrypted_path, f))
        # You must clear the manifest otherwise the vault will
        # be invalid
        self.__reset_manifest()

    def verify(self) -> None:
        """
        Verifies the vault has the correct structure and vault manifest.
        It also checks that all of the files in the manifest are encrypted.
        """
        if not self.root_path.exists():
            raise FileNotFoundError(
                f"Vault does not exist at given path: {self.root_path}"
            )
        if not self.encrypted_path.exists():
            raise FileNotFoundError(
                f"Vault encrypted directory does not exist at given path: {self.encrypted_path}"
            )
        if not DataVault.verify_manifest(self.vault_manifest_path):
            raise FileNotFoundError(
                f"Vault manifest is invalid at given path: {self.vault_manifest_path}"
            )

        # All files in the manifest must be encrypted
        missing_files = []
        for f in self.manifest()["files"]:
            if not os.path.exists(os.path.join(self.encrypted_path, f)):
                missing_files.append(f)

        if len(missing_files) > 0:
            raise FileNotFoundError(
                textwrap.deindent(
                    f"""
            Vault manifest contains files that are not encrypted: {missing_files}
            
            >>> THIS SHOULD NOT HAPPEN AND IS CONSIDERED A SERIOUS ISSUE. <<<

            Check your vault directory {self.root_path} for the decrypted
            version of these files. If you can't find them there, you may need
            to search for an older version of the vault in version control. Otherwise,
            these files have likely been entirely lost.

            Once the files have been found, there are several ways to recover the vault:

            1. Recreate the vault from scratch.
            2. Remove the files from the autogenerated vault manifest ({self.vault_manifest_path})
            and rerun the vault encryption.
            
            If you do not need these files, you can simply delete them from the manifest.
            """
                )
            )

    #
    # Private helpers
    #

    def __reset_manifest(self):
        """
        Generate an empty vault manifest
        """
        #
        with open(self.vault_manifest_path, "w") as f:
            json.dump(self.__empty_vault_manifest(), f, indent=2)

    def __empty_vault_manifest(self) -> VaultManifest:
        """
        Returns an empty vault config as a dict.
        """
        return {
            "_": "DO NOT EDIT THIS FILE. IT IS AUTOMATICALLY GENERATED.",
            "version": self.VERSION,
            "files": {},
        }

    def __next_manifest(self) -> VaultManifest:
        """
        Returns the next version of the vault manifest that should be persisted
        after the next encryption.
        """
        return {
            "_": "DO NOT EDIT THIS FILE. IT IS AUTOMATICALLY GENERATED.",
            "version": self.VERSION,
            "files": {f: md5_hash_for_file(self.root_path / f) for f in self.files()},
        }
