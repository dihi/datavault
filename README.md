# Data Vault 🔒

[![PyPI version](https://badge.fury.io/py/dihi-datavault.svg)](https://badge.fury.io/py/dihi-datavault)
[![Test](https://github.com/dihi/datavault/actions/workflows/test.yml/badge.svg)](https://github.com/dihi/datavault/actions/workflows/test.yml)

Store and encrypt sensitive data in your git repo.

## Installation

Pick your poison:

 - `pip install dihi-datavault` then `datavault`
 - `poetry add dihi-datavault` then `poetry run datavault`
 - `pipx install dihi-datavault` then `pipx run datavault`

## Usage

First, create a new vault.

```bash
datavault new path/to/vault
```

This command will...

  - Provide you with a secret to use when encrypting your files
  - Create a folder at `path/to/vault` where you place files you wish to be encrypted
  - Create a `path/to/vault/.encrypted` directory to store the encrypted files along with a manifest which tracks the state of files in the vault
  - Create a `path/to/vault/.gitignore` file which will ignore the unencrypted files

You're now free to add files to your new vault and encrypt them:

```bash
echo "apple" > path/to/vault/apple.txt
echo "banana" > path/to/vault/banana.txt
datavault inspect
datavault encrypt
```

You can also clear out the contents of the vault as needed...

```bash
datavault clear-decrypted
datavault clear-encrypted
```

Now lets say you've just pulled the repo and have none of the original files...

```bash
datavault decrypt
```

## Development

Useful commands:

 - `poetry run pytest` to run the tests
 - `poetry publish -r testpypi` and `poetry publish -r testpypi` to test the deployment
 - `poetry version X.Y.Z` to bump the version, then `git tag vX.Y.Z` and `git push --tags`
 - `poetry publish` to release
