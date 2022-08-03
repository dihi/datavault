# Data Vault 🔒

[![PyPI version](https://badge.fury.io/py/datavault.svg)](https://badge.fury.io/py/datavault)
[![Test](https://github.com/dihi/datavault/actions/workflows/test.yml/badge.svg)](https://github.com/dihi/datavault/actions/workflows/test.yml)

Sometimes you'd like to store encrypted files in your repository securely.
This package helps with that.

## Usage

```bash
# Step 1: Create a new datavault
datavault new path/to/vault
# Not only will you get a vault, but you'll also get some fancy
# instructions. *Follow them.*

# Step 2: Add some things to it
echo "test" > path/to/vault/test.txt

# Step 3: Inspect it
datavault inspect

# Step 4: Encrypt it (yes you need the equals sign at the end of your key)
export DATAVAULT_SECRET=o8qbhGg4OkF0dwYb8Kc3VYjinhaLGb57ZWz8DzAdWN4=
datavault encrypt

# Now lets say you've just pulled the repo and have none of the original
# files...

# Step 5: Decrypt the vault
datavault decrypt

# By default, datavault hunts for a vault to encrypt/decrypt/inspect,
# you can specify the path as needed
datavault encrypt path/to/vault
datavault decrypt path/to/vault
datavault inspect path/to/vault

# You can also clear out the contents of the vault as needed
datavault clear
datavault clear-encrypted
```
