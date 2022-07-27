# Data Vault 🔒

Sometimes you'd like to store encrypted files in your repository securely.
This package helps with that.

## Usage

```bash
# Step 1: Create a new datavault
datavault new path/to/vault
# Not only will you get a vault, but you'll also get some fancy
# instructions. Follow them.

# Step 2: Add some things to it
echo "test" > path/to/vault/decrypted/test.txt

# Step 3: Inspect it
datavault inspect
# You can see the changes that have been made to the vault.

# Step 4: Encrypt it, yes you need the equals sign at the end of your key
export DATAVAULT_SECRET=o8qbhGg4OkF0dwYb8Kc3VYjinhaLGb57ZWz8DzAdWN4=
datavault encrypt

# Step 1 will give you a valid secret to use. If you didn't write it down,
# you can always run `datavault secret` for a new key.

# Step 5: Decrypt the files
rm -Rf path/to/vault/decrypted/*
datavault decrypt


# By default, datavault encrypts, decrypts, and inspects all vaults
# within the working directory. If you need to specify a specific path,
# you can do that.

datavault encrypt path/to/vault
datavault decrypt path/to/vault
datavault inspect path/to/vault
```

