from dataclasses import dataclass
import os
from pathlib import Path
import click

from datavault import KEEPFILE, DataVault, __version__

import colorama
from colorama import Fore

colorama.init()


#
# Helpers
#


def confirm(message: str) -> bool:
    """
    Ask the user if they are sure they want to push the red button.
    """
    answer = ""
    while answer not in ["y", "n"]:
        answer = input(f"{message} [y/n] ").lower()
    return answer == "y"


def fetch_secret() -> str:
    """
    Loads the key from the current directory named `key.key`
    """
    secret = os.environ.get("DATAVAULT_SECRET")
    if not secret:
        raise Exception("DATAVAULT_SECRET is not set as an environment variable.")
    return secret


def show_changes(vault: DataVault):
    """
    Shows all the changes to the files in the vault.
    """
    changes = vault.changes()

    click.echo("The following changes have occurred since the last encryption:")

    for file in changes["additions"]:
        click.echo(f"{Fore.GREEN}ADDED{Fore.RESET}\t\t{file}")
    for file in changes["deletions"]:
        click.echo(f"{Fore.RED}REMOVED{Fore.RESET}\t\t{file}")
    for file in changes["updates"]:
        click.echo(f"{Fore.YELLOW}UPDATED{Fore.RESET}\t\t{file}")
    for file in changes["unchanged"]:
        click.echo(f"{Fore.BLUE}UNCHANGED{Fore.RESET}\t{file}")


#
# Click Commands
#


@click.group(
    help="DataVault helps you manage encrypted data inside of a repository.",
    invoke_without_command=True,
)
@click.option("-v", "--version", is_flag=True, help="Show version and exit.")
def main(version=False):
    """
    Main entry point for the datavault CLI.
    """
    if version:
        print(
            f"DataVault version v{__version__} which supports DataVault manifest v{DataVault.VERSION}."
        )
        exit(0)


# New Command
#
@main.command()
@click.argument("vault_path")
def new(vault_path):
    """
    Create a new data vault.
    """
    if Path(vault_path).exists():
        click.echo(f"Can't create a vault there. A file already exists at that path.")
        exit(1)

    vault = DataVault(vault_path)
    vault.create()

    ignoreline = str(vault.decrypted_dir / "*")
    keepline = f"!{vault.decrypted_dir / KEEPFILE}"
    secret = DataVault.generate_secret()
    click.echo(
    f"""
    Your vault has been created at '{vault_path}'.

    You can add files to your vault by adding them to the decrypted directory:
    
    {Fore.YELLOW}> {vault.decrypted_dir}{Fore.RESET}

    You can encrypt your vault by running:

    {Fore.YELLOW}DATAVAULT_SECRET={secret} datavault encrypt '{vault_path}'{Fore.RESET}

    Or you can encrypt all vaults in a directory at once:

    {Fore.YELLOW}DATAVAULT_SECRET={secret} datavault encrypt{Fore.RESET}

    Keep the secret some place safe! If you lose it you'll no longer be able
    to decrypt your vaults; if anyone else gains access to it, they'll
    be able to decrypt the data.

    You should also ignore the files in version control. With git, add
    the following to your .gitignore file:
    {Fore.YELLOW}
    {ignoreline}
    {keepline}
    {Fore.RESET}
    These may not be exact, so please ensure that you are not committing
    any of the decrypted vault files!
    """
    )


# Encrypt Command
#
@main.command(help="Encrypt all vaults in the search path.")
@click.argument("search_path", default=os.getcwd())
@click.option(
    "-i",
    "--interactive",
    default=False,
    is_flag=True,
    help="Confirm before encrypting.",
)
def encrypt(search_path, interactive):
    vaults = DataVault.find_all(search_path)
    if len(vaults) == 0:
        click.echo("No data vault manifests were found.")
        exit(1)
    if len(vaults) > 1:
        click.echo(f"Found {len(vaults)} vaults.")

    for vault in vaults:
        click.echo(f"Encrypting vault at '{vault.root_dir}'")
        if vault.has_changes():
            show_changes(vault)
            if not interactive or confirm(
                "Are you sure you want to encrypt these changes?"
            ):
                vault.encrypt(fetch_secret())
                click.echo(f"{vault.root_dir} encrypted.")
            else:
                print("Encryption cancelled.")
                exit(1)
        elif vault.is_decrypted_dir_empty():
            click.echo("Decrypted directory is empty. Skipping.")
        else:
            click.echo("Decrypted directory has no changes. Skipping.")
        click.echo()
    click.echo("Done.")


# Decrypt Command
#
@main.command(help="Decrypt all vaults in the search path.")
@click.argument("search_path", default=os.getcwd())
@click.option(
    "-i",
    "--interactive",
    default=False,
    is_flag=True,
    help="Confirm before decrypting in case of conflicts.",
)
@click.option(
    "-f",
    "--force",
    default=False,
    is_flag=True,
    help="Force decrypting and overwrite if there are changes.",
)
def decrypt(search_path, interactive, force):
    if interactive and force:
        click.echo(
            "You can't force decrypt and interactively decrypt at the same time."
        )
        exit(1)

    vaults = DataVault.find_all(search_path)

    if len(vaults) == 0:
        click.echo("No data vault manifests were found.")
        exit(1)

    if len(vaults) > 1:
        click.echo(f"Found {len(vaults)} vaults.")

    for vault in vaults:
        click.echo(f"Decrypting '{vault.root_dir}'")

        if vault.is_encrypted_dir_empty():
            click.echo("Encrypted directory is empty. Nothing to decrypt.")
            continue

        if force:
            vault.decrypt(fetch_secret())
            click.echo(f"{vault.root_dir} decrypted.")
            continue

        if vault.has_changes():
            click.echo("This vault has changes.")
            show_changes(vault)

            if (
                interactive
                and confirm(
                    f"{Fore.YELLOW}Are you sure you want to replace the changes with newly decrypted files?{Fore.RESET}"
                )
            ):
                vault.decrypt(fetch_secret())
                click.echo(f"{vault.root_dir} decrypted.")
            else:
                click.echo(
                    "Due to the changes, you must use -f to force decrypt or -i to decrypt interactively."
                )
        else:
            # Vault has no changes, so just decrypt it.
            vault.decrypt(fetch_secret())
            click.echo(f"{vault.root_dir} decrypted.")
        click.echo()
    click.echo("Done.")

# Inspect Command
#
@main.command(help="Show the changes across all vaults in the search path.")
@click.argument("search_path", default=os.getcwd())
def inspect(search_path):
    vaults = DataVault.find_all(search_path)
    if len(vaults) == 0:
        click.echo("No data vault manifests were found.")
        exit(1)
    if len(vaults) > 1:
        click.echo(f"Found {len(vaults)} vaults.")
        click.echo()
    for vault in vaults:
        click.echo(f"Vault located at '{vault.root_dir}'")
        if vault.is_decrypted_dir_empty():
            click.echo("-> Decrypted directory is empty. Skipping")
        elif not vault.has_changes():
            click.echo("-> Decrypted directory has no changes. Skipping.")
        else:
            show_changes(vault)
        click.echo()


# Secret Command
#
@main.command(help="Genearate a new secret for your vault.")
def secret():
    click.echo(
        f"If you have yet to encrypt your data, you can use the following secret:"
    )
    click.echo(
        f"{Fore.YELLOW}DATAVAULT_SECRET={DataVault.generate_secret()}{Fore.RESET}"
    )
    click.echo(
    """
    Keep this some place safe! If you lose it you'll no longer be able
    to decrypt your vaults; if anyone else gains access to it, they'll
    be able to decrypt all of your data.
    """
    )


if __name__ == "__main__":
    main()
