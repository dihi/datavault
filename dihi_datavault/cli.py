import os
import textwrap
from pathlib import Path

import click
import colorama
from colorama import Fore

from dihi_datavault import DataVault, __version__

colorama.init()


#
# Helpers
#


def display(message: str) -> None:
    click.echo(textwrap.dedent(message).strip())


def confirm(message: str) -> bool:
    """
    Ask the user if they are sure they want to push the red button.
    """
    answer = ""
    while answer not in ["y", "n"]:
        answer = input(f"{Fore.CYAN}{message} [y/n] {Fore.RESET}").lower()
    return answer == "y"


def ask(message: str, default: str) -> str:
    """
    Ask the user a question.
    """
    return input(f"{Fore.CYAN}{message} [{default}] {Fore.RESET}") or default


def fetch_secret() -> str:
    """
    Loads the key from the current directory named `key.key`
    """
    secret = os.environ.get("DATAVAULT_SECRET")
    if not secret:
        raise Exception("DATAVAULT_SECRET is not set as an environment variable.")
    return secret


def find_vault(vault_path: str) -> DataVault:
    vaults = DataVault.find_all(vault_path)
    if len(vaults) == 0:
        click.echo("No data vault manifests were found.")
        exit(1)
    if len(vaults) > 1:
        click.echo(
            f"Found {len(vaults)} vaults. Please specify the one you want to inspect."
        )
        exit(1)
    return vaults[0]


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


def datavault_gitignore_lines(vault):
    ignoreline = f"{vault.root_path}/*"
    keepline = f"!{vault.root_path}/{DataVault.ENCRYPTED_NAMESPACE}"

    return (ignoreline, keepline)


#
# Click Commands
#


@click.group(
    help="DataVault helps you manage encrypted data inside of a repository.",
    invoke_without_command=True,
)
@click.option("--version", is_flag=True, help="Show version and exit.")
@click.option("--help", is_flag=True, help="Show this message and exit.")
@click.pass_context
def main(ctx: click.Context, version, help):
    """
    Main entry point for the datavault CLI.
    """
    if version:
        print(
            f"DataVault version v{__version__} which supports DataVault manifest v{DataVault.VERSION}."
        )
        exit(0)

    if help or ctx.invoked_subcommand is None:
        click.echo(main.get_help(ctx))
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
    secret = DataVault.generate_secret()
    vault.create()

    display(
        f"""
    {Fore.YELLOW}Your vault has been created at '{vault_path}'.{Fore.RESET}
    You can add files to your vault by adding them to that directory.

    To encrypt your vault, run:
    {Fore.YELLOW}DATAVAULT_SECRET={secret} datavault encrypt{Fore.RESET}

    Keep the secret some place safe! If you lose it you'll no longer be able
    to decrypt your vaults; if anyone else gains access to it, they'll
    be able to decrypt the data.
    """
    )


# Encrypt Command
#
@main.command(help="Encrypt the vault found int the given path.")
@click.argument("vault_path", default=os.getcwd())
@click.option(
    "-i",
    "--interactive",
    default=False,
    is_flag=True,
    help="Confirm before encrypting.",
)
def encrypt(vault_path, interactive):
    vault = find_vault(vault_path)

    click.echo(f"Encrypting vault at '{vault.root_path}'")
    if vault.is_empty():
        click.echo("Vault is empty. Nothing to encrypt.")
    elif vault.has_changes():
        show_changes(vault)
        if not interactive or confirm(
            "Are you sure you want to encrypt these changes?"
        ):
            vault.encrypt(fetch_secret())
            click.echo(f"{vault.root_path} encrypted.")
        else:
            print("Encryption cancelled.")
            exit(1)
    else:
        click.echo("Vault has no changes. Nothing to encrypt.")


# Decrypt Command
#
@main.command(help="Decrypt all vaults in the search path.")
@click.argument("vault_path", default=os.getcwd())
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
def decrypt(vault_path, interactive, force):
    if interactive and force:
        click.echo(
            "You can't force decrypt and interactively decrypt at the same time."
        )
        exit(1)

    vault = find_vault(vault_path)
    click.echo(f"Decrypting '{vault.root_path}'")

    if vault.no_encypted_files():
        click.echo("Vault is empty. Nothing to decrypt.")
    elif force:
        vault.decrypt(fetch_secret())
        click.echo(f"{vault.root_path} decrypted.")
    elif vault.has_changes():
        click.echo("This vault has changes.")
        show_changes(vault)

        if interactive and confirm(
            f"{Fore.YELLOW}Are you sure you want to replace the changes with newly decrypted files?{Fore.RESET}"
        ):
            vault.decrypt(fetch_secret())
            click.echo(f"{vault.root_path} decrypted.")
        else:
            click.echo(
                "Due to the changes, you must use -f to force decrypt or -i to decrypt interactively."
            )
    else:
        # Vault has no changes, so just decrypt it.
        vault.decrypt(fetch_secret())
        click.echo(f"{vault.root_path} decrypted.")


# Inspect Command
#
@main.command(help="Show the changes across all vaults in the search path.")
@click.argument("vault_path", default=os.getcwd())
def inspect(vault_path):
    vault = find_vault(vault_path)

    click.echo(f"Vault located at '{vault.root_path}'")
    if vault.is_empty():
        click.echo("Vault is empty. Nothing to inspect.")
    elif not vault.has_changes():
        click.echo("Vault has no changes. Nothing to inspect.")
    else:
        show_changes(vault)
    click.echo()


# Clear Command
#
@main.command(help="Clear the decrypted contents from the vault")
@click.option(
    "-f", "--force", help="Skip interactive mode", default=False, is_flag=True
)
@click.argument("vault_path", default=os.getcwd())
def clear_decrypted(vault_path, force):
    vault = find_vault(vault_path)
    if force or confirm(
        f"Are you sure you want to clear the decrypted contents of the vault at '{vault_path}'?"
    ):
        vault.clear()
        click.echo(f"{vault.root_path} cleared.")
    else:
        click.echo("Clear cancelled.")
        exit(1)


# Clear Encrypted Command
#
@main.command(help="Clear the encrypted contents from the vault")
@click.option(
    "-f", "--force", help="Skip interactive mode", default=False, is_flag=True
)
@click.argument("vault_path", default=os.getcwd())
def clear_encrypted(vault_path, force):
    vault = find_vault(vault_path)
    if force or confirm(
        f"Are you sure you want to clear the encrypted vault at '{vault_path}'?"
    ):
        vault.clear_encrypted()
        click.echo(f"{vault.root_path} cleared.")
    else:
        click.echo("Clear cancelled.")
        exit(1)


# Secret Command
#
@main.command(help="Genearate a new secret for your vault.")
def secret():
    display(
        f"""
    If you have yet to encrypt your data, you can use the following secret:

    {Fore.YELLOW}DATAVAULT_SECRET={DataVault.generate_secret()}{Fore.RESET}

    Keep this some place safe! If you lose it you'll no longer be able
    to decrypt your vaults; if anyone else gains access to it, they'll
    be able to decrypt all of your data.
    """
    )


if __name__ == "__main__":
    main()
