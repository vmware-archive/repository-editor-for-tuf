# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

import click
import logging
import math
from click.exceptions import ClickException
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional, List, Tuple

from tuf.api.metadata import(
    DelegatedRole,
    Delegations,
    SuccinctRoles,
    Targets
)

from tufrepo import helpers
from tufrepo import verifier
from tufrepo.librepo.keys import Keyring
from tufrepo.git_repo import GitRepository
from tufrepo.keys_impl import EnvVarKeyring, InsecureFileKeyring, PrivateKey

logger = logging.getLogger("tufrepo")

@dataclass
class AppData:
    keyring: Keyring
    role: str = None
    repo: GitRepository = None

    def __init__(self, keyring: Keyring) -> None:
        self.keyring = keyring
        self.repo = GitRepository(self.keyring)


class Context(click.Context):
    """click.Context where obj type is Appdata"""
    def __init__(self):
        super().__init__()
        self.obj: AppData


# -------------------------------- cli commands --------------------------------


@click.group()
@click.pass_context
@click.option("-v", "--verbose", count=True, default=0)
@click.option("--keyring", type=click.Choice(["file", "env"]), default="file")
def cli(ctx: Context, verbose: int, keyring: str):
    """Edit and sign TUF repository metadata

    This tool expects to be run in a directory with TUF metadata that is within
    a git repository.

    By default private keys are read in plaintext fom privkeys.json: this can
    be changed with "--keyring" to use environment variables named
    TUF_REPO_PRIVATE_KEY_<keyid> (useful in automation, like running in CI).
    """

    logging.basicConfig(format="%(levelname)s:%(message)s")
    logger.setLevel(max(1, 10 * (5 - verbose)))

    if keyring == "env":
        ctx.obj = AppData(EnvVarKeyring())
    else:
        ctx.obj = AppData(InsecureFileKeyring())

@cli.command()
@click.pass_context
def init(ctx: Context):
    """Initialize a repository

    All metadata will be assigned expiry period of 365 days: use
    'edit ROLE set-expiry' to change. A key will be generated for each role
    and stored in the keyring."""
    # Use expiry period of 1 year for everything
    period = int(timedelta(days=365).total_seconds())

    with ctx.obj.repo.edit("root", init=True) as root:
        root.unrecognized_fields["x-tufrepo-expiry-period"] = period
        for role in ["root", "timestamp", "snapshot", "targets"]:
            key: PrivateKey = ctx.obj.keyring.generate_key()
            root.add_key(key.public, role)
            ctx.obj.keyring.store_key(role, key)

    for role in ["timestamp", "snapshot", "targets"]:
        with ctx.obj.repo.edit(role, init=True) as signed:
            signed.unrecognized_fields["x-tufrepo-expiry-period"] = period

    ctx.obj.repo.snapshot()

@cli.command()
@click.pass_context
@click.option("--all-targets", is_flag=True, default=False)
@click.argument("roles", nargs=-1)
def sign(ctx: Context, all_targets: bool, roles: Tuple[str]):
    """Sign the given roles, using all usable keys in keyring

    If --all-targets is used, will sign all targets roles that have usable keys
    in the keyring"""
    if all_targets:
        skip = ["root", "timestamp", "snapshot"]
        roles = [r for r in ctx.obj.repo.keyring if r not in skip]
    for role in roles:
        ctx.obj.repo.sign(role)

@cli.command()
@click.pass_context
@click.option("--root-hash")
def verify(ctx: Context, root_hash: Optional[str] = None):
    """"""
    verifier.verify_repo(root_hash)
    print(f"Keyring contains keys for [{', '.join(ctx.obj.keyring.keys())}].")


@cli.command()
@click.pass_context
def snapshot(ctx: Context):
    """Update both snapshot and timestamp meta information if needed"""
    if ctx.obj.repo.snapshot():
        ctx.obj.repo.timestamp()

@cli.command()
@click.pass_context
def timestamp(ctx: Context):
    """Update timestamp meta information"""
    ctx.obj.repo.timestamp()

@cli.command()
@click.pass_context
@click.argument("role")
def init_succinct_roles(ctx: Context, role: str):
    """Create a new set of delegated bin files based on the succinct hash bin
    delegation information in ROLE.

    Note: it's required to call 'tufrepo edit ROLE add_succinct_delegation'
    command first in order to provide succinct hash bin delegations information
    first."""

    targets: Targets
    with ctx.obj.repo.edit(role) as targets:
        if targets.delegations is None or targets.delegations.succinct_roles is None:
            raise ClickException(
                "'ROLE' doesn't contain information about succinct delegations"
            )

        for bin_name in targets.delegations.succinct_roles.get_roles():
            # Use expiry period of 1 year for everything
            period = int(timedelta(days=365).total_seconds())
            with ctx.obj.repo.edit(bin_name, init=True) as signed:
                signed.unrecognized_fields["x-tufrepo-expiry-period"] = period



@cli.command()
@click.pass_context
@click.option("--no-target-in-repo", is_flag=True, default=False)
@click.option("--no-follow-delegations", is_flag=True, default=False)
@click.option("--role", default="targets", metavar="ROLE", show_default=True)
@click.argument("target-path")
@click.argument("local-file")
def add_target(
    ctx: Context,
    no_target_in_repo: bool,
    no_follow_delegations: bool,
    role: str,
    target_path: str,
    local_file: str,
):
    """Add target file to the repository

    TARGET_PATH is used in the metadata to identify the target file. LOCAL_FILE
    is used to calculate the file hashes. By default LOCAL_FILE (and
    hash-prefixed symlinks) are also added to git, but this can be prevented
    with --no-target-in-repo if the target files are not stored in git.

    By default the target is added to whatever targets-metadata the target path
    is last delegated to. The delegation search starting point is the top-level
    targets by default but can be redefined with --role. The delegation search
    can be disabled completely with --no-follow-delegations.

    """
    final_role = ctx.obj.repo.add_target(
        role, not no_follow_delegations, not no_target_in_repo, target_path, local_file
    )
    print(f"Added '{target_path}' as target to role '{final_role}'")


@cli.command
@click.pass_context
@click.option("--no-follow-delegations", is_flag=True, default=False)
@click.option("--role", default="targets", metavar="ROLE", show_default=True)
@click.argument("target-path")
def remove_target(
    ctx: Context,
    no_follow_delegations: bool,
    role: str,
    target_path: str,
    ):
    """Remove target file from the repository"""

    final_role = ctx.obj.repo.remove_target(
        role, not no_follow_delegations, target_path
    )

    if not final_role:
        print(f"Target {target_path} not found")
    else:
        print(f"Removed {target_path} from role {final_role}.")
        print("Actual target files have not been removed")



# ------------------------------- edit commands --------------------------------


@cli.group()
@click.pass_context
@click.argument("role")
def edit(ctx: Context, role: str):
    """Edit metadata for ROLE using the sub-commands."""
    ctx.obj.role = role

@edit.command()
@click.pass_context
def touch(ctx: Context):
    """Mark ROLE as modified to force a new version"""
    with ctx.obj.repo.edit(ctx.obj.role):
        pass

@edit.command()
@click.pass_context
@click.option(
    "--expiry",
    help="expiry value and unit",
    default=(1, "days"),
    type=(int, click.Choice(["minutes", "days", "weeks"], case_sensitive=False)),
)
def init(ctx: Context, expiry: Tuple[int, str]):
    """Create new metadata for ROLE. Example:

    tufrepo edit root init --expiry 52 weeks"""
    delta = timedelta(**{expiry[1]: expiry[0]})
    period = int(delta.total_seconds())
    with ctx.obj.repo.edit(ctx.obj.role, init=True) as signed:
        signed.unrecognized_fields["x-tufrepo-expiry-period"] = period


@edit.command()
@click.pass_context
@click.argument("delegate")
@click.argument("threshold", type=int)
def set_threshold(ctx: Context, delegate: str, threshold: int):
    """Set the threshold of delegated role DELEGATE."""
    with ctx.obj.repo.edit(ctx.obj.role) as signed:
        helpers.set_threshold(signed, delegate, threshold)


@edit.command()
@click.pass_context
@click.argument(
    "expiry",
    type=(int, click.Choice(["minutes", "days", "weeks"], case_sensitive=False)),
)
def set_expiry(ctx: Context, expiry: Tuple[int, str]):
    """Set expiry period for the role. Example:

    tufrepo edit root set-expiry 52 weeks"""
    delta = timedelta(**{expiry[1]: expiry[0]})
    period = int(delta.total_seconds())

    with ctx.obj.repo.edit(ctx.obj.role) as signed:
        signed.unrecognized_fields["x-tufrepo-expiry-period"] = period


@edit.command()
@click.pass_context
@click.argument("delegate", required=False)
def add_key(ctx: Context, delegate: Optional[str]):
    """Add a new signing key for a delegated role or succinct hash bin
    delegations.

    If a user wants to add a key to a single delegated role then the DELEGATE
    string argument must be provided.

    If DELEGATE argument is not provided tufrepo will assume you want to add
    the new key to succinct hash bin delegation.

    The private key secret will be written to privkeys.json."""
    delegator = ctx.obj.role
    keyring: InsecureFileKeyring = ctx.obj.keyring
    key = keyring.generate_key()

    targets: Targets
    with ctx.obj.repo.edit(delegator) as targets:

        # Add a key to one standard role.
        if delegate is not None:
            helpers.add_key(targets, delegator, delegate, key.public)
            keyring.store_key(delegate, key)

        # Add a key to succinct hash bin delegations.
        else:
            if targets.delegations is None or targets.delegations.succinct_roles is None:
                raise ClickException(
                    "'ROLE' doesn't contain information about succinct delegations"
                )

            helpers.add_key(targets, delegator, None, key.public)

            for bin_name in targets.delegations.succinct_roles.get_roles():
                ctx.obj.keyring.store_key(bin_name, key)


@edit.command()
@click.pass_context
@click.argument("delegate")
@click.argument("keyid")
def remove_key(ctx: Context, delegate: str, keyid: str):
    """Remove signing key from delegated role DELEGATE"""
    delegator = ctx.obj.role

    with ctx.obj.repo.edit(delegator) as signed:
        helpers.remove_key(signed, delegator, delegate, keyid)



@edit.command()
@click.pass_context
@click.option("--terminating/--non-terminating", default=False)
@click.option("--path", "paths", multiple=True)
@click.option("--hash-prefix", "hash_prefixes", multiple=True)
@click.option("--succinct", "bin_amount", type=int)
@click.argument("delegate")
def add_delegation(
    ctx: Context,
    terminating: bool,
    paths: Tuple[str],
    hash_prefixes: Tuple[str],
    bin_amount: Optional[int],
    delegate: str,
):
    """Delegate from ROLE to DELEGATE.

    There are three modes for this command:
    - add a new delegated role in ROLE with "paths" information provided.
    - add a new delegated role in ROLE with "hash-prefix" information provided.
    - add а succinct hash bin delegation

    If you want to add a new delegated role (the first two modes) then the new
    role will have the name "DELEGATE" and you can use the three options:
    "terminating", "path" and "hash-prefix".

    IF you want to add a new succinct hash bin delegation then you should use
    the "succinct" option and you are not allowed to use any of the other three
    options.
    For the "succinct" option you should provide a number representing the
    number of bins. It MUST be a power of 2.
    Finally, if you add a new succinct hash bin delegation then "DELEGATE" will
    be the name prefix of all bins.
    """

    sum_lengths_paths_and_prefixes = len(paths) + len(hash_prefixes)
    # sum_lengths_paths_and_prefixes must be at least 1 if a user wants to
    # delegate to a new role as either paths or hash_prefixes must be set.
    if bin_amount is not None and sum_lengths_paths_and_prefixes > 0:
        raise ClickException(
            "Not allowed to set delegated role options and the succinct option"
        )

    if bin_amount is None and sum_lengths_paths_and_prefixes == 0:
        raise ClickException(
            "Either paths/hash_prefix options must be set or succinct option"
        )

    targets: Targets
    with ctx.obj.repo.edit(ctx.obj.role) as targets:
        # Add delegated role "delegate"
        if sum_lengths_paths_and_prefixes > 0:
            if (
                targets.delegations is None
                or targets.delegations.succinct_roles is not None
            ):
                targets.delegations = Delegations({}, {})

            _paths = list(paths) if paths else None
            _prefixes = list(hash_prefixes) if hash_prefixes else None

            try:
                role = DelegatedRole(delegate, [], 1, terminating, _paths, _prefixes)
            except ValueError:
                raise ClickException(f"Only one of (paths, hash_prefixes) must be set")

            targets.delegations.roles[role.name] = role

        # Add succinct hash bin delegation.
        # In this case "delegate" is the prefix of all bins.
        elif bin_amount is not None:
            if bin_amount < 2:
                raise ClickException("Succinct number must be at least 2")
            # If the the result of math.log2(bin_amount) is NOT a natural number
            # then bin_amount is NOT a power of 2.
            if not math.log2(bin_amount).is_integer():
                raise ClickException("Succinct number must be a power of 2")

            bit_length = int(math.log2(bin_amount))
            succinct_roles =  SuccinctRoles([], 1, bit_length, delegate)
            targets.delegations = Delegations({}, None, succinct_roles)


@edit.command()
@click.pass_context
@click.argument("delegate")
def remove_delegation(
    ctx: Context,
    delegate: str,
):
    """Remove DELEGATE from ROLE"""
    tar: Targets
    with ctx.obj.repo.edit(ctx.obj.role) as tar:
        if tar.delegations is not None and tar.delegations.roles is not None:
            del tar.delegations.roles[delegate]

if __name__ == "__main__":
    cli()
