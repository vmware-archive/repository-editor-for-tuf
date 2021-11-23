# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

import click
import logging
from datetime import timedelta
from typing import List, Optional, OrderedDict, Tuple

from tuf.api.metadata import DelegatedRole, Delegations, TargetFile

from tufrepo import helpers
from tufrepo import verifier
from tufrepo.git_repo import GitRepository
from tufrepo.keys import Keyring

logger = logging.getLogger("tufrepo")

def get_role(ctx: click.Context) -> str:
    """Return parent commands 'role' parameter"""
    assert ctx.parent
    return ctx.parent.params["role"]

@click.group()
@click.option("-v", "--verbose", count=True)
def cli(verbose: int = 0):
    """Edit and sign TUF repository metadata

    This tool expects to be run in a (git) metadata repository"""

    logging.basicConfig(format="%(levelname)s:%(message)s")
    logger.setLevel(max(1, 10 * (5 - verbose)))


@cli.command()
@click.argument("roles", nargs=-1)
def sign(roles: Tuple[str]):
    """Sign the given roles, using all usable keys in keyring"""
    repo = GitRepository(Keyring())
    for role in roles:
        repo.sign(role)

@cli.command()
@click.option("--root-hash")
def verify(root_hash: Optional[str] = None):
    """"""
    verifier.verify_repo(root_hash)
    print(f"Keyring contains keys for [{', '.join(Keyring().keys())}].")


@cli.command()
def snapshot():
    """"""
    repo = GitRepository(Keyring())
    repo.snapshot()


@cli.group()
@click.argument("role")
def edit(role: str):  # pylint: disable=unused-argument
    """Edit metadata for ROLE using the sub-commands."""

@edit.command()
@click.pass_context
def touch(ctx: click.Context):
    """Mark ROLE as modified to force a new version"""

    role = get_role(ctx)
    repo = GitRepository(Keyring())
    with repo.edit(role):
        pass

@edit.command()
@click.pass_context
@click.option(
    "--expiry",
    help="expiry value and unit",
    default=(1, "days"),
    type=(int, click.Choice(["minutes", "days", "weeks"], case_sensitive=False)),
)
def init(ctx: click.Context, expiry: Tuple[int, str]):
    """Create new metadata for ROLE. Example:

    tufrepo edit root init --expiry 52 weeks"""
    delta = timedelta(**{expiry[1]: expiry[0]})
    period = int(delta.total_seconds())
    role = get_role(ctx)

    repo = GitRepository(Keyring())
    repo.init_role(role, period)


@edit.command()
@click.pass_context
@click.argument("delegate")
@click.argument("threshold", type=int)
def set_threshold(ctx: click.Context, delegate: str, threshold: int):
    """Set the threshold of delegated role DELEGATE."""
    role = get_role(ctx)
    repo = GitRepository(Keyring())
    with repo.edit(role) as signed:
        helpers.set_threshold(signed, delegate, threshold)


@edit.command()
@click.pass_context
@click.argument(
    "expiry",
    type=(int, click.Choice(["minutes", "days", "weeks"], case_sensitive=False)),
)
def set_expiry(ctx: click.Context, expiry: Tuple[int, str]):
    """Set expiry period for the role. Example:

    tufrepo edit root set-expiry 52 weeks"""
    delta = timedelta(**{expiry[1]: expiry[0]})
    period = int(delta.total_seconds())
    role = get_role(ctx)

    repo = GitRepository(Keyring())
    with repo.edit(role) as signed:
        # This should maybe be a repo feature? argument to edit?
        signed.unrecognized_fields["x-tufrepo-expiry-period"] = period


@edit.command()
@click.pass_context
@click.argument("delegate")
def add_key(ctx: click.Context, delegate: str):
    """Add new signing key for delegated role DELEGATE

    The private key secret will be written to privkeys.json."""
    delegator = get_role(ctx)
    keyring = Keyring()
    key = keyring.generate_key()
    repo = GitRepository(keyring)

    with repo.edit(delegator) as signed:    
        helpers.add_key(signed, delegator, delegate, key.public)
    keyring.store_key(delegate, key)


@edit.command()
@click.pass_context
@click.argument("delegate")
@click.argument("keyid")
def remove_key(ctx: click.Context, delegate: str, keyid: str):
    """Remove signing key from delegated role DELEGATE"""
    delegator = get_role(ctx)
    repo = GitRepository(Keyring())
    with repo.edit(delegator) as signed:
        helpers.remove_key(signed, delegator, delegate, keyid)


@edit.command()
@click.pass_context
@click.argument("target-path")
@click.argument("local-file")
def add_target(ctx: click.Context, target_path: str, local_file: str):
    """Add a target to a Targets metadata role"""
    repo = GitRepository(Keyring())
    with repo.edit(get_role(ctx)) as targets:
        targetfile = TargetFile.from_file(target_path, local_file)
        targets.targets[targetfile.path] = targetfile


@edit.command()
@click.pass_context
@click.argument("target-path")
def remove_target(ctx: click.Context, target_path: str):
    """Remove TARGET from a Targets role ROLE"""
    repo = GitRepository(Keyring())
    with repo.edit(get_role(ctx)) as targets:
        del targets.targets[target_path]


@edit.command()
@click.pass_context
@click.argument("delegate")
@click.option("--terminating/--non-terminating", default=False)
@click.option("--path", "paths", multiple=True)
@click.option("--hash-prefix", "hash_prefixes", multiple=True)
def add_delegation(
    ctx: click.Context,
    delegate: str,
    terminating: bool,
    paths: Tuple[str],
    hash_prefixes: Tuple[str],
):
    """Delegate from ROLE to DELEGATE"""
    repo = GitRepository(Keyring())
    paths = list(paths) if paths else None
    hash_prefixes = list(hash_prefixes) if hash_prefixes else None

    with repo.edit(get_role(ctx)) as targets:
        if targets.delegations is None:
            targets.delegations = Delegations({}, OrderedDict())

        role = DelegatedRole(delegate, [], 1, terminating, paths, hash_prefixes)
        targets.delegations.roles[role.name] = role

@edit.command()
@click.pass_context
@click.argument("delegate")
def remove_delegation(
    ctx: click.Context,
    delegate: str,
):
    repo = GitRepository(Keyring())
    with repo.edit(get_role(ctx)) as targets:
        del targets.delegations.roles[delegate]
