# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

import click
import logging
from datetime import timedelta
from typing import Optional, Tuple

from tufrepo.repo import Repo
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
    repo = Repo(Keyring())
    repo.sign(list(roles))


@cli.command()
@click.option("--root-hash")
def verify(root_hash: Optional[str] = None):
    """"""
    repo = Repo(Keyring())
    repo.verify(root_hash)


@cli.command()
def snapshot():
    """"""
    repo = Repo(Keyring())
    repo.snapshot()


@cli.group()
@click.argument("role")
def edit(role: str):  # pylint: disable=unused-argument
    """Edit metadata for ROLE using the sub-commands."""


@edit.command()
@click.pass_context
def touch(ctx: click.Context):
    """Mark ROLE as modified to force a new version"""
    repo = Repo(Keyring())
    repo.touch(get_role(ctx))


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
    repo = Repo(Keyring())
    delta = timedelta(**{expiry[1]: expiry[0]})
    repo.init_role(get_role(ctx), int(delta.total_seconds()))


@edit.command()
@click.pass_context
@click.argument("delegate")
@click.argument("threshold", type=int)
def set_threshold(ctx: click.Context, delegate: str, threshold: int):
    """Set the threshold of delegated role DELEGATE."""
    repo = Repo(Keyring())
    repo.set_threshold(get_role(ctx), delegate, threshold)


@edit.command()
@click.pass_context
@click.argument(
    "expiry",
    type=(int, click.Choice(["minutes", "days", "weeks"], case_sensitive=False)),
)
def set_expiry(ctx: click.Context, expiry: Tuple[int, str]):
    """Set expiry period for the role. Example:

    tufrepo edit root set-expiry 52 weeks"""
    repo = Repo(Keyring())
    delta = timedelta(**{expiry[1]: expiry[0]})
    repo.set_expiry(get_role(ctx), int(delta.total_seconds()))


@edit.command()
@click.pass_context
@click.argument("delegate")
def add_key(ctx: click.Context, delegate: str):
    """Add new signing key for delegated role DELEGATE

    The private key secret will be written to privkeys.json."""
    repo = Repo(Keyring())
    repo.add_key(get_role(ctx), delegate)


@edit.command()
@click.pass_context
@click.argument("delegate")
@click.argument("keyid")
def remove_key(ctx: click.Context, delegate: str, keyid: str):
    """Remove signing key from delegated role DELEGATE"""
    repo = Repo(Keyring())
    repo.remove_key(get_role(ctx), delegate, keyid)


@edit.command()
@click.pass_context
@click.argument("target")
@click.argument("local-file")
def add_target(ctx: click.Context, target: str, local_file: str):
    """Add a target to a Targets metadata role"""
    repo = Repo(Keyring())
    repo.add_target(get_role(ctx), target, local_file)


@edit.command()
@click.pass_context
@click.argument("target")
def remove_target(ctx: click.Context, target: str):
    """Remove TARGET from a Targets role ROLE"""
    repo = Repo(Keyring())
    repo.remove_target(get_role(ctx), target)


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
    repo = Repo(Keyring())
    role = get_role(ctx)
    paths_list = list(paths) if paths else None
    prefix_list = list(hash_prefixes) if hash_prefixes else None
    repo.add_delegation(role, delegate, terminating, paths_list, prefix_list)

@edit.command()
@click.pass_context
@click.argument("delegate")
def remove_delegation(
    ctx: click.Context,
    delegate: str,
):
    repo = Repo(Keyring())
    role = get_role(ctx)
    repo.remove_delegation(role, delegate)
