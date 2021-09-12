# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

import click
import logging
from datetime import timedelta
from typing import Optional, Tuple

from tufrepo.repo import Repo
from tufrepo.keys import Keyring

logger = logging.getLogger(__name__)


@click.group()
@click.pass_context
@click.option("-v", "--verbose", count=True)
def cli(ctx: click.Context, verbose: int = 0):
    """Edit and sign TUF repository metadata

    This tool expects to be run in a (git) metadata repository"""

    logging.basicConfig(format="%(levelname)s:%(message)s")
    logger.setLevel(max(1, 10 * (5 - verbose)))

    ctx.obj = Repo(Keyring())


@cli.command()
@click.pass_context
@click.argument("roles", nargs=-1)
def sign(ctx: click.Context, roles: Tuple[str]):
    """Sign the given roles, using all usable keys in keyring"""
    repo: Repo = ctx.obj
    repo.sign(list(roles))


@cli.command()
@click.pass_context
@click.option("--root-hash")
def verify(ctx: click.Context, root_hash: Optional[str] = None):
    """"""
    repo: Repo = ctx.obj
    repo.verify(root_hash)


@cli.command()
@click.pass_context
def snapshot(ctx: click.Context):
    """"""
    repo: Repo = ctx.obj
    repo.snapshot()


@cli.group()
@click.argument("role")
def edit(role: str):  # pylint: disable=unused-argument
    """Edit metadata for ROLE using the sub-commands."""


@edit.command()
@click.pass_context
def touch(ctx: click.Context):
    """Mark ROLE as modified to force a new version"""
    assert ctx.parent
    repo: Repo = ctx.obj
    repo.touch(ctx.parent.params["role"])


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
    assert ctx.parent
    repo: Repo = ctx.obj
    delta = timedelta(**{expiry[1]: expiry[0]})
    repo.init_role(ctx.parent.params["role"], int(delta.total_seconds()))


@edit.command()
@click.pass_context
@click.argument("delegate")
@click.argument("threshold", type=int)
def set_threshold(ctx: click.Context, delegate: str, threshold: int):
    """Set the threshold of delegated role DELEGATE."""
    assert ctx.parent
    repo: Repo = ctx.obj
    repo.set_threshold(ctx.parent.params["role"], delegate, threshold)


@edit.command()
@click.pass_context
@click.argument(
    "expiry",
    type=(int, click.Choice(["minutes", "days", "weeks"], case_sensitive=False)),
)
def set_expiry(ctx: click.Context, expiry: Tuple[int, str]):
    """Set expiry period for the role. Example:

    tufrepo edit root set-expiry 52 weeks"""
    assert ctx.parent
    repo: Repo = ctx.obj
    delta = timedelta(**{expiry[1]: expiry[0]})
    repo.set_expiry(ctx.parent.params["role"], int(delta.total_seconds()))


@edit.command()
@click.pass_context
@click.argument("delegate")
def add_key(ctx: click.Context, delegate: str):
    """Add new signing key for delegated role DELEGATE

    The private key secret will be written to privkeys.json."""
    assert ctx.parent
    repo: Repo = ctx.obj
    repo.add_key(ctx.parent.params["role"], delegate)


@edit.command()
@click.pass_context
@click.argument("delegate")
@click.argument("keyid")
def remove_key(ctx: click.Context, delegate: str, keyid: str):
    """Remove signing key from delegated role DELEGATE"""
    assert ctx.parent
    repo: Repo = ctx.obj
    repo.remove_key(ctx.parent.params["role"], delegate, keyid)


@edit.command()
@click.pass_context
@click.argument("target")
@click.argument("local-file")
def add_target(ctx: click.Context, target: str, local_file: str):
    """Add a target to a Targets metadata role"""
    assert ctx.parent
    repo: Repo = ctx.obj
    repo.add_target(ctx.parent.params["role"], target, local_file)


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
    assert ctx.parent
    repo: Repo = ctx.obj
    paths_list = list(paths) if paths else None
    hash_prefixes_list = list(hash_prefixes) if hash_prefixes else None
    repo.add_delegation(
        ctx.parent.params["role"], delegate, terminating, paths_list, hash_prefixes_list
    )
