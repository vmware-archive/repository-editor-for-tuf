# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

# Git + filesystem based implementation of Repository. Invoked by the CLI.

import glob
import logging
import os
import subprocess

from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, Generator, List, Optional

from click.exceptions import ClickException
from securesystemslib.exceptions import StorageError
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Signed,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

from tufrepo import helpers
from tufrepo.librepo.repo import AbortEdit, Repository
from tufrepo.librepo.keys import Keyring

logger = logging.getLogger("tufrepo")

_signed_init = {
    Root.type: Root,
    Snapshot.type: Snapshot,
    Targets.type: Targets,
    Timestamp.type: Timestamp,
}


class GitRepository(Repository):
    """Manages loading, saving (signing) repository metadata in files stored in git"""

    def __init__(self, keyring: Keyring):
        self._keyring = keyring

    @property
    def keyring(self) -> Keyring:
        return self._keyring

    @staticmethod
    def _git(command: List[str]):
        """Helper to run git commands in the repository git repo"""
        full_cmd = ["git"] + command
        proc = subprocess.run(full_cmd)
        return proc.returncode

    @staticmethod
    def _get_expiry(expiry_period: int) -> datetime:
        delta = timedelta(seconds=expiry_period)
        now = datetime.utcnow().replace(microsecond=0)
        return now + delta

    @staticmethod
    def _get_filename(role: str, version: Optional[int] = None):
        """Returns versioned filename"""
        if role == "timestamp":
            return f"{role}.json"
        else:
            if version is None:
                # Find largest version number in filenames
                filenames = glob.glob(f"*.{role}.json")
                versions = [int(name.split(".", 1)[0]) for name in filenames]
                try:
                    version = max(versions)
                except ValueError:
                    # No files found
                    version = 1

            return f"{version}.{role}.json"

    def _load(self, role: str) -> Metadata:
        fname = self._get_filename(role)
        try:
            return Metadata.from_file(fname)
        except StorageError as e:
            raise ClickException(f"Failed to open {fname}.") from e

    def _save(self, role: str, md: Metadata, clear_sigs: bool = True):
        self._sign_role(role, md, clear_sigs)

        fname = self._get_filename(role, md.signed.version)
        md.to_file(fname, JSONSerializer())

        self._git(
            ["add", "--intent-to-add", self._get_filename(role, md.signed.version)]
        )

    def init_role(self, role: str, period: int):
        signed_init = _signed_init.get(role, Targets)
        md = Metadata(signed_init(expires=self._get_expiry(period)))
        md.signed.unrecognized_fields["x-tufrepo-expiry-period"] = period
        self._save(role, md)

    def snapshot(self):
        """Update snapshot and timestamp meta information

        This command only updates the meta information in snapshot/timestamp
        according to current filenames: it does not validate those files in any
        way. Run 'verify' after 'snapshot' to validate repository state.
        """

        # Find targets role name and newest version
        # NOTE: we trust the version in the filenames to be correct here
        targets_roles: Dict[str, MetaFile] = {}
        for filename in glob.glob("*.*.json"):
            version, keyname = filename[: -len(".json")].split(".")
            version = int(version)
            if keyname in ["root", "snapshot", "timestamp"]:
                continue
            keyname = f"{keyname}.json"

            curr_role = targets_roles.get(keyname)
            if not curr_role or version > curr_role.version:
                targets_roles[keyname] = MetaFile(version)

        removed = super().snapshot(targets_roles)

        for keyname, meta in removed.items():
            # delete the older file (if any): it is not part of snapshot
            try:
                os.remove(f"{meta.version}.{keyname}")
            except FileNotFoundError:
                pass

    @contextmanager
    def edit(self, role: str) -> Generator[Signed, None, None]:
        md = self._load(role)
        version = md.signed.version
        old_filename = self._get_filename(role, version)
        remove_old = False

        # Find out expiry and need for version bump
        try:
            period = md.signed.unrecognized_fields["x-tufrepo-expiry-period"]
        except KeyError:
            raise ClickException(
                "Expiry period not found in metadata: use 'set-expiry'"
            )
        expiry = self._get_expiry(period)

        diff_cmd = ["diff", "--exit-code", "--no-patch", "--", old_filename]
        if os.path.exists(old_filename) and self._git(diff_cmd) == 0:
            version += 1
            # only snapshots need deleting (targets are deleted in snapshot())
            if role == "snapshot":
                remove_old = True

        try:
            with super()._edit(role, expiry, version) as signed:
                yield signed
        except AbortEdit:
            pass # caller aborted edit
        else:
            if remove_old:
                os.remove(old_filename)

    def add_target(self, role, follow_delegations: bool, target_in_repo: bool, target_path: str, local_file: str) -> str:
        """Adds a file to the repository as a target

        role: name of targets role that is the starting point for the targets-role search
        follow_delegations: should delegations under role be followed to find the correct targets-role
        target_in_repo: should local_file (and hash-prefixed symlinks) be added to git as well

        Returns the name of the role the target was actually added into
        """
        targetfile = None

        # special case delegation search: if follow_delegations, then we look
        # for the first "leaf" targets role (that does not delegate further)
        while not targetfile:
            with self.edit(role) as targets:
                targets: Targets

                if targets.delegations and follow_delegations:
                    # see if target path is delegated (always pick first valid delegation)
                    delegations = targets.delegations.get_roles_for_target(target_path)
                    new_role, _ = next(delegations, (None, None))
                    if new_role:
                        role = new_role
                        raise AbortEdit("Skip add-target: use delegation instead")

                # role does not delegate further: add the target
                targetfile = TargetFile.from_file(target_path, local_file)
                targets.targets[targetfile.path] = targetfile

                if target_in_repo:
                    self._git(["add", "--intent-to-add", local_file])
                    # create hash-symlinks for target file
                    for h in targetfile.hashes.values():
                        dir, src_file = os.path.split(local_file)
                        dst = os.path.join(dir, f"{h}.{src_file}")
                        if os.path.islink(dst):
                            os.remove(dst)
                        os.symlink(src_file, dst)
                        self._git(["add", "--intent-to-add", dst])

        return role

    def remove_target(self, role: str, follow_delegations: bool, target_path: str) -> Optional[str]:
        """Removes a file from the repository

        role: name of targets role that is the starting point for the targets-role search
        follow_delegations: should delegations under role be followed to find the correct targets-role

        Returns the name of the role the target was actually removed from (or
        None if nothing was removed)
        """
        targetfile = None
        roles = [role]

        # Delegation search here works like the one in tuf.ngclient
        while roles:
            role = roles.pop(-1)
            with self.edit(role) as targets:
                targets: Targets

                if target_path in targets.targets:
                    del targets.targets[target_path]
                    return role

                # target file was not found in this metadata: try delegations
                if targets.delegations and follow_delegations:
                    child_roles = []
                    for (
                        child, terminating
                    ) in targets.delegations.get_roles_for_target(target_path):
                        child_roles.append(child)
                        if terminating:
                            # prevent further delegation search
                            roles.clear()
                            break
                    roles.extend(reversed(child_roles))

                raise AbortEdit("skipping remove-target: target not found in metadata")

        # No target found
        return None

