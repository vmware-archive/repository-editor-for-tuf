# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

# Git + filesystem based implementation of Repository. Invoked by the CLI.

import glob
import logging
import os
import subprocess

from contextlib import contextmanager, suppress
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

        Deletes snapshot and targets files once they are no longer part of the
        repository.
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

        # delete the removed files (if any)
        for keyname, meta in removed.items():
            with suppress(FileNotFoundError):
                os.remove(f"{meta.version}.{keyname}")

    @contextmanager
    def edit(self, role: str) -> Generator[Signed, None, None]:
        md = self._load(role)
        version = md.signed.version
        old_filename = self._get_filename(role, version)

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

        # allow user to cancel the edit by raising AbortEdit
        with suppress(AbortEdit):
            with super()._edit(role, expiry, version) as signed:
                yield signed

    def add_target(
        self,
        role,
        follow_delegations: bool,
        target_in_repo: bool,
        target_path: str,
        local_file: str,
    ) -> str:
        """Adds a file to the repository as a target

        role: name of targets role that is the starting point for the targets-role search
        follow_delegations: should delegations under role be followed to find the correct targets-role
        target_in_repo: should local_file (and hash-prefixed symlinks) be added to git as well

        Returns the name of the role the target was actually added into
        """

        targetfile = TargetFile.from_file(target_path, local_file)
        final_role = super().add_target(role, follow_delegations, targetfile)

        # Add the actual file to git and create hash-prefixed symlinks
        if target_in_repo:
            self._git(["add", "--intent-to-add", local_file])
            for h in targetfile.hashes.values():
                dir, src_file = os.path.split(local_file)
                dst = os.path.join(dir, f"{h}.{src_file}")
                if os.path.islink(dst):
                    os.remove(dst)
                os.symlink(src_file, dst)
                self._git(["add", "--intent-to-add", dst])

        return final_role
