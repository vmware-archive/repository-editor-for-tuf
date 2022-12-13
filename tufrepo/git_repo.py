# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

# Git + filesystem based implementation of Repository. Invoked by the CLI.

import glob
import logging
import os
import subprocess

from contextlib import suppress
from datetime import datetime, timedelta
from typing import Dict, List, Optional

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

from tufrepo.librepo.repo import MetadataDescriptor, Repository
from tufrepo.librepo.keys import Keyring

logger = logging.getLogger("tufrepo")

_signed_init = {
    Root.type: Root,
    Snapshot.type: Snapshot,
    Targets.type: Targets,
    Timestamp.type: Timestamp,
}


def _git(command: List[str]):
    """Helper to run git commands in the repository git repo"""
    full_cmd = ["git"] + command
    proc = subprocess.run(full_cmd)
    return proc.returncode

class GitMetadata(MetadataDescriptor):
    def __init__(self, role: str, keyring: Keyring, init: bool = False):
        self._role = role
        self._keyring = keyring
        self._fname = self._get_filename(role)
        if init:
            # safety check
            filenames = glob.glob(f"*.{role}.json")
            versions = [int(name.split(".", 1)[0]) for name in filenames]
            if versions:
                raise ValueError(f"cannot initialize {role} as versions already exist")

            signed_init = _signed_init.get(role, Targets)
            self._md = Metadata(signed_init())
        else:
            try:
                self._md = Metadata.from_file(self._fname)
            except StorageError as e:
                raise ClickException(f"Failed to open {self._fname}.") from e
        self._version = self.signed.version

    @property
    def signed(self) -> Signed:
        return self._md.signed

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

    def _sign_role(self):
        try:
            for signer in self._keyring[self._role]:
                logger.info("Signing role %s", self._role)
                self._md.sign(signer, append=True)
        except KeyError:
            logger.info(f"No keys for role %s found in keyring", self._role)

    def close(self, sign_only: bool = False):
        if not sign_only:
            # Find out expiry and need for version bump
            try:
                period = self.signed.unrecognized_fields["x-tufrepo-expiry-period"]
            except KeyError:
                raise ClickException(
                    "Expiry period not found in metadata: use 'set-expiry'"
                )

            self.signed.expires = datetime.utcnow() + timedelta(seconds=period)

            diff_cmd = ["diff", "--exit-code", "--no-patch", "--", self._fname]
            if os.path.exists(self._fname) and _git(diff_cmd) == 0:
                self.signed.version += 1

            self._md.signatures.clear()

        self._sign_role()

        fname = self._get_filename(self._role, self.signed.version)
        self._md.to_file(fname, JSONSerializer())
        _git(["add", "--intent-to-add", fname])



class GitRepository(Repository):
    """Manages loading, saving (signing) repository metadata in files stored in git"""

    def __init__(self, keyring: Keyring):
        self._keyring = keyring

    def open(self, role:str, init: bool = False) -> GitMetadata:
        return GitMetadata(role, self._keyring, init)

    def snapshot(self) -> bool:
        """Update snapshot meta information

        This command only updates the meta information in snapshot
        according to current filenames: it does not validate those files in any
        way. Run 'verify' after 'snapshot' to validate repository state.

        Deletes targets files once they are no longer part of the
        repository.

        Returns False if a new snapshot version was not needed, True otherwise.
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

        updated, removed = super().snapshot(targets_roles)

        # delete the removed files (if any)
        for keyname, meta in removed.items():
            with suppress(FileNotFoundError):
                os.remove(f"{meta.version}.{keyname}")

        return updated

    def timestamp(self):
        """Update timestamp meta information

        Deletes the old snapshot file once it's no longer part of the
        repository.
        """

        # NOTE: we trust the version in the filename to be correct here
        current_version = 0
        for filename in glob.glob("*.snapshot.json"):
            version, _ = filename[: -len(".json")].split(".")
            current_version = max(current_version, int(version))

        old_snapshot_meta = super().timestamp(MetaFile(current_version))

        if old_snapshot_meta:
            with suppress(FileNotFoundError):
                os.remove(f"{old_snapshot_meta.version}.snapshot.json")

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
            _git(["add", "--intent-to-add", local_file])
            for h in targetfile.hashes.values():
                dir, src_file = os.path.split(local_file)
                dst = os.path.join(dir, f"{h}.{src_file}")
                if os.path.islink(dst):
                    os.remove(dst)
                os.symlink(src_file, dst)
                _git(["add", "--intent-to-add", dst])

        return final_role
