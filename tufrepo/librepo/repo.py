# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

# Repo class implements repository operations. It is invoked by the CLI.

import logging

from abc import abstractmethod, ABC
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, Generator, List, Optional, Tuple

from tuf.api.metadata import Metadata, MetaFile, Signed, TargetFile, Targets, Timestamp

from tufrepo.librepo.keys import Keyring

logger = logging.getLogger("tufrepo")

class AbortEdit(Exception):
    pass

class Repository(ABC):

    def _sign_role(self, role: str, metadata: Metadata, clear_sigs: bool):
        if clear_sigs:
            metadata.signatures.clear()

        try:
            for key in self.keyring[role]:
                keyid = key.public.keyid
                logger.info("Signing role %s with key %s", role, keyid[:7])
                metadata.sign(key.signer, append=True)
        except KeyError:
            logger.info(f"No keys for role %s found in keyring", role)

    @property
    @abstractmethod
    def keyring(self) -> Keyring:
        """return a Keyring containing the private keys needed for signing"""
        raise NotImplementedError

    @abstractmethod
    def _load(self, role:str) -> Metadata:
        """Load metadata from storage or cache"""

    @abstractmethod
    def _save(self, role: str, md: Metadata, clear_sigs: bool = True):
        """Sign and persist metadata in storage"""

    @abstractmethod
    def init_role(self, role:str, period: int):
        """Initialize new metadata"""

    @contextmanager
    @abstractmethod
    def edit(self, role:str) -> Generator[Signed, None, None]:
        """Context manager for editing a roles metadata

        Context manager takes care of loading the roles metadata, updating expiry
        and version. The caller can do other changes to the Signed object and when
        the context manager exits, a new version of the roles metadata is stored.

        Context manager user can raise AbortEdit from inside thw with-block to
        cancel the edit: in this case none of the changes are stored.
        """

    def sign(self, role: str):
        """sign without modifying content, or removing existing signatures"""
        md = self._load(role)
        self._save(role, md, False)

    def snapshot(self, current_targets: Dict[str, MetaFile]) -> Tuple[bool, Dict[str, MetaFile]]:
        """Update snapshot and timestamp meta information

        Updates the meta information in snapshot/timestamp according to input.

        Returns a tuple:
         - True if a new snapshot was created
         - metafiles for targets metadata that were removed from repository
        """

        # Snapshot update is needed if
        # * any targets files are not in snapshot or
        # * any targets version is incorrect
        updated_snapshot = False
        removed: Dict[str, MetaFile] = {}

        with self.edit("snapshot") as snapshot:
            for keyname, new_meta in current_targets.items():
                if keyname not in snapshot.meta:
                    updated_snapshot = True
                    snapshot.meta[keyname] = new_meta
                    continue

                old_meta = snapshot.meta[keyname]
                if new_meta.version < old_meta.version:
                    raise ValueError(f"{keyname} version rollback")
                elif new_meta.version > old_meta.version:
                    updated_snapshot = True
                    snapshot.meta[keyname] = new_meta
                    removed[keyname] = old_meta

            if not updated_snapshot:
                # prevent edit() from saving a new snapshot version
                raise AbortEdit("Skip snapshot: No targets version changes")

        if not updated_snapshot:
            logger.info("Snapshot update not needed")
        else:
            logger.info(f"Snapshot updated with {len(snapshot.meta)} targets")

        return updated_snapshot, removed

    def timestamp(self, snapshot_version: int) -> Optional[int]:
        """Update timestamp meta information

        Updates timestamp with given snapshot version number.

        Returns the snapshot version that was removed from repository (if any).
        """
        with self.edit("timestamp") as timestamp:
            timestamp: Timestamp
            old_snapshot_version = timestamp.snapshot_meta.version
            timestamp.snapshot_meta = MetaFile(snapshot_version)

        logger.info("Timestamp updated")
        if old_snapshot_version == snapshot_version:
            return None
        return old_snapshot_version

    def add_target(self, role:str, follow_delegations: bool, targetfile: TargetFile) -> str:
        """Adds a file to the repository as a target

        role: name of targets role that is the starting point for the targets-role search
        follow_delegations: should delegations under role be followed to find the correct targets-role

        Returns the name of the role the target was actually added into
        """

        # special case delegation search: if follow_delegations, then we look
        # for the first "leaf" targets role (that does not delegate further)
        while True:
            with self.edit(role) as targets:
                targets: Targets

                if targets.delegations and follow_delegations:
                    # see if target path is delegated (always pick first valid delegation)
                    delegations = targets.delegations.get_roles_for_target(targetfile.path)
                    new_role, _ = next(delegations, (None, None))
                    if new_role:
                        role = new_role
                        raise AbortEdit("Skip add-target: use delegation instead")

                # role does not delegate further: add the target
                targets.targets[targetfile.path] = targetfile
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
                    child_roles: List[str] = []
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