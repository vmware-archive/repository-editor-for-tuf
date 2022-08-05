# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

# Repo class implements repository operations. It is invoked by the CLI.

import logging

from abc import abstractmethod, ABC
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, Generator

from tuf.api.metadata import Metadata, MetaFile, Signed

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

    @contextmanager
    def _edit(self, role:str, expiry: datetime, version: int) -> Generator[Signed, None, None]:
        """Helper function for edit() implementations"""
        md = self._load(role)

        yield md.signed

        md.signed.expires = expiry
        md.signed.version = version
        self._save(role, md)

    def snapshot(self, current_targets: Dict[str, MetaFile]) -> Dict[str, MetaFile]:
        """Update snapshot and timestamp meta information

        Updates the meta information in snapshot/timestamp according to input.

        Returns the targets metafiles that were removed from snapshot
        """

        # Snapshot update is needed if
        # * any targets files are not in snapshot or
        # * any targets version is incorrect
        updated_snapshot = False
        removed_targets: Dict[str, MetaFile] = {}

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
                    removed_targets[keyname] = old_meta

            if not updated_snapshot:
                # prevent edit() from saving a new snapshot version
                raise AbortEdit("Skip snapshot: No targets version changes")

        if not updated_snapshot:
            logger.info("Snapshot update not needed")
        else:
            logger.info(f"Snapshot updated with {len(snapshot.meta)} targets")
            # Timestamp update
            with self.edit("timestamp") as timestamp:
                timestamp.snapshot_meta = MetaFile(snapshot.version)
            logger.info("Timestamp updated")

        return removed_targets
