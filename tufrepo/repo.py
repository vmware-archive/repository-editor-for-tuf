# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

# Repo class implements repository operations. It is invoked by the CLI.

from abc import abstractmethod
import glob
import logging
import os
import shutil
import subprocess

from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timedelta
from tempfile import TemporaryDirectory
from typing import Dict, Generator, List, Optional, Tuple

from click.exceptions import ClickException
from securesystemslib.exceptions import StorageError
from securesystemslib.hash import digest_fileobject
from tuf.exceptions import RepositoryError
from tuf.api.metadata import (
    Key,
    Metadata,
    MetaFile,
    Role,
    Root,
    Signed,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient import Updater

from tufrepo.filesystem_fetcher import FilesystemFetcher
from tufrepo.keys import Keyring

logger = logging.getLogger("tufrepo")


###  Some editing helpers for Metadata

def editor_init(role: str, expiry_date: datetime) -> Metadata:
    if role == "root":
        roles = {
            "root": Role([], 1),
            "targets": Role([], 1),
            "snapshot": Role([], 1),
            "timestamp": Role([], 1),
        }
        signed = Root(1, "1.0.19", expiry_date, {}, roles, True)
    elif role == "timestamp":
        signed = Timestamp(1, "1.0.19", expiry_date, MetaFile(1))
    elif role == "snapshot":
        signed = Snapshot(1, "1.0.19", expiry_date, {})
    else:
        signed = Targets(1, "1.0.19", expiry_date, {}, None)
    
    return Metadata(signed, OrderedDict())

def editor_set_threshold(self: Signed, delegate: str, threshold: int):
    role = None
    if isinstance(self, Root):
        role = self.roles.get(delegate)
    elif isinstance(self, Targets):
        if self.delegations is not None:
            role = self.delegations.roles.get(delegate)
    else:
        raise ClickException(f"Not a delegator")

    if role is None:
        raise ClickException(f"Role {delegate} not found")
    role.threshold = threshold

def editor_add_key(self: Signed, delegator: str, delegate: str, key: Key):
    if isinstance(self, Root) or isinstance(self, Targets):
        try:
            self.add_key(delegate, key)
        except ValueError:
            raise ClickException(f"{delegator} does not delegate to {delegate}")
    else:
        raise ClickException(f"{delegator} is not delegating metadata")

def editor_remove_key(self: Signed, delegator: str, delegate: str, keyid: str):
    if isinstance(self, Root) or isinstance(self, Targets):
        try:
            self.remove_key(delegate, keyid)
        except ValueError:
            raise ClickException(f"{delegator} does not delegate to {delegate}")
    else:
        raise ClickException(f"{delegator} is not delegating metadata")


class Repository:
    def __init__(self, keyring: Keyring) -> None:
        self.keyring = keyring

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

    @abstractmethod
    def _load(self, role:str) -> Metadata:
        """Load metadata from storage or cache"""

    @abstractmethod
    def _save(self, role: str, md: Metadata, clear_sigs: bool = True):
        """Sign and persist metadata in storage"""

    @abstractmethod
    def init_role(self, role:str, period: int):
        """Initialize new metadata"""

    def sign(self, role: str):
        """sign without modifying content, or removing existing signatures"""
        md = self._load(role)
        self._save(role, md, False)

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
                    raise ClickException(f"{keyname} version rollback")
                elif new_meta.version > old_meta.version:
                    updated_snapshot = True
                    snapshot.meta[keyname] = new_meta
                    removed_targets[keyname] = old_meta

        if updated_snapshot:
            logger.info(f"Snapshot updated with {len(snapshot.meta)} targets")
            # Timestamp update
            with self.edit("timestamp") as timestamp:
                timestamp.snapshot_meta = MetaFile(snapshot.version)
            logger.info("Timestamp updated")
        else:
            logger.info("Snapshot update not needed")

        return removed_targets

    @contextmanager
    def edit(self, role:str, expiry: datetime, version: int) -> Generator[Signed, None, None]:
        md = self._load(role)

        yield md.signed

        md.signed.expires = expiry
        md.signed.version = version
        self._save(role, md)


### git+file implementation of Repository
class FilesystemRepository(Repository):
    """Manages loading, saving (signing) repository metadata in files stored in git"""

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

    def _load(self, role:str) -> Metadata:
        fname = self._get_filename(role)
        try:
            return Metadata.from_file(fname)
        except StorageError as e:
            raise ClickException(f"Failed to open {fname}.") from e

    def _save(self, role: str, md: Metadata, clear_sigs: bool = True):
        self._sign_role(role, md, clear_sigs)

        fname = self._get_filename(role, md.signed.version)
        md.to_file(fname, JSONSerializer())

        self._git(["add", "--intent-to-add", self._get_filename(role, md.signed.version)])

    def init_role(self, role:str, period: int):
        md = editor_init(role, self._get_expiry(period))
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
    def edit(self, role:str) -> Generator[Signed, None, None]:
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

        with super().edit(role, expiry, version) as signed:
            yield signed

        if remove_old:
            os.remove(old_filename)


### verify repository contents
def verify_repo(root_hash: Optional[str]):
    if not os.path.exists("1.root.json"):
        raise ClickException("Failed to find 1.root.json")

    if root_hash is not None:
        # verify initial root is what we expected
        with open("1.root.json") as initial_root:
            digest_object = digest_fileobject(initial_root)
        digest = digest_object.hexdigest()
        if digest != root_hash:
            raise ClickException(f"Unexpected hash digest {digest} for 1.root.json")

    # Do a normal client update to ensure metadata is good
    client_dir = TemporaryDirectory()
    shutil.copy("1.root.json", f"{client_dir.name}/root.json")
    fsfetcher = FilesystemFetcher({"http://localhost/fakeurl/": "."})
    try:
        updater = Updater(
            repository_dir=client_dir.name,
            metadata_base_url="http://localhost/fakeurl/",
            target_base_url="http://localhost/fakeurl/",
            fetcher=fsfetcher,
        )
        updater.refresh()
    except RepositoryError as e:
        # TODO: improve this message by checking for common mistakes?
        raise ClickException("Top-level metadata fails to validate") from e

    # recursively verify all targets in delegation tree
    # This code is pretty horrible
    snapshot: Snapshot = updater._trusted_set.snapshot.signed
    delegators: List[Tuple[str, Targets]] = [
        ("targets", updater._trusted_set["targets"].signed)
    ]
    while delegators:
        delegator_name, delegator = delegators.pop(0)
        if delegator.delegations is None:
            continue

        for role in delegator.delegations.roles.values():
            try:
                metainfo = snapshot.meta[f"{role.name}.json"]
            except KeyError:
                raise ClickException(
                    f"Snapshot is invalid: {role.name} not found in snapshot"
                )
            filename = f"{metainfo.version}.{role.name}.json"
            try:
                with open(filename, "rb") as file:
                    role_data = file.read()
            except FileNotFoundError:
                raise ClickException(
                    f"Snapshot is invalid: file {filename} not found"
                )
            else:
                logger.debug("Verifying %s", role.name)
                try:
                    updater._trusted_set.update_delegated_targets(
                        role_data, role.name, delegator_name
                    )
                    delegators.append(
                        (role.name, updater._trusted_set[role.name].signed)
                    )
                except RepositoryError as e:
                    raise ClickException(
                        "Delegated target fails to validate"
                    ) from e

    deleg_count = len(updater._trusted_set) - 4

    print(f"Metadata with {deleg_count} delegated targets verified")
