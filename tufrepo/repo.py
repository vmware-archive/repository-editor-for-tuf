# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

# Repo class implements repository operations. It is invoked by the CLI.

import glob
import io
import logging
import os
import shutil
import subprocess

from collections import OrderedDict
from datetime import datetime, timedelta
from tempfile import TemporaryDirectory
from typing import Dict, List, Optional, Tuple

from click.exceptions import ClickException
from securesystemslib.exceptions import StorageError
from securesystemslib.hash import digest_fileobject
from tuf.exceptions import RepositoryError
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    Targets,
    Timestamp,
    TargetFile,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient import Updater

from tufrepo.filesystem_fetcher import FilesystemFetcher
from tufrepo.keys import Keyring

logger = logging.getLogger("tufrepo")


class Repo:
    def __init__(self, keyring: Keyring):
        self.keyring = keyring

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

    def _sign_role(self, role: str, metadata: Metadata):
        try:
            for key in self.keyring[role]:
                keyid = key.public.keyid
                logger.info("Signing role %s with key %s", role, keyid[:7])
                metadata.sign(key.signer, append=True)
        except KeyError:
            logger.info(f"No keys for role %s found in keyring", role)

    def sign(self, roles: List[str]):
        for role in roles:
            role_md = Metadata.from_file(self._get_filename(role))
            self._sign_role(role, role_md)
            role_md.to_file(self._get_filename(role), JSONSerializer())

    @staticmethod
    def _git(command: List[str]):
        """Helper to run git commands in the repository git repo"""
        full_cmd = ["git"] + command
        proc = subprocess.run(full_cmd)
        return proc.returncode

    def _write_edited_role(self, role: str, md: Metadata, period: Optional[int] = None):
        old_filename = Repo._get_filename(role, md.signed.version)

        # only bump version once (if file is unchanged according to git)
        diff_cmd = ["diff", "--exit-code", "--no-patch", "--", old_filename]
        if os.path.exists(old_filename) and self._git(diff_cmd) == 0:
            md.signed.version += 1

        # Store expiry period if given
        if period is not None:
            md.signed.unrecognized_fields["x-tufrepo-expiry-period"] = period

        # Update expires
        try:
            _period = md.signed.unrecognized_fields["x-tufrepo-expiry-period"]
        except KeyError:
            raise ClickException(
                "Expiry period not found in metadata: use 'set-expiry'"
            )
        md.signed.expires = self._get_expiry(_period)

        # Remove now invalid signatures, sign with any keys we have
        md.signatures.clear()
        self._sign_role(role, md)

        new_filename = self._get_filename(role, md.signed.version)
        md.to_file(new_filename, JSONSerializer())

        # Don't delete old target versions: they are still part of snapshot
        if (old_filename is not None and
            new_filename != old_filename and
            role in ["root", "timestamp", "snapshot"]):

            os.remove(old_filename)

        self._git(["add", "--intent-to-add", new_filename])

    def _load_role_for_edit(self, role: str) -> Metadata:
        fname = self._get_filename(role)
        try:
            return Metadata.from_file(fname)
        except StorageError as e:
            raise ClickException(f"Failed to open {fname}.") from e

    def verify(self, root_hash: Optional[str]):
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
        print(f"Keyring contains keys for [{', '.join(self.keyring.keys())}].")

    def snapshot(self):
        """Update snapshot and timestamp meta information

        This command only updates the meta information in snapshot/timestamp
        according to current filenames: it does not validate those files in any
        way. Run 'verify' after 'snapshot' to validate repository state.
        """

        snapshot_md = self._load_role_for_edit("snapshot")
        snapshot: Snapshot = snapshot_md.signed

        # Find targets role name and newest version
        # NOTE: we trust the version in the filenames to be correct here
        targets_roles: Dict[str, int] = {}
        for filename in glob.glob("*.*.json"):
            version, role = filename[: -len(".json")].split(".")
            version = int(version)
            if role in ["root", "snapshot", "timestamp"]:
                continue
            if version > targets_roles.get(role, 0):
                targets_roles[role] = version

        # Snapshot update is needed if
        # * any targets files are not in snapshot or
        # * any targets version is incorrect
        updated_snapshot = False
        for role, version in targets_roles.items():
            if f"{role}.json" not in snapshot.meta:
                meta_version = 0
            else:
                meta_version = snapshot.meta[f"{role}.json"].version

            if version < meta_version:
                raise ClickException(f"Role {role} version rollback")
            elif version > meta_version:
                updated_snapshot = True
                snapshot.meta[f"{role}.json"] = MetaFile(version)

                # delete the older file (if any): it is not part of snapshot
                try:
                    os.remove(f"{meta_version}.{role}.json")
                except FileNotFoundError:
                    pass

        if not updated_snapshot:
            logger.info("Snapshot update not needed")
            return

        logger.info(f"Updating Snapshot with {len(snapshot.meta)} targets metadata")
        self._write_edited_role("snapshot", snapshot_md)

        # Timestamp update
        timestamp_md = self._load_role_for_edit("timestamp")
        timestamp: Timestamp = timestamp_md.signed
        logger.info(f"Updating Timestamp with snapshot version {snapshot.version}")
        timestamp.snapshot_meta = MetaFile(snapshot.version)
        self._write_edited_role("timestamp", timestamp_md)

    def init_role(self, role: str, expiry_period: int):
        filename = self._get_filename(role)
        if os.path.exists(filename):
            raise ClickException(f"Role {role} already exists")

        expiry_date = self._get_expiry(expiry_period)

        if role == "root":
            roles = {
                "root": Role([], 1),
                "targets": Role([], 1),
                "snapshot": Role([], 1),
                "timestamp": Role([], 1),
            }
            root_signed = Root(1, "1.0.19", expiry_date, {}, roles, True)
            role_md = Metadata(root_signed, OrderedDict())
        elif role == "timestamp":
            timestamp_signed = Timestamp(1, "1.0.19", expiry_date, MetaFile(1))
            role_md = Metadata(timestamp_signed, OrderedDict())
        elif role == "snapshot":
            snapshot_signed = Snapshot(1, "1.0.19", expiry_date, {})
            role_md = Metadata(snapshot_signed, OrderedDict())
        else:
            targets_signed = Targets(1, "1.0.19", expiry_date, {}, None)
            role_md = Metadata(targets_signed, OrderedDict())

        role_md.signed.unrecognized_fields["x-tufrepo-expiry-period"] = expiry_period

        self._write_edited_role(role, role_md)

    def touch(self, role: str):
        md = self._load_role_for_edit(role)
        self._write_edited_role(role, md)

    def set_threshold(self, delegator: str, delegate: str, threshold: int):
        md = self._load_role_for_edit(delegator)

        role = None
        if isinstance(md.signed, Root):
            role = md.signed.roles.get(delegate)
        elif isinstance(md.signed, Targets):
            if md.signed.delegations is not None:
                role = md.signed.delegations.roles.get(delegate)
        else:
            raise ClickException(f"{delegator} is not a delegator")

        if role is None:
            raise ClickException(f"Role {delegate} not found")
        role.threshold = threshold

        self._write_edited_role(delegator, md)

    def set_expiry(self, role: str, expiry_period: int):
        md = self._load_role_for_edit(role)
        self._write_edited_role(role, md, expiry_period)

    def add_key(self, delegator: str, delegate: str):
        md = self._load_role_for_edit(delegator)
        key = self.keyring.generate_key()

        if isinstance(md.signed, Root) or isinstance(md.signed, Targets):
            try:
                md.signed.add_key(delegate, key.public)
            except ValueError:
                raise ClickException(f"{delegator} does not delegate to {delegate}")
        else:
            raise ClickException(f"{delegator} is not delegating metadata")

        self._write_edited_role(delegator, md)
        self.keyring.store_key(delegate, key)

    def remove_key(self, delegator: str, delegate: str, keyid: str):
        md = self._load_role_for_edit(delegator)

        if isinstance(md.signed, Root) or isinstance(md.signed, Targets):
            try:
                md.signed.remove_key(delegate, keyid)
            except ValueError:
                raise ClickException(f"{delegator} does not delegate to {delegate}")
        else:
            raise ClickException(f"{delegator} is not delegating metadata")

        self._write_edited_role(delegator, md)
        print(f"Removed {delegate} key {keyid[:7]} from {delegator}")

    def add_delegation(
        self,
        delegator: str,
        delegate: str,
        terminating: bool,
        paths: Optional[List[str]],
        hash_prefixes: Optional[List[str]],
    ):
        md = self._load_role_for_edit(delegator)
        targets: Targets = md.signed

        role = DelegatedRole(delegate, [], 1, terminating, paths, hash_prefixes)

        if targets.delegations is None:
            targets.delegations = Delegations({}, OrderedDict())
        targets.delegations.roles[role.name] = role

        self._write_edited_role(delegator, md)

        logger.info("Delegated from %s to %s", delegator, delegate)

    def remove_delegation(self, delegator: str, delegate: str):
        md = self._load_role_for_edit(delegator)
        targets: Targets = md.signed

        del targets.delegations.roles[delegate]
        # TODO remove keys if unused?
        # TODO remove the delegated role targets file?

        self._write_edited_role(delegator, md)

    def add_target(self, role: str, target_path: str, local_file: str):
        targets_md = self._load_role_for_edit(role)
        targetfile = TargetFile.from_file(target_path, local_file)
        targets_md.signed.targets[targetfile.path] = targetfile

        self._write_edited_role(role, targets_md)

        logger.info("Added target %s", targetfile.path)

    def remove_target(self, role: str, target_path: str):
        targets_md = self._load_role_for_edit(role)
        targets: Targets = targets_md.signed

        del targets.targets[target_path]

        self._write_edited_role(role, targets_md)

        logger.info("Removed target %s", target_path)
