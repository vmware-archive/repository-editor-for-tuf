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
from typing import List, Optional, Tuple

from click.exceptions import ClickException
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

logger = logging.getLogger(__name__)


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
        if old_filename and new_filename != old_filename and role != "root":
            os.remove(old_filename)

        self._git(["add", "--intent-to-add", new_filename])

    def _load_role_for_edit(self, role: str) -> Metadata:
        return Metadata.from_file(self._get_filename(role))

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
                client_dir.name,
                "http://localhost/fakeurl/",
                "http://localhost/fakeurl/",
                fsfetcher,
            )
            updater.refresh()
        except RepositoryError as e:
            # TODO: improve this message by checking for common mistakes?
            print(e)
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

            for role in delegator.delegations.roles:
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

        # finally make sure no json files exist outside the delegation tree
        for filename in glob.glob("*.*.json"):
            _, role = filename[: -len(".json")].split(".")
            if role not in updater._trusted_set:
                raise ClickException(
                    f"Delegated target file {filename} is not part of trusted metadata"
                )

        deleg_count = len(updater._trusted_set) - 4

        print(f"Metadata with {deleg_count} delegated targets verified")
        print(f"Keyring contains keys for [{', '.join(self.keyring.keys())}].")

    def snapshot(self):
        """Update snapshot and timestamp meta information

        This command only updates the meta information in snapshot/timestamp
        according to current files: it does not validate those files in any
        way. Run 'verify' after 'snapshot' to validate repository state.
        """

        # Find all Targets metadata in repo...
        targets = {}
        for filename in glob.glob("*.*.json"):
            version, role = filename[: -len(".json")].split(".")
            if role not in ["root", "snapshot", "timestamp"]:
                targets[f"{role}.json"] = int(version)

        # Snapshot update needed?
        update_needed = False
        snapshot_md = self._load_role_for_edit("snapshot")
        snapshot: Snapshot = snapshot_md.signed
        if len(snapshot.meta) != len(targets):
            update_needed = True
        else:
            for fname, metainfo in snapshot.meta.items():
                if fname not in targets or metainfo.version != targets[fname]:
                    update_needed = True

        if update_needed:
            logger.info(f"Updating Snapshot with {len(targets)} targets metadata")
            snapshot.meta = {f"{name}": MetaFile(ver) for name, ver in targets.items()}
            self._write_edited_role("snapshot", snapshot_md)
        else:
            logger.info("Snapshot is already up-to-date")

        # Timestamp update needed?
        timestamp_md = self._load_role_for_edit("timestamp")
        timestamp: Timestamp = timestamp_md.signed
        if timestamp.meta["snapshot.json"].version != snapshot.version:
            logger.info(f"Updating Timestamp with snapshot version {snapshot.version}")
            timestamp.update(MetaFile(snapshot.version))
            self._write_edited_role("timestamp", timestamp_md)
        else:
            logger.info("Timestamp is already up-to-date")

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
            meta = {"snapshot.json": MetaFile(1)}
            timestamp_signed = Timestamp(1, "1.0.19", expiry_date, meta)
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
                roles = md.signed.delegations.roles
                role = next((r for r in roles if r.name == delegate), None)
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

        if isinstance(md.signed, Root):
            md.signed.add_key(delegate, key.public)
        elif isinstance(md.signed, Targets):
            try:
                roles = md.signed.delegations.roles
                role = next(role for role in roles if role.name == delegate)
            except (StopIteration, AttributeError):
                raise ClickException(f"{delegator} does not delegate to {delegate}")
            role.keyids.add(key.public.keyid)
            md.signed.delegations.keys[key.public.keyid] = key.public
        else:
            raise ClickException(f"{delegator} is not delegating metadata")

        self._write_edited_role(delegator, md)

        self.keyring.store_key(key)

    def remove_key(self, delegator: str, delegate: str, keyid: str):
        md = self._load_role_for_edit(delegator)

        if isinstance(md.signed, Root):
            md.signed.remove_key(delegate, keyid)
        elif isinstance(md.signed, Targets):
            try:
                roles = md.signed.delegations.roles
                role = next(role for role in roles if role.name == delegate)
            except (StopIteration, AttributeError):
                raise ClickException(f"{delegator} does not delegate to {delegate}")
            role.keyids.remove(keyid)
            key_in_use = False
            for role in roles:
                if keyid in role.keyids:
                    key_in_use = True
                    break
            if not key_in_use:
                del md.signed.delegations.keys[keyid]
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
            targets.delegations = Delegations({}, [])
        # TODO delegations needs an api for this -- or roles needs to be a ordereddict
        # this is buggy and does not support ordering in any way
        targets.delegations.roles.append(role)

        self._write_edited_role(delegator, md)

        logger.info("Delegated from %s to %s", delegator, delegate)

    def add_target(self, role: str, target_path: str, local_file: str):
        targets_md = self._load_role_for_edit(role)

        with open(local_file, "rb") as file:
            digest_object = digest_fileobject(file)
            digest = digest_object.hexdigest()
            file.seek(0, io.SEEK_END)
            length = file.tell()
        targetfile = TargetFile(length, {"sha256": digest}, target_path)
        targets_md.signed.targets[targetfile.path] = targetfile

        self._write_edited_role(role, targets_md)

        logger.info("Added target %s", targetfile.path)