# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

# Verify as a whole should recognize at least these different cases:
# 1. Expired timestamp
#    * Root is valid
#    * Timestamp is valid, but expired
#    -> touch timestamp, continue
# 2. Expired snapshot
#    * Root, timestamp are valid
#    * snapshot is valid, but expired
#    -> touch snapshot, continue
# 3. New version of metadata in delegation tree
#    * Delegation tree is valid (WRT client update workflow)
#    * There is a new metadata file in delegation tree: metadata is not in snapshot at all yet or the version in snapshot is N-1
#    -> snapshot, continue
# 4. Error cases
#    * delegation tree is invalid in ways not described before
#    * there is a metadata file that is not in delegation tree and not in snapshot
#    * There is a new version of a metadata already in snapshot, but version is not N+1 (N+2, ...)
#    * snapshot contains a metadata and file does not exist
# 5. Default case
#    * Delegation tree is valid (WRT client update workflow)
#    * All files are in snapshot, only one 
#    -> All good?

from typing import Dict, List, Optional, Tuple

from securesystemslib.hash import digest_fileobject
from tuf.api.metadata import Snapshot, Targets
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet

class Verifier:
    def _track_role_version (self, role: str, version: int):
        md = self._trusted_set[role]
        if version != md.signed.version:
            raise Exception(f"Expected {role} {version} but got {md.signed.version}")
        self.tracked_versions[role] = version

    def __init__(self, root_hash: Optional[str] = None):
        """Verifies the initial root

        Raises FileNotFound if required files are not there
        """
        # Keep track of the versions in our snapshot / delegation tree
        self.tracked_versions:Dict[str, int] = {}

        with open("1.root.json", "rb") as f:
            root_bytes = f.read()

        # verify initial root is what we expected
        if root_hash is not None:
            digest = digest_fileobject(root_bytes).hexdigest()
            if digest != root_hash:
                raise Exception(f"Unexpected hash digest {digest} for 1.root.json")

        # Verify all root versions
        self._trusted_set = TrustedMetadataSet(root_bytes)

    def verify_delegation_tree(self):
        """Verifies the delegation tree

        Raises FileNotFound if required files are not there
        
        # TODO: TUF #1498 would enable handling expiry properly
        """

        try:
            while True:
                version = self._trusted_set.root.signed.version + 1
                with open(f"{version}.root.json", "rb") as f:
                    self._trusted_set.update_root(f.read())
        except FileNotFoundError:
            self._trusted_set.root_update_finished()
            self._track_role_version("root", self._trusted_set.root.signed.version)

        # verify timestamp
        with open("timestamp.json", "rb") as f:
            self._trusted_set.update_timestamp(f.read())
        self._track_role_version("timestamp", self._trusted_set.timestamp.signed.version)
 
        # verify snapshot
        version = self._trusted_set.timestamp.signed.meta["snapshot.json"].version
        with open("{version}.snapshot.json", "rb") as f:
            self._trusted_set.update_snapshot(f.read())
        self._track_role_version("snapshot", version)

        # verify targets
        version = self._trusted_set.snapshot.signed.meta[f"targets.json"].version
        with open("{version}.targets.json", "rb") as f:
            self._trusted_set.update_delegated_targets(f.read(), "targets", "root")
        self._track_role_version("targets", version)

        # verify all other delegated targets in delegation tree
        snapshot: Snapshot = self.trusted_set.snapshot.signed
        delegators: List[Tuple[str, Targets]] = [
            ("targets", self.trusted_set["targets"].signed)
        ]
        while delegators:
            delegator_name, delegator = delegators.pop(0)
            if delegator.delegations is None:
                continue

            for role in delegator.delegations.roles:
                try:
                    version = snapshot.meta[f"{role.name}.json"].version
                except FileNotFoundError:
                    # role is not in snapshot yet, or role has been removed
                    continue
                with open(f"{version}.{role.name}.json", "rb") as f:
                    self.trusted_set.update_delegated_targets(
                        f.read(), role.name, delegator_name
                    )
                    self._track_role_version(role.name, version)
                    delegators.append(
                        (role.name, self.trusted_set[role.name].signed)
                    )

    def verify_remaining()