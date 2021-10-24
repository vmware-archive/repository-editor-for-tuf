# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

import copy
import glob
import json
import logging
import os
from securesystemslib.keys import generate_ed25519_key
from securesystemslib.signer import SSlibSigner
from tuf.api.metadata import (
    Key,
    Metadata,
    Root,
    Targets,
)
from typing import Dict, List, Set

logger = logging.getLogger("tufrepo")


class PrivateKey:
    def __init__(self, key: Key, private: str) -> None:
        self.public = key
        self.private = private

        keydict = copy.deepcopy(self.public.to_securesystemslib_key())
        keydict["keyval"]["private"] = private
        self.signer = SSlibSigner(keydict)

    def __hash__(self):
        return hash(self.public.keyid)

    def __eq__(self, other):
        if isinstance(other, PrivateKey):
            return self.public.keyid == other.public.keyid
        return NotImplemented

class Keyring(Dict[str, Set[PrivateKey]]):
    """ "Private key management for a repository

    On Keyring initialization private keys are loaded for all secrets in
      * env variables (TUF_REPO_PRIVATE_KEY_*) and
      * privkeys.json file
    for all delegating roles in this repository.

    Private key secrets are only written to disk when store_key() is called.
    """

    def _load_key(self, rolename: str, key: Key):
        # Load a private key from env var or the private key file
        env_var = f"TUF_REPO_PRIVATE_KEY_{key.keyid}"
        private = os.getenv(env_var) or self._privkeyfile.get(key.keyid)

        if private:
            if rolename not in self:
                self[rolename] = set()
            self[rolename].add(PrivateKey(key, private))

    def __init__(self) -> None:
        try:
            with open("privkeys.json", "r") as f:
                self._privkeyfile: Dict[str, str] = json.loads(f.read())
        except json.JSONDecodeError as e:
            raise RuntimeError("Failed to read privkeys.json")
        except FileNotFoundError:
            self._privkeyfile = {}

        # find all delegating roles in the repository
        roles: Dict[str, int] = {}
        for filename in glob.glob("*.*.json"):
            ver_str, delegating_role = filename[: -len(".json")].split(".")
            if delegating_role not in ["timestamp", "snapshot"]:
                roles[delegating_role] = max(
                    int(ver_str), roles.get(delegating_role, 0)
                )

        # find all signing keys for all roles
        for delegating_role, version in roles.items():
            md = Metadata.from_file(f"{version}.{delegating_role}.json")
            if isinstance(md.signed, Root):
                for rolename, role in md.signed.roles.items():
                    for keyid in role.keyids:
                        self._load_key(rolename, md.signed.keys[keyid])
            elif isinstance(md.signed, Targets):
                if md.signed.delegations is None:
                    continue
                for role in md.signed.delegations.roles.values():
                    for keyid in role.keyids:
                        self._load_key(role.name, md.signed.delegations.keys[keyid])

        logger.info("Loaded keyring with keys for %d roles", len(self))

    def generate_key(self) -> PrivateKey:
        "Generate a private key"
        keydict = generate_ed25519_key()
        del keydict["keyid_hash_algorithms"]
        private = keydict["keyval"].pop("private")
        return PrivateKey(Key.from_dict(keydict["keyid"], keydict), private)

    def store_key(self, role: str, key: PrivateKey) -> None:
        "Write private key to privkeys.json"

        # Add new key to keyring
        if role not in self:
            self[role] = set()
        self[role].add(key)

        # write private key to privkeys file
        try:
            with open("privkeys.json", "r") as f:
                privkeyfile: Dict[str, str] = json.loads(f.read())
        except FileNotFoundError:
            privkeyfile = {}
        privkeyfile[key.public.keyid] = key.private
        with open("privkeys.json", "w") as f:
            f.write(json.dumps(privkeyfile, indent=2))

        logger.info(
            "Added key %s for role %s to keyring",
            key.public.keyid[:7],
            role,
        )
