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
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


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

    On Keyring initialization private keys are loaded for all found secrets in
      * env variables (TUF_REPO_PRIVATE_KEY_*) and
      * privkeys.json file
    if they match a delegation keyid in the repository

    Private key secrets are only written to disk when generate_and_store_key()
    is called.
    """

    def __init__(self) -> None:
        # find all delegating roles in the repository
        roles: Dict[str, int] = {}
        for filename in glob.glob("*.*.json"):
            ver_str, delegating_role = filename[: -len(".json")].split(".")
            if delegating_role not in ["timestamp", "snapshot"]:
                roles[delegating_role] = max(
                    int(ver_str), roles.get(delegating_role, 0)
                )

        # find all signing keys for all roles
        role_keys: Dict[str, List[Key]] = {}
        for delegating_role, version in roles.items():
            md = Metadata.from_file(f"{version}.{delegating_role}.json")
            if isinstance(md.signed, Root):
                for rolename, role in md.signed.roles.items():
                    if rolename not in role_keys:
                        role_keys[rolename] = []
                    for keyid in role.keyids:
                        role_keys[rolename].append(md.signed.keys[keyid])
            elif isinstance(md.signed, Targets):
                if md.signed.delegations is None:
                    continue
                for role in md.signed.delegations.roles:
                    if role.name not in role_keys:
                        role_keys[role.name] = []
                    for keyid in role.keyids:
                        role_keys[role.name].append(md.signed.delegations.keys[keyid])

        try:
            with open("privkeys.json", "r") as f:
                privkeyfile: Dict[str, str] = json.loads(f.read())
        except json.JSONDecodeError as e:
            raise RuntimeError("Failed to read privkeys.json")
        except FileNotFoundError:
            privkeyfile = {}

        # figure out which keys we have private keys for, store in keyring
        for rolename, keys in role_keys.items():
            role_priv_keys = set()
            for key in keys:
                # Get private key from env variable or privkeys.json
                env_var = f"TUF_REPO_PRIVATE_KEY_{key.keyid}"
                private = os.getenv(env_var) or privkeyfile.get(key.keyid)
                if private:
                    role_priv_keys.add(PrivateKey(key, private))

            if role_priv_keys:
                self[rolename] = role_priv_keys

        logger.info("Loaded keyring with keys for %d roles", len(self))

    def generate_and_store_key(self, role: str) -> Key:
        "Generate a key. Return public key, write private key to privkeys.json"
        keydict = generate_ed25519_key()
        del keydict["keyid_hash_algorithms"]
        private = keydict["keyval"].pop("private")
        privkey = PrivateKey(Key.from_dict(keydict["keyid"], keydict), private)

        # Add new key to keyring
        if role not in self:
            self[role] = set()
        self[role].add(privkey)

        # write private key to privkeys file
        try:
            with open("privkeys.json", "r") as f:
                privkeyfile: Dict[str, str] = json.loads(f.read())
        except FileNotFoundError:
            privkeyfile = {}
        privkeyfile[privkey.public.keyid] = privkey.private
        with open("privkeys.json", "w") as f:
            f.write(json.dumps(privkeyfile, indent=2))

        logger.info(
            "Added key %s for role %s to keyring",
            privkey.public.keyid[:7],
            role,
        )

        return privkey.public
