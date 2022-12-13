# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

import abc
import copy
import glob
import json
import logging
import os

from securesystemslib.keys import generate_ed25519_key
from securesystemslib.signer import SSlibSigner, Signer
from tuf.api.metadata import (
    Key,
    Metadata,
    Root,
    Targets,
    SuccinctRoles,
)
from typing import DefaultDict, Dict, Set

logger = logging.getLogger("tufrepo")


class Keyring(DefaultDict[str, Set[Signer]], metaclass=abc.ABCMeta):
    """A base class for the private keyring management implementations."""

    def __init__(self):
        super().__init__(set)
        self._load_private_keys()

    @abc.abstractmethod
    def _load_key(self, rolename: str, key: Key) -> None:
        """Load signer for given role into keyring"""
        raise NotImplementedError

    def _load_private_keys(self):
        """Loads secrets for all delegating roles in this repository by using
        self._load_key(). This currently loads all delegating metadata to
        find the public keys."""

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
                if md.signed.delegations.roles is not None:
                    for role in md.signed.delegations.roles.values():
                        for keyid in role.keyids:
                            self._load_key(
                                role.name, md.signed.delegations.keys[keyid]
                            )
                elif md.signed.delegations.succinct_roles is not None:
                    for bin in md.signed.delegations.succinct_roles.get_roles():
                        for keyid in  md.signed.delegations.keys.keys():
                            self._load_key(bin, md.signed.delegations.keys[keyid])


class InsecureFileKeyring(Keyring):
    """Private key management in plain text file

    loads secrets from plain text privkeys.json file for all delegating roles
    in this repository. This currently loads all delegating metadata to find
    the public keys.

    Supports writing secrets to disk with store_key().
    """

    def _load_key(self, rolename: str, key: Key):
        # Load a private key from the insecure private key file
        private = self._privkeyfile.get(key.keyid)
        if private:
            keydict = copy.deepcopy(key.to_securesystemslib_key())
            keydict["keyval"]["private"] = private
            self[rolename].add(SSlibSigner(keydict))


    def __init__(self) -> None:
        # defaultdict with an empy set as initial value
        try:
            with open("privkeys.json", "r") as f:
                self._privkeyfile: Dict[str, str] = json.loads(f.read())
        except json.JSONDecodeError as e:
            raise RuntimeError("Failed to read privkeys.json")
        except FileNotFoundError:
            self._privkeyfile = {}

        super().__init__()
        logger.info("Loaded keys for %d roles from privkeys.json", len(self))

    def generate_key(self, role: str) -> Key:
        "Generate a private key, store in keychain and privkeys.json"
        keydict = generate_ed25519_key()
        del keydict["keyid_hash_algorithms"]
        private = keydict["keyval"]["private"]
        key = Key.from_securesystemslib_key(keydict)

        # Add new key to keyring
        self[role].add(SSlibSigner(keydict))

        # write private key to privkeys file
        self._privkeyfile[key.keyid] = private
        with open("privkeys.json", "w") as f:
            f.write(json.dumps(self._privkeyfile, indent=2))

        logger.info(
            "Added key %s for role %s to keyring",
            key.keyid[:7],
            role,
        )

        return key

    def generate_succinct_key(self, succinct_roles: SuccinctRoles) -> Key:
        "Generate a private key, store in keychain and privkeys.json"
        keydict = generate_ed25519_key()
        del keydict["keyid_hash_algorithms"]
        private = keydict["keyval"].pop("private")
        key = Key.from_securesystemslib_key(keydict)
        signer = SSlibSigner(keydict)

        # Add new key to keyring
        # write private key to privkeys file
        for bin_name in succinct_roles.get_roles():
            self[bin_name].add(signer)
            self._privkeyfile[key.keyid] = private

        with open("privkeys.json", "w") as f:
            f.write(json.dumps(self._privkeyfile, indent=2))

        logger.info(
            "Added key %s for succinct roles %s to keyring",
            key.keyid[:7],
            succinct_roles.name_prefix,
        )
        return key

class EnvVarKeyring(Keyring):
    """Private key management using environment variables
    
    Load private keys from env variables (TUF_REPO_PRIVATE_KEY_*) for all
    delegating roles in this repository. This currently loads all delegating
    metadata to find the public keys.
    """

    def _load_key(self, rolename: str, key: Key):
        # Load a private key from env var or the private key file
        private = os.getenv(f"TUF_REPO_PRIVATE_KEY_{key.keyid}")
        if private:
            keydict = copy.deepcopy(key.to_securesystemslib_key())
            keydict["keyval"]["private"] = private
            self[rolename].add(SSlibSigner(keydict))

    def __init__(self) -> None:
        # defaultdict with an empy set as initial value
        super().__init__()
        logger.info("Loaded keys for %d roles from env vars", len(self))


class URIKeyring(Keyring):
    """Private key management using embedded private key URIs

    Use signers for all keys that have a custom "x-tufrepo-online-uri" field.
    This currently loads all delegating metadata to find the public keys.
    """

    def _load_key(self, rolename: str, key: Key):
        # Use the URI from key metadata
        uri = key.unrecognized_fields.get("x-tufrepo-online-uri")
        if uri:
            signer = Signer.from_priv_key_uri(uri, key)
            self[rolename].add(signer)

    def __init__(self) -> None:
        # defaultdict with an empy set as initial value
        super().__init__()
        logger.info("Loaded keys for %d roles from env vars", len(self))
