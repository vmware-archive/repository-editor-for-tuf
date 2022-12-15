# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

import abc
import copy
import glob
import json
import logging
import os

from securesystemslib.keys import generate_ed25519_key
from securesystemslib.signer import SSlibKey, SSlibSigner, Signer
from tuf.api.metadata import (
    Key,
    Metadata,
    Root,
    Targets,
)
from typing import DefaultDict, Dict, Set, Tuple

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

    loads secrets from plain text keys.json file for all delegating roles
    in this repository. This currently loads all delegating metadata to find
    the public keys.

    Supports writing secrets to disk.
    """

    def _load_key(self, rolename: str, key: Key):
        # Load a private key from the insecure private key file
        uri = self._privkeyfile.get(key.keyid)
        if uri:
            self[rolename].add(Signer.from_priv_key_uri(uri, key))

    def __init__(self) -> None:
        os.makedirs("private_keys", exist_ok=True)
        try:
            # import old key format
            with open("privkeys.json", "r") as f:
                privkeys = json.loads(f.read())

            print("Importing old privkeys.json key format...")
            self._privkeyfile = {}
            for keyid, secret in privkeys.items():
                with open(f"private_keys/{keyid}", "w") as secfile:
                    secfile.write(secret)
                self._privkeyfile[keyid] = f"file:private_keys/{keyid}?encrypted=false"
            with open(f"private_keys/keys.json", "w") as keysfile:
                keysfile.write(json.dumps(self._privkeyfile, indent=2))

            os.remove("privkeys.json")
            print("Private keys now in private_keys/")
        except json.JSONDecodeError as e:
            raise RuntimeError("Failed to read old privkeys.json")
        except FileNotFoundError:
            # import not needed: open current keys.json
            try:
                with open("private_keys/keys.json", "r") as f:
                    self._privkeyfile: Dict[str, str] = json.loads(f.read())
            except json.JSONDecodeError as e:
                raise RuntimeError("Failed to read private_keys/keys.json")
            except FileNotFoundError:
                self._privkeyfile = {}

        super().__init__()
        logger.info("Loaded keys for %d roles from private_keys/keys.json", len(self))

    @staticmethod
    def generate_key() -> Tuple[str, Key]:
        "Generate a key, store private key material in a file"
        keydict = generate_ed25519_key()
        del keydict["keyid_hash_algorithms"]
        private = keydict["keyval"]["private"]

        key = SSlibKey.from_securesystemslib_key(keydict)
        uri = f"file:private_keys/{key.keyid}?encrypted=false"

        # write private key to private_keys/
        with open(f"private_keys/{key.keyid}", "w") as secfile:
            secfile.write(private)
        return uri, key

    def add_signer(self, role, uri, key):
        # update keys.json
        self._privkeyfile[key.keyid] = uri
        with open(f"private_keys/keys.json", "w") as keysfile:
            keysfile.write(json.dumps(self._privkeyfile, indent=2))

        # update keyring itself
        assert(isinstance(key, SSlibKey))
        self[role].add(Signer.from_priv_key_uri(uri, key))


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
