# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Some helpers for editing Metadata"""

from click.exceptions import ClickException
from collections import OrderedDict
from datetime import datetime

from tuf.api.metadata import Key, MetaFile, Metadata, Role, Root, Signed, Snapshot, Targets, Timestamp

def init(role: str, expiry_date: datetime) -> Metadata:
    if role == "root":
        roles = {
            "root": Role([], 1),
            "targets": Role([], 1),
            "snapshot": Role([], 1),
            "timestamp": Role([], 1),
        }
        signed:Signed = Root(1, "1.0.19", expiry_date, {}, roles, True)
    elif role == "timestamp":
        signed = Timestamp(1, "1.0.19", expiry_date, MetaFile(1))
    elif role == "snapshot":
        signed = Snapshot(1, "1.0.19", expiry_date, {})
    else:
        signed = Targets(1, "1.0.19", expiry_date, {}, None)
    
    return Metadata(signed, OrderedDict())

def set_threshold(self: Signed, delegate: str, threshold: int):
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

def add_key(self: Signed, delegator: str, delegate: str, key: Key):
    if isinstance(self, Root) or isinstance(self, Targets):
        try:
            self.add_key(delegate, key)
        except ValueError:
            raise ClickException(f"{delegator} does not delegate to {delegate}")
    else:
        raise ClickException(f"{delegator} is not delegating metadata")

def remove_key(self: Signed, delegator: str, delegate: str, keyid: str):
    if isinstance(self, Root) or isinstance(self, Targets):
        try:
            self.remove_key(delegate, keyid)
        except ValueError:
            raise ClickException(f"{delegator} does not delegate to {delegate}")
    else:
        raise ClickException(f"{delegator} is not delegating metadata")
