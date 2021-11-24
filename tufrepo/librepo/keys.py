import copy
from typing import Mapping
from securesystemslib.signer import SSlibSigner
from tuf.api.metadata import Key

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

Keyring = Mapping[str, set[PrivateKey]]