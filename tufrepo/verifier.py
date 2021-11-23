import logging
import os
import shutil

from tempfile import TemporaryDirectory
from typing import List, Optional, Tuple

from click.exceptions import ClickException
from securesystemslib.hash import digest_fileobject
from tuf.exceptions import RepositoryError
from tuf.api.metadata import Snapshot, Targets
from tuf.ngclient import Updater

from tufrepo.filesystem_fetcher import FilesystemFetcher

logger = logging.getLogger("tufrepo")


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
