
# Repository Editor for TUF

## Overview

_Repository Editor for TUF_ project provides a command line tool to edit and
maintain a [TUF](https://theupdateframework.io/) repository. Project aims to:
 * Produce a command line tool for demos, tutorials, testing and and small
   scale repositories in general. In particular, support use cases of:
   * Repository maintainer _(repository setup, key rotations, delegations)_
   * Timestamp/snapshot automation _(hands-free, running on CI)_
   * Target file maintainer _(publishing targets)_
 * Smoke test the TUF Metadata API for repository functionality

## Status

_Repository Editor for TUF_ works already and can be used to create and maintain
TUF repositories for demo purposes.

It is also at early stages of development and should be considered
experimental and unstable:
 * User interface is not complete and is likely to change
 * Functionality is still missing (in particular many `add-*` sub-commands
   for edit exist but matching `remove-*` functionality is missing)
 * Private key management and target file handling need design

## How it works

### Metadata is stored in git

The tufrepo tool works in a git-stored TUF metadata directory: metadata files
are automatically added to git. Git is used for a few reasons:
 * This means the tool needs no state tracking as git knows whether a file
   has been modified already
 * Reviewing changes, committing them as logical chunks and reverting wrong
   changes becomes easy
 * publishing and sharing repositories (and even running tufrepo on CI)
   is possible

### Commands are used to edit metadata

The 'edit' command modifies a single metadata file (there are many
sub-commands, see examples). The 'snapshot' command updates the repository
snapshot and timestamp. During 'edit' and 'snapshot' commands the tool takes
care of:
 * expiry updates
 * metadata version numbers
 * file name changes
 * signing (with all private keys available)

The 'sign' command signs metadata without otherwise modifying it.
Signing happens automatically during 'edit' and 'snapshot' but sometimes
all keys are not available at edit time -- in these cases signing without
modifying the signed content is useful.

The 'status' command verifies repository validity.

### Key management

All of the metadata is stored in git and the git repository is meant to be
shareable publicly. This means private keys must be stored elsewhere.

Currently tufrepo stores private keys in named "keyrings" in .tufctl
configuration file in the repo directory (the file is not committed to git).
This is a preliminary solution and likely to change in the future.

The tool will automatically use the available keys to sign when signing is
needed.

## Testing in virtualenv

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt -e .

    tufrepo --help

## Examples

Note: The tool outputs very little currently: Running `git diff` once in a while helps keep track of changes so far.

### Repository initialization

    # initialize a git repository for the metadata
    mkdir repo && cd repo
    git init .

    # Create root metadata
    tufrepo edit root init

    # Add keys for top-level roles, put keys in various keyrings
    # (root now gets signed with keys offline1 and offline2)
    tufrepo edit root add-key root offline1
    tufrepo edit root add-key root offline2
    tufrepo edit root set-threshold root 2
    tufrepo edit root add-key snapshot online
    tufrepo edit root add-key timestamp online
    tufrepo edit root add-key targets dev

    # Create other top-level metadata (sign with keyrings online or dev)
    tufrepo edit timestamp init
    tufrepo edit snapshot init
    tufrepo edit targets init

    # Update snapshot/timestamp contents (sign with keyring online)
    tufrepo snapshot

    git commit -a -m "initial top-level metadata"


### Delegation

    # Add delegation (sign with keyring dev)
    tufrepo edit targets add-delegation --path "files/*" role1
    tufrepo edit targets add-key role1 dev2

    # Create the delegate targets role (sign with keyring dev2)
    tufrepo edit role1 init

    # Update snapshot/timestamp contents (sign with keyring online)
    tufrepo snapshot

    git commit -a -m "Delegation to role1"

### Target info update example:

    # Developer uploads a file (sign with key dev2)
    tufrepo edit role1 add-target files/file1.txt /path/to/file1.txt

    # Update snapshot/timestamp contents (sign with key online)
    tufrepo snapshot

    git commit -a -m "Add target 'files/file1.txt'"

## Contributing

Contributions are very welcome. If you wish to contribute code and have not
signed our contributor license agreement (CLA), our bot will update the issue
with details when you open a Pull Request. For any questions about the CLA
process, please refer to our [FAQ](https://cla.vmware.com/faq).

## License

The code is dual-licensed under MIT and Apache 2.0 licenses (for maximum
compatibility with TUF project), see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE](LICENSE).