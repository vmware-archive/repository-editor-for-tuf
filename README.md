
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
 * Testing is minimal
 * Private key management is minimal: removing keys requires editing a file,
   using an existing key is not supported
 * No releases or packages are available

## How it works

### Metadata is stored in git

The tufrepo tool works in a git-stored TUF metadata directory: metadata files
are automatically added to git. Git is used for a few reasons:
 * Tool needs no state tracking as git knows if file has been modified
 * Reviewing changes, combining changes to logical chunks and reverting wrong
   changes becomes easy
 * publishing and sharing repositories (and even running tufrepo on CI)
   is possible

### Commands are used to edit metadata

While editing, the tool takes care of:
 * expiry updates
 * version number updates
 * file name changes, deleting obsolete files
 * signing (with all appropriate private keys that available)

Following commands are available to user:

| Command               | Description
| ---                   | ---
| `init`                | Initialize a minimal repository from scratch
| `add-target`          | Add target file to the repository
| `remove-target`       | Remove target file from the repository
| `snapshot`            | Update snapshot and timestamp meta information
| `sign`                | Sign roles (without otherwise modifying them)
| `init-succinct-roles` | Initialize delegated roles for a succinct delegation
| `verify`              | Verify the current status of the repository
| `edit`                | Edit a role with subcommands listed below

A specific role can be edited with following edit-subcommands:

| Edit sub-command    | Description
| ---                 | ---
| `init`              | Create new metadata for role
| `add-delegation`    | Delegate from role to another role
| `remove-delegation` | Remove delegation to another role
| `add-key`           | Add new signing key for a delegated role
| `remove-key`        | Remove signing key for a delegated role
| `set-threshold`     | Set the threshold of delegated role
| `set-expiry`        | Set expiry period for the role
| `touch`             | No changes, just update version and expiry

When editing, the results can be checked with `git diff` and then committed
with `git commit -a`. Note that git status affects the automatic version number
changes: version number is bumped once per git changeset.

### Key management

All of the metadata is stored in git and the git repository is meant to be
shareable publicly. This means private keys must be stored elsewhere.

tufrepo can currently read private key secrets from two places:
 * privkeys.json in the repo directory (this does not get committed to git).
   Encrypted keys are not yet supported.
 * environment variables. This is useful when running tufrepo on CI and reading
   the secrets from the CI secrets storage
The tool will automatically use the available keys to sign whenever signing is
needed.

tufrepo writes new keys (created during `edit <role> add-key`) to
privkeys.json.

This key management solution is preliminary and likely to change in the future.

## Testing in virtualenv

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt -e .

    tufrepo --help

If you want to debug a specific command locally you can have a look at
`click` documentation about it: https://click.palletsprojects.com/en/8.1.x/testing/.
It may be  worth setting a temporary folder where you can test your command in
order to simulate tufrepo behavior.

## Examples

Note: The tool outputs very little currently: Running `git diff` once in a
while helps keep track of changes so far.

### Repository initialization

    # initialize a git repository for the metadata
    mkdir repo && cd repo
    git init .
    echo "privkeys.json" > .gitignore

    # Create top level metadata
    tufrepo init

    git commit -a -m "initial top-level metadata"

### Editing metadata

    # shorter expiry for timestamp
    tufrepo edit timestamp set-expiry 12 hours

    # require two of three root keys
    tufrepo edit root add-key root
    tufrepo edit root add-key root
    tufrepo edit root set-threshold root 2

    git commit -a -m "timestamp expiry & more root keys"

### Delegation

    # Add delegation (sign with targets key)
    tufrepo edit targets add-delegation --path "files/*" role1
    tufrepo edit targets add-key role1

    # Create the delegate targets role (sign with role1 key)
    tufrepo edit role1 init

    # Update snapshot/timestamp contents (sign with snapshot/timestamp keys)
    tufrepo snapshot

    git commit -a -m "Delegation to role1"

### Succinct delegation

    # Add delegation to 16 roles named "bin-0" to "bin-f" to role1 (sign with role1 key)
    tufrepo edit role1 add-delegation --succinct 16 bin

    # Create the 16 roles, add shared succinct role key(s), sign with that key
    tufrepo init-succinct-roles role1

    # Update snapshot/timestamp contents (sign with snapshot/timestamp keys)
    tufrepo snapshot

    git commit -a -m "Succinct delegation"

### Adding target files

    # Developer adds target "files/file1.txt": this is delegated first to "role1",
    # then to "bin-2", so change is signed by the succinct role key
    tufrepo add-target files/file1.txt ../targets/files/file1.txt

    # Update snapshot/timestamp contents (sign with snapshot/timestamp key)
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
