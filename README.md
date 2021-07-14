
# Repository Editor for TUF

## Overview

_Repository Editor for TUF_ is a command line tool to edit and maintain a
[TUF](https://theupdateframework.io/) repository. It is currently at early
stages of development and should be considered experimental and not stable.

The goals of the project are:
 * Produce a command line tool for demos, tutorials, testing and and small
   scale repositories in general. In particular, support use cases of:
   * Repository maintainer (repository setup, key rotations, delegations)
   * Timestamp/snapshot automation (hands-free, running on CI)
   * Target file maintainer (publishing targets)
 * Function as the repository-side smoke test for TUF Metadata API: Demonstrate
   that the functionality of the API is sufficient to implement repository
   tools
 * Experiment with repository-side functionality, try to identify components
   that should be implemented as part of the TUF reference implementation

## Contributing

Contributions are very welcome. Before you start working on changes, please read our 
[Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License

The code is dual-licensed under MIT and Apache 2.0 licenses (for maximum compatibility with TUF project), see [LICENSE-MIT](LICENSE-MIT) and [LICENSE](LICENSE).
