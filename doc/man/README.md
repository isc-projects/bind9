<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->
# Building the Manpage

## Building from the tarball

When building BIND from the tarball, there will be pre-generated `.in` manpage templates.
For every page relevant to the build (`man_srcset`), meson will generate the manpage and install it using `install_man`.

Sphinx can also be used like in git tree builds described below but the pages generated with sphinx will not be installed if templated ones are available.

## Building from the git tree

Sphinx is required when building the manpages from the git tree.
If `sphinx-build` didn't exist when creating the build directory, build targets for the manpage will not exist.
Use the command `meson configure --clearcache` to force the next build to probe for sphinx again.

The source set `manrst_srcset` is used only to determine when a rebuild is necessary from meson's perspective and doesn't actually pass the source files.
Sphinx works by handling entire directories and so meson needs to use `depend_files` for the task.

To find which optional manpages need to be built or not, we pass the build directory to sphinx using the environment variable `BIND_BUILD_ROOT`.
Sphinx will then inspect the meson-generated `intro-targets.json` file to see which optional build components are enabled.

If an optional component like LMDB is disabled in the build directory, its corresponding manpage needs to be removed.
From meson's perspective, the entire folder is the output and doesn't concern itself with the insides specifically.
This is done by checking which optional targets are not built but have the page entry in the output folder.

If the `BIND_BUILD_ROOT` is not specified, sphinx will build every page.
This is used when creating a release tarball.
Meson will use the script `util/meson-dist-package.sh` to create the templates when runnnig the `dist` command.
If sphinx is not available in the build directory, this step will be skipped and so the tarballs must be created on a system with `sphinx-build`.
