libsodium-sys
=============

libsodium-sys is a wrapper around a static version of libsodium with a build script on top of it to integrate the C library into the Rust ecosystem.

Building
========

This project contains libsodium, and a rust build script (build.rs) that essentially runs:

1. `./configure`
2. `make`
3. `make install`

Usually, build scripts won't print output unless there is a failure, but you can force progress information by running the build in very verbose mode:

```cargo build -vv```

Project Structure
=================

This project has three important pieces:

1. The `libsodium-stable` folder contains the packaged stable release of libsodium which already has the autoconf files so we can simply run the standard configure, make, and make install steps.
2. The `build.rs` file manages the building of libsodium from source

Updating libsodium
==================

To update the libsodium dependency:

1. Delete the existing libsodium files that exist
2. Download the new version and verify its integrity with minisig
3. Build, test, commit, and push the new version