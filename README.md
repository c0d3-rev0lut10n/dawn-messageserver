# Server for the Dawn messenger

*licensed under GPL version 3 or higher*

This is the repository containing the source code of the messaging server for Dawn. This code is still experimental and any use for production, especially for applications where security is critical, is **NOT** recommended as of now.

Client-side source code can be found in the following repositories:

* [Dawn cryptographic library](https://github.com/c0d3-rev0lut10n/dawn-crypto)
* [Dawn standard library](https://github.com/c0d3-rev0lut10n/dawn-stdlib)
* [Dawn stdlib bindings for android](https://github.com/c0d3-rev0lut10n/dawn-stdlib-android)

## Install

As of now, only building directly from source is intended. Pre-compiled binaries for all major platforms will come in the future.

### Prerequisites

* git
* A working Rust installation with cargo
* OpenSSL development package

	Install on Ubuntu with: `sudo apt install libssl-dev`

### Building

The following guide is an example of the procedure on a Linux system. 

1. Clone this repository

	`git clone https://github.com/c0d3-rev0lut10n/dawn-messageserver`
	`cd dawn-messageserver`

2. Clean the build environment (only needed if you compiled it already previously)

	`cargo clean`

3. Build

	`cargo b --release`

4. Run your binary and enjoy!

	`./target/release/dawn-messageserver-n2g`


## Update

1. Pull the new version of the source code

	`git pull`


2. *optional* Clean the build environment

	`cargo clean`

3. Build and enjoy your update (overwrites the installed version)

	`cargo b --release`

## API reference

*todo*
