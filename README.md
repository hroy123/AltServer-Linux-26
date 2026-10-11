# AltServer-Linux-26

This is an update of **NyaMisty's AltServer-Linux** for current Apple GrandSlam authentication and iOS/iPadOS 26 code-signing requirements.

This repository was reconstructed from the source tree that successfully built and ran on an Orange Pi Zero 2 (AArch64). The immediate goal is reproducibility: clone this repository on a clean machine, build it, install AltStore, launch it, and verify Wi-Fi refresh.

## Main changes

| File / component | Change |
| --- | --- |
| `AltSign_patched/AppleAPI+Authentication.cpp` | Updated GrandSlam authentication path, including SRP verification, SPD processing/decryption and app-token handling. |
| `AltSign_patched/AppleAPI.cpp` | Apple API request behavior used by the working authentication build. |
| `ldid_patched/ldid.cpp` | iOS 26-compatible signer with dual SHA-1/SHA-256 CodeDirectories, DER entitlements, designated requirements, CMS hash-agility attributes, nested signing behavior and correct executable-segment flags. |
| `AltServer_patched/` | Checked-in Linux-patched AltServer sources from the known-working build. |
| `src/AnisetteDataManager.cpp` | Treats Apple's `X-Apple-I-Client-Time` as UTC using `timegm()`. |
| `makefiles/AltSign-build/AltSign.mak` | Builds the checked-in working `AltSign_patched` and `ldid_patched` sources directly. |
| `Makefile` | Builds directly from the checked-in working AltServer sources and uses the static linker ordering required by the tested AArch64 build, including `-lpthread -ldl`. |
| `upstream_repo/` | Vendored upstream AltServer/AltSign source used for headers, dependencies and reference; retained as ordinary repository content so the working tree is self-contained. |

## Tested working configuration

The source snapshot imported into this repository had been tested with:

- Orange Pi Zero 2
- AArch64
- Armbian / Debian Bullseye
- iPadOS 26.6.1
- GrandSlam authentication: working
- AltStore installation over USB: working
- AltStore launch: working
- Wi-Fi refresh via netmuxd: working

The GitHub-cleaned repository still needs a **fresh-clone build test**. That is the next validation step.

## Build test

Clone the repository and build in a separate build directory:

```bash
git clone --recursive https://github.com/hroy123/AltServer-Linux-26.git
cd AltServer-Linux-26

mkdir build
cd build
make -f ../Makefile -j3
```

On AArch64 the resulting executable should be:

```text
AltServer-aarch64
```

This project still requires the original AltServer-Linux static build dependencies, including CoreCrypto, cpprestsdk, Boost, libzip/zlib and the libimobiledevice/libplist-related dependencies.

## Usage

Install an IPA:

```bash
./AltServer-aarch64 -u UDID -a APPLE_ID -p PASSWORD app.ipa
```

Run as the AltServer daemon:

```bash
./AltServer-aarch64
```

For the current command-line options:

```bash
./AltServer-aarch64 -h
```

### Anisette server

The existing AltServer-Linux anisette-server mechanism is retained. A custom server can be selected with:

```bash
export ALTSERVER_ANISETTE_SERVER="http://your-anisette-server/"
```

### Wi-Fi refresh

Wi-Fi transport continues to use netmuxd as in NyaMisty's AltServer-Linux.

## What was deliberately removed

The repository excludes local build products, static libraries, object files, debugging backups, developer certificates, private keys, provisioning profiles, pairing files and signed application bundles.

The three `*_patched` source directories are **not build junk in this repository**: they contain the known-working source snapshot and are intentionally tracked.

## Credits

This project builds on:

- [NyaMisty/AltServer-Linux](https://github.com/NyaMisty/AltServer-Linux)
- AltServer / AltSign by Riley Testut and contributors
- ldid and its upstream contributors
- Kabir Oberai's authentication work, credited by the upstream source
- libimobiledevice and related open-source dependencies

The current compatibility work was developed by comparing the Linux implementation with known-working Apple/AltServer behavior and validating both the GrandSlam authentication path and the generated iOS code-signature structures.

This is an independent community project and is not an official AltStore release.
