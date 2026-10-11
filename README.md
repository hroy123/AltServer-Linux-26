# AltServer-Linux-26

AltServer-Linux-26 is an updated version of [NyaMisty's AltServer-Linux](https://github.com/NyaMisty/AltServer-Linux) for current Apple authentication and iOS/iPadOS 26 signing requirements.

The project was updated and tested on an Orange Pi Zero 2 running AArch64 Debian/Armbian. The current source can authenticate with Apple, obtain application tokens, sign AltStore with an Apple development certificate, install it over USB, launch it on iPadOS 26, and support Wi-Fi refresh through netmuxd.

The repository keeps the known-working patched AltServer, AltSign, and ldid source trees directly in the project so the exact code used for the successful build is preserved and can be reproduced from a fresh clone.

## Apple authentication

Apple's GrandSlam authentication flow has changed since the original AltServer-Linux implementation. The authentication code in this repository was updated to work with the current protocol.

The updated implementation completes the GrandSlam exchange, verifies the SRP server proof, derives the current SPD encryption keys from the raw SRP premaster secret, decrypts the SPD payload, and retrieves the application tokens used by AltServer.

The existing anisette mechanism is retained, including support for a custom anisette server through the `ALTSERVER_ANISETTE_SERVER` environment variable.

## iOS 26 code signing

The bundled ldid implementation has been updated to generate signatures accepted by current iOS/iPadOS 26 devices.

The signer generates SHA-1 and SHA-256 CodeDirectories, XML and DER entitlements, designated requirements, the required special-slot layout, and CMS hash-agility attributes expected by current Apple signing behavior.

Executable-segment flags are also generated correctly for main executables and nested code. Nested frameworks and application components are signed using the behavior required by the parent application.

## Linux build changes

The Linux build system has been adjusted to compile the known-working patched AltServer, AltSign, and ldid sources directly from this repository rather than regenerating them from older upstream source during each build.

The linker configuration has also been updated for the tested AArch64 Linux build. Anisette client timestamps are generated as UTC.

The upstream AltServer/AltSign tree is retained in `upstream_repo/` for headers, dependencies, and reference.

## Current status

The current source has been tested with:

- Orange Pi Zero 2
- AArch64 Debian/Armbian
- iPadOS 26.6.1
- Apple GrandSlam authentication
- application-token retrieval
- AltStore signing
- USB installation through usbmuxd
- successful AltStore launch
- Wi-Fi refresh through netmuxd

Very large applications can require substantially more memory during Mach-O signing. Large-IPA behavior is still being investigated.

## Compilation

Clone the repository and its submodules:

```bash
git clone --recursive https://github.com/hroy123/AltServer-Linux-26.git
cd AltServer-Linux-26
```

Create a build directory:

```bash
mkdir build
cd build
```

Build AltServer:

```bash
make -f ../Makefile -j1
```

For troubleshooting, save the full build output:

```bash
make -f ../Makefile -j1 > ~/altserver-build.log 2>&1
```

On AArch64 the resulting executable is:

```text
AltServer-aarch64
```

The project requires the usual AltServer-Linux build dependencies, including OpenSSL, CoreCrypto, cpprestsdk, Boost, libzip/zlib, libplist, libimobiledevice, and related usbmuxd components.

## Usage

### Run AltServer

Run AltServer as a daemon:

```bash
./AltServer-aarch64
```

Display the available options:

```bash
./AltServer-aarch64 -h
```

### Install an IPA over USB

Connect and trust the iPhone or iPad, then obtain its UDID:

```bash
idevice_id -l
```

Install an IPA with:

```bash
./AltServer-aarch64 -u DEVICE_UDID -a APPLE_ID -p APPLE_ID_PASSWORD /path/to/application.ipa
```

### Use a custom anisette server

Set the anisette server before running AltServer:

```bash
export ALTSERVER_ANISETTE_SERVER="http://127.0.0.1:6970"
./AltServer-aarch64
```

### Wi-Fi refresh

Wi-Fi refresh can be provided through netmuxd. Run netmuxd in place of the standard usbmuxd service as required by your setup, then run AltServer as a background service or daemon.

## Repository layout

`AltServer_patched/` contains the known-working AltServer source used by the Linux build.

`AltSign_patched/` contains the known-working AltSign source, including the updated Apple authentication implementation.

`ldid_patched/` contains the iOS 26-compatible signing implementation.

`src/` contains Linux-specific overrides used by the main AltServer build.

`upstream_repo/` contains the vendored upstream AltServer/AltSign source used for dependencies and reference.

## Credits

This project builds on NyaMisty's AltServer-Linux, Riley Testut and the AltStore/AltServer/AltSign contributors, ldid and its contributors, Kabir Oberai's authentication work referenced by the upstream source, and the libimobiledevice ecosystem.

This is an independent community project and is not an official AltStore release.
