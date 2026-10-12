# AltServer-Linux-26

AltServer-Linux-26 is an updated version of [NyaMisty's AltServer-Linux](https://github.com/NyaMisty/AltServer-Linux) for current Apple authentication and iOS/iPadOS 26 signing requirements.

**Companion project:** [Anisette-Server-26](https://github.com/hroy123/Anisette-server-26), the tested Anisette server for this AltServer build.

This update also owes a great deal to the Rust-based [`isideload`](https://github.com/nab138/isideload) project and [`SideSign`](https://github.com/SideStore/SideSign), whose working implementations were instrumental in resolving the modern Apple authentication and iOS signing issues encountered here. AI-assisted analysis and coding were equally essential; without it, I would not have been able to carry a project like this through to completion.

This project was developed and tested on an Orange Pi Zero 2 running AArch64 Debian/Armbian. The current source can authenticate with Apple, obtain application tokens, sign AltStore with an Apple development certificate, install it over USB, launch it on iPadOS 26, and support Wi-Fi refresh through netmuxd or usbmuxd.

The repository keeps the known-working patched AltServer, AltSign, and ldid source trees directly in the project so the exact code used for the successful build is preserved and can be reproduced from a fresh clone.

This release was tested with [Anisette-Server-26](https://github.com/hroy123/Anisette-server-26), running in Docker on the same Orange Pi. AltServer ran directly on the host, and app installation and refresh were verified.

## September 2026 Apple authentication

Apple's GrandSlam authentication flow has changed since the original AltServer-Linux implementation. The authentication code in this repository was updated to work with the current protocol.

The updated implementation completes the GrandSlam exchange, verifies the SRP server proof, derives the current SPD encryption keys from the raw SRP premaster secret, decrypts the SPD payload, and retrieves the application tokens used by AltServer.

The existing anisette mechanism is retained, including support for a custom anisette server through the `ALTSERVER_ANISETTE_SERVER` environment variable.

## iOS 26 code signing

The bundled ldid implementation has been updated to generate signatures accepted by current iOS/iPadOS iPhone 26 devices.

The signer generates SHA-1 and SHA-256 CodeDirectories, XML and DER entitlements, designated requirements, the required special-slot layout, and CMS hash-agility attributes expected by current Apple signing behavior.

Executable-segment flags are also generated correctly for main executables and nested code. Nested frameworks and application components are signed using the behavior required by the parent application.


### Large IPA installs

On the Orange Pi test system, large IPAs can exhaust the default RAM-backed `/tmp` filesystem during signing even when the root filesystem still has plenty of free space. A simple workaround is to temporarily increase the size of `/tmp` before installing the IPA:

```bash
sudo mount -o remount,size=1G /tmp
```

You can verify the new size with:

```bash
df -h /tmp
```

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

Run AltServer in the foreground:

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

**Use this AltServer-Linux-26 build together with [Anisette-Server-26](https://github.com/hroy123/Anisette-server-26)**, installed and running on the same Orange Pi. Set its address before starting AltServer:

```bash
export ALTSERVER_ANISETTE_SERVER="http://127.0.0.1:6970"
./AltServer-aarch64
```

### Run in Screen (manual)

GNU Screen keeps programs running after you disconnect from SSH, but **does not automatically restart them after a reboot**. From the directory containing `AltServer-aarch64`:

```bash
screen -S altserver
export ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:6970
./AltServer-aarch64
```

Detach with **Ctrl+A**, then **D**. Later reconnect with `screen -r altserver`.

### Wi-Fi refresh with netmuxd

Start netmuxd according to its installation instructions. On the tested setup, netmuxd provides Wi-Fi device connectivity for AltServer. To run netmuxd manually in Screen:

```bash
screen -S netmuxd
/path/to/netmuxd
```

Replace `/path/to/netmuxd` with the actual executable path. Detach with **Ctrl+A**, then **D**. Do not run a competing usbmuxd instance if netmuxd is replacing it.

### Automatic startup after reboot (systemd)

For an unattended Orange Pi, **systemd is recommended instead of Screen**. An optional script installs service definitions for both AltServer and netmuxd:

```bash
chmod +x install-startup-services.sh
sudo ALT_BIN=/absolute/path/to/AltServer-aarch64 \
     NETMUXD_BIN=/absolute/path/to/netmuxd \
     ./install-startup-services.sh
```

Use your actual executable paths. The script checks for a conflicting active `usbmuxd.service`, refuses to overwrite existing service definitions, and **creates but does not start** the services, so you can review them before switching from manually running Screen sessions.

After checking `sudo systemctl cat netmuxd-26.service altserver-26.service`, stop any existing Screen instances running these programs and enable the services:

```bash
sudo systemctl enable --now netmuxd-26.service altserver-26.service
systemctl status netmuxd-26.service altserver-26.service
```

The services will then be started automatically on future boots. To inspect logs, use `journalctl -u altserver-26.service -u netmuxd-26.service -f`. The startup helper is provided as a convenience and has not yet been validated on a clean installation; check the netmuxd service's arguments and your local usbmuxd arrangement before enabling it.

## Repository layout

`AltServer_patched/` contains the known-working AltServer source used by the Linux build.

`AltSign_patched/` contains the known-working AltSign source, including the updated Apple authentication implementation.

`ldid_patched/` contains the iOS 26-compatible signing implementation.

`src/` contains Linux-specific overrides used by the main AltServer build.

`upstream_repo/` contains the vendored upstream AltServer/AltSign source used for dependencies and reference.

## Credits

This project builds on NyaMisty's AltServer-Linux, Riley Testut and the AltStore/AltServer/AltSign contributors, ldid and its contributors, Kabir Oberai's authentication work referenced by the upstream source, and the libimobiledevice ecosystem.

The developers and contributors of the Rust-based [`isideload`](https://github.com/nab138/isideload) implementation were instrumental in resolving the current Apple GrandSlam authentication path, especially the SRP/SPD key-derivation and application-token behavior.

The developers and contributors of [`SideSign`](https://github.com/SideStore/SideSign) were also instrumental in resolving modern iOS signing issues by providing a working implementation for comparison, particularly around current entitlements, CodeDirectory/CMS signing behavior, and executable signing requirements.

AI-assisted analysis and coding were essential throughout this project. It was used extensively to compare implementations, isolate protocol differences, interpret signing structures, trace low-level failures, and iteratively test fixes across the authentication and code-signing paths.

This is an independent community project and is not an official AltStore release.

## Dependencies

For USB installation on Debian/Armbian, install the required device communication tools:

```bash
sudo apt update
sudo apt install usbmuxd libimobiledevice-utils
```

These provide the standard usbmuxd service and utilities such as `idevice_id`, `ideviceinfo`, and `idevicepair`.

## Minimal AltStore install example

The following small shell example asks you to connect the iPhone/iPad by USB, detects its UDID, asks for your Apple ID and password, and then runs AltServer to install `AltStore.ipa`.

```bash
#!/usr/bin/env bash
set -e

echo "Connect your iPhone/iPad by USB, unlock it, and tap Trust if prompted."
read -rp "Press Enter when the device is connected..."

UDID="$(idevice_id -l | head -n 1)"

if [ -z "$UDID" ]; then
    echo "No USB device detected."
    exit 1
fi

echo "Detected device: $UDID"

read -rp "Apple ID: " APPLE_ID
read -rsp "Apple ID password: " APPLE_PASSWORD
echo

./AltServer-aarch64 \
    -u "$UDID" \
    -a "$APPLE_ID" \
    -p "$APPLE_PASSWORD" \
    AltStore.ipa
```

If you use a local anisette server, export it before running the script:

```bash
export ALTSERVER_ANISETTE_SERVER="http://127.0.0.1:6970"
```

