# elanfp

Minimal C driver, fingerprint matcher and PAM module for the **ELAN
04f3:0c4b** fingerprint sensor, so the sensor can be used to authenticate
`sudo` without fprintd, libfprint or the proprietary TOD driver.

It is written for one machine and one sensor (firmware 0x0700, 80x80 frames)
and checks the sensor/frame dimensions at runtime. Runtime dependencies:
libusb-1.0, Linux-PAM (sudo module), OpenSSL 3 libcrypto (FIDO2 daemon).
Build with gcc and [xmake](https://xmake.io). No Python runtime is needed.

## Build

```sh
xmake            # builds elanfp, pam_elanfp.so and elanfp-fido
```

The tool needs read/write access to the USB device (e.g. membership of the
group owning `/dev/bus/usb/*`, `usb` on Gentoo) or root.

## Command line

```sh
elanfp capture [out.pgm]                  # save one fingerprint image
elanfp enroll <user> [finger] [-d dir]    # 16 guided touches of one finger
elanfp verify <user> [-d dir]             # one touch, prints the match score
```

Fingers are stored as `<dir>/<user>/<finger>.tpl` (default dir
`/var/lib/elanfp`, mode 0700/0600). Enroll each finger you naturally use;
remove one by deleting its file.

## Fingerprint for sudo

```sh
xmake
sudo ./install.sh                         # enable for sudo and sudo -i
sudo elanfp enroll "$USER" right-index    # repeat for other fingers
sudo elanfp verify "$USER"
sudo -k; sudo true                        # touch the sensor when asked
```

`sudo` then shows *Place your finger on the fingerprint reader*. A matching
finger authenticates without a password; after ~11 s without a touch, or
three non-matching touches, the normal password prompt follows.

Remove with `sudo ./install.sh uninstall` (keeps enrolled fingers) or
`sudo ./install.sh purge`.

The installer preserves the password stack, but authentication changes still
carry risk:

- Copies `elanfp` to `/usr/local/bin` and `pam_elanfp.so` to
  `/lib64/security`, creates `/var/lib/elanfp`.
- Adds one line, `auth sufficient pam_elanfp.so`, before the first `auth`
  line of `/etc/pam.d/sudo` and `/etc/pam.d/sudo-i` (backups:
  `*.elanfp-backup`). No other PAM service is touched; uninstall removes
  its line without restoring an old backup over subsequent user edits.
- `sufficient` can only end authentication early with success. Every
  failure — not enrolled, sensor missing, timeout, mismatch, SSH session —
  continues with the password modules. libpam also skips the line if the
  module file is missing or cannot be loaded.
- USB and matching work runs in a forked child. A child crash falls through
  to the password stack; a hung child can still delay PAM authentication.
- Over SSH (`SSH_CONNECTION`/`SSH_TTY` set, or a remote `PAM_RHOST`) the
  module returns immediately.

Keep a root shell open the first time you try it anyway.

## Firefox / WebAuthn / passkeys

PAM is not a WebAuthn provider. Websites need public-key credentials, not the
fingerprint image or the sudo module. `elanfp-fido` exposes a **software
FIDO2 security key** through Linux UHID, which the browser sees via hidraw.
It matches an enrolled finger before normal registration or authentication.

**Security limit:** this is not a hardware-backed or certified security key.
Private keys are stored on disk, protected by ownership and mode 0600, not
encrypted by this program. Root access, a compromised kernel, or an offline
disk copy can bypass fingerprint protection. Use full-disk encryption and
keep an independent recovery method for every account. A fingerprint alone
cannot regenerate lost credential files.

Browser support is opt-in and independent of PAM:

```sh
xmake
sudo ./build/linux/x86_64/release/elanfp enroll "$USER" right-index
sudo ./install-fido.sh "$USER"            # OpenRC service + targeted hidraw rule
sudo rc-service elanfp-fido start
# Optional, after testing:
sudo rc-update add elanfp-fido default
```

The FIDO installer does not edit PAM, start a service, or change Firefox
preferences. It grants hidraw access only to the configured Unix user for
this virtual device; it does not open general `/dev/uhid` access.

In Firefox, register a **new security-key/passkey credential** at the website.
Choose the security-key option, not a phone/QR-code flow. Touch the sensor
when Firefox requests interaction. Existing credentials belonging to another
security key do not transfer to this authenticator. A website explicitly
requiring a platform authenticator, hardware attestation, CTAP1/U2F, or a PIN
is not supported by this software key.

The daemon supports CTAP2 `FIDO_2_0`, ES256, built-in fingerprint verification,
resident/discoverable credentials, and `none` attestation. It has no FIDO PIN
or biometric-enrollment protocol; enroll fingers with `elanfp`. Browser
cancellation stops the scan worker and sends the sensor's stop/LED-off command.

Credentials live separately in `/var/lib/elanfp-fido`, so uninstalling PAM or
purging fingerprint templates does not delete website keys. Back this directory
up securely; losing it loses the registered passkeys. Re-enrolling fingerprints
does not require re-registering keys if the credential directory is retained.

```sh
sudo rc-service elanfp-fido stop
sudo ./install-fido.sh uninstall          # retains credential files
```

Troubleshooting: inspect `/var/log/elanfp-fido.log`; check that a finger is
enrolled for the configured user, `CONFIG_UHID` is enabled, and the virtual
hidraw node belongs to that user. A sandboxed Firefox may additionally block
hidraw access. Do not disable browser security or grant world-writable HID
permissions to work around that. To upgrade, stop the service, rebuild,
rerun `install-fido.sh <user>`, then start it again; keys are retained.

### Scan indicator

Pending scans use the documented LED-on command `40 31`; completion and
errors use STOP/LED-off `00 0b`. This applies to CLI, PAM and FIDO scans
running the updated code. On the tested IdeaPad 3 15ITL05, the user confirmed
red/orange during successful Firefox registration and authentication, then
a return to the normal white power indication. No independent RGB selector
or raw embedded-controller writes are used.

### Verification

```sh
xmake build test-fido
xmake run test-fido
```

The C regression checks Firefox's `uv`-before-`up` map encoding, verification
denial, ambiguous duplicate keys, and truncated CBOR without needing a sensor.
Responses remain canonically encoded; inputs accept unique map keys in any
order for Firefox interoperability.

Live verification used Firefox 153.3.0 ESR with the real UHID device:
registration and authentication succeeded, and the assertion carried UP+UV.
Independent python-fido2 checks exercised real ES256 signatures, RP binding,
resident-account discovery, persisted counters, cancellation and malformed
requests. Python was used only as temporary independent test tooling, not as
a runtime dependency.

## How it works

### Sensor protocol

Recovered from `libfprint-2-tod1-elan` (the vendor's TOD driver), with
libfprint's `elan` driver as reference. Commands go to bulk EP 0x01, replies
come from EP 0x83, frames from EP 0x82.

| Command | Reply | Meaning |
|---|---|---|
| `40 19` | 2 bytes | firmware version |
| `40 21 0a` | 1 byte | sensor generation (bits 4-6) |
| `00 0c` | 4 bytes | width = b0+1, height = b2+1 (rounded to even) |
| `40 23` | 1 byte, read after 100 ms | run calibration, `03` = done |
| `40 24` | 2 bytes, big endian | sensor mean value |
| `00 09` | w·h·2 bytes on EP 0x82 | frame, little-endian u16 |
| `40 31` | none | LED on; no documented colour argument |
| `40 3f` | 1 byte, waits up to 11 s | wait for finger: `55` finger, `af` recalibrate, `ca`/`cc` stale prefetch |
| `9a 14` | none | discard prefetched frame |
| `40 3e` | 1 byte, waits up to 11 s | wait for finger lift: `aa` |
| `00 0b` | none | stop / LED off |

A background frame is taken at start (accepted when its mean is within 500 of
the sensor mean, otherwise calibrate and retry). A capture waits for a finger,
reads frames until `frame - background` has a mean above 500, and requests a
new background if more than 16% of pixels fell 255 below it. Thresholds are
the vendor driver's values for this product id.

### Matching

The vendor matcher is closed source; `src/match.c` is an independent one:

1. Band-pass the frame (difference of box-blurred images, keeping the
   ~8 px ridge period), normalise by local ridge energy, and mask out pixels
   without finger contact or ridge structure.
2. Compare probe and enrolment sample by masked normalised cross-correlation
   over rotations of ±30° and shifts of ±40 px: exhaustive at half
   resolution, then the 4 best candidates refined at full resolution
   (±4°, ±3 px), with at least 20% of the frame overlapping.
3. A finger's score is its **second best** sample score: a genuine finger
   correlates with several enrolment samples, a chance alignment of another
   finger rarely with more than one.

Measured on this sensor with three fingers of one person (12 samples each,
every sample checked against the others and against the other fingers):

| | lowest | highest |
|---|---|---|
| genuine score | 729 (488 for one 55%-area partial touch) | 973 |
| other-finger score | 262 | 601 |

The threshold is 680. Matching one finger takes ~0.27 s worst case
(single-threaded, int16 SIMD dot products); a genuine touch usually stops
after a few samples.

### Source layout

| File | Role |
|---|---|
| `src/elan.c` | USB protocol, calibration, capture and retry policy |
| `src/match.c` | feature extraction and matching |
| `src/store.c` | template files, per-user finger directory |
| `src/image.c` | 8-bit conversion and PGM output |
| `src/main.c` | `elanfp` command line |
| `src/pam_elanfp.c` | PAM module |
| `src/fido/` | software CTAP2 authenticator, credentials, HID/UHID transport |
| `install-fido.sh` | separate opt-in browser authenticator installer |
| `install.sh` | install / uninstall for sudo |

## Limitations

- Convenience, not strong security: no liveness or spoof detection, and the
  matcher is tuned on a small sample. The password always remains valid.
- Scripts using `sudo -S` wait ~11 s for a finger before reading stdin.
- Failed fingerprint attempts are not counted by `pam_faillock`, and a
  fingerprint login is not blocked by an existing faillock lockout.
- The software FIDO2 key adds no hardware key isolation, secure boot trust,
  liveness protection, or independent biometric security certification.

Protocol references: [FIDO CTAP](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html),
[upstream ELAN commands](https://gitlab.freedesktop.org/libfprint/libfprint/-/blob/master/libfprint/drivers/elan.h).
