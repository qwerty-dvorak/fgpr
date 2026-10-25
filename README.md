# elanfp

Minimal C driver, fingerprint matcher and PAM module for the **ELAN
04f3:0c4b** fingerprint sensor, so the sensor can be used to authenticate
`sudo` without fprintd, libfprint or the proprietary TOD driver.

It is written for one machine and one sensor (firmware 0x0700, 80x80 frames)
and checks for that at runtime. Dependencies: libusb-1.0, Linux-PAM, gcc and
[xmake](https://xmake.io).

## Build

```sh
xmake            # build/linux/x86_64/release/{elanfp,pam_elanfp.so}
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

What the installer changes, and why it cannot lock you out:

- Copies `elanfp` to `/usr/local/bin` and `pam_elanfp.so` to
  `/lib64/security`, creates `/var/lib/elanfp`.
- Adds one line, `auth sufficient pam_elanfp.so`, before the first `auth`
  line of `/etc/pam.d/sudo` and `/etc/pam.d/sudo-i` (backups:
  `*.elanfp-backup`). No other PAM service is touched; uninstall restores
  the files byte for byte.
- `sufficient` can only end authentication early with success. Every
  failure — not enrolled, sensor missing, timeout, mismatch, SSH session —
  continues with the password modules. libpam also skips the line if the
  module file is missing or cannot be loaded.
- All USB and matching work runs in a forked child; a crash or hang there
  only means "use the password", never a broken `sudo`.
- Over SSH (`SSH_CONNECTION`/`SSH_TTY` set, or a remote `PAM_RHOST`) the
  module returns immediately.

Keep a root shell open the first time you try it anyway.

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
| `install.sh` | install / uninstall for sudo |

## Limitations

- Convenience, not strong security: no liveness or spoof detection, and the
  matcher is tuned on a small sample. The password always remains valid.
- Scripts using `sudo -S` wait ~11 s for a finger before reading stdin.
- Failed fingerprint attempts are not counted by `pam_faillock`, and a
  fingerprint login is not blocked by an existing faillock lockout.
