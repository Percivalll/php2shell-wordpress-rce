# php2shell WordPress RCE

External HTTP-only RCE against the default official Docker Hub
`wordpress:7.1.2` image (PHP 8.3.35 / Apache 2.4.68 / mod_php prefork).

Image digest:
`sha256:e04cf657f24889e96b5544828cdd5a92a0b51819f3e1899183f9be6ea0485edf`.

The target is a fresh container with image defaults: no custom `php.ini`, no
WordPress plugin or authentication, no extra environment variables, volumes,
capabilities, or privileged mode. All target interaction is HTTP.

## Result

Verified command execution as the web user:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

![php2shell WordPress RCE demo](assets/demo.gif)

*Default-container demo: worker pin, address leak, R1/R2, and the webroot proof.*

A fresh container completes in about 25 seconds.  Address discovery, both
session-file producers, and arming each run on a newly forked prefork child,
and the driver verifies that the previous child really died before moving on.
After one successful leak, `--base`/`--h` reuse the addresses and let later
runs on the same container skip discovery entirely.

Addresses are obtained entirely over HTTP through a 4 KiB `Set-Cookie`
out-of-bounds read; the chain then installs a fake PHP session serializer and
calls `zif_system`.

## Layout

```text
README.md                  project overview
REPORT.md                  full implementation and verification report
SECURITY.md                authorized-use and disclosure notice
demo.sh                    one-command PoC runner
assets/demo.gif            demo recording embedded below
exploit/transport.py       HTTP and multipart transport
exploit/profiles.py        A/B request profiles and leak parser
exploit/arm.py             arm producer and trigger
exploit/arm_file2.py       arm trigger with dummy-filename grooming
exploit/big_a.py           parameterised A request (heap grooming knobs)
exploit/b_leak20.py        B request / 4 KiB OOB read
exploit/early_ok.py        arm producer
exploit/poc.py             legacy request helpers used by the A/B tools
exploit/stage_rce.py       session-file producers, R1, and R2
exploit/run_ext.py         end-to-end orchestration
exploit/pin_adaptive.py    discover the worker count and free exactly one
exploit/pin_slow_pause.py  149-worker pin
```

## Quick start

Requirements: Docker, Python 3, and network access from the client to the
target HTTP port. The exploit itself uses only the Python standard library.

```bash
docker run -d --name php2shell-target -p 18100:80 \
  wordpress:7.1.2

cd exploit
python3 run_ext.py --port 18100 --shell 'id>/var/www/html/pwn.txt'
curl http://127.0.0.1:18100/pwn.txt
```

`run_ext.py` starts the worker pin itself (all workers but one), performs the leak,
arms the worker, installs the fake serializer, executes the command, and fetches
the proof. It does not call Docker, gdb, or `/proc`.

## Chain overview

1. Pin every worker but one with unfinished chunked POSTs.  Each pin carries
   4 KiB/s, well above `mod_reqtimeout`'s 500 B/s body minimum.
2. **Leak first, on the fresh child.**  A request OOMs in
   `php_session_reset_id` / `php_url_encode`, leaving a stale `PS(id)`.  A
   second request reclaims it with a forged `zend_string` of length `0x1000`,
   and `Set-Cookie` returns 4096 bytes of heap.  The first compilation of
   `index.php` leaves an op_array at the head of the ZendMM chunk; this is what
   puts libphp handler pointers in the window, so the leak must run before any
   request that executes `index.php`.
3. `raw[0x6c8] - 0x50ddbf` gives the libphp base.  The 4 KiB window's pointer
   cluster gives the chunk (the 2 MiB window sees a different cluster and must
   not be used for `H`); `H = chunk + 0x6a000`.
4. Rotate to a clean child, write the 30 MiB `sess_r1big`, write the 16 KiB
   `sess_trig2`, then rotate once more and arm the fresh child
   (`BG.data = H`, `BG.level = 1`).  A dirty worker's raised `real_size` makes
   the 30 MiB session write stop at a few hundred bytes.
5. R1 installs `PS(serializer) = H + 0x310` (`BG.level = 2`); R2 makes
   `php_session_decode()` call `zif_system` with the command string.

Detailed request shapes, offsets, and failure modes are in [REPORT.md](REPORT.md).

## Verified runs

| Run | Access | libphp base | chunk | H |
|---|---|---|---|---|
| `run-1` | published port 18099 | `0x751c8b681000` | `0x751c89a00000` | `0x751c89a6a000` |
| `run-2` | published port 18100 | `0x78cde6d86000` | `0x78cde5000000` | `0x78cde506a000` |
| `default` | no published port, external tunnel | `0x73e6330d7000` | `0x73e631400000` | `0x73e63146a000` |

Stability batch after the pin/leak/ordering fixes:

| Target | Result | Time |
|---|---|---|
| 8 fresh containers | 8/8 `uid=33(www-data)` | 24-26 s each |
| same container, `--base/--h` reuse | 1/1 `uid=33(www-data)` | 24 s |
| 1 further fresh container | stopped before arming: `0x7c` in `H` pointer bytes | - |

The single pre-exploitation stop is the ASLR gate documented below, not a
heap or timing failure.

## Limitations

- Offsets are calibrated for `wordpress:7.1.2` with PHP 8.3.35 / Apache
  2.4.68. Other PHP builds or images need re-calibration.
- The adaptive pin discovers the worker count; the fixed 149-connection mode
  assumes the default `MaxRequestWorkers=150`.
- The leak must run before `producer-bigfn` (or any other request that compiles
  `index.php`).  Once the script is cached in opcache, the 4 KiB window becomes
  zeroed heap with no libphp pointers.  Retry the leak in place; rotating
  during the leak loses the useful layout.
- If the fake-string pointer contains a `0x7c` byte, PHP rejects the upload
  progress key as a session delimiter.  This is a per-process ASLR condition:
  every address in that process shares the offending byte, so a different
  chunk or filler layout cannot escape it.  The driver detects it before
  arming; use a fresh container (or another target process).

## Safety

This project contains a working exploit for an authorized laboratory
environment. Do not use it against systems without explicit permission. See
[SECURITY.md](SECURITY.md).
