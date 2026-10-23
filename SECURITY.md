# Security Notice

This repository contains a proof-of-concept exploit for a PHP session / OOM
state issue affecting the specific default WordPress image and PHP build
described in [README.md](README.md).

## Authorized use only

Use this code only on systems where you have explicit, documented permission
to perform security testing. The authors do not authorize use against third
parties, production services, or any system outside an isolated laboratory.

## Scope

- The exploit is image/build-specific. Addresses and offsets are not universal.
- It is a research and verification artifact, not a general-purpose scanner.
- The proof command writes a file to the target webroot. Do not run it on a
  system whose data you are not prepared to modify.

## Reporting

If you believe you have found a security issue in this project, contact the
maintainer privately rather than opening a public issue with exploit details.

## Defensive guidance

- Disable `session.upload_progress` when it is not required.
- Keep PHP patched and avoid assuming a particular build's memory layout.
- Monitor anomalous long `Set-Cookie` values, repeated 500/OOM responses, and
  unexpected `/tmp/sess_*` files.
- Treat upload-progress and session handling as security-sensitive PHP engine
  configuration, not just application code.
