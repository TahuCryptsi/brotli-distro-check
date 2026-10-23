# brotli-distro-check

![cve](https://img.shields.io/badge/CVE-2026--111497-red)
![cvss4](https://img.shields.io/badge/CVSS4-9.2-critical)
![type](https://img.shields.io/badge/type-version_audit-blue)
![lang](https://img.shields.io/badge/lang-bash-lightgrey)

Detect whether your Linux system's brotli library or binary falls in the vulnerable
range (**1.0.3 through 1.2.0**) for CVE-2026-111497 (Node.js security blog: HIGH,
"out-of-bounds write permits remote code execution"; NVD CVSS 4.0 = 9.2).

Single bash file. No dependencies. Supports dpkg, apk, rpm, filesystem scan, and
Node.js bundled brotli (`process.versions.brotli`).

## Why version-string checks lie for Node

Node 22.23.4 reports `process.versions.brotli === "1.1.0"` even after the fix,
because Node applies security backports without bumping the bundled library version.
This tool deliberately reports Node bundles as **at-risk** (exit 2, inconclusive)
because the version string alone cannot distinguish patched from unpatched builds.
Run the companion behavioral probe [node-brotli-check](https://github.com/TahuCryptsi/node-brotli-check)
for a definitive answer (it exercises the decoder with the CVE-2026-111497 regression
stream and reads back the error constant).

## Usage

```bash
./brotli-distro-check.sh
# or in a container:
docker run --rm -v $PWD/brotli-distro-check.sh:/t.sh:ro --entrypoint /bin/sh node:20-alpine -c "apk add bash >/dev/null; bash /t.sh"
```

Exit codes: `0` = not found or not vulnerable, `1` = vulnerable, `2` = at-risk/inconclusive (Node bundles).

## Verified matrix

| Runtime | Version | Expected | Actual exit | Notes |
|---|---|---|---|---|
| node:22-alpine | v22.23.4, brotli 1.1.0 | patched (backport) | 2 (at-risk) | version string lies; behavior probe confirms patched |
| node:20-alpine | v20.20.2, brotli 1.1.0 | vulnerable (EOL) | 1 with behavior probe | behavioral check confirms unpatched |
| ubuntu:24.04 apt | libbrotli1 1.1.0-2build2 | vulnerable | 1 | Debian tracker confirms unfixed |
| debian:bookworm | libbrotli1 1.0.9-2+b6 | vulnerable | 1 | matches Debian security tracker |
| alpine:3.20 base | no brotli | not found | 0 | library not in base image |

## Related

- [node-brotli-check](https://github.com/TahuCryptsi/node-brotli-check) — behavioral probe for Node.js builtin brotli (definitive patched/unpatched verdict)

## References

- NVD CVE-2026-111497 (CVSS 4.0 = 9.2): <https://nvd.nist.gov/vuln/detail/CVE-2026-111497>
- Node.js October 2026 security releases: <https://nodejs.org/en/blog/vulnerability/october-2026-security-releases>
- Debian security tracker: <https://security-tracker.debian.org/tracker/CVE-2026-111497>
- Fix commit (v1.2.1): google/brotli@b418fa81

## License

MIT.
