# SBOM summary

Generated 2026-11-05T21:06:59Z from commit `aa29d73ad5124ab0c6c23257885533faed923601` for Malcolm `26.09.0` (images `ghcr.io/idaholab/malcolm/*:26.09.0`, `linux/amd64`). Tools: syft 1.54.1, osv-scanner 2.7.0. Counts below are derived from the files in this directory by `tools/enrich.py`.

| Deployable | Source components | Built components | Built image digest | OSV vulns (source) | OSV vulns (built) | Built: critical / high / medium / low / unknown |
|---|---:|---:|---|---:|---:|---|
| api | 11 | 157 | `d2d1d6f2df02` | 0 | 4 | 2 / 0 / 2 / 0 / 0 |
| arkime | 4 | 1202 | `f9aa3e5632b6` | 0 | 179 | 3 / 48 / 65 / 6 / 70 |
| dashboards-helper | 2 | 195 | `b131ba6c79cf` | 0 | 32 | 2 / 4 / 8 / 2 / 35 |
| dashboards | 0 | 2202 | `a1b2b621c936` | 0 | 88 | 6 / 59 / 33 / 12 / 5 |
| dirinit | 0 | 38 | `23db75e101b7` | 0 | 1 | 0 / 1 / 0 / 0 / 0 |
| file-upload | 1 | 217 | `8c56c3142c89` | 0 | 28 | 0 / 4 / 8 / 2 / 14 |
| filebeat | 6 | 434 | `7bd1b95202a6` | 0 | 43 | 0 / 12 / 20 / 4 / 58 |
| filescan | 19 | 257 | `3e56c5a029ba` | 1 | 17 | 0 / 0 / 0 / 1 / 35 |
| freq | 2 | 137 | `a9e291ecdad4` | 0 | 14 | 0 / 4 / 8 / 2 / 0 |
| htadmin | 0 | 212 | `a1b528e03dd0` | 0 | 2 | 0 / 2 / 0 / 0 / 0 |
| keycloak | 0 | 611 | `27a24287c17d` | 0 | 21 | 2 / 8 / 10 / 1 / 0 |
| logstash | 3 | 647 | `0463ab65ec29` | 0 | 60 | 1 / 28 / 19 / 3 / 22 |
| netbox | 14 | 2013 | `e8280275db2c` | 75 | 403 | 42 / 161 / 135 / 26 / 88 |
| nginx | 1 | 83 | `58605c356024` | 0 | 53 | 15 / 28 / 9 / 1 / 0 |
| opensearch | 0 | 1210 | `ce69986b9205` | 0 | 66 | 2 / 38 / 33 / 1 / 21 |
| pcap-capture | 1 | 171 | `827e98f35057` | 0 | 19 | 0 / 10 / 10 / 3 / 0 |
| pcap-monitor | 8 | 186 | `b473c6ac0a78` | 0 | 21 | 2 / 10 / 10 / 3 / 0 |
| postgresql | 0 | 82 | `7c73b7a3735e` | 0 | 63 | 0 / 1 / 2 / 0 / 60 |
| strelka-backend | 0 | 632 | `157525022840` | 0 | 383 | 32 / 149 / 169 / 25 / 38 |
| strelka-frontend | 0 | 98 | `b6e03852f46a` | 0 | 97 | 7 / 22 / 2 / 0 / 92 |
| strelka-manager | 0 | 88 | `4b2d854fec3d` | 0 | 49 | 7 / 22 / 2 / 0 / 44 |
| suricata | 2 | 307 | `8e8f6b9f299e` | 0 | 35 | 0 / 10 / 10 / 3 / 35 |
| valkey | 0 | 45 | `fe9db25367b5` | 0 | 1 | 0 / 1 / 0 / 0 / 0 |
| zeek | 6 | 619 | `feedd2ad0a90` | 0 | 169 | 6 / 95 / 55 / 12 / 15 |
| installer | 8 | 36 | `pip venv` | 6 | 0 | 0 / 0 / 0 / 0 / 0 |
| **total** | 88 | 11879 | | 82 | 1848 | |

Distinct CVE identifiers across built views: 525. Rows in vulns.csv: 2277; rows in licenses.csv: 11967.

## Most widespread CVEs (built views)

| CVE | Deployables | Packages | Severity | Fixed in |
|---|---:|---|---|---|
| CVE-2026-111943 | 14 | rustls-webpki@0.103.13, stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25.0, stdlib@1.25.14, stdlib@1.26.5, stdlib@1.26.6, stdli | unknown | 1.26.10 1.27.3 |
| CVE-2026-56857 | 14 | stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25.0, stdlib@1.25.14, stdlib@1.26.5, stdlib@1.26.6, stdlib@1.26.7, stdlib@1.27.1 | unknown | 1.26.9 1.27.2 |
| CVE-2026-56866 | 14 | stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25.0, stdlib@1.25.14, stdlib@1.26.5, stdlib@1.26.6, stdlib@1.26.7, stdlib@1.27.1 | unknown | 1.26.9 1.27.2 |
| CVE-2026-78659 | 14 | golang.org/x/net@v0.56.0, golang.org/x/net@v0.58.0, golang.org/x/net@v0.59.0, stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25. | unknown | 1.26.9 1.27.2 |
| CVE-2026-78660 | 14 | golang.org/x/net@v0.56.0, golang.org/x/net@v0.58.0, golang.org/x/net@v0.59.0, stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25. | unknown | 1.26.9 1.27.2 |
| CVE-2026-78663 | 14 | golang.org/x/net@v0.56.0, golang.org/x/net@v0.58.0, golang.org/x/net@v0.59.0, stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25. | unknown | 1.26.9 1.27.2 |
| CVE-2026-78667 | 14 | stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25.0, stdlib@1.25.14, stdlib@1.26.5, stdlib@1.26.6, stdlib@1.26.7, stdlib@1.27.1 | unknown | 1.26.9 1.27.2 |
| CVE-2026-78669 | 14 | golang.org/x/net@v0.56.0, golang.org/x/net@v0.58.0, golang.org/x/net@v0.59.0, stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25. | unknown | 1.26.9 1.27.2 |
| CVE-2026-94439 | 14 | stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25.0, stdlib@1.25.14, stdlib@1.26.5, stdlib@1.26.6, stdlib@1.26.7, stdlib@1.27.1 | unknown | 1.26.9 1.27.2 |
| CVE-2026-94440 | 14 | stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25.0, stdlib@1.25.14, stdlib@1.26.5, stdlib@1.26.6, stdlib@1.26.7, stdlib@1.27.1 | unknown | 1.26.9 1.27.2 |
| CVE-2026-94448 | 14 | stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25.0, stdlib@1.25.14, stdlib@1.26.5, stdlib@1.26.6, stdlib@1.26.7, stdlib@1.27.1 | unknown | 1.26.9 1.27.2 |
| CVE-2026-97030 | 14 | stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25.0, stdlib@1.25.14, stdlib@1.26.5, stdlib@1.26.6, stdlib@1.26.7, stdlib@1.27.1 | unknown | 1.26.9 1.27.2 |
| CVE-2026-97031 | 14 | stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25.0, stdlib@1.25.14, stdlib@1.26.5, stdlib@1.26.6, stdlib@1.26.7, stdlib@1.27.1 | unknown | 1.26.9 1.27.2 |
| CVE-2026-97032 | 14 | golang.org/x/net@v0.56.0, golang.org/x/net@v0.58.0, golang.org/x/net@v0.59.0, stdlib@1.23.3, stdlib@1.24.6, stdlib@1.25. | unknown | 1.26.9 1.27.2 |
| CVE-2026-78661 | 10 | golang.org/x/net@v0.56.0, golang.org/x/net@v0.58.0, golang.org/x/net@v0.59.0 | unknown | 0.62.0 |

## Data-quality notes

- api (source): 11 component(s) without license data
- api (built): 7 component(s) without a purl; 10 component(s) without license data
- arkime (source): 4 component(s) without license data
- arkime (built): 1 component(s) without a purl; 8 component(s) without license data
- dashboards-helper (source): 2 component(s) without license data
- dashboards-helper (built): 1 component(s) without a purl; 45 component(s) without license data
- dashboards (built): 1 component(s) without a purl; 57 component(s) without license data
- dirinit (built): 1 component(s) without a purl; 1 component(s) without license data
- file-upload (source): 1 component(s) without license data
- file-upload (built): 1 component(s) without a purl; 18 component(s) without license data
- filebeat (source): 6 component(s) without license data
- filebeat (built): 15 component(s) without a purl; 252 component(s) without license data
- filescan (source): 19 component(s) without license data
- filescan (built): 15 component(s) without a purl; 62 component(s) without license data
- freq (source): 2 component(s) without license data
- freq (built): 1 component(s) without a purl; 2 component(s) without license data
- htadmin (built): 1 component(s) without a purl; 8 component(s) without license data
- keycloak (built): 1 component(s) without a purl; 219 component(s) without license data
- logstash (source): 3 component(s) without license data
- logstash (built): 4 component(s) without a purl; 146 component(s) without license data
- netbox (source): 14 component(s) without license data
- netbox (built): 15 component(s) without a purl; 1644 component(s) without license data
- nginx (source): 1 component(s) without license data
- nginx (built): 1 component(s) without a purl; 4 component(s) without license data
- opensearch (built): 1 component(s) without a purl; 304 component(s) without license data
- pcap-capture (source): 1 component(s) without license data
- pcap-capture (built): 1 component(s) without a purl; 23 component(s) without license data
- pcap-monitor (source): 8 component(s) without license data
- pcap-monitor (built): 1 component(s) without a purl; 24 component(s) without license data
- postgresql (built): 1 component(s) without a purl; 6 component(s) without license data
- strelka-backend (built): 27 component(s) without a purl; 88 component(s) without license data
- strelka-frontend (built): 1 component(s) without a purl; 45 component(s) without license data
- strelka-manager (built): 1 component(s) without a purl; 40 component(s) without license data
- suricata (source): 2 component(s) without license data
- suricata (built): 1 component(s) without a purl; 66 component(s) without license data
- valkey (built): 1 component(s) without a purl; 2 component(s) without license data
- zeek (source): 6 component(s) without license data
- zeek (built): 1 component(s) without a purl; 41 component(s) without license data
- installer (source): 8 component(s) without license data
- installer (built): 14 component(s) without a purl; 15 component(s) without license data
