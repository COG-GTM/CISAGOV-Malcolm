#!/usr/bin/env python3
"""Derive vulns.csv, licenses.csv, provenance.json and summary.md from the SBOMs
and osv-scanner results under sbom/. Called by generate.sh; every number in
summary.md is computed from the committed files so it can be re-derived.
"""

import argparse
import csv
import datetime as dt
import glob
import json
import os
import re
import subprocess
import sys

VIEWS = ('source', 'built')
IMAGE_NAME = {'filebeat': 'filebeat-oss', 'logstash': 'logstash-oss', 'nginx': 'nginx-proxy'}

STRONG_COPYLEFT = re.compile(r'\b(AGPL|GPL-[123]|GPL-?[123]\.0|SSPL|EUPL|OSL|CECILL(?!-B|-C))', re.I)
WEAK_COPYLEFT = re.compile(r'\b(LGPL|MPL|EPL|CDDL|CPL|Artistic|CECILL-C|OFL)', re.I)


def load(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def run(cmd):
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ''


def component_licenses(comp):
    out = []
    for lic in comp.get('licenses') or []:
        if 'expression' in lic:
            out.append(lic['expression'])
        elif 'license' in lic:
            l = lic['license']
            out.append(l.get('id') or l.get('name') or '')
    return [x for x in out if x]


def copyleft_flag(expr):
    if not expr:
        return 'unknown'
    if STRONG_COPYLEFT.search(expr):
        return 'strong'
    if WEAK_COPYLEFT.search(expr):
        return 'weak'
    return 'no'


def severity_bucket(score):
    if score is None:
        return 'unknown'
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    return 'low'


def fixed_versions(vuln, pkg):
    name = (pkg.get('name') or '').lower()
    eco = (pkg.get('ecosystem') or '').split(':')[0].lower()
    fixes = []
    for aff in vuln.get('affected') or []:
        ap = aff.get('package') or {}
        if (ap.get('name') or '').lower() != name:
            continue
        if eco and (ap.get('ecosystem') or '').split(':')[0].lower() != eco:
            continue
        for rng in aff.get('ranges') or []:
            for ev in rng.get('events') or []:
                if 'fixed' in ev and ev['fixed'] not in fixes:
                    fixes.append(ev['fixed'])
    return fixes


def parse_from_lines(dockerfile):
    bases = []
    with open(dockerfile, encoding='utf-8') as f:
        for line in f:
            m = re.match(r'^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?', line, re.I)
            if m:
                bases.append({'image': m.group(1), 'stage': m.group(2)})
    return bases


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo-root', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--work', required=True)
    ap.add_argument('--version', required=True)
    ap.add_argument('--image-repo', required=True)
    ap.add_argument('--platform', required=True)
    ap.add_argument('--deployables', nargs='+', required=True)
    opts = ap.parse_args()

    out = opts.out
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

    previous = {}
    prov_path = os.path.join(out, 'provenance.json')
    if os.path.exists(prov_path):
        previous = load(prov_path).get('deployables', {})

    vuln_rows, lic_rows = [], []
    summary = {}
    deployables = {}

    for dep in opts.deployables:
        summary[dep] = {}
        dockerfile = os.path.join(opts.repo_root, 'Dockerfiles', f'{dep}.Dockerfile')
        is_image = os.path.exists(dockerfile)
        entry = {
            'kind': 'container-image' if is_image else 'python-tooling',
            'dockerfile': f'Dockerfiles/{dep}.Dockerfile' if is_image else None,
            'base_images': parse_from_lines(dockerfile) if is_image else [],
            'source_paths': None,
            'views': {},
        }
        src_list = os.path.join(opts.work, f'{dep}.sources.txt')
        if os.path.exists(src_list):
            with open(src_list, encoding='utf-8') as f:
                entry['source_paths'] = [l.strip() for l in f if l.strip()]
        elif dep in previous:
            entry['source_paths'] = previous[dep].get('source_paths')

        for view in VIEWS:
            cdx_path = os.path.join(out, view, f'{dep}.cdx.json')
            if not os.path.exists(cdx_path):
                continue
            cdx = load(cdx_path)
            comps = [c for c in cdx.get('components') or [] if c.get('type') != 'file']
            by_type = {}
            for c in comps:
                by_type[c.get('type', '?')] = by_type.get(c.get('type', '?'), 0) + 1
                lics = component_licenses(c)
                lic_rows.append({
                    'view': view, 'deployable': dep, 'type': c.get('type', ''),
                    'name': c.get('name', ''), 'version': c.get('version', ''),
                    'purl': c.get('purl', ''),
                    'licenses': ' AND '.join(lics) if len(lics) > 1 else (lics[0] if lics else ''),
                    'copyleft': copyleft_flag(' '.join(lics)),
                })
            no_purl = sum(1 for c in comps if not c.get('purl'))
            unlicensed = sum(1 for c in comps if not component_licenses(c))

            osv_path = os.path.join(out, 'osv', view, f'{dep}.osv.json')
            ids, cves, buckets = set(), set(), {}
            if os.path.exists(osv_path):
                osv = load(osv_path)
                for res in osv.get('results') or []:
                    for pkg in res.get('packages') or []:
                        p = pkg.get('package') or {}
                        group_sev = {}
                        for g in pkg.get('groups') or []:
                            for gid in g.get('ids') or []:
                                group_sev[gid] = g.get('max_severity')
                        for v in pkg.get('vulnerabilities') or []:
                            vid = v.get('id', '')
                            aliases = [a for a in (v.get('aliases') or []) if a.startswith('CVE-')]
                            if vid.startswith('CVE-'):
                                aliases = [vid] + [a for a in aliases if a != vid]
                            try:
                                score = float(group_sev.get(vid)) if group_sev.get(vid) not in (None, '') else None
                            except ValueError:
                                score = None
                            cvss = ''
                            for s in v.get('severity') or []:
                                if s.get('type', '').startswith('CVSS'):
                                    cvss = s.get('score', '')
                                    break
                            ids.add(vid)
                            cves.update(aliases)
                            b = severity_bucket(score)
                            buckets[b] = buckets.get(b, 0) + 1
                            vuln_rows.append({
                                'view': view, 'deployable': dep,
                                'ecosystem': p.get('ecosystem', ''), 'package': p.get('name', ''),
                                'version': p.get('version', ''), 'vuln_id': vid,
                                'cve_ids': ' '.join(aliases), 'max_severity': group_sev.get(vid) or '',
                                'severity_bucket': b, 'cvss': cvss,
                                'fixed_versions': ' '.join(fixed_versions(v, p)),
                                'summary': (v.get('summary') or '').replace('\n', ' ').strip(),
                            })

            view_entry = {
                'cyclonedx': f'{view}/{dep}.cdx.json',
                'spdx': f'{view}/{dep}.spdx.json',
                'osv': f'osv/{view}/{dep}.osv.json' if os.path.exists(osv_path) else None,
                'components': len(comps),
                'components_by_type': dict(sorted(by_type.items())),
                'components_without_purl': no_purl,
                'components_without_license': unlicensed,
                'osv_vulnerabilities': len(ids),
                'osv_cves': len(cves),
                'osv_by_severity': dict(sorted(buckets.items())),
                'bom_serial': cdx.get('serialNumber'),
                'bom_timestamp': (cdx.get('metadata') or {}).get('timestamp'),
            }
            syft_json = os.path.join(opts.work, f'{dep}.{view}.syft.json')
            if os.path.exists(syft_json):
                meta = (load(syft_json).get('source') or {}).get('metadata') or {}
                if view == 'built' and is_image:
                    view_entry['image'] = {
                        'ref': f'{opts.image_repo}/{IMAGE_NAME.get(dep, dep)}:{opts.version}',
                        'manifest_digest': meta.get('manifestDigest'),
                        'repo_digests': meta.get('repoDigests'),
                        'image_id': meta.get('imageID'),
                        'architecture': meta.get('architecture'),
                        'os': meta.get('os'),
                        'layers': len(meta.get('layers') or []),
                    }
                elif view == 'built':
                    view_entry['resolved_environment'] = {
                        'requirements': 'scripts/installer/requirements.txt',
                        'resolved': f'built/{dep}.requirements-resolved.txt',
                        'python': run([os.environ.get('PYTHON', 'python3'), '--version']),
                    }
            elif dep in previous and view in previous[dep].get('views', {}):
                for k in ('image', 'resolved_environment'):
                    if k in previous[dep]['views'][view]:
                        view_entry[k] = previous[dep]['views'][view][k]
            entry['views'][view] = view_entry
            summary[dep][view] = view_entry
        deployables[dep] = entry

    with open(os.path.join(out, 'vulns.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['view', 'deployable', 'ecosystem', 'package', 'version', 'vuln_id',
                                          'cve_ids', 'max_severity', 'severity_bucket', 'cvss', 'fixed_versions',
                                          'summary'])
        w.writeheader()
        w.writerows(sorted(vuln_rows, key=lambda r: (r['view'], r['deployable'], r['package'], r['vuln_id'])))

    with open(os.path.join(out, 'licenses.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['view', 'deployable', 'type', 'name', 'version', 'purl', 'licenses', 'copyleft'])
        w.writeheader()
        w.writerows(sorted(lic_rows, key=lambda r: (r['view'], r['deployable'], r['name'], r['version'])))

    git = lambda *a: run(['git', '-C', opts.repo_root] + list(a))
    provenance = {
        'schema': 'malcolm-sbom-provenance/1',
        'generated_at': now,
        'generator': 'sbom/generate.sh',
        'operator': os.environ.get('SBOM_OPERATOR') or os.environ.get('GITHUB_SERVER_URL', '') and
                    f"{os.environ.get('GITHUB_SERVER_URL')}/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/{os.environ.get('GITHUB_RUN_ID')}" or '',
        'repository': {
            'remote': git('remote', 'get-url', 'origin'),
            'commit': git('rev-parse', 'HEAD'),
            'ref': os.environ.get('GITHUB_REF') or git('rev-parse', '--abbrev-ref', 'HEAD'),
            'dirty': bool(git('status', '--porcelain', '--', ':!sbom')),
        },
        'malcolm_version': opts.version,
        'image_repo': opts.image_repo,
        'platform': opts.platform,
        'tools': {
            'syft': run(['syft', 'version', '-o', 'json']) and json.loads(run(['syft', 'version', '-o', 'json'])).get('version'),
            'osv-scanner': (run(['osv-scanner', '--version']).splitlines() or [''])[0].split()[-1],
            'python': run([os.environ.get('PYTHON', 'python3'), '--version']),
        },
        'formats': {'cyclonedx': '1.5 (JSON)', 'spdx': '2.3 (JSON)'},
        'vulnerability_source': 'OSV (https://osv.dev) via osv-scanner, queried at generated_at',
        'deployables': deployables,
    }
    with open(prov_path, 'w', encoding='utf-8') as f:
        json.dump(provenance, f, indent=2, sort_keys=False)
        f.write('\n')

    # summary.md
    lines = [
        '# SBOM summary',
        '',
        f'Generated {now} from commit `{provenance["repository"]["commit"]}` for Malcolm `{opts.version}` '
        f'(images `{opts.image_repo}/*:{opts.version}`, `{opts.platform}`). Tools: syft {provenance["tools"]["syft"]}, '
        f'osv-scanner {provenance["tools"]["osv-scanner"]}. Counts below are derived from the files in this directory by `tools/enrich.py`.',
        '',
        '| Deployable | Source components | Built components | Built image digest | OSV vulns (source) | OSV vulns (built) | Built: critical / high / medium / low / unknown |',
        '|---|---:|---:|---|---:|---:|---|',
    ]
    tot = {'src_c': 0, 'blt_c': 0, 'src_v': 0, 'blt_v': 0}
    all_cves = {}
    for dep in opts.deployables:
        s = summary[dep].get('source', {})
        b = summary[dep].get('built', {})
        digest = ((b.get('image') or {}).get('manifest_digest') or '')
        digest = digest.replace('sha256:', '')[:12] if digest else ('pip venv' if b.get('resolved_environment') else '')
        sev = b.get('osv_by_severity', {})
        sevs = ' / '.join(str(sev.get(k, 0)) for k in ('critical', 'high', 'medium', 'low', 'unknown'))
        lines.append(f'| {dep} | {s.get("components", "")} | {b.get("components", "")} | `{digest}` | '
                     f'{s.get("osv_vulnerabilities", "")} | {b.get("osv_vulnerabilities", "")} | {sevs} |')
        tot['src_c'] += s.get('components', 0)
        tot['blt_c'] += b.get('components', 0)
        tot['src_v'] += s.get('osv_vulnerabilities', 0)
        tot['blt_v'] += b.get('osv_vulnerabilities', 0)
    lines.append(f'| **total** | {tot["src_c"]} | {tot["blt_c"]} | | {tot["src_v"]} | {tot["blt_v"]} | |')

    for r in vuln_rows:
        if r['view'] != 'built':
            continue
        for cve in r['cve_ids'].split():
            all_cves.setdefault(cve, {'deployables': set(), 'packages': set(), 'sev': r['severity_bucket'], 'fix': r['fixed_versions']})
            all_cves[cve]['deployables'].add(r['deployable'])
            all_cves[cve]['packages'].add(f"{r['package']}@{r['version']}")
    lines += ['', f'Distinct CVE identifiers across built views: {len(all_cves)}. '
                  f'Rows in vulns.csv: {len(vuln_rows)}; rows in licenses.csv: {len(lic_rows)}.', '',
              '## Most widespread CVEs (built views)', '',
              '| CVE | Deployables | Packages | Severity | Fixed in |', '|---|---:|---|---|---|']
    top = sorted(all_cves.items(), key=lambda kv: (-len(kv[1]['deployables']), kv[0]))[:15]
    for cve, info in top:
        lines.append(f'| {cve} | {len(info["deployables"])} | {", ".join(sorted(info["packages"]))[:120]} | {info["sev"]} | {info["fix"] or "none listed"} |')

    lines += ['', '## Data-quality notes', '']
    for dep in opts.deployables:
        for view in VIEWS:
            v = summary[dep].get(view)
            if not v:
                continue
            notes = []
            if v['components_without_purl']:
                notes.append(f'{v["components_without_purl"]} component(s) without a purl')
            if v['components_without_license']:
                notes.append(f'{v["components_without_license"]} component(s) without license data')
            if notes:
                lines.append(f'- {dep} ({view}): ' + '; '.join(notes))
    with open(os.path.join(out, 'summary.md'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    print(f'enrich: {len(vuln_rows)} vuln rows, {len(lic_rows)} license rows, {len(all_cves)} distinct CVEs (built)')


if __name__ == '__main__':
    main()
