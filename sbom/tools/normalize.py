#!/usr/bin/env python3
"""Post-process syft output so it validates and scans correctly.

  normalize.py licenses <file.cdx.json> <file.spdx.json>
      syft copies license identifiers from distro copyright files verbatim; a few
      (e.g. "UnRAR", "SMAIL-GPL") are not SPDX identifiers and fail schema
      validation. CycloneDX: move such ids from license.id to license.name.
      SPDX: rewrite them as LicenseRef-<id> and declare them in
      hasExtractedLicensingInfos. Nothing else is touched.

  normalize.py osv-input <file.cdx.json> <out.cdx.json>
      Write a copy for osv-scanner with the Go standard library version
      "go1.23.3" written as "1.23.3". osv-scanner cannot parse the "go" prefix
      syft uses and otherwise reports every historical stdlib advisory as
      affecting the image. The committed SBOMs keep syft's spelling.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, 'spdx-license-ids.json'), encoding='utf-8') as f:
    SPDX_IDS = set(json.load(f))
SPDX_IDS_LOWER = {x.lower() for x in SPDX_IDS}
TOKEN = re.compile(r'(\s+|\(|\))')
OPERATORS = {'AND', 'OR', 'WITH'}


def known(tok):
    t = tok[:-1] if tok.endswith('+') else tok
    return t in SPDX_IDS or t.lower() in SPDX_IDS_LOWER or t.startswith('LicenseRef-') or t in ('NONE', 'NOASSERTION')


def license_ref(tok):
    return 'LicenseRef-' + re.sub(r'[^A-Za-z0-9.-]', '-', tok)


def rewrite_expression(expr, unknown):
    parts = TOKEN.split(expr)
    prev = None
    for i, tok in enumerate(parts):
        if not tok or tok.isspace() or tok in '()':
            continue
        if tok in OPERATORS:
            prev = tok
            continue
        if prev != 'WITH' and not known(tok):
            unknown.add(tok)
            parts[i] = license_ref(tok)
        prev = tok
    return ''.join(parts)


def load(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def dump(doc, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=1)
        f.write('\n')


def walk_components(doc):
    stack = list(doc.get('components') or [])
    if doc.get('metadata', {}).get('component'):
        stack.append(doc['metadata']['component'])
    while stack:
        c = stack.pop()
        yield c
        stack.extend(c.get('components') or [])


def fix_cdx(path):
    doc = load(path)
    changed = set()
    for comp in walk_components(doc):
        for lic in comp.get('licenses') or []:
            l = lic.get('license')
            if l and 'id' in l and not known(l['id']):
                changed.add(l['id'])
                l['name'] = l.pop('id')
    if changed:
        dump(doc, path)
    return changed


def fix_spdx(path):
    doc = load(path)
    unknown = set()
    for pkg in doc.get('packages') or []:
        for key in ('licenseDeclared', 'licenseConcluded'):
            if pkg.get(key):
                pkg[key] = rewrite_expression(pkg[key], unknown)
    for fl in doc.get('files') or []:
        if fl.get('licenseConcluded'):
            fl['licenseConcluded'] = rewrite_expression(fl['licenseConcluded'], unknown)
        if fl.get('licenseInfoInFiles'):
            fl['licenseInfoInFiles'] = [rewrite_expression(x, unknown) for x in fl['licenseInfoInFiles']]
    if unknown:
        infos = doc.setdefault('hasExtractedLicensingInfos', [])
        have = {i.get('licenseId') for i in infos}
        for tok in sorted(unknown):
            ref = license_ref(tok)
            if ref not in have:
                infos.append({'licenseId': ref, 'extractedText': 'NOASSERTION', 'name': tok,
                              'comment': 'identifier as recorded by syft; not on the SPDX license list'})
        dump(doc, path)
    return unknown


GO_STDLIB = re.compile(r'^go(\d)')


def osv_input(src, dst):
    doc = load(src)
    n = 0
    for comp in walk_components(doc):
        v = comp.get('version') or ''
        if comp.get('name') == 'stdlib' and (comp.get('purl') or '').startswith('pkg:golang/stdlib') and GO_STDLIB.match(v):
            comp['version'] = GO_STDLIB.sub(r'\1', v)
            comp['purl'] = comp['purl'].replace('@' + v, '@' + comp['version'], 1)
            n += 1
    dump(doc, dst)
    return n


def main(argv):
    if len(argv) == 4 and argv[1] == 'licenses':
        c = fix_cdx(argv[2])
        s = fix_spdx(argv[3])
        if c or s:
            print(f'   normalized non-SPDX license ids: {", ".join(sorted(c | s))}')
        return 0
    if len(argv) == 4 and argv[1] == 'osv-input':
        osv_input(argv[2], argv[3])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
