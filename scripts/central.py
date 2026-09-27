#!/usr/bin/env python3
"""Bundle signed staging artifacts and explicitly upload/status/publish via Central.

Credentials stay out of argv and logs; Gradle user properties
or MAVEN_CENTRAL_USERNAME/MAVEN_CENTRAL_PASSWORD supply the Portal token.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import zipfile
import urllib.request
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
API = "https://central.sonatype.com/api/v1/publisher"


def properties(path):
    result = {}
    for line in path.read_text().splitlines():
        if line and not line.lstrip().startswith(('#', '!')) and '=' in line:
            key, value = line.split('=', 1)
            result[key.strip()] = value.strip()
    return result


def bundle():
    version = properties(ROOT / 'gradle.properties')['version']
    staging = ROOT / 'build/staging-repo'
    files = sorted(p for p in staging.glob(f'com/netonstream/*/{version}/*')
                   if p.suffix in ('.pom', '.module', '.jar', '.klib'))
    coordinates = {p.parent.parent.name for p in files}
    targets = ('macosarm64', 'macosx64', 'linuxx64', 'linuxarm64',
               'iosarm64', 'iossimulatorarm64', 'iosx64', 'mingwx64',
               'androidnativearm64', 'androidnativex64')
    assert coordinates == {'openssl'} | {f'openssl-{t}' for t in targets}, coordinates
    output = ROOT / f'build/central-{version}.zip'
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            signature = Path(str(path) + '.asc')
            assert signature.is_file(), f'Missing signature: {path.name}'
            for item in (path, signature):
                data = item.read_bytes()
                name = str(item.relative_to(staging))
                archive.writestr(name, data)
                for algorithm in ('md5', 'sha1', 'sha256', 'sha512'):
                    archive.writestr(name + '.' + algorithm, hashlib.new(algorithm, data).hexdigest())
    print(f'{output}: {len(coordinates)} coordinates, {len(files)} signed artifacts')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('bundle', 'upload', 'status', 'publish'))
    parser.add_argument('--id')
    args = parser.parse_args()
    if args.action == 'bundle':
        bundle()
        return
    props = properties(Path.home() / '.gradle/gradle.properties')
    username = os.environ.get('MAVEN_CENTRAL_USERNAME') or props.get('mavenCentralUsername')
    password = os.environ.get('MAVEN_CENTRAL_PASSWORD') or props.get('mavenCentralPassword')
    if not username or not password:
        raise SystemExit('Missing Maven Central Portal credentials')
    token = base64.b64encode(f'{username}:{password}'.encode()).decode()
    headers = {'Authorization': 'Bearer ' + token}
    if args.action == 'upload':
        output = bundle()
        receipt = output.with_suffix('.deployment-id')
        if receipt.exists():
            raise SystemExit(f'Already uploaded; inspect {receipt.name} before retrying')
        boundary = uuid.uuid4().hex
        headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="bundle"; filename="{output.name}"\r\n'
                'Content-Type: application/octet-stream\r\n\r\n').encode()
        body += output.read_bytes() + f'\r\n--{boundary}--\r\n'.encode()
        query = urllib.parse.urlencode({'name': output.stem, 'publishingType': 'USER_MANAGED'})
        request = urllib.request.Request(API + '/upload?' + query, data=body, headers=headers, method='POST')
        with urllib.request.urlopen(request, timeout=300) as response:
            deployment = response.read().decode().strip()
        receipt.write_text(deployment + '\n')
        print('Deployment:', deployment)
    else:
        if not args.id:
            raise SystemExit('--id is required')
        endpoint = '/status' if args.action == 'status' else '/deployment/' + args.id
        query = '?' + urllib.parse.urlencode({'id': args.id}) if args.action == 'status' else ''
        request = urllib.request.Request(API + endpoint + query, headers=headers, method='POST', data=b'')
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read()
        print(json.dumps(json.loads(body), indent=2) if args.action == 'status' else 'Publication requested')


if __name__ == '__main__':
    main()
