"""Install only pinned upstream IP databases; never submit target IPs remotely."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import time
import urllib.request

from geo_lookup import DATASETS, DATA_DIR, UPSTREAM_COMMIT, verify_database


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('IP database download redirects are not accepted')


def download(spec, target):
    url = 'https://raw.githubusercontent.com/lionsoul2014/ip2region/' + UPSTREAM_COMMIT + '/data/' + spec['name']
    opener = urllib.request.build_opener(NoRedirect())
    deadline = time.monotonic() + 120
    with opener.open(url, timeout=15) as response, target.open('xb') as stream:
        count, digest = 0, hashlib.sha256()
        while chunk := response.read(1024 * 1024):
            count += len(chunk)
            if count > spec['size'] or time.monotonic() > deadline:
                raise ValueError('IP database download exceeds bounds')
            digest.update(chunk)
            stream.write(chunk)
        if count != spec['size'] or digest.hexdigest() != spec['sha256']:
            raise ValueError('IP database download integrity mismatch')
        stream.flush()
        os.fchmod(stream.fileno(), 0o644)
        os.fsync(stream.fileno())


def install(destination):
    destination = destination.absolute()
    if destination.resolve() != destination or destination.is_symlink():
        raise ValueError('unsafe destination')
    if not destination.exists():
        destination.mkdir(mode=0o755, parents=False)
        os.chmod(destination, 0o755)  # root's umask may otherwise hide it from the web user.
    # Stage both families before replacing either installed file.
    with tempfile.TemporaryDirectory(prefix='.ipdata-download-', dir=destination) as directory:
        stage = Path(directory)
        for version, spec in DATASETS.items():
            existing = destination / spec['name']
            if existing.is_symlink() or (existing.exists() and not existing.is_file()):
                raise ValueError('unsafe installed IP database')
            target = stage / spec['name']
            try:
                verify_database(existing, version)
            except (OSError, ValueError, IndexError):
                download(spec, target)
            else:
                shutil.copyfile(existing, target)
            verify_database(target, version)
            os.chmod(target, 0o644)
        for spec in DATASETS.values():
            os.replace(stage / spec['name'], destination / spec['name'])
    print('ip2region IPv4/IPv6 databases verified and installed (offline queries).')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, default=DATA_DIR)
    args = parser.parse_args()
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        parser.error('run as root')
    try:
        install(args.destination)
    except (OSError, ValueError, IndexError) as error:
        parser.exit(1, 'IP database installation failed (' + type(error).__name__ + '); existing settings were not changed.\n')


if __name__ == '__main__':
    main()
