#!/usr/bin/python3
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2021 Frédéric Pierret (fepitre) <frederic.pierret@qubes-os.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import os
import sys
import requests
import tempfile
import json
import subprocess
import shutil
import argparse
import logging
import apt
import apt_pkg
import debian.deb822
import rstr

from dateutil.parser import parse as parsedate
from libs.openpgp import OpenPGPEnvironment, OpenPGPException
from shlex import quote

logger = logging.getLogger('debrebuild')
console_handler = logging.StreamHandler(sys.stderr)
logger.addHandler(console_handler)


class PackageException(Exception):
    pass


class BuildInfoException(Exception):
    pass


class RebuilderException(Exception):
    pass


class Package:
    def __init__(self, name, version, architecture=None):
        self.name = name
        self.version = version
        self.architecture = architecture
        self.first_seen = None
        self.hash = None

    def to_index_format(self):
        if self.architecture:
            result = "{} {} {}".format(
                self.name, self.version, self.architecture)
        else:
            result = "{} {}".format(self.name, self.version)
        return result

    def to_apt_install_format(self, build_arch=None):
        result = "{}={}".format(self.name, self.version)
        if build_arch and self.architecture in ("all", build_arch):
            result = "{}:{}={}".format(self.name, self.architecture, self.version)
        return result

    def __repr__(self):
        return f'Package({self.name}, {self.version}, architecture={self.architecture})'


class BuildInfo:
    def __init__(self, buildinfo_file):

        if not os.path.exists(buildinfo_file):
            raise BuildInfoException(
                "Cannot find buildinfo file: {}".format(buildinfo_file))

        with open(buildinfo_file) as fd:
            self.parsed_info = debian.deb822.BuildInfo(fd)

        # in case of binnmu we have e.g.
        #   Source: 0ad (0.0.23-1)
        self.source, self.source_version = self.parsed_info.get_source()
        self.architecture = [arch for arch in self.parsed_info.get_architecture()
                             if arch not in ("source", "all")]
        if len(self.architecture) > 1:
            raise BuildInfoException(
                "More than one architecture in Architecture field")
        self.binary = self.parsed_info.get_binary()
        self.version = self.parsed_info['version']
        if not self.source_version:
            self.source_version = self.version
        self.build_path = self.parsed_info.get('build-path', None)
        self.build_arch = self.parsed_info.get('build-architecture', None)
        if not self.build_arch:
            raise BuildInfoException("Need Build-Architecture field")
        self.build_date = self.parsed_info.get_build_date().strftime("%Y%m%dT%H%M%SZ")
        self.host_arch = self.parsed_info.get('host-architecture', self.build_arch)
        self.env = self.parsed_info.get_environment()
        self.build_source = self.parsed_info.is_build_source()
        self.build_archall = self.parsed_info.is_build_arch_all()
        self.build_archany = self.parsed_info.is_build_arch_any()

        self.checksums = {}
        for alg in ('md5', 'sha1', 'sha256', 'sha512'):
            if self.parsed_info.get('checksums-{}'.format(alg), None):
                self.checksums[alg] = self.parsed_info['checksums-{}'.format(alg)]

        self.logentry = self.parsed_info.get_changelog()
        if self.logentry:
            # Due to storing the binnmu changelog entry in deb822 buildinfo,
            # the first character is an unwanted newline
            self.logentry = str(self.logentry).lstrip('\n')
            # while the linebreak at the beginning is wrong, there are two
            # missing at the end
            self.logentry += '\n\n'

        self.build_depends = []
        self.required_timestamps = []

    def get_debian_suite(self):
        return self.parsed_info.get_debian_suite()

    def get_build_path(self):
        if not self.build_path:
            self.build_path = "/build/{}-{}".format(
                self.source, rstr.letters(10))
        return self.build_path

    def get_build_depends(self):
        # Storing self.build_depends is needed as we refresh information
        # from apt cache
        if not self.build_depends:
            installed = self.parsed_info.relations['installed-build-depends']
            for dep in installed:
                name = dep[0]['name']
                _, version = dep[0]['version']
                self.build_depends.append(Package(name, version))
        return self.build_depends


class Rebuilder:
    def __init__(self, buildinfo_file, snapshot_url,
                 base_mirror="http://snapshot.debian.org/archive/debian",
                 extra_repository_files=None, extra_repository_keys=None,
                 gpg_sign_keyid=None,
                 gpg_verify=False,
                 gpg_verify_key=None,
                 proxy=None,
                 use_metasnap=False):
        self.buildinfo = None
        self.snapshot_url = snapshot_url
        self.base_mirror = base_mirror
        self.extra_repository_files = extra_repository_files
        self.extra_repository_keys = extra_repository_keys
        self.gpg_sign_keyid = gpg_sign_keyid
        self.proxy = proxy
        self.session = requests.Session()
        self.session.proxies = {
                "http:": self.proxy,
                "https": self.proxy
            }
        self.use_metasnap = use_metasnap
        self.tempaptdir = None
        self.tempaptcache = None
        self.required_timestamp_sources = []
        self.source_timestamp = None
        self.tmpdir = os.environ.get('TMPDIR', '/tmp')

        if buildinfo_file.startswith('http://') or \
                buildinfo_file.startswith('https://'):
            try:
                resp = self.session.get(buildinfo_file)
                resp.raise_for_status()
                # We store remote buildinfo in a temporary file
                handle, buildinfo_file = tempfile.mkstemp(
                    prefix="buildinfo-", dir=self.tmpdir)
                with open(handle, 'w') as fd:
                    fd.write(resp.text)
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.HTTPError) as e:
                raise RebuilderException("Cannot get buildinfo: {}".format(e))
        else:
            buildinfo_file = realpath(buildinfo_file)

        if gpg_verify and gpg_verify_key:
            gpg_env = OpenPGPEnvironment()
            try:
                gpg_env.import_key(gpg_verify_key)
                data = gpg_env.verify_file(buildinfo_file)
                logger.info(
                    "GPG ({}): OK".format(data.primary_key_fingerprint))
            except OpenPGPException as e:
                raise RebuilderException(
                    "Failed to verify buildinfo: {}".format(str(e)))
            finally:
                gpg_env.close()

        self.buildinfo = BuildInfo(buildinfo_file)
        if buildinfo_file.startswith(
                os.path.join(self.tmpdir, 'buildinfo-')):
            os.remove(buildinfo_file)

    def get_env(self):
        env = []
        for key, val in self.buildinfo.env.items():
            env.append("{}=\"{}\"".format(key, val))
        return env

    def get_response(self, url):
        resp = self.session.get(url)
        return resp

    def get_sources_list(self):
        sources_list = []
        url = "{}/{}".format(self.base_mirror, self.buildinfo.build_date)
        base_dist = self.buildinfo.get_debian_suite()
        release_url = "{}/dists/{}/Release".format(url, base_dist)
        resp = self.get_response(release_url)
        if resp.ok:
            sources_list.append("deb {}/ {} main".format(url, base_dist))
            sources_list.append("deb-src {}/ unstable main".format(url))
        resp.close()

        # WIP
        sources_list.append(
            "deb-src http://deb.debian.org/debian {} main".format(base_dist))

        if self.extra_repository_files:
            for repo_file in self.extra_repository_files:
                try:
                    with open(repo_file) as fd:
                        for line in fd:
                            if not line.startswith('#') and \
                                    not line.startswith('\n'):
                                sources_list.append(line.rstrip('\n'))
                except FileNotFoundError:
                    raise RebuilderException(
                        "Cannot find repository file: {}".format(repo_file))

        return sources_list

    def get_build_depends_timestamps(self):
        """
            Returns a list of tuple(timestamp, pkgs)
            where pkgs is a list of packages living there
        """
        required_timestamps = {}
        for pkg in self.buildinfo.get_build_depends():
            if not pkg.first_seen:
                self.get_bin_date(pkg)
            required_timestamps.setdefault(
                parsedate(pkg.first_seen).strftime("%Y%m%dT%H%M%SZ"), []).append(pkg)
        # sort by the number of packages found there, convert to list of tuples
        required_timestamps = sorted(required_timestamps.items(),
                key=lambda x: len(x[1]), reverse=True)
        return required_timestamps

    def get_sources_list_from_timestamp(self):
        """
            Returns a list of tuple(source_list, pkgs)
            where pkgs is a list of packages living there
        """
        sources_list = []
        # Check snapshot mirror validity
        for timestamp, pkgs in self.get_build_depends_timestamps():
            sources_list.append(
                ("deb {}/{} unstable main".format(self.base_mirror, timestamp),
                 pkgs))
        return sources_list

    def get_src_date(self):
        srcpkgname = self.buildinfo.source
        srcpkgver = self.buildinfo.source_version
        logger.debug("Get source package info: {}={}".format(
            srcpkgname, srcpkgver))
        json_url = "/mr/package/{}/{}/srcfiles?fileinfo=1".format(
            srcpkgname, srcpkgver)
        json_url = self.snapshot_url + json_url
        resp = self.get_response(json_url)
        logger.debug("Source URL: {}".format(json_url))
        try:
            data = resp.json()
        except json.decoder.JSONDecodeError:
            raise RebuilderException(
                "Cannot parse response for source: {}".format(self.buildinfo.source))

        package_from_main = []
        for result in data.get('result', []):
            for val in data.get('fileinfo', {}).get(result['hash']):
                if val['archive_name'] == 'debian' and \
                        val['name'].endswith('.dsc'):
                    package_from_main.append(val)
        if len(package_from_main) > 1:
            raise RebuilderException(
                "More than one package with the same hash in Debian official")
        if not package_from_main:
            raise RebuilderException(
                "No package with the right hash in Debian official")

        return package_from_main[0]['first_seen']

    def get_bin_date(self, package):
        pkgname = package.name
        pkgver = package.version
        pkgarch = package.architecture
        logger.debug("Get binary package info: {}={}".format(
            pkgname, pkgver))
        json_url = "/mr/binary/{}/{}/binfiles?fileinfo=1".format(
            pkgname, pkgver)
        json_url = self.snapshot_url + json_url
        resp = self.get_response(json_url)
        logger.debug("Binary URL: {}".format(json_url))
        try:
            data = resp.json()
        except json.decoder.JSONDecodeError:
            raise RebuilderException(
                "Cannot parse response for package: {}".format(package.name))

        pkghash = None
        if len(data.get('result', [])) == 1:
            pkghash = data['result'][0]['hash']
            package.architecture = data['result'][0]['architecture']
            if pkgarch and pkgarch != package.architecture:
                raise RebuilderException(
                    "Package {} was explicitly requested {} but only {} was "
                    "found".format(pkgname, pkgarch, package.architecture))
            if not pkgarch and self.buildinfo.build_arch != package.architecture and \
                    "all" != package.architecture:
                raise RebuilderException(
                    "Package {} was implicitly requested {} but only {} was "
                    "found".format(
                        pkgname, self.buildinfo.build_arch, package.architecture))
            pkgarch = package.architecture
        else:
            if not pkgarch:
                pkgarch = self.buildinfo.build_arch
            for result in data.get('result', []):
                if result['architecture'] == pkgarch:
                    pkghash = result['hash']
                    break
            if not pkghash:
                raise RebuilderException(
                    "Cannot find package in architecture {}".format(pkgarch))
            package.architecture = pkgarch

        package_from_main = [pkg for pkg in data['fileinfo'].get(pkghash, []) if
                             pkg['archive_name'] == 'debian']
        if len(package_from_main) > 1:
            raise RebuilderException(
                "More than one package with the same hash in Debian official")
        if not package_from_main:
            raise RebuilderException(
                "No package with the right hash in Debian official")
        package.first_seen = package_from_main[0]['first_seen']
        package.hash = pkghash
        return package.first_seen

    def find_build_dependencies_from_metasnap(self):
        import urllib.parse
        pkgs = [pkg.to_apt_install_format()
                for pkg in self.buildinfo.get_build_depends()[:]]
        pkgs = urllib.parse.quote_plus(",".join(pkgs))
        url = f'https://metasnap.debian.net/cgi-bin/' \
              f'api?archive=debian' \
              f'&pkgs={pkgs}' \
              f'&arch={self.buildinfo.build_arch}' \
              f'&suite=unstable' \
              f'&comp=main'
        resp = self.get_response(url)
        if resp.ok:
            # latest first
            content = reversed(resp.text.strip('\n').split('\n'))
            for line in content:
                arch, timestamp = line.split()
                if arch != self.buildinfo.build_arch:
                    raise RebuilderException("Unable to handle multiple architectures")
                self.required_timestamp_sources.append(
                    f"deb {self.base_mirror}/{timestamp} unstable main")
        else:
            logger.error(RebuilderException("Cannot get timestamps from metasnap"))

    def find_build_dependencies(self):
        # Prepare APT cache for finding dependencies
        self.prepare_aptcache()

        notfound_packages = self.buildinfo.get_build_depends()[:]
        temp_sources_list = self.tempaptdir + '/etc/apt/sources.list'
        with open(temp_sources_list, "a") as fd:
            for timestamp_source, pkgs in self.get_sources_list_from_timestamp():
                if not notfound_packages:
                    break
                if not any(pkg in notfound_packages for pkg in pkgs):
                    logger.info("Skipping snapshot: {}".format(timestamp_source))
                    continue
                logger.info("Remaining packages to be found: {}".format(
                    len(notfound_packages)))
                self.required_timestamp_sources.append(timestamp_source)
                logger.debug("Timestamp source ({} packages): {}".format(len(pkgs), timestamp_source))
                fd.write("\n{}".format(timestamp_source))
                fd.flush()

                # provides sources.list explicitly, otherwise `update()`
                # doesn't reload it until the next `open()`
                self.tempaptcache.update(sources_list=temp_sources_list)
                self.tempaptcache.open()

                for notfound_pkg in notfound_packages[:]:
                    pkg = self.tempaptcache.get("{}:{}".format(
                        notfound_pkg.name, notfound_pkg.architecture))
                    if pkg and pkg.versions.get(notfound_pkg.version):
                        notfound_packages.remove(notfound_pkg)

                self.tempaptcache.close()

        if notfound_packages:
            for notfound_pkg in notfound_packages:
                logger.debug(notfound_pkg.name)
            raise RebuilderException("Cannot locate the following packages via "
                                     "snapshots or the current repo/mirror")

    def prepare_aptcache(self):
        self.tempaptdir = tempfile.mkdtemp(
            prefix="debrebuild-", dir=self.tmpdir)

        # Create apt.conf
        temp_apt_conf = "{}/etc/apt/apt.conf".format(self.tempaptdir)
        # Create sources.list
        temp_sources_list = "{}/etc/apt/sources.list".format(self.tempaptdir)

        apt_dirs = [
            '/etc/apt', '/etc/apt/trusted.gpg.d'
        ]
        for directory in apt_dirs:
            os.makedirs("{}/{}".format(self.tempaptdir, directory))

        with open(temp_apt_conf, "w") as fd:
            apt_conf = """
Apt {{
   Architecture "{build_arch}";
   Architectures "{build_arch}";
}};

Acquire::Check-Valid-Until "false";
Acquire::Languages "none";
Acquire::http::Dl-Limit "1000";
Acquire::https::Dl-Limit "1000";
Acquire::Retries "5";
Binary::apt-get::Acquire::AllowInsecureRepositories "false";
""".format(build_arch=self.buildinfo.build_arch, tempdir=self.tempaptdir)
            if self.proxy:
                apt_conf += '\nAcquire::http::proxy "{}";\n'.format(self.proxy)
            fd.write(apt_conf)

        with open(temp_sources_list, "w") as fd:
            fd.write("\n".join(self.get_sources_list()))

        keyrings = [
            "/usr/share/keyrings/debian-archive-keyring.gpg",
            "/usr/share/keyrings/debian-archive-removed-keys.gpg",
        ]
        if self.extra_repository_keys:
            keyrings += self.extra_repository_keys
        for keyring_src in keyrings:
            keyring_dst = "{}/etc/apt/trusted.gpg.d/{}".format(
                self.tempaptdir, os.path.basename(keyring_src))
            os.symlink(keyring_src, keyring_dst)

        # Init temporary APT cache
        try:
            logger.debug("Initialize APT cache")
            self.tempaptcache = apt.Cache(rootdir=self.tempaptdir, memonly=True)
            self.tempaptcache.close()
        except (PermissionError, apt_pkg.Error):
            raise RebuilderException("Failed to initialize APT cache")

    def get_apt_build_depends(self):
        apt_build_depends = []
        for pkg in self.buildinfo.get_build_depends():
            apt_build_depends.append(
                pkg.to_apt_install_format(self.buildinfo.build_arch))
        return apt_build_depends

    def get_chroot_basemirror(self):
        # basemirror = 'deb {}/{}/ {} main'.format(
        #     self.base_mirror, self.buildinfo.get_build_date(), self.buildinfo.get_debian_suite())

        # We select the oldest required snapshot to ensure that essential packages
        # like "apt" will not be removed due to downgrade process
        basemirror = self.required_timestamp_sources[-1].replace(
            'unstable', self.buildinfo.get_debian_suite())

        return basemirror

    def has_build_essential_dependency(self):
        has_build_essential = False
        for pkg in self.buildinfo.get_build_depends():
            if pkg.name == "build-essential":
                has_build_essential = True
                break
        return has_build_essential

    def mmdebstrap(self, output, build_arch):
        if build_arch in ("source", "all", "any"):
            build = build_arch
        else:
            build = "binary"
        cmd = [
            'env', '-i',
            'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
            'TMPDIR={}'.format(self.tmpdir),
            'mmdebstrap',
            '--arch={}'.format(self.buildinfo.build_arch),
            '--include={}'.format(' '.join(self.get_apt_build_depends())),
            '--variant=apt',
            '--aptopt=Acquire::Check-Valid-Until "false"',
            '--aptopt=Acquire::http::Dl-Limit "1000";',
            '--aptopt=Acquire::https::Dl-Limit "1000";',
            '--aptopt=Acquire::Retries "5";',
            '--aptopt=APT::Get::allow-downgrades "true";'
        ]
        if self.proxy:
            cmd += [
                '--aptopt=Acquire::http::proxy "{}";'.format(self.proxy)
            ]

        # Workaround for missing build-essential in buildinfo dependencies
        if not self.has_build_essential_dependency():
            cmd += [
                '--essential-hook=chroot "$1" sh -c "apt-get --yes install build-essential"'
            ]

        if self.extra_repository_keys:
            cmd += [
                '--essential-hook=copy-in {} /etc/apt/trusted.gpg.d/'.format(
                    ' '.join(self.extra_repository_keys))]

        if self.extra_repository_files:
            cmd += [
                '--essential-hook=chroot "$1" sh -c "apt-get --yes install apt-transport-https ca-certificates"'
            ]

        cmd += [
            '--essential-hook=chroot "$1" sh -c \"{}\"'.format(" && ".join(
                [
                    'rm /etc/apt/sources.list',
                    "echo '{}' >> /etc/apt/sources.list".format('\n'.join(self.get_sources_list() + self.required_timestamp_sources)),
                    'apt-get update'
                ]
            ))
        ]

        binnmucmds = []
        if self.buildinfo.logentry:
            binnmucmds += [
                "{{ printf '%s' {}; cat debian/changelog; }} > debian/changelog.debrebuild".format(quote(self.buildinfo.logentry)),
                "mv debian/changelog.debrebuild debian/changelog"
            ]

        cmd += [
            '--customize-hook=chroot "$1" env --unset=TMPDIR sh -c \"{}\"'.format(" && ".join(
                [
                    'apt-get source --only-source -d {}={}'.format(self.buildinfo.source, self.buildinfo.source_version),
                    'mkdir -p {}'.format(os.path.dirname(quote(self.buildinfo.build_path))),
                    'dpkg-source --no-check -x /*.dsc {}'.format(quote(self.buildinfo.build_path)),
                    'cd {}'.format(quote(self.buildinfo.build_path)),
                ] + binnmucmds + [
                    'env {} dpkg-buildpackage -uc -a {} --build={}'.format(' '.join(self.get_env()), self.buildinfo.host_arch, build)
                ]
            ))
        ]

        cmd += [
            '--customize-hook=sync-out {} {}'.format(os.path.dirname(quote(self.buildinfo.build_path)), output),
            self.buildinfo.get_debian_suite(),
            '/dev/null',
            self.get_chroot_basemirror()
        ]
        logger.debug(' '.join(cmd))
        if subprocess.run(cmd).returncode != 0:
            raise RebuilderException("mmdebstrap failed")

    def verify_checksums(self, new_buildinfo):
        status = True
        for alg in self.buildinfo.checksums.keys():
            checksums = self.buildinfo.checksums[alg]
            new_checksums = new_buildinfo.checksums[alg]
            files = [f for f in checksums if not f['name'].endswith('.dsc')]
            new_files = [f for f in new_checksums if not f['name'].endswith('.dsc')]

            if len(files) != len(new_files):
                logger.debug("old buildinfo: {}".format(' '.join(files)))
                logger.debug("new buildinfo: {}".format(' '.join(new_files)))
                raise RebuilderException(
                    f"New buildinfo contains a different number of files in {alg} checksums.")

            for f in files:
                new_file = None
                for nf in new_files:
                    if nf['name'] == f['name']:
                        new_file = nf
                        break
                if not new_file:
                    raise RebuilderException(f"Cannot find {f['name']} in new files")
                cur_status = True
                for prop in f.keys():
                    if prop == "size":
                        if f["size"] != new_file["size"]:
                            logger.error("Size differs for {}".format(f))
                            cur_status = False
                    if prop not in new_file.keys():
                        raise RebuilderException(
                            "{} is not used in both buildinfo files".format(prop))
                    if f[prop] != new_file[prop]:
                        logger.error("Value of {} differs for {}".format(prop, f))
                        cur_status = False
                if cur_status:
                    logger.info("{}: OK".format(f))
                else:
                    status = False

        if not status:
            raise RebuilderException("Failed to verify checksums")

    def generate_intoto_metadata(self, output, new_buildinfo):
        new_files = [f['name'] for f in new_buildinfo.checksums["sha256"]
                     if not f['name'].endswith('.dsc')]
        cmd = [
            "in-toto-run", "--step-name=rebuild", "--no-command",
            "--products"
        ] + list(new_files)
        if self.gpg_sign_keyid:
            cmd += ["--gpg", self.gpg_sign_keyid]
        else:
            cmd += ["--gpg"]
        if subprocess.run(cmd, cwd=output).returncode != 0:
            raise RebuilderException("in-toto metadata generation failed")
        logger.info("in-toto metadata generation: OK")

    @staticmethod
    def get_host_architecture():
        try:
            builder_architecture = subprocess.check_output(
                ["dpkg", "--print-architecture"]).decode('utf8').rstrip('\n')
        except FileNotFoundError:
            raise RebuilderException("Cannot determinate builder host architecture")
        return builder_architecture

    def run(self, builder, output, no_checksums_verification=False):
        # Predict new buildinfo name created by builder
        # Based on dpkg/scripts/dpkg-genbuildinfo.pl
        if self.buildinfo.architecture:
            build_arch = self.get_host_architecture()
        elif self.buildinfo.build_archall:
            build_arch = "all"
        elif self.buildinfo.build_source:
            build_arch = "source"
        else:
            raise RebuilderException("Nothing to build")

        new_buildinfo_file = "{}/{}_{}_{}.buildinfo".format(
            output, self.buildinfo.source, self.buildinfo.version, build_arch)
        logger.debug("New buildinfo file: {}".format(new_buildinfo_file))
        if os.path.exists(new_buildinfo_file):
            raise RebuilderException(
                "Refusing to overwrite existing buildinfo file")

        # Stage 1: Parse provided buildinfo file and setup the rebuilder
        try:
            self.source_timestamp = self.get_src_date()
            if self.use_metasnap:
                logger.debug("Use metasnap for getting required timestamps")
                self.find_build_dependencies_from_metasnap()
            if not self.required_timestamp_sources:
                logger.debug("Use snapshot for getting required timestamps")
                self.find_build_dependencies()
        except (apt_pkg.Error, apt.cache.FetchFailedException,
                requests.exceptions.ConnectionError) as e:
            raise RebuilderException(f"Failed to fetch packages: {str(e)}")
        except KeyboardInterrupt:
            raise RebuilderException("Interruption")
        finally:
            if self.tempaptdir and self.tempaptdir.startswith(
                    os.path.join(self.tmpdir, 'debrebuild-')):
                if self.tempaptcache:
                    self.tempaptcache.close()
                shutil.rmtree(self.tempaptdir)

        # Stage 2: Run the actual rebuild of provided buildinfo file
        if builder == "none":
            return
        if builder == "mmdebstrap":
            self.mmdebstrap(output, build_arch)

        # Stage 3: Everything post-build actions with rebuild artifacts
        new_buildinfo = BuildInfo(realpath(new_buildinfo_file))
        try:
            self.verify_checksums(new_buildinfo)
            logger.info("Checksums: OK")
        except RebuilderException as e:
            msg = "Checksums: FAIL: {}.".format(str(e))
            if no_checksums_verification:
                logger.error(msg)
            else:
                raise RebuilderException(msg)
        self.generate_intoto_metadata(output, new_buildinfo)


def get_args():
    parser = argparse.ArgumentParser(
        description='Given a buildinfo file from a Debian package, '
                    'generate instructions for attempting to reproduce '
                    'the binary packages built from the associated source '
                    'and build information.'
    )
    parser.add_argument(
        "buildinfo",
        help="Input buildinfo file. Local or remote file."
    )
    parser.add_argument(
        "--output",
        help="Directory for the build artifacts",
    )
    parser.add_argument(
        "--builder",
        help="Which building software should be used. (default: none)",
        default="none"
    )
    parser.add_argument(
        "--query-url",
        help="API url for querying package and binary information "
             "(default: http://snapshot.debian.org)",
        default="http://snapshot.debian.org"
    )
    parser.add_argument(
        "--use-metasnap",
        help="Use metasnap.debian.net. In contrast to snapshot.debian.org "
             "service, the metasnap.debian.net service will always return a "
             "minimal set of timestamps if the package versions were at some "
             "point part of Debian unstable main.",
        action="store_true"
    )
    parser.add_argument(
        "--extra-repository-file",
        help="Add repository file content to the list of apt sources during "
             "the package build.",
        action="append"
    )
    parser.add_argument(
        "--extra-repository-key",
        help="Add key file (.asc) to the list of trusted keys during "
             "the package build.",
        action="append"
    )
    parser.add_argument(
        "--gpg-sign-keyid",
        help="GPG keyid to use for signing in-toto metadata."
    )
    parser.add_argument(
        "--gpg-verify",
        help="Verify buildinfo GPG signature.",
        action="store_true"
    )
    parser.add_argument(
        "--gpg-verify-key",
        help="GPG key to use for buildinfo GPG check."
    )
    parser.add_argument(
        "--proxy",
        help="Proxy address to use."
    )
    parser.add_argument(
        "--no-checksums-verification",
        help="Don't fail on checksums verification between original and"
             " rebuild packages",
        action="store_true",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Display logger info messages."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Display logger debug messages."
    )
    return parser.parse_args()


def realpath(path):
    return os.path.abspath(os.path.expanduser(path))


def main():
    args = get_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.ERROR)

    if args.builder not in ("none", "mmdebstrap"):
        logger.error("Unknown builder: {}".format(args.builder))
        return 1

    if args.gpg_verify_key:
        args.gpg_verify_key = realpath(args.gpg_verify_key)

    if args.extra_repository_file:
        args.extra_repository_file = \
            [realpath(repo_file) for repo_file in args.extra_repository_file]

    if args.extra_repository_key:
        args.extra_repository_key = \
            [realpath(key_file) for key_file in args.extra_repository_key]

    if args.gpg_verify and not args.gpg_verify_key:
        logger.error(
            "Cannot verify buildinfo signature without GPG keyring provided")
        return 1

    try:
        rebuilder = Rebuilder(
            buildinfo_file=args.buildinfo,
            snapshot_url=args.query_url,
            extra_repository_files=args.extra_repository_file,
            extra_repository_keys=args.extra_repository_key,
            gpg_sign_keyid=args.gpg_sign_keyid,
            gpg_verify=args.gpg_verify,
            gpg_verify_key=args.gpg_verify_key,
            proxy=args.proxy,
            use_metasnap=args.use_metasnap
        )
        rebuilder.run(builder=args.builder, output=realpath(args.output),
                      no_checksums_verification=args.no_checksums_verification)
    except RebuilderException as e:
        logger.error(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
