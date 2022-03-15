debrebuild
===

```
usage: debrebuild.py [-h] [--output OUTPUT] [--builder BUILDER] [--query-url QUERY_URL] [--snapshot-mirror SNAPSHOT_MIRROR]
                     [--metasnap-url METASNAP_URL] [--use-metasnap] [--extra-repository-file EXTRA_REPOSITORY_FILE]
                     [--extra-repository-key EXTRA_REPOSITORY_KEY] [--gpg-sign-keyid GPG_SIGN_KEYID] [--gpg-verify]
                     [--gpg-verify-key GPG_VERIFY_KEY] [--proxy PROXY] [--verbose] [--debug]
                     buildinfo

Given a buildinfo file from a Debian package, generate instructions for attempting to reproduce the binary packages built from the
associated source and build information.

positional arguments:
  buildinfo             Input buildinfo file. Local or remote file.

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT       Directory for the build artifacts
  --builder BUILDER     Which building software should be used. (default: none)
  --query-url QUERY_URL
                        API url for querying package and binary information (default: http://snapshot.notset.fr).
  --snapshot-mirror SNAPSHOT_MIRROR
                        Snapshot mirror to use (default: http://snapshot.notset.fr)
  --metasnap-url METASNAP_URL
                        Metasnap service url (default: http://snapshot.notset.fr).
  --use-metasnap        Service to query the minimal set of timestamps containing all package versions referenced in a buildinfo file.
  --extra-repository-file EXTRA_REPOSITORY_FILE
                        Add repository file content to the list of apt sources during the package build.
  --extra-repository-key EXTRA_REPOSITORY_KEY
                        Add key file (.asc) to the list of trusted keys during the package build.
  --gpg-sign-keyid GPG_SIGN_KEYID
                        GPG keyid to use for signing in-toto metadata.
  --gpg-verify          Verify buildinfo GPG signature.
  --gpg-verify-key GPG_VERIFY_KEY
                        GPG key to use for buildinfo GPG check.
  --proxy PROXY         Proxy address to use.
  --verbose             Display logger info messages.
  --debug               Display logger debug messages.
```

`debrebuild` can parse buildinfo file having GPG signature and verify its signature with provided key file.

Highly inspired from original Debian tool `debrebuild` https://salsa.debian.org/debian/devscripts and newer features from  https://salsa.debian.org/josch/devscripts/-/commits/debrebuild and https://salsa.debian.org/fepitre/devscripts/-/commits/debrebuild.


#### INSTALLATION

Currently `debrebuild` works under `bullseye` or `sid`. You can install the dependencies by using as `root`:
```shell
$ apt install -y mmdebstrap in-toto python3-requests python3-apt python3-debian python3-dateutil python3-rstr debian-keyring debian-archive-keyring debian-ports-archive-keyring
```

It requires notably `mmdebstrap >= 0.7.5` and `python3-debian >= 0.1.40`. The latter is still not available in `bullseye`.
Until it would be available, you may use `PyPi` repository (ensure to have `python3-pip` installed for `pip3` command).
For system-wide installation use the following command as `root`:
```shell
$ pip3 install 'python-debian>=0.1.40'
```

You may skip `python3-debian` installation in the `apt` command in order to not have multiple `python-debian` versions
installed.

#### EXAMPLES

```shell
$ ./debrebuild.py --output=./artifacts --builder=mmdebstrap tests/data/gzip_1.10-2_all-amd64-source.buildinfo
```

####  BUILDERS

`debrebuild` can use different backends to perform the actual package rebuild.
The desired backend is chosen using the --builder option. The default is
`none`.

    none            Dry-run mode. No build is performed.

    mmdebstrap      Use mmdebstrap to build the package. This requires no
                    setup and no superuser privileges.
