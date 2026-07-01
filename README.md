# pkgbasify

Automatically convert a FreeBSD system to use [pkgbase].

This project is sponsored by the [FreeBSD Foundation](https://freebsdfoundation.org/).

## Disclaimer

Both the pkgbasify tool and pkgbase itself are experimental.
Running pkgbasify may result in irreversible data loss and/or a system that fails to boot.
It is highly recommended to make backups before running this tool.

That said, I am not aware of any bugs in pkgbasify and have done my best to make it as robust as possible.
I currently believe pkgbasify to be as reliable as manual conversion if not better.

If you find a bug in pkgbasify please open an issue!

## Usage

Ensure you have at least 5 GiB of free disk space.
Conversion can likely succeed with less, but pkg is [not yet](https://github.com/freebsd/pkg/issues/75)
able to detect and handle insufficient space gracefully.
It can be difficult to recover if the system runs out of space during conversion.

pkgbasify runs several pre-flight checks before starting conversion:

- **Securelevel**: `kern.securelevel` must be less than 1, otherwise system immutable flags (`schg`) cannot be cleared and pkg will be unable to overwrite protected base system files. pkgbasify will refuse to proceed if this check fails.
- **chflags**: The ability to set and clear file flags is tested. This can fail due to elevated securelevel, or in a jail without `allow.chflags`. pkgbasify will refuse to proceed if this check fails.
- **Jail detection**: If running inside a jail, pkgbasify will warn and recommend using `--jail` from the host instead (see [Jail Conversion](#jail-conversion)). The user may choose to proceed.
- **Disk space**: At least 5 GiB free on the root filesystem.
- **Read-only `/var/empty`**: On ZFS, `/var/empty` must not be a read-only filesystem.
- **Symlinks in `/etc`**: Unexpected symlinks are flagged since pkg may overwrite them.

Download the script, give it permission to execute, run it as root:

1. `fetch https://github.com/FreeBSDFoundation/pkgbasify/raw/refs/heads/main/pkgbasify.lua`
2. `chmod +x ./pkgbasify.lua`
3. `./pkgbasify.lua`

If conversion succeeds: 

4. Verify that expected users and groups are present in `/etc/master.passwd` and `/etc/group`, and that `/etc/ssh/sshd_config` is as expected.
   These should be handled automatically by [pkg(8)], but since the consequences are high it is recommended to double check.
5. Restart the system.

If there is an error during installation of the pkgbase packages, the system may be left in a partially-converted state.
In this case, the user should fix whatever issue caused the error and run `./pkgbasify.lua --force` to try and complete the conversion.

See also [Common Problems and Solutions](#common-problems-and-solutions).

## Options

```
-h, --help            Print usage message and exit
--version             Print the version and exit
--force               Attempt conversion even if /usr/bin/uname
                      is already owned by a package (e.g. to fix
                      a partial conversion)
--repo-name <name>    Name of the pkgbase repository
                      (default: FreeBSD-base)
--no-create-repo-conf Don't create a repository configuration;
                      requires the user to configure a pkgbase
                      repository manually
--rootdir <dir>       Operate on the given directory rather than /
--jail <jail>         Operate on the jail with the given jid or
                      name, matching the version of the jail's
                      userland (see "Jail Conversion" below)
```

## Jail Conversion

pkgbasify can convert a jail to pkgbase in two ways:

### From the host (recommended)

Run pkgbasify on the host system with the `--jail` flag:

```
./pkgbasify.lua --jail <jid-or-name>
```

This is the recommended approach because the host has full access to
modify files inside the jail without any privilege restrictions.

### From inside the jail

Running pkgbasify directly inside a jail is possible but may fail if
the jail lacks sufficient privileges. pkgbasify will detect that it is
running inside a jail and warn about potential issues.

The general securelevel and chflags pre-flight checks (described in
[Usage](#usage)) are particularly relevant inside jails:

- A jail inherits its securelevel from the host if not explicitly set.
  If the host has `kern.securelevel >= 1`, the jail will too.
- The jail must be configured with `allow.chflags` (or `enforce_statfs`
  set appropriately) for pkg to manipulate file flags.

If these checks fail, pkgbasify will warn and offer to continue, but
conversion will very likely fail.

Kernel packages are automatically excluded when converting a jail, as
jails share the host kernel.

## Behavior

On FreeBSD 15, pkgbasify performs the following steps:

1. Run pre-flight checks (securelevel, chflags, jail detection, disk space, `/var/empty` readonly, `/etc` symlinks).
2. Select a repository based on the output of [freebsd-version(1)] and create `/usr/local/etc/pkg/repos/FreeBSD.conf`.
3. Select package sets that correspond to the currently installed base system components.
   - For example: if the lib32 component is not already installed,
     pkgbasify will not install `FreeBSD-set-lib32`.
   - pkgbasify never installs `FreeBSD-set-src` package even if `/usr/src` is present and non-empty.
     This prevents unwanted overwriting of potentially modified source files and/or a VCS repository.
4. Prompt the user to create a "pre-pkgbasify" boot environment using [bectl(8)] if possible.
5. Download selected packages
6. Register selected packages in the pkg database without installing any files (`pkg install --register-only`).
7. Install selected packages, overwriting normal files and merging config files (`pkg install --force`).
   - As per normal [pkg(8)] behavior, `.pkgnew` files are created for config files for which merge fails.
8. If [sshd(8)] is running, restart the service.
9. Run [pwd_mkdb(8)] and [cap_mkdb(1)].
10. Remove `/boot/kernel/linker.hints`.

[bectl(8)]: https://man.freebsd.org/cgi/man.cgi?query=bectl&sektion=8&manpath=freebsd-release
[pkgbase]: https://wiki.freebsd.org/PkgBase
[freebsd-version(1)]: https://man.freebsd.org/cgi/man.cgi?query=freebsd-version&sektion=1&manpath=freebsd-release
[pkg(8)]: https://man.freebsd.org/cgi/man.cgi?query=pkg&sektion=8&manpath=freebsd-ports
[sshd(8)]: https://man.freebsd.org/cgi/man.cgi?query=sshd&sektion=8&manpath=freebsd-release
[pwd_mkdb(8)]: https://man.freebsd.org/cgi/man.cgi?query=pwd_mkdb&sektion=8&manpath=freebsd-release
[cap_mkdb(1)]: https://man.freebsd.org/cgi/man.cgi?query=cap_mkdb&sektion=1&manpath=freebsd-release

## Common Problems and Solutions

### "Fail to create hardlink"

```
[1/66] Installing FreeBSD-runtime-15.snap20250604185611...
[1/66] Extracting FreeBSD-runtime-15.snap20250604185611:  33%
pkg: Fail to create hardlink: /.pkgtemp..profile.6vmf7kjyXtm8 <-> /root/.pkgtemp..profile.h5D7P2AMln3A:Cross-device link
[1/66] Extracting FreeBSD-runtime-15.snap20250604185611: 100%
Error: exit
```

This may be caused by a mountpoint over the top of a file or directory that `pkg` is trying to update.
`pkg` expects that the `TMPDIR` and the destination are on the same filesystem.
Unmount whatever is on top, and run `./pkgbasify.lua --force` to finish conversion.
In this case, `/root` had been put on its own zfs dataset.

### "Fail to set time on /var/empty:Read-only file system"

```
[1/66] Installing FreeBSD-runtime-15.snap20250604185611...
[1/66] Extracting FreeBSD-runtime-15.snap20250604185611: 100%
pkg: Fail to set time on /var/empty:Read-only file system
Error: exit
```

This may be caused by having a zfs filesystem `zroot/var/empty` with the property `readonly=on`.
Set `readonly=off` and run `./pkgbasify.lua --force` to finish conversion.
