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

Download the script, give it permission to execute, run it as root:

1. `fetch https://github.com/FreeBSDFoundation/pkgbasify/raw/refs/heads/main/pkgbasify.lua`
2. `chmod +x ./pkgbasify.lua`
3. `./pkgbasify.lua`

If conversion succeeds: 

4. Verify that expected users and groups are present in `/etc/master.passwd` and `/etc/group`, and that `/etc/ssh/sshd_config` is as expected.
   These should be handled automatically by pkgbasify, but since the consequences are high it is recommended to double check.
5. Restart the system.

If there is an error during installation of the pkgbase packages, the system may be left in a partially-converted state.
In this case, the user should fix whatever issue caused the error and run `./pkgbasify.lua --force` to try and complete the conversion.

See also [Common Problems and Solutions](#common-problems-and-solutions).

## Behavior

pkgbasify performs the following steps:

1. Make a copy of the [etcupdate(8)] current database (`/var/db/etcupdate/current`).
   This makes it possible for pkgbasify to merge config files after converting the system.
2. Select a repository based on the output of [freebsd-version(1)] and create `/usr/local/etc/pkg/repos/FreeBSD-base.conf`.
3. Select packages that correspond to the currently installed base system components.
   - For example: if the lib32 component is not already installed,
     pkgbasify will skip installation of lib32 packages.
   - pkgbasify never installs the `FreeBSD-src` package even if `/usr/src` is present and non-empty.
     This prevents unwanted overwriting of potentially modified source files and/or a VCS repository.
4. Prompt the user to create a "pre-pkgbasify" boot environment using [bectl(8)] if possible.
5. Install the selected packages with [pkg(8)],
   overwriting base system files and creating `.pkgsave` files as per standard [pkg(8)] behavior.
6. Run a three-way-merge between the `.pkgsave` files (ours),
   the new files installed by pkg (theirs),
   and the old files in the copy of the etcupdate database.
   - If there are merge conflicts, an error is logged and manual intervention may be required.
   - `.pkgsave` files without a corresponding entry in the old etcupdate database are skipped.
7. If [sshd(8)] is running, restart the service.
8. Run [pwd_mkdb(8)] and [cap_mkdb(1)].
9. Remove `/boot/kernel/linker.hints`.

[bectl(8)]: https://man.freebsd.org/cgi/man.cgi?query=bectl&sektion=8&manpath=freebsd-release
[pkgbase]: https://wiki.freebsd.org/PkgBase
[etcupdate(8)]: https://man.freebsd.org/cgi/man.cgi?query=etcupdate&sektion=8&manpath=freebsd-release
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

### "Fail to rename ..." while extracting FreeBSD-src

```
[323/371] Installing FreeBSD-src-14.1p8...
[323/371] Extracting FreeBSD-src-14.1p8: 100%
pkg: Fail to rename /usr/src/contrib/llvm-project/libcxx/include/.pkgtemp.__string.olNBRRqZQLwR -> /usr/src/contrib/llvm-project/libcxx/include/__string:Not a directory
Error: exit
```

This can be caused by a dirty `/usr/src` directory.
The recommended fix is to remove `/usr/src` and run `./pkgbasify.lua --force` to finish conversion and let pkg fully reinstall `/usr/src`.
