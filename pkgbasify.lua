#!/usr/libexec/flua

-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright(c) 2025 The FreeBSD Foundation.
--
-- This software was developed by Isaac Freund <ifreund@freebsdfoundation.org>
-- under sponsorship from the FreeBSD Foundation.

-- See also the pkgbase wiki page: https://wiki.freebsd.org/PkgBase

local options = {
	create_repo_conf = true,
	repo_name = "FreeBSD-base",
	rootdir = "/",
	jail = nil,
}

local function repo_conf_dir()
	return options.rootdir .. "/usr/local/etc/pkg/repos/"
end
local function repo_conf_file()
	return repo_conf_dir() .. options.repo_name .. ".conf"
end

-- Run a command using the OS shell and capture the stdout
-- Strips exactly one trailing newline if present, does not strip any other whitespace.
-- Asserts that the command exits cleanly
local function capture(command)
	local p = io.popen(command)
	local output = p:read("*a")
	assert(p:close())
	-- Strip exactly one trailing newline from the output, if there is one
	return output:match("(.-)\n$") or output
end

local function prompt_yn(question)
	while true do
		io.write(question .. " (y/n) ")
		local input = io.read()
		if input == "y" or input == "Y" then
			return true
		elseif input == "n" or input == "N" then
			return false
		end
	end
end

local function append_list(list, other)
	for _, item in ipairs(other) do
		table.insert(list, item)
	end
end

local function err(msg)
	io.stderr:write("Error: " .. msg .. "\n")
end

local function fatal(msg)
	err(msg)
	os.exit(1)
end

local function freebsd_version()
	local raw
	if options.jail then
		raw = capture("freebsd-version -j " .. options.jail)
	else
		raw = capture("freebsd-version")
	end
	-- e.g. 15.0-CURRENT, 14.2-STABLE, 14.1-RxLEASE, 14.1-RELEASE-p6,
	local major, minor, branch = assert(raw:match("(%d+)%.(%d+)%-(%u+)"))
	return math.tointeger(major), math.tointeger(minor), branch, raw
end

-- Returns the URL for the pkgbase repository that matches the version
-- reported by freebsd-version(1)
local function base_repo_url()
	local major, minor, branch, raw = freebsd_version()
	if major < 14 then
		fatal("Unsupported FreeBSD version: " .. raw)
	end
	if branch == "RELEASE" or branch:match("^BETA") or branch:match("^RC") then
		return "pkg+https://pkg.FreeBSD.org/${ABI}/base_release_" .. minor
	elseif branch == "CURRENT" or
		branch == "STABLE" or
		branch == "PRERELEASE" or
		branch:match("^ALPHA")
	then
		return "pkg+https://pkg.FreeBSD.org/${ABI}/base_latest"
	else
		fatal("Unsupported FreeBSD version: " .. raw)
	end
end

local function create_base_repo_conf(path)
	assert(os.execute("mkdir -p " .. path:match(".*/")))
	local f <close> = assert(io.open(path, "w"))
	if freebsd_version() >= 15 then
		assert(f:write(string.format([[
%s: {
  enabled: yes
}
]], options.repo_name)))
	else
		assert(f:write(string.format([[
%s: {
  url: "%s",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
]], options.repo_name, base_repo_url())))
	end
end

-- Set to true if the pkg install or any later step errors. We will always
-- attempt to execute every step after pkg install even if it fails, but we
-- should exit with an error code if there was a failure along the way.
local err_post_install = false
local function check_err(ok, err_msg)
	if not ok then
		err(err_msg)
		err_post_install = true
	end
end

local function merge_pkgsaves(workdir)
	local old_dir = workdir .. "/current"
	for old in capture("find " .. old_dir .. " -type f"):gmatch("[^\n]+") do
		local path = old:sub(#old_dir + 1)
		assert(path:sub(1,1) == "/")
		local theirs = options.rootdir .. path
		local ours = theirs .. ".pkgsave"
		if os.execute("test -e " .. ours) then
			local merged = workdir .. "/merged/" .. path
			check_err(os.execute("mkdir -p " .. merged:match(".*/")))
			-- Using cat and a redirection rather than, for example, mv preserves
			-- file attributes of theirs (mode, ownership, etc). This is critical
			-- when merging executable scripts in /etc/rc.d/ for example.
			if os.execute("diff3 -m " .. ours .. " " .. old .. " " .. theirs .. " > " .. merged) and
				os.execute("cat " .. merged .. " > " .. theirs)
			then
				print("Merged " .. theirs)
			else
				print("Failed to merge " .. theirs .. ", manual intervention may be necessary")
			end
		end
	end
end

local function execute_conversion(workdir, package_list)
	if options.create_repo_conf then
		if os.execute("test -e " .. repo_conf_file()) then
			print("Overwriting " .. repo_conf_file())
		else
			print("Creating " .. repo_conf_file())
		end
		create_base_repo_conf(repo_conf_file())
	end

	if capture("pkg config BACKUP_LIBRARIES") ~= "yes" then
		print("Adding BACKUP_LIBRARIES=yes to /usr/local/etc/pkg.conf")
		local f <close> = assert(io.open("/usr/local/etc/pkg.conf", "a"))
		assert(f:write("BACKUP_LIBRARIES=yes\n"))
	end

	local pkg = "pkg --rootdir " .. options.rootdir ..
		" -o REPOS_DIR=" .. options.rootdir .. "/etc/pkg/," .. repo_conf_dir() .. " "

	local packages = table.concat(package_list, " ")
	-- Fetch the packages separately so that we can retry if there is a temporary
	-- network issue or similar.
	while not os.execute(pkg .. " install --fetch-only -y -r "
		.. options.repo_name .. " " .. packages)
	do
		if not prompt_yn("Fetching packages failed, try again?") then
			print("Canceled")
			os.exit(1)
		end
	end

	-- pkg install is not necessarily fully atomic, even if it fails some subset
	-- of the packages may have been installed. Therefore, we must attempt all
	-- followup work even if install fails.
	check_err(os.execute(pkg .. " install --no-repo-update -y -r " ..
		options.repo_name .. " " .. packages))

	merge_pkgsaves(workdir)

	if options.rootdir == "/" then
		if os.execute("service sshd status > /dev/null 2>&1") then
			print("Restarting sshd")
			check_err(os.execute("service sshd restart"))
		end
	end

	check_err(os.execute("pwd_mkdb -d " .. options.rootdir ..
		"/etc -p " .. options.rootdir .. "/etc/master.passwd"))
	check_err(os.execute("cap_mkdb " .. options.rootdir .. "/etc/login.conf"))

	-- Ensure linker.hints is regenerated at next boot.
	check_err(os.execute("rm -f " .. options.rootdir .. "/boot/kernel/linker.hints"))

	if err_post_install then
		print([[
An error occurred during conversion leaving the system in a partially
converted state.

Please determine and resolve the root cause of the error.

When you believe the error will not happen again, run pkgbasify with
the --force argument to try and complete the conversion.
]])
		os.exit(1)
	else
		local prefix = options.rootdir
		if prefix == "/" then
			prefix = ""
		end
		print(string.format([[
Conversion finished.

Please verify that the contents of the following critical files are as expected:
%s/etc/master.passwd
%s/etc/group
%s/etc/ssh/sshd_config

After verifying those files, restart the system.
]], prefix, prefix, prefix))
		os.exit(0)
	end
end

-- Returns the osversion as an integer
local function rquery_osversion(pkg)
	-- It feels like pkg should provide a less ugly way to do this.
	-- TODO is FreeBSD-runtime the correct pkg to check against?
	local tags = capture(pkg .. "rquery -r " .. options.repo_name ..
		" %At FreeBSD-runtime"):gmatch("[^\n]+")
	local values = capture(pkg .. "rquery -r " .. options.repo_name ..
		" %Av FreeBSD-runtime"):gmatch("[^\n]+")
	while true do
		local tag = tags()
		local value = values()
		if not tag or not value then
			break
		end
		if tag == "FreeBSD_version" then
			return math.tointeger(value)
		end
	end
	fatal("Missing FreeBSD_version annotation for FreeBSD-runtime package")
end

local function confirm_version_compatibility(pkg)
	local osversion_local = math.tointeger(capture(pkg .. " config osversion"))
	local osversion_remote = rquery_osversion(pkg)
	if osversion_remote < osversion_local then
		-- This may be overly restrictive, having to wait for remote repositories to
		-- update before the system can be pkgbasified is poor UX.
		print(string.format("System has newer __FreeBSD_version than remote pkgbase packages (%d vs %d).",
			osversion_local, osversion_remote))
		return prompt_yn(string.format("Continue anyway and downgrade the system to %d?", osversion_remote))
	elseif osversion_remote > osversion_local then
		print(string.format("System has older __FreeBSD_version than remote pkgbase packages (%d vs %d).",
			osversion_local, osversion_remote))
		print("It is recommended to update your system before running pkgbasify.")
		return prompt_yn("Ignore the osversion and continue anyway?")
	end
	assert(osversion_local == osversion_remote)
	return true
end

local function create_boot_environment()
	-- Don't create a boot environment if running in a jail
	if capture("sysctl -n security.jail.jailed") == "1" then
		return
	end

	if not os.execute("bectl check") then
		return
	end

	if prompt_yn("Create a boot environment before conversion?") then
		local timestamp = capture("date +'%Y-%m-%d_%H%M%S'")
		if not os.execute("bectl create -r pre-pkgbasify_" .. timestamp) then
			fatal("Failed to create boot environment")
		end
	end
end

-- Returns true if the path is a non-empty directory.
-- Returns false if the path is empty, not a directory, or does not exist.
local function non_empty_dir(path)
	local p = io.popen("find " .. path .. " -maxdepth 0 -type d -not -empty 2>/dev/null")
	local output = p:read("*a"):gsub("%s+", "") -- remove whitespace
	local success = p:close()
	return output ~= "" and success
end

-- Returns a list of pkgbase packages matching the files present on the system
local function select_packages(pkg)
	local kernel = {}
	local kernel_dbg = {}
	local base = {}
	local base_dbg = {}
	local lib32 = {}
	local lib32_dbg = {}
	local src = {}
	local tests = {}

	local rquery = capture(pkg .. "rquery -r " .. options.repo_name .. " %n")
	for package in rquery:gmatch("[^\n]+") do
		if package == "FreeBSD-src" or package:match("FreeBSD%-src%-.*") then
			table.insert(src, package)
		elseif package == "FreeBSD-tests" or package:match("FreeBSD%-tests%-.*") then
			table.insert(tests, package)
		elseif package:match("FreeBSD%-kernel%-.*") then
			-- Kernels other than FreeBSD-kernel-generic are ignored
			if package == "FreeBSD-kernel-generic" then
				table.insert(kernel, package)
			elseif package == "FreeBSD-kernel-generic-dbg" then
				table.insert(kernel_dbg, package)
			end
		elseif package:match(".*%-dbg%-lib32") then
			table.insert(lib32_dbg, package)
		elseif package:match(".*%-lib32") then
			table.insert(lib32, package)
		elseif package:match(".*%-dbg") then
			table.insert(base_dbg, package)
		else
			table.insert(base, package)
		end
	end
	-- No asserts on lib32(-dbg) since they aren't present for all targets
	assert(#kernel == 1)
	assert(#kernel_dbg == 1)
	assert(#base > 0)
	assert(#base_dbg > 0)
	assert(#tests > 0)
	-- FreeBSD-src was not yet available for FreeBSD 14.0
	assert(#src >= 0)

	local selected = {}
	append_list(selected, kernel)
	append_list(selected, base)

	if non_empty_dir(options.rootdir .. "/usr/lib/debug/boot/kernel") then
		append_list(selected, kernel_dbg)
	end
	if os.execute("test -e " .. options.rootdir .. "/usr/lib/debug/lib/libc.so.7.debug") then
		append_list(selected, base_dbg)
	end
	-- Checking if /usr/lib32 is non-empty is not sufficient, as base.txz
	-- includes several empty /usr/lib32 subdirectories.
	if os.execute("test -e " .. options.rootdir .. "/usr/lib32/libc.so.7") then
		append_list(selected, lib32)
	end
	if os.execute("test -e " .. options.rootdir .. "/usr/lib/debug/usr/lib32/libc.so.7.debug") then
		append_list(selected, lib32_dbg)
	end
	if non_empty_dir(options.rootdir .. "/usr/tests") then
		append_list(selected, tests)
	end

	return selected
end

local function select_package_sets(pkg)
	local components = {
		["kernel"] = {},
		["kernel-dbg"] = {},
	}

	local kernel_packages = {
		-- Most architectures use this
		["FreeBSD-kernel-generic"] = true,
		-- PowerPC uses either of these, depending on platform
		["FreeBSD-kernel-generic64"] = true,
		["FreeBSD-kernel-generic64le"] = true,
	}

	local rquery = capture(pkg .. "rquery -U -r FreeBSD-base %n")
	for package in rquery:gmatch("[^\n]+") do
		local setname = package:match("^FreeBSD%-set%-(.+)$")
		if setname then
			components[setname] = components[setname] or {}
			table.insert(components[setname], package)
		elseif kernel_packages[package] then
			table.insert(components["kernel"], package)
		elseif kernel_packages[package:match("(.*)%-dbg$")] then
			table.insert(components["kernel-dbg"], package)
		end
	end
	assert(#components["kernel"] > 0)
	assert(#components["base"] > 0)

	local selected = {}
	append_list(selected, components["base"])
	if os.execute("test -e " .. options.rootdir .. "/usr/lib/debug/lib/libc.so.7.debug") then
		append_list(selected, components["base-dbg"])
	end
	if not options.jail then
		append_list(selected, components["kernel"])
		if non_empty_dir(options.rootdir .. "/usr/lib/debug/boot/kernel") then
			append_list(selected, components["kernel-dbg"])
		end
	end
	-- Checking if /usr/lib32 is non-empty is not sufficient, as base.txz
	-- includes several empty /usr/lib32 subdirectories.
	if os.execute("test -e " .. options.rootdir .. "/usr/lib32/libc.so.7") then
		append_list(selected, components["lib32"])
	end
	if os.execute("test -e " .. options.rootdir .. "/usr/lib/debug/usr/lib32/libc.so.7.debug") then
		append_list(selected, components["lib32-dbg"])
	end
	if non_empty_dir(options.rootdir .. "/usr/tests") then
		append_list(selected, components["tests"])
	end

	return selected
end

local function setup_conversion(workdir)
	-- We must make a copy of the etcupdate db before running pkg install as
	-- the etcupdate db matching the pre-pkgbasify system state will be overwritten.
	assert(os.execute("cp -a " .. options.rootdir .. "/var/db/etcupdate/current " ..
		workdir .. "/current"))

	-- Use a temporary pkg db until we are sure we will carry through with the
	-- conversion to avoid polluting the standard one.
	-- Let pkg handle actually creating the pkgdb directory so that it sets the
	-- permissions it expects and does not error out due to a "too lax" umask.
	local tmp_db = workdir .. "/pkgdb/"

	-- Use a temporary repo configuration file for the setup phase so that there
	-- is nothing to clean up on failure.
	local tmp_repos = workdir .. "/pkgrepos/"
	create_base_repo_conf(tmp_repos .. options.repo_name .. ".conf")

	local pkg = "pkg -o PKG_DBDIR=" .. tmp_db .. " -o REPOS_DIR=" .. options.rootdir .. "/etc/pkg," .. tmp_repos .. " "

	assert(os.execute(pkg .. "-o IGNORE_OSVERSION=yes update"))

	if not confirm_version_compatibility(pkg) then
		print("Canceled")
		os.exit(1)
	end

	if options.create_repo_conf then
		-- The repo_conf_file is created/overwritten in execute_conversion()
		if os.execute("test -e " .. repo_conf_file()) then
			if not prompt_yn("Overwrite " .. repo_conf_file() .. "?") then
				print("Canceled")
				os.exit(1)
			end
		end
	end

	if freebsd_version() >= 15 then
		return select_package_sets(pkg)
	else
		return select_packages(pkg)
	end
end

local function bootstrap_pkg()
	-- Some versions of pkg do not handle `bootstrap -y` gracefully.
	-- This has been fixed in https://github.com/freebsd/pkg/pull/2426 but
	-- but we still need to check before running the bootstrap in case the pkg
	-- version has the broken behavior.
	if os.execute("pkg -N > /dev/null 2>&1") then
		return true
	else
		return os.execute("pkg bootstrap -y")
	end
end

local function confirm_risk()
	print("Running this tool will irreversibly modify your system to use pkgbase.")
	print("This tool and pkgbase are experimental and may result in a broken system.")
	print("It is highly recommended to backup your system before proceeding.")
	return prompt_yn("Do you accept this risk and wish to continue?")
end

local function check_etc_symlinks()
	local etc
	if options.rootdir == "/" then
		etc = "/etc"
	else
		etc = options.rootdir .. "/etc"
	end
	local known_symlinks = {
		[etc .. "/aliases"] = true,
		[etc .. "/localtime"] = true,
		[etc .. "/motd"] = true,
		[etc .. "/os-release"] = true,
		[etc .. "/rmt"] = true,
		[etc .. "/termcap"] = true,
		[etc .. "/unbound"] = true,
	}
	local found = capture("find " .. etc .. " -type l ! -path '" .. etc ..
		"/ssl/*' ! -path '" .. etc .. "/mail/certs/*' 2>/dev/null || true")

	local unexpected = {}
	for link in found:gmatch("[^\n]+") do
		if not known_symlinks[link] then
			table.insert(unexpected, link)
		end
	end

	if #unexpected == 0 then
		return true
	end

	print("\nFound unexpected symlinks in " .. etc)
	for _, link in ipairs(unexpected) do
		print("    " .. link)
	end
	print([[
These symlinks will be overwritten by pkg(8) if they conflict with files in
base system packages. Please ensure that your system configuration will not be
broken if these symlinks are overwritten.]])
	return prompt_yn("Continue and overwrite symlinks in " .. etc .. "?")
end

local function check_no_readonly_var_empty()
	if not os.execute("test -e /var/empty/.zfs") then
		return true -- Not a zfs filesystem
	end
	return capture("zfs get -H -o value readonly /var/empty") == "off"
end

local function check_disk_space()
	-- KiB available on the root filesystem
	local avail = tonumber(capture(
		"df -k " .. options.rootdir .. " | awk '{x=$4}END{print x}'"))
	if avail >= (5 * 1024 * 1024) then
		return true
	else
		print([[
Less than 5GiB space available on the root filesystem.
It is recommended to have at lest 5GiB available before conversion as pkg does
not detect and handle insufficient space gracefully during installation.
]])
		return prompt_yn("Continue despite possibly insufficient disk space?")
	end
end

local usage = [[
Usage: pkgbasify.lua [options]

    -h, --help            Print this usage message and exit
    --force               Attempt conversion even if /usr/bin/uname
                          is owned by a package.
    --repo-name <name>    Name of the pkgbase repository (Default: FreeBSD-base)
    --no-create-repo-conf Don't create a repository configuration,
                          requires the user to configure a pkgbase repository
    --rootdir <dir>       Operate on the given directory rather than /
    --jail <jail>         Operate on the jail with the given jid or name,
                          matching the version of the jail's userland.
]]

local function parse_options()
	local i = 1
	while i <= #arg do
		if arg[i] == "-h" or arg[i] == "--help" then
			io.stdout:write(usage)
			os.exit(0)
		elseif arg[i] == "--force" then
			options.force = true
		elseif arg[i] == "--no-create-repo-conf" then
			options.create_repo_conf = false
		elseif arg[i] == "--repo-name" then
			i = i + 1
			if i > #arg then
				fatal("--repo-name requires an argument")
			end
			options.repo_name = arg[i]
		elseif arg[i] == "--rootdir" then
			i = i + 1
			if i > #arg then
				fatal("--rootdir requires an argument")
			end
			options.rootdir = arg[i]
		elseif arg[i] == "--jail" then
			i = i + 1
			if i > #arg then
				fatal("--jail requires an argument")
			end
			options.jail = arg[i]
			options.rootdir = capture("jls -j " .. options.jail .. " -h path"):match(".+\n(.*)")
		else
			io.stderr:write("Error: unknown option " .. arg[i] .. "\n")
			io.stderr:write(usage)
			os.exit(1)
		end
		i = i + 1
	end
end

local function main()
	parse_options()

	if capture("id -u") ~= "0" then
		fatal("This tool must be run as the root user.")
	end
	-- It is possible to have a pkgbase system without pkg bootstrapped, for
	-- example if bsdinstall was used to install a pkgbase system. Therefore
	-- we must bootstrap pkg to be able to check if the system is already
	-- using pkgbase.
	if not bootstrap_pkg() then
		fatal("Failed to bootstrap pkg.")
	end

	if not options.force and
		os.execute("pkg --rootdir " .. options.rootdir .. " which /usr/bin/uname > /dev/null 2>&1")
	then
		fatal([[
The system is already using pkgbase.
Pass --force to run pkgbasify anyway, for example to fix a partial conversion.]])
	end
	if not check_disk_space() then
		print("Canceled")
		os.exit(1)
	end
	if options.rootdir == "/" and not check_no_readonly_var_empty() then
		print([[
/var/empty is a readonly zfs filesystem.
This will cause conversion to fail as pkg will be unable to set the time of
/var/empty. Set readonly=off and run pkgbasify again.
]])
		os.exit(1)
	end
	if not confirm_risk() then
		print("Canceled")
		os.exit(1)
	end
	if not check_etc_symlinks() then
		print("Canceled")
		os.exit(1)
	end

	local workdir = capture("mktemp -d -t pkgbasify")

	local package_list = setup_conversion(workdir)

	if options.rootdir == "/" then
		create_boot_environment()
	end

	-- This is the point of no return, execute_conversion() will start mutating
	-- global system state.
	-- Before this point, any error should leave the system to exactly the state
	-- it was in before running pkgbasify.
	-- After this point, no error should be fatal and pkgbasify should attempt
	-- to finish conversion regardless of what happens.
	execute_conversion(workdir, package_list)
end

main()
