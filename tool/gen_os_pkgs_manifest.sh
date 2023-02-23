#!/bin/bash
#
# Copyright (C) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: GPL-2.0-only
#

manifest_filename="os_packages.manifest.txt"
packages_count=0
dpkg_db_path="/var/lib/dpkg"
error=0

usage () {
    echo "Generate manifest for OS packages in Linux"
    echo ""
    echo "Usage:"
    echo "  $(basename $0)"
    echo "  $(basename $0) [-h]"
    echo "  $(basename $0) [-r /path/to/rootfs]"
    echo ""
    echo "Options"
    echo "  no option           generate manifest from default path"
    echo "  -h                  display this help"
    echo "  -r /path/to/rootfs  generate manifest from the root filesystem"
}

if [ $# -eq 0 ]
then
    #No options, generate manifest with default os-release and package database
    rootfs_path=""
elif [ $# -eq 1 -o $# -gt 2 ]
then
    error=1
else
    if [ $1 == "-r" ]
    then
        if [ -d $2 ]
	then
	    rootfs_path=${2%/}
        else
	    echo "Error: $2 does not exist"
	    error=1
	fi
    else
        error=1
    fi
fi

if [ ${error} -eq 1 ]
then
    usage
    exit $error
fi

if [ -f "${rootfs_path}/etc/os-release" ]
then
   os_release="${rootfs_path}/etc/os-release"
elif [ -f "${rootfs_path}/usr/lib/os-release" ]
then
   os_release="${rootfs_path}/usr/lib/os-release"
else
    echo "Error: cannot determine OS release"
    exit 1
fi

source "${os_release}"

distro_name=${ID?}
distro_version=${VERSION_ID?}

if [ "${distro_name}" = "ubuntu" ]
then
    #do nothing
    :
elif [ "${distro_name}" = "debian" ]
then
    #do nothing
    :
elif [ "${distro_name}" = "rhel" ]
then
    #do nothing
    :
elif [ "${distro_name}" = "centos" ]
then
    #do nothing
    :
elif [ "${distro_name}" = "fedora" ]
then
    #do nothing
    :
elif [ "${distro_name}" = "suse" ]
then
    #do nothing
    :
elif [ "${distro_name}" = "opensuse" ]
then
    #do nothing
    :
elif [ "${distro_name}" = "opensuse-leap" ]
then
    #do nothing
    :
elif [ "${distro_name}" = "opensuse-tumbleweed" ]
then
    #do nothing
    :
elif [ "${distro_name}" = "alpine" ]
then
    #do nothing
    :
else
    echo "Warning: this script is not verified on ${distro_name}"
fi

temp_filename=$(mktemp $manifest_filename.XXXXXXXXXX)

echo "DISTRO_NAME=${distro_name}" > "${temp_filename}"
echo "DISTRO_VERSION=${distro_version}" >> "${temp_filename}"

echo "" >> "${temp_filename}"

gen_filename () {
    if [ ! -f "${manifest_filename}" ]
    then
        mv "${temp_filename}" "${manifest_filename}"
        echo "${PWD}/${manifest_filename} is generated."
    else
        mv "${temp_filename}" "${temp_filename}.txt"
        echo "${PWD}/${temp_filename}.txt is generated."
    fi
}

if command -v rpm &> /dev/null
then
    packages_count=$(rpm --root "${rootfs_path}/" -qa | wc -l)
    if [ ${packages_count} -gt 0 ]
    then
        rpm --root "${rootfs_path}/" -qa --qf "%{NAME} %{VERSION}-%{RELEASE}\n" >> "${temp_filename}"
        gen_filename
        exit 0
    fi

fi

if command -v dpkg-query &> /dev/null
then
    packages_count=$(dpkg-query --admindir="${rootfs_path}${dpkg_db_path}" -W | wc -l)
    if [ ${packages_count} -gt 0 ]
    then
        dpkg-query --admindir="${rootfs_path}${dpkg_db_path}" -W --showformat='${Package} ${Version}\n' >> ${temp_filename}
        gen_filename
        exit 0
    fi
fi


if command -v apk &> /dev/null
then
    packages_count=$(apk info --root "${rootfs_path}/" | wc -l)
    if [ ${packages_count} -gt 0 ]
    then
        apk info --root "${rootfs_path}/" | while read line
            do
            pkg_name_version=$(apk search -e $line)
            echo $line ${pkg_name_version#"$line-"} >> ${temp_filename}
        done
        gen_filename
        exit 0
    fi
fi

rm ${temp_filename}
echo "Error: no package manager found."
exit 1
