#
# Copyright (C) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: GPL-2.0-only
#

python () {
    sls_release_version = d.getVar("SLS_REL_VER", True)
    if sls_release_version:
        d.setVar("PKGR", "r" + d.getVar("DISTRO_VERSION", True) + "c" + sls_release_version)
        d.setVar("SLS_EXTEND_VERSION", "r" + d.getVar("DISTRO_VERSION", True) + "c" + sls_release_version)
    else:
        raise Exception("SLS_REL_VER variable is not set")
}
