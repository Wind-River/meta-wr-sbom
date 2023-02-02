#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: GPL-2.0-only
#

from abc import ABCMeta, abstractmethod
#from oe.utils import execute_pre_post_process
from oe_sbom.package_manager import *
#from oe.manifest import *
import oe.path
import filecmp
import shutil
import os
import subprocess
import re


def image_list_installed_packages(d, rootfs_dir=None):
    if not rootfs_dir:
        rootfs_dir = d.getVar('IMAGE_ROOTFS', True)

    img_type = d.getVar('IMAGE_PKGTYPE', True)
    if img_type == "rpm":
        return RpmPkgsList(d, rootfs_dir).list_pkgs()
    elif img_type == "ipk":
        return OpkgPkgsList(d, rootfs_dir, d.getVar("IPKGCONF_TARGET", True)).list_pkgs()
    elif img_type == "deb":
        return DpkgPkgsList(d, rootfs_dir).list_pkgs()

