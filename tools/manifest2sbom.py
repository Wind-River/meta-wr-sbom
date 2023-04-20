#
# Copyright (C) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: GPL-2.0-only
#

import os
import sys
import spdx
import datetime
import json

def gen_SPDXPattern():
    doc = spdx.SPDXDocument()
    doc.creationInfo.created = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    doc.creationInfo.creators.append("Tool: meta-wr-sbom gen_manifest.sh")
    doc.creationInfo.creators.append("Organization: WindRiver")
    doc.creationInfo.creators.append("Person: N/A")
    return doc

def get_yocto_version(bitbake_version):
    bb_version_to_yocto_version = {"2.2": "4.1", "2.0": "4.0", "1.52": "3.4", "1.50": "3.3", "1.48": "3.2", "1.46": "3.1", "1.44": "3.0", "1.42": "2.7", "1.40": "2.6", "1.38": "2.5", "1.36": "2.4", "1.34": "2.3", "1.32": "2.2", "1.30": "2.1", "1.28": "2.0", "1.26": "1.8", "1.24": "1.7", "1.22": "1.6", "1.20": "1.5", "1.18": "1.4", "1.18": "1.4", "1.16": "1.3"}
    bb_ver = bitbake_version.split('.')
    return bb_version_to_yocto_version[bb_ver[0]+'.'+bb_ver[1]]

doc = gen_SPDXPattern()    
f_manifest = open("manifest.lst")
f_lic = open("lic.lst")
file_output = open("image_sbom.spdx.json", "w")

packages_license = dict()
for read_lic in f_lic:
    pkg_lic = read_lic.strip().split('\t')
    if len(pkg_lic) < 2:
        continue
    packages_license[pkg_lic[0]] = pkg_lic[1].split('=')[1].strip('"')

for line in f_manifest:
    if line.startswith("DISTRO_NAME"):
        distro_name = line.strip().split('=')[1].strip('"')
        continue

    if line.startswith("DISTRO_VERSION"):
        distro_version = line.strip().split('=')[1].strip('"')
        continue

    if line.startswith("BB_VERSION"):
        bb_ver = line.strip().split('=')[1].strip('"')
        continue

    pkg_ver = line.strip().split()
    if len(pkg_ver) == 0:
        continue
    pkgname = pkg_ver[0]
    version = pkg_ver[1]

    package = spdx.SPDXPackage()
    package.name = pkgname
    package.SPDXID = "SPDXRef-%s-%s" % ("Recipe", pkgname)
    package.versionInfo = version
    package.licenseDeclared = packages_license[pkgname]
    doc.packages.append(package)

doc.name = distro_name
if 'Wind River' in distro_name:
    doc.comment = "DISTRO: " + "WRLinux-" + distro_version
elif 'Yocto' in distro_name:
    doc.comment = "DISTRO: " + "Yocto-" + distro_version
else:
    doc.comment = "DISTRO: " + "Yocto-" + get_yocto_version(bb_ver)

f_manifest.close()
f_lic.close()
doc.to_json(file_output, sort_keys=True)
file_output.close()

print("./image_sbom.spdx.json generated.")
