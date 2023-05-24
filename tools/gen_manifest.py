#!/usr/bin/env python3
#
# Copyright OpenEmbedded Contributors
# Copyright (C) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: GPL-2.0-only
#

#####################################################################################
# Prerequisite:
#   1. Enter your project top directory.
#   2. Fully build your project.
#   3. For Wind River Linux 6, 7 and 8 versions, execute "make bbs".
#
#
# Execute the script:
#   ${the_path}/gen_manifest.py target_image_name;
#
# The target_image_name is the image target to generate manifest, such as 'wrlinux-image-small'.
#
# If the script execute success, the manifest will generate at current directory.
#####################################################################################


import os
import sys
import datetime
import json
import hashlib
import itertools

if len(sys.argv) < 2:
    print("Please specify a image target to generate the sbom.")
    #print("Project directory means the folder where [config.log] and [Makefile] file located.")
    sys.exit(1)

target_image = sys.argv[1]

SPDX_VERSION = "2.2"

class _Property(object):
    """
    A generic SPDX object property. The different types will derive from this
    class
    """

    def __init__(self, *, default=None):
        self.default = default

    def setdefault(self, dest, name):
        if self.default is not None:
            dest.setdefault(name, self.default)


class _String(_Property):
    """
    A scalar string property for an SPDX object
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def set_property(self, attrs, name):
        def get_helper(obj):
            return obj._spdx[name]

        def set_helper(obj, value):
            obj._spdx[name] = value

        def del_helper(obj):
            del obj._spdx[name]

        attrs[name] = property(get_helper, set_helper, del_helper)

    def init(self, source):
        return source


class _Object(_Property):
    """
    A scalar SPDX object property of a SPDX object
    """

    def __init__(self, cls, **kwargs):
        super().__init__(**kwargs)
        self.cls = cls

    def set_property(self, attrs, name):
        def get_helper(obj):
            if not name in obj._spdx:
                obj._spdx[name] = self.cls()
            return obj._spdx[name]

        def set_helper(obj, value):
            obj._spdx[name] = value

        def del_helper(obj):
            del obj._spdx[name]

        attrs[name] = property(get_helper, set_helper)

    def init(self, source):
        return self.cls(**source)


class _ListProperty(_Property):
    """
    A list of SPDX properties
    """

    def __init__(self, prop, **kwargs):
        super().__init__(**kwargs)
        self.prop = prop

    def set_property(self, attrs, name):
        def get_helper(obj):
            if not name in obj._spdx:
                obj._spdx[name] = []
            return obj._spdx[name]

        def del_helper(obj):
            del obj._spdx[name]

        attrs[name] = property(get_helper, None, del_helper)

    def init(self, source):
        return [self.prop.init(o) for o in source]


class _StringList(_ListProperty):
    """
    A list of strings as a property for an SPDX object
    """

    def __init__(self, **kwargs):
        super().__init__(_String(), **kwargs)


class _ObjectList(_ListProperty):
    """
    A list of SPDX objects as a property for an SPDX object
    """

    def __init__(self, cls, **kwargs):
        super().__init__(_Object(cls), **kwargs)


class MetaSPDXObject(type):
    """
    A metaclass that allows properties (anything derived from a _Property
    class) to be defined for a SPDX object
    """
    def __new__(mcls, name, bases, attrs):
        attrs["_properties"] = {}

        for key in attrs.keys():
            if isinstance(attrs[key], _Property):
                prop = attrs[key]
                attrs["_properties"][key] = prop
                prop.set_property(attrs, key)

        return super().__new__(mcls, name, bases, attrs)


class SPDXObject(metaclass=MetaSPDXObject):
    """
    The base SPDX object; all SPDX spec classes must derive from this class
    """
    def __init__(self, **d):
        self._spdx = {}

        for name, prop in self._properties.items():
            prop.setdefault(self._spdx, name)
            if name in d:
                self._spdx[name] = prop.init(d[name])

    def serializer(self):
        return self._spdx

    def __setattr__(self, name, value):
        if name in self._properties or name == "_spdx":
            super().__setattr__(name, value)
            return
        raise KeyError("%r is not a valid SPDX property" % name)

#
# These are the SPDX objects implemented from the spec. The *only* properties
# that can be added to these objects are ones directly specified in the SPDX
# spec, however you may add helper functions to make operations easier.
#
# Defaults should *only* be specified if the SPDX spec says there is a certain
# required value for a field (e.g. dataLicense), or if the field is mandatory
# and has some sane "this field is unknown" (e.g. "NOASSERTION")
#

class SPDXAnnotation(SPDXObject):
    annotationDate = _String()
    annotationType = _String()
    annotator = _String()
    comment = _String()

class SPDXChecksum(SPDXObject):
    algorithm = _String()
    checksumValue = _String()


class SPDXRelationship(SPDXObject):
    spdxElementId = _String()
    relatedSpdxElement = _String()
    relationshipType = _String()
    comment = _String()
    annotations = _ObjectList(SPDXAnnotation)


class SPDXExternalReference(SPDXObject):
    referenceCategory = _String()
    referenceType = _String()
    referenceLocator = _String()


class SPDXPackageVerificationCode(SPDXObject):
    packageVerificationCodeValue = _String()
    packageVerificationCodeExcludedFiles = _StringList()


class SPDXPackage(SPDXObject):
    name = _String()
    SPDXID = _String()
    versionInfo = _String()
    downloadLocation = _String(default="NOASSERTION")
    supplier = _String(default="NOASSERTION")
    homepage = _String()
    licenseConcluded = _String(default="NOASSERTION")
    licenseDeclared = _String(default="NOASSERTION")
    summary = _String()
    description = _String()
    sourceInfo = _String()
    copyrightText = _String(default="NOASSERTION")
    licenseInfoFromFiles = _StringList(default=["NOASSERTION"])
    externalRefs = _ObjectList(SPDXExternalReference)
    packageVerificationCode = _Object(SPDXPackageVerificationCode)
    hasFiles = _StringList()
    packageFileName = _String()
    annotations = _ObjectList(SPDXAnnotation)
    comment = _String()


class SPDXFile(SPDXObject):
    SPDXID = _String()
    fileName = _String()
    licenseConcluded = _String(default="NOASSERTION")
    copyrightText = _String(default="NOASSERTION")
    licenseInfoInFiles = _StringList(default=["NOASSERTION"])
    checksums = _ObjectList(SPDXChecksum)
    fileTypes = _StringList()


class SPDXCreationInfo(SPDXObject):
    created = _String()
    licenseListVersion = _String()
    comment = _String()
    creators = _StringList()


class SPDXExternalDocumentRef(SPDXObject):
    externalDocumentId = _String()
    spdxDocument = _String()
    checksum = _Object(SPDXChecksum)


class SPDXExtractedLicensingInfo(SPDXObject):
    name = _String()
    comment = _String()
    licenseId = _String()
    extractedText = _String()


class SPDXDocument(SPDXObject):
    spdxVersion = _String(default="SPDX-" + SPDX_VERSION)
    dataLicense = _String(default="CC0-1.0")
    SPDXID = _String(default="SPDXRef-DOCUMENT")
    name = _String()
    documentNamespace = _String()
    creationInfo = _Object(SPDXCreationInfo)
    comment = _String()
    packages = _ObjectList(SPDXPackage)
    files = _ObjectList(SPDXFile)
    relationships = _ObjectList(SPDXRelationship)
    documentDescribes = _StringList()
    externalDocumentRefs = _ObjectList(SPDXExternalDocumentRef)
    hasExtractedLicensingInfos = _ObjectList(SPDXExtractedLicensingInfo)

    def __init__(self, **d):
        super().__init__(**d)

    def to_json(self, f, *, sort_keys=False, indent=2, separators=None):
        class Encoder(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, SPDXObject):
                    return o.serializer()

                return super().default(o)

        sha1 = hashlib.sha1()
        for chunk in Encoder(
            sort_keys=sort_keys,
            indent=indent,
            separators=separators,
        ).iterencode(self):
            chunk = chunk.encode("utf-8")
            f.write(chunk)
            sha1.update(chunk)

        return sha1.hexdigest()

    @classmethod
    def from_json(cls, f):
        return cls(**json.load(f))

    def add_relationship(self, _from, relationship, _to, *, comment=None, annotation=None):
        if isinstance(_from, SPDXObject):
            from_spdxid = _from.SPDXID
        else:
            from_spdxid = _from

        if isinstance(_to, SPDXObject):
            to_spdxid = _to.SPDXID
        else:
            to_spdxid = _to

        r = SPDXRelationship(
            spdxElementId=from_spdxid,
            relatedSpdxElement=to_spdxid,
            relationshipType=relationship,
        )

        if comment is not None:
            r.comment = comment

        if annotation is not None:
            r.annotations.append(annotation)

        self.relationships.append(r)

    def find_by_spdxid(self, spdxid):
        for o in itertools.chain(self.packages, self.files):
            if o.SPDXID == spdxid:
                return o
        return None

    def find_external_document_ref(self, namespace):
        for r in self.externalDocumentRefs:
            if r.spdxDocument == namespace:
                return r
        return None

def getInstalledPkgs(license_manifest):
    recipeDict = {}

    f_license_manifest = open(license_manifest)
    for line in f_license_manifest:
        line_data = line.strip().split(":")
        if line_data[0] == "PACKAGE NAME":
            package_name = line_data[1].strip()
        if line_data[0] == "PACKAGE VERSION":
            package_version = line_data[1].strip()
        if line_data[0] == "RECIPE NAME":
            recipe_name = line_data[1].strip()
        if line_data[0] == "LICENSE":
            declared_license = line_data[1].strip()
        if line.strip() == '' and package_name:
            pkgInfo = dict()
            if recipe_name not in recipeDict.keys():
                recipeDict[recipe_name] = {}
            if package_version not in recipeDict[recipe_name].keys():
                recipeDict[recipe_name][package_version] = []

            pkgInfo["name"] = package_name
            pkgInfo["versionInfo"] = package_version
            pkgInfo["recipe"] = recipe_name
            pkgInfo["licenseDeclared"] = declared_license
            package_name = ''
            recipeDict[recipe_name][package_version].append(pkgInfo)
    if package_name:            #if the last line is not empty
        pkgInfo = dict()
        if recipe_name not in recipeDict.keys():
            recipeDict[recipe_name] = {}
        if package_version not in recipeDict[recipe_name].keys():
            recipeDict[recipe_name][package_version] = []

        pkgInfo["name"] = package_name
        pkgInfo["versionInfo"] = package_version
        pkgInfo["recipe"] = recipe_name
        pkgInfo["licenseDeclared"] = declared_license
        package_name = ''
        recipeDict[recipe_name][package_version].append(pkgInfo)

    f_license_manifest.close()
    return recipeDict

def gen_SPDXPattern():
    doc = SPDXDocument()
    doc.creationInfo.created = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    doc.creationInfo.creators.append("Tool: meta-wr-sbom gen_manifest.py")
    doc.creationInfo.creators.append("Organization: WindRiver")
    doc.creationInfo.creators.append("Person: N/A")
    return doc

def get_yocto_version(bitbake_version):
    bb_version_to_yocto_version = {"2.2": "4.1", "2.0": "4.0", "1.52": "3.4", "1.50": "3.3", "1.48": "3.2", "1.46": "3.1", "1.44": "3.0", "1.42": "2.7", "1.40": "2.6", "1.38": "2.5", "1.36": "2.4", "1.34": "2.3", "1.32": "2.2", "1.30": "2.1", "1.28": "2.0", "1.26": "1.8", "1.24": "1.7", "1.22": "1.6", "1.20": "1.5", "1.18": "1.4", "1.18": "1.4", "1.16": "1.3"}
    bb_ver = bitbake_version.split('.')
    return bb_version_to_yocto_version[bb_ver[0]+'.'+bb_ver[1]]

def generate_sbom(recipeDict):
    doc = gen_SPDXPattern()
    doc.name = env_data["DISTRO_NAME"]
    if 'Wind River' in env_data["DISTRO_NAME"]:
        doc.comment = "DISTRO: " + "WRLinux-" + env_data["DISTRO_VERSION"]
    elif 'Yocto' in env_data["DISTRO_NAME"]:
        doc.comment = "DISTRO: " + "Yocto-" + env_data["DISTRO_VERSION"]
    else:
        doc.comment = "DISTRO: " + "Yocto-" + get_yocto_version(env_data["BB_VERSION"])

    for name in recipeDict.keys():
        if name == "base-passwd" or \
            name.startswith("packagegroup-"):
            continue
        for version in recipeDict[name].keys():
            package = SPDXPackage()
            package.name = name
            package.SPDXID = "SPDXRef-%s-%s" % ("Recipe", name)
            package.versionInfo = version
            package.licenseDeclared = recipeDict[name][version][0]["licenseDeclared"]
            doc.packages.append(package)

    output_file = open(target_image + ".spdx.json", "wb")
    doc.to_json(output_file, sort_keys=True)
    output_file.close()

    print("./%s.spdx.json generated." % target_image)

def compareInstalledPkgs():
    packages_dirs = []

    def getSubDirs(currentDir, currentLevel):
        if currentLevel != 0:
            dirItems = os.listdir(currentDir)
            for item in dirItems:
                if os.path.isdir(os.path.join(currentDir,item)):
                    getSubDirs(os.path.join(currentDir,item), currentLevel - 1)
        else:       #search to the packages-split dir level
            if currentDir.endswith("packages-split"):
                dirItems = os.listdir(currentDir)
                for item in dirItems:
                    pkgDir = os.path.join(currentDir, item)
                    if os.path.isdir(pkgDir):
                        packages_dirs.append(pkgDir)

    getSubDirs(os.path.join(env_data["TMPDIR"], "work"), 4)

    recipeDict = {}
    for splitPkgDir in packages_dirs:
        recipe_name = os.listdir(os.path.join(splitPkgDir, "../../license-destdir"))[0]
        spec_file = os.path.join(splitPkgDir, "../..", recipe_name + ".spec")
        f_spec = open(spec_file)
        for line in f_spec:
            line_data = line.strip().split(":")
            if line_data[0] == "Version":
                package_version = line_data[1].strip()
            if line_data[0] == "License":
                declared_license = line_data[1].strip()
        f_spec.close()

        if recipe_name in recipeDict.keys():               # the recipe had added
            if package_version in recipeDict[recipe_name].keys():
                if recipeDict[recipe_name][package_version]:
                    continue

        for root, dirs, files in os.walk(splitPkgDir):
            if files:
                pkgFile = os.path.join(root, files[0])
                pkgFile_relpath = os.path.relpath(pkgFile, splitPkgDir)
                if os.path.exists(os.path.join(env_data["IMAGE_ROOTFS"], pkgFile_relpath)):
                    if recipe_name not in recipeDict.keys():
                        recipeDict[recipe_name] = {}
                    if package_version not in recipeDict[recipe_name].keys():
                        recipeDict[recipe_name][package_version] = []
                    pkgInfo = dict()
                    pkgInfo["name"] = os.path.basename(splitPkgDir)
                    pkgInfo["versionInfo"] = package_version
                    pkgInfo["recipe"] = recipe_name
                    pkgInfo["licenseDeclared"] = declared_license
                    recipeDict[recipe_name][package_version].append(pkgInfo)

    return recipeDict

env_data = {}
def main():
    env_metadata = os.popen("bitbake %s -e" % target_image)

    for line in env_metadata:
        line = line.strip()
        if line.startswith("#"):
            continue
        if line.startswith("DISTRO_VERSION=") or \
        line.startswith("DISTRO_NAME=") or \
        line.startswith("BB_VERSION=") or \
        line.startswith("INHERIT=") or \
        line.startswith("LICENSE_DIRECTORY=") or \
        line.startswith("TMPDIR=") or \
        line.startswith("IMAGE_ROOTFS="):
            line_data = line.split("=")
            env_data[line_data[0]] = line_data[1].strip().strip('"')
    
    env_metadata.close()
    del env_metadata
    
    license_manifest_dir = ''
    license_deploy_tree = os.walk(env_data["LICENSE_DIRECTORY"])
    for root, dirs, files in license_deploy_tree:
        for dirname in dirs:
            if dirname.startswith(target_image):
                if os.path.exists(os.path.join(root, dirname, "license.manifest")):
                    if dirname > license_manifest_dir:
                        license_manifest_dir = dirname
                        license_manifest_file = os.path.join(root, dirname, "license.manifest")
    
    if license_manifest_dir:
        pkgsInfo = getInstalledPkgs(license_manifest_file)
    elif "rm_work" not in env_data["INHERIT"]:
        if not os.path.exists(env_data["IMAGE_ROOTFS"]):
            print("The IMAGE_ROOTFS path %s not exists." % env_data["IMAGE_ROOTFS"])
            exit(1)
        pkgsInfo = compareInstalledPkgs()
    else:
        print("Fail to found license manifest and IMAGE_ROOTFS path.")
        exit(1)

    generate_sbom(pkgsInfo)

if __name__ == "__main__":
    main()
