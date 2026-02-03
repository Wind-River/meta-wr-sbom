#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: GPL-2.0-only
#

DEPLOY_DIR_SPDX ??= "${DEPLOY_DIR}/spdx/${MACHINE}"

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

SPDXDIR ??= "${WORKDIR}/spdx"
SPDXDEPLOY = "${SPDXDIR}/deploy"
SPDXWORK = "${SPDXDIR}/work"

SPDX_TOOL_NAME ??= "oe-spdx-creator"
SPDX_TOOL_VERSION ??= "1.0"

SPDXRUNTIMEDEPLOY = "${SPDXDIR}/runtime-deploy"

SPDX_INCLUDE_SOURCES ??= "0"
SPDX_INCLUDE_PACKAGED ??= "0"
SPDX_ARCHIVE_SOURCES ??= "0"
SPDX_ARCHIVE_PACKAGED ??= "0"

SPDX_UUID_NAMESPACE ??= "sbom.openembedded.org"
SPDX_NAMESPACE_PREFIX ??= "http://spdx.org/spdxdoc"

SPDX_LICENSES ??= "${WRSBOM_LAYER}/meta/files/spdx-licenses.json"

BB_HASH_IGNORE_MISMATCH = '1'

SPDX_BLACKLIST ??= "external-arm-toolchain"

do_image_complete[depends] = "virtual/kernel:do_create_spdx"

def get_doc_namespace(d, doc):
    import uuid
    namespace_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, d.getVar("SPDX_UUID_NAMESPACE", True))
    return "%s/%s-%s" % (d.getVar("SPDX_NAMESPACE_PREFIX", True), doc.name, str(uuid.uuid5(namespace_uuid, doc.name)))

def create_annotation(d, comment):
    from datetime import datetime, timezone
    import oe_sbom.spdx

    creation_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    annotation = oe_sbom.spdx.SPDXAnnotation()
    annotation.annotationDate = creation_time
    annotation.annotationType = "OTHER"
    annotation.annotator = "Tool: %s - %s" % (d.getVar("SPDX_TOOL_NAME", True), d.getVar("SPDX_TOOL_VERSION", True))
    annotation.comment = comment
    return annotation

def get_variable_value(d, var, pn, pkg=None):
    sep = ":" if ":" in (d.getVar("OVERRIDES") or "") else "_"

    value = None
    if pkg:
       value = d.getVar(f"{var}{sep}{pkg}", True)
    if not value:
       value = d.getVar(f"{var}{sep}{pn}", True)
    if not value:
       value = d.getVar(f"{var}{sep}DEFAULT", True)

    if not value:
       return None
    return value

def generate_origin_annotation(d, pn, pkg=None):
    allowed_origins = ['open-source', 'commercial', 'off-the-shelf']

    origin_str = get_variable_value(d,'ORIGIN', pn, pkg)
    if not origin_str:
       return []

    origin = origin_str.lower()
    if not (origin in allowed_origins):
       bb.warn("Invalid ORIGIN type %s for %s" % (origin_str, pkg if pkg else pn))
       return []

    return [create_annotation(d, "origin: %s" % origin)]

def normalize_timestamp(ts_str):
    from datetime import datetime, timezone

    try:
        fmt = "%Y-%m-%d"
        ts = datetime.strptime(ts_str, fmt)
    except Exception as e:
        bb.debug(1, "Failed to parse timestamp %s: %s" % (ts_str, str(e)))
        return None

    return ts.replace(hour=23, minute=59, second=59, microsecond=0, tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')

def generate_validuntil_annotation(d, pn, pkg=None):
    validuntil_str = get_variable_value(d, 'VALIDUNTILDATE', pn, pkg)
    if not validuntil_str:
       return []

    validuntil = normalize_timestamp(validuntil_str)
    if not validuntil:
       bb.warn("Invalid validuntil timestamp %s for %s" % (validuntil_str, pkg if pkg else pn))
       return []

    return [create_annotation(d, 'validUntilDate: %s' % validuntil)]

def generate_eos_annotation(d, pn, pkg=None):
    eos_str = get_variable_value(d, 'EOS', pn, pkg)
    if not eos_str:
       return []

    eos = normalize_timestamp(eos_str)
    if not eos:
       bb.warn("Invalid EOS timestamp %s for %s" % (eos_str, pkg if pkg else pn))
       return []

    return [create_annotation(d, 'eos: %s' % eos)]

def recipe_spdx_is_native(d, recipe):
    return any(a.annotationType == "OTHER" and
      a.annotator == "Tool: %s - %s" % (d.getVar("SPDX_TOOL_NAME", True), d.getVar("SPDX_TOOL_VERSION", True)) and
      a.comment == "isNative" for a in recipe.annotations)

def get_spdxdir_from_annotation(d, recipe):
    for a in recipe.annotations:
        if (a.annotationType == "OTHER" and
          a.annotator == "Tool: %s - %s" % (d.getVar("SPDX_TOOL_NAME", True), d.getVar("SPDX_TOOL_VERSION", True)) and
          a.comment.startswith("SPDXDIR:")):
              return a.comment.replace('SPDXDIR:', '')

def is_work_shared_spdx(d):
    return bb.data.inherits_class('kernel', d) or ('work-shared' in d.getVar('WORKDIR', True))

python() {
    import json
    if d.getVar("SPDX_LICENSE_DATA", True):
        return

    with open(d.getVar("SPDX_LICENSES", True), "r") as f:
        data = json.load(f)
        # Transform the license array to a dictionary
        data["licenses"] = {l["licenseId"]: l for l in data["licenses"]}
        d.setVar("SPDX_LICENSE_DATA", data)
}

# json.load() may not load ${SPDX_LICENSES} *deterministically*, so ignoring its value when calculating signature for SPDX_LICENSE_DATA.
SPDX_LICENSE_DATA[vardepvalue] = ""

# idstring shall only contain letters, numbers, . and/or -.
# replace other character with "-"
def clean_idstring(id):
    import re
    return re.sub(r'[^a-zA-Z0-9.-]', '-', id)

def convert_license_to_spdx(lic, document, d, existing={}):
    from pathlib import Path
    import oe_sbom.spdx

    available_licenses = (d.getVar("AVAILABLE_LICENSES", True) or '').split()
    license_data = d.getVar("SPDX_LICENSE_DATA", True)
    extracted = {}

    def add_extracted_license(ident, name):
        nonlocal document

        if name in extracted:
            return

        extracted_info = oe_sbom.spdx.SPDXExtractedLicensingInfo()
        extracted_info.name = name
        extracted_info.licenseId = clean_idstring(ident)
        extracted_info.extractedText = "None"

        if name == "PD":
            # Special-case this.
            extracted_info.extractedText = "Software released to the public domain"
        elif name in available_licenses:
            # This license can be found in COMMON_LICENSE_DIR or LICENSE_PATH
            for directory in [d.getVar('COMMON_LICENSE_DIR', True)] + d.getVar('LICENSE_PATH', True).split():
                try:
                    with (Path(directory) / name).open(errors="replace") as f:
                        extracted_info.extractedText = f.read()
                        break
                except FileNotFoundError:
                    pass
            if extracted_info.extractedText == "None":
                # Error out, as the license was in available_licenses so should
                # be on disk somewhere.
                bb.warn("Cannot find text for license %s" % name)
        else:
            # If it's not SPDX, or PD, or in available licenses, then NO_GENERIC_LICENSE must be set
            filename = d.getVarFlag('NO_GENERIC_LICENSE', name, True)
            if filename:
                filename = d.expand("${S}/" + filename)
                with open(filename, errors="replace") as f:
                    extracted_info.extractedText = f.read()
            else:
                bb.warn("Cannot find any text for license %s" % name)

        extracted[name] = extracted_info
        document.hasExtractedLicensingInfos.append(extracted_info)

    def convert(l):
        from oe_sbom.spdx_license_map import spdx_license_map

        if l == "(" or l == ")":
            return l

        if l == "&":
            return "AND"

        if l == "|":
            return "OR"

        if l == "CLOSED":
            return "NONE"

        if l in spdx_license_map.keys():
            spdx_license = spdx_license_map[l]
        else:
            spdx_license = l

        if spdx_license in license_data["licenses"]:
            return spdx_license

        try:
            spdx_license = existing[l]
        except KeyError:
            spdx_license = "LicenseRef-" + l
            add_extracted_license(spdx_license, l)

        return spdx_license

    lic_split = lic.replace("(", " ( ").replace(")", " ) ").split()

    return ' '.join(convert(l) for l in lic_split)

def get_distro_type(d):
    if 'Yocto' in d.getVar("DISTRO_NAME", True):
        return "yocto", d.getVar("DISTRO_VERSION", True)
    elif 'Wind River' in d.getVar("DISTRO_NAME", True):
        return "wrlinux", d.getVar("DISTRO_VERSION", True)
    else:
        wr_version = d.getVar("WRLINUX_VERSION", True)
        if wr_version:
            return "wrlinux", d.getVar("WRLINUX_VERSION", True)
        else:
            bb_version = d.getVar("BB_VERSION", True)
            return "yocto", get_yocto_version(bb_version)

def get_final_pkg_name(d, package):
    distro_ver = d.getVar("DISTRO_VERSION", True)
    if 'Wind River' in d.getVar("DISTRO_NAME", True):
        if (distro_ver.split('.')[0] == '10') and (int(distro_ver.split('.')[1]) > 21):
            pkg_name = d.getVar("PKG:%s" % package, True) or package
        elif (distro_ver.split('.')[0] == '10') and (distro_ver.split('.')[1] == '21') and (int(distro_ver.split('.')[3]) >= 5):
            pkg_name = d.getVar("PKG:%s" % package, True) or package
        else:
            pkg_name = d.getVar("PKG_%s" % package, True) or package
    else:
        if d.getVar("BB_VERSION", True) > '1.50.0':
            pkg_name = d.getVar("PKG:%s" % package, True) or package
        else:
            pkg_name = d.getVar("PKG_%s" % package, True) or package
    return pkg_name

def process_sources(d):
    pn = d.getVar('PN', True)
    assume_provided = (d.getVar("ASSUME_PROVIDED", True) or "").split()
    if pn in assume_provided:
        for p in d.getVar("PROVIDES", True).split():
            if p != pn:
                pn = p
                break

    # glibc-locale: do_fetch, do_unpack and do_patch tasks have been deleted,
    # so avoid archiving source here.
    if pn.startswith('glibc-locale'):
        return False
    if d.getVar('PN', True) == "libtool-cross":
        return False
    if d.getVar('PN', True) == "libgcc-initial":
        return False
    if d.getVar('PN', True) == "shadow-sysroot":
        return False

    # We just archive gcc-source for all the gcc related recipes
    if d.getVar('BPN', True) in ['gcc', 'libgcc']:
        bb.debug(1, 'spdx: There is bug in scan of %s is, do nothing' % pn)
        return False

    return True


def add_package_files(d, doc, spdx_pkg, topdir, get_spdxid, get_types, *, archive=None, ignore_dirs=[], ignore_top_level_dirs=[]):
    from pathlib import Path
    import oe_sbom.spdx
    import hashlib

    source_date_epoch = d.getVar("SOURCE_DATE_EPOCH", True)
    if source_date_epoch:
        source_date_epoch = int(source_date_epoch)

    sha1s = []
    spdx_files = []

    file_counter = 1
    for subdir, dirs, files in os.walk(str(topdir)):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        if subdir == str(topdir):
            dirs[:] = [d for d in dirs if d not in ignore_top_level_dirs]

        for file in files:
            filepath = Path(subdir) / file
            filename = str(filepath.relative_to(topdir))

            if filepath.is_file() and not filepath.is_symlink():
                spdx_file = oe_sbom.spdx.SPDXFile()
                spdx_file.SPDXID = get_spdxid(file_counter)
                for t in get_types(filepath):
                    spdx_file.fileTypes.append(t)
                spdx_file.fileName = filename

                if archive is not None:
                    with filepath.open("rb") as f:
                        info = archive.gettarinfo(fileobj=f)
                        info.name = filename
                        info.uid = 0
                        info.gid = 0
                        info.uname = "root"
                        info.gname = "root"

                        if source_date_epoch is not None and info.mtime > source_date_epoch:
                            info.mtime = source_date_epoch

                        archive.addfile(info, f)

                sha1 = bb.utils.sha1_file(str(filepath))
                sha1s.append(sha1)
                spdx_file.checksums.append(oe_sbom.spdx.SPDXChecksum(
                        algorithm="SHA1",
                        checksumValue=sha1,
                    ))
                spdx_file.checksums.append(oe_sbom.spdx.SPDXChecksum(
                        algorithm="SHA256",
                        checksumValue=bb.utils.sha256_file(str(filepath)),
                    ))

                doc.files.append(spdx_file)
                doc.add_relationship(spdx_pkg, "CONTAINS", spdx_file)
                spdx_pkg.hasFiles.append(spdx_file.SPDXID)

                spdx_files.append(spdx_file)

                file_counter += 1

    sha1s.sort()
    verifier = hashlib.sha1()
    for v in sha1s:
        verifier.update(v.encode("utf-8"))
    spdx_pkg.packageVerificationCode.packageVerificationCodeValue = verifier.hexdigest()

    return spdx_files

def add_package_sources_from_debug(d, package_doc, spdx_package, package, package_files, sources, search_paths):
    from pathlib import Path
    import hashlib
    import oe_sbom.packagedata
    import oe_sbom.spdx

    debug_search_paths = [
        Path(d.getVar('PKGD', True)),
        Path(d.getVar('STAGING_DIR_TARGET', True)),
        Path(d.getVar('STAGING_DIR_NATIVE', True)),
        Path(d.getVar('STAGING_KERNEL_DIR', True)),
    ]
    topdir = d.getVar('TOPDIR', True)
    for path in search_paths:
        debug_search_paths.append(Path(topdir + '/' + path))

    pkg_data = oe_sbom.packagedata.read_subpkgdata_extended(package, d)

    if pkg_data is None:
        return

    for file_path, file_data in pkg_data["files_info"].items():
        if not "debugsrc" in file_data:
            continue

        for pkg_file in package_files:
            if file_path.lstrip("/") == pkg_file.fileName.lstrip("/"):
                break
        else:
            bb.warn("No package file found for %s" % str(file_path))
            continue

        for debugsrc in file_data["debugsrc"]:
            ref_id = "NOASSERTION"
            for search in debug_search_paths:
                if debugsrc.startswith("/usr/src/kernel"):
                    debugsrc_path = search / debugsrc.replace('/usr/src/kernel/', '')
                else:
                    debugsrc_path = search / debugsrc.lstrip("/")
                if not debugsrc_path.exists():
                    continue

                file_sha256 = bb.utils.sha256_file(debugsrc_path)

                if file_sha256 in sources:
                    source_file = sources[file_sha256]

                    doc_ref = package_doc.find_external_document_ref(source_file.doc.documentNamespace)
                    if doc_ref is None:
                        doc_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
                        doc_ref.externalDocumentId = "DocumentRef-dependency-" + source_file.doc.name
                        doc_ref.spdxDocument = source_file.doc.documentNamespace
                        doc_ref.checksum.algorithm = "SHA1"
                        doc_ref.checksum.checksumValue = source_file.doc_sha1
                        package_doc.externalDocumentRefs.append(doc_ref)

                    ref_id = "%s:%s" % (doc_ref.externalDocumentId, source_file.file.SPDXID)
                else:
                    bb.debug(1, "Debug source %s with SHA256 %s not found in any dependency" % (str(debugsrc_path), file_sha256))
                break
            else:
                bb.debug(1, "Debug source %s not found in sources at all" % (debugsrc))

            package_doc.add_relationship(pkg_file, "GENERATED_FROM", ref_id, comment=debugsrc)

def spdx_deploy_path(d, subdir, name):
    import os.path
    import glob

    multiconfig = d.getVar('BBMULTICONFIG', True)
    deploy_dir_spdx = d.getVar('DEPLOY_DIR_SPDX', True)

    if multiconfig == '':
        return os.path.join(deploy_dir_spdx, subdir, name)

    try:
        deploy_path = glob.glob(os.path.join(deploy_dir_spdx, "..", "*", subdir, name))[0]
    except IndexError:
        # FIXME: This should not happen.
        deploy_path = ""

    return deploy_path

def collect_dep_recipes(d, doc, spdx_recipe):
    from pathlib import Path
    import oe_sbom.sbom
    import oe_sbom.spdx

    dep_recipes = []
    taskdepdata = d.getVar("BB_TASKDEPDATA", False)
    deps = sorted(set(
        dep[0] for dep in taskdepdata.values() if
            dep[1] == "do_create_spdx" and dep[0] != d.getVar("PN", True)
    ))
    for dep_pn in deps:
        dep_recipe_path = spdx_deploy_path(d, "recipes", ("recipe-%s.spdx.json" % dep_pn))
        if dep_recipe_path == '':
            # FIXME: This should not happen.
            continue
        dep_recipe_path = Path(dep_recipe_path)

        spdx_dep_doc, spdx_dep_sha1 = oe_sbom.sbom.read_doc(dep_recipe_path)

        for pkg in spdx_dep_doc.packages:
            if pkg.name == dep_pn:
                spdx_dep_recipe = pkg
                break
        else:
            continue

        dep_recipes.append(oe_sbom.sbom.DepRecipe(spdx_dep_doc, spdx_dep_sha1, spdx_dep_recipe))

        dep_recipe_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
        dep_recipe_ref.externalDocumentId = "DocumentRef-dependency-" + spdx_dep_doc.name
        dep_recipe_ref.spdxDocument = spdx_dep_doc.documentNamespace
        dep_recipe_ref.checksum.algorithm = "SHA1"
        dep_recipe_ref.checksum.checksumValue = spdx_dep_sha1

        doc.externalDocumentRefs.append(dep_recipe_ref)

        doc.add_relationship(
            "%s:%s" % (dep_recipe_ref.externalDocumentId, spdx_dep_recipe.SPDXID),
            "BUILD_DEPENDENCY_OF",
            spdx_recipe
        )

    return dep_recipes

collect_dep_recipes[vardepsexclude] += "BB_TASKDEPDATA"


def collect_dep_sources(d, dep_recipes):
    import oe_sbom.sbom

    search_paths = []
    sources = {}
    for dep in dep_recipes:
        # Don't collect sources from native recipes as they
        # match non-native sources also.
        if recipe_spdx_is_native(d, dep.recipe):
            continue
        recipe_files = set(dep.recipe.hasFiles)

        for spdx_file in dep.doc.files:
            if spdx_file.SPDXID not in recipe_files:
                continue

            if "SOURCE" in spdx_file.fileTypes:
                for checksum in spdx_file.checksums:
                    if checksum.algorithm == "SHA256":
                        sources[checksum.checksumValue] = oe_sbom.sbom.DepSource(dep.doc, dep.doc_sha1, dep.recipe, spdx_file)
                        break
        search_paths.append(get_spdxdir_from_annotation(d, dep.recipe))

    return sources, search_paths


python do_create_spdx() {
    from datetime import datetime, timezone
    import oe_sbom.sbom
    import oe_sbom.spdx
    import oe_sbom.packagedata
    import uuid
    from pathlib import Path
    from contextlib import contextmanager
    import oe_sbom.cve_check

    @contextmanager
    def optional_tarfile(name, guard, mode="w:xz"):
        import tarfile

        if guard:
            name.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(name=name, mode=mode) as f:
                yield f
        else:
            yield None

    def get_version_from_PV(PV_str):
        if '+git' in PV_str:
            return PV_str.split('+git')[0]
        else:
            return PV_str

    def get_packagegroup():
        package_bb = d.getVar("FILE", True)
        if 'recipes-' in package_bb:
            packagegroup = package_bb.split('recipes-')[1].split('/')[0]
            return packagegroup
        else:
            return 'None'

    deploy_dir_spdx = Path(d.getVar("DEPLOY_DIR_SPDX", True))
    top_dir = Path(d.getVar("TOPDIR", True))
    spdx_workdir = Path(d.getVar("SPDXWORK", True))
    include_packaged = d.getVar("SPDX_INCLUDE_PACKAGED", True) == "1"
    include_sources = d.getVar("SPDX_INCLUDE_SOURCES", True) == "1"
    archive_sources = d.getVar("SPDX_ARCHIVE_SOURCES", True) == "1"
    archive_packaged = d.getVar("SPDX_ARCHIVE_PACKAGED", True) == "1"

    creation_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc = oe_sbom.spdx.SPDXDocument()

    doc.name = "recipe-" + d.getVar("PN", True)
    doc.documentNamespace = get_doc_namespace(d, doc)
    doc.creationInfo.created = creation_time
    doc.creationInfo.comment = "This document was created by analyzing recipe files during the build."
    doc.creationInfo.licenseListVersion = d.getVar("SPDX_LICENSE_DATA", True)["licenseListVersion"]
    doc.creationInfo.creators.append("Tool: meta-wr-sbom")
    doc.creationInfo.creators.append("Organization: Wind River Systems, Inc.")

    recipe = oe_sbom.spdx.SPDXPackage()
    recipe.name = d.getVar("PN", True)
    if d.getVar("SLS_EXTEND_VERSION", True):
        recipe.versionInfo = d.getVar("PV", True) + "-" + d.getVar("SLS_EXTEND_VERSION", True)
    else:
        recipe.versionInfo = d.getVar("PV", True)
    recipe.SPDXID = oe_sbom.sbom.get_recipe_spdxid(d)
    recipe.comment = " PackageGroup: " + get_packagegroup()
    if bb.data.inherits_class("native", d) or bb.data.inherits_class("cross", d):
        recipe.annotations.append(create_annotation(d, "isNative"))
    recipe.annotations.append(create_annotation(d, "SPDXDIR:%s" % d.getVar("PKGD", True).replace(str(top_dir) +'/', '')))


    for s in d.getVar('SRC_URI', True).split():
        if not s.startswith("file://"):
            recipe.downloadLocation = s
            break
    else:
        recipe.downloadLocation = "NOASSERTION"

    homepage = d.getVar("HOMEPAGE", True)
    if homepage:
        recipe.homepage = homepage

    license = d.getVar("LICENSE", True)
    if license:
        recipe.licenseDeclared = convert_license_to_spdx(license, doc, d)

    summary = d.getVar("SUMMARY", True)
    if summary:
        recipe.summary = summary

    description = d.getVar("DESCRIPTION", True)
    if description:
        recipe.description = description

    # Some CVEs may be patched during the build process without incrementing the version number,
    # so querying for CVEs based on the CPE id can lead to false positives. To account for this,
    # save the CVEs fixed by patches to source information field in the SPDX.
    patched_cves = oe_sbom.cve_check.get_patched_cves(d)
    patched_cves = list(patched_cves)
    patched_cves = ' '.join(patched_cves)
    if patched_cves:
        recipe.sourceInfo = "CVEs fixed: " + patched_cves

    cpe_ids = oe_sbom.cve_check.get_cpe_ids(d.getVar("CVE_PRODUCT", True), d.getVar("CVE_VERSION", True))
    if cpe_ids:
        for cpe_id in cpe_ids:
            cpe = oe_sbom.spdx.SPDXExternalReference()
            cpe.referenceCategory = "SECURITY"
            cpe.referenceType = "cpe23Type"
            cpe.referenceLocator = cpe_id
            recipe.externalRefs.append(cpe)

    doc.packages.append(recipe)
    doc.add_relationship(doc, "DESCRIBES", recipe)

    if process_sources(d) and include_sources:
        recipe_archive = deploy_dir_spdx / "recipes" / (doc.name + ".tar.xz")
        with optional_tarfile(recipe_archive, archive_sources) as archive:
            spdx_get_src(d)

            add_package_files(
                d,
                doc,
                recipe,
                spdx_workdir,
                lambda file_counter: "SPDXRef-SourceFile-%s-%d" % (d.getVar("PN", True), file_counter),
                lambda filepath: ["SOURCE"],
                ignore_dirs=[".git"],
                ignore_top_level_dirs=["temp"],
                archive=archive,
            )

            if archive is not None:
                recipe.packageFileName = str(recipe_archive.name)

    dep_recipes = collect_dep_recipes(d, doc, recipe)

    doc_sha1 = oe_sbom.sbom.write_doc(d, doc, "recipes")
    dep_recipes.append(oe_sbom.sbom.DepRecipe(doc, doc_sha1, recipe))

    recipe_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
    recipe_ref.externalDocumentId = "DocumentRef-recipe-" + recipe.name
    recipe_ref.spdxDocument = doc.documentNamespace
    recipe_ref.checksum.algorithm = "SHA1"
    recipe_ref.checksum.checksumValue = doc_sha1

    sources, search_paths = collect_dep_sources(d, dep_recipes)
    found_licenses = {license.name:recipe_ref.externalDocumentId + ":" + license.licenseId for license in doc.hasExtractedLicensingInfos}

    if not recipe_spdx_is_native(d, recipe):
        bb.build.exec_func("read_subpackage_metadata", d)

        pkgdest = Path(d.getVar("PKGDEST", True))
        for package in d.getVar("PACKAGES", True).split():
            if not oe_sbom.packagedata.packaged(package, d):
                continue

            package_doc = oe_sbom.spdx.SPDXDocument()

            pkg_name = get_final_pkg_name(d, package)

            package_doc.name = pkg_name
            package_doc.documentNamespace = get_doc_namespace(d, package_doc)
            package_doc.creationInfo.created = creation_time
            package_doc.creationInfo.comment = "This document was created by analyzing packages created during the build."
            package_doc.creationInfo.licenseListVersion = d.getVar("SPDX_LICENSE_DATA", True)["licenseListVersion"]
            package_doc.creationInfo.creators.append("Tool: meta-wr-sbom")
            package_doc.creationInfo.creators.append("Organization: Wind River Systems, Inc.")
            package_doc.externalDocumentRefs.append(recipe_ref)

            package_license = d.getVar("LICENSE:%s" % package, True) or d.getVar("LICENSE", True)

            spdx_package = oe_sbom.spdx.SPDXPackage()

            spdx_package.SPDXID = oe_sbom.sbom.get_package_spdxid(pkg_name)
            spdx_package.name = pkg_name
            spdx_package.versionInfo = d.getVar("PV", True)
            spdx_package.licenseDeclared = convert_license_to_spdx(package_license, package_doc, d, found_licenses)

            pn = d.getVar('PN', True)
            annotations = []
            annotations.extend(generate_origin_annotation(d, pn, pkg_name))
            annotations.extend(generate_validuntil_annotation(d, pn, pkg_name))
            annotations.extend(generate_eos_annotation(d, pn, pkg_name))
            if annotations:
                spdx_package.annotations.extend(annotations)

            package_doc.packages.append(spdx_package)

            package_doc.add_relationship(spdx_package, "GENERATED_FROM", "%s:%s" % (recipe_ref.externalDocumentId, recipe.SPDXID))
            package_doc.add_relationship(package_doc, "DESCRIBES", spdx_package)

            package_archive = deploy_dir_spdx / "packages" / (package_doc.name + ".tar.xz")
            with optional_tarfile(package_archive, archive_packaged) as archive:
                package_files = add_package_files(
                    d,
                    package_doc,
                    spdx_package,
                    str(pkgdest / package),
                    lambda file_counter: oe_sbom.sbom.get_packaged_file_spdxid(pkg_name, file_counter),
                    lambda filepath: ["BINARY"],
                    ignore_dirs=['CONTROL', 'DEBIAN'],
                    archive=archive,
                )

                if archive is not None:
                    spdx_package.packageFileName = str(package_archive.name)

            add_package_sources_from_debug(d, package_doc, spdx_package, package, package_files, sources, search_paths)

            oe_sbom.sbom.write_doc(d, package_doc, "packages")
}
# NOTE: depending on do_unpack is a hack that is necessary to get it's dependencies for archive the source
addtask do_create_spdx after do_package do_packagedata do_unpack before do_build do_rm_work

SSTATETASKS += "do_create_spdx"
do_create_spdx[sstate-inputdirs] = "${SPDXDEPLOY}"
do_create_spdx[sstate-outputdirs] = "${DEPLOY_DIR_SPDX}"
do_create_spdx[sstate-lockfile] = "${WORKDIR}/create_spdx_sstate.lock"

python do_create_spdx_setscene () {
    sstate_setscene(d)
}
addtask do_create_spdx_setscene

do_create_spdx[dirs] = "${SPDXWORK}"
do_create_spdx[cleandirs] = "${SPDXDEPLOY} ${SPDXWORK}"
do_create_spdx[depends] += "${PATCHDEPENDENCY}"
do_create_spdx[deptask] = "do_create_spdx"
do_create_spdx[lockfiles] = "${SPDXWORK}/create_spdx.lock"

# Add the package specific ORIGINs, VALIDUNTILDATEs and EOSs to the sstate dependencies
python () {
    pkgs = (d.getVar('PACKAGES') or '').split()
    for pkg in pkgs:
        d.appendVarFlag("do_create_spdx", "vardeps", " ORIGIN:{}".format(pkg))
        d.appendVarFlag("do_create_spdx", "vardeps", " VALIDUNTILDATE:{}".format(pkg))
        d.appendVarFlag("do_create_spdx", "vardeps", " EOS:{}".format(pkg))
}

do_create_spdx[vardeps] += "ORIGIN:DEFAULT VALIDUNTILDATE:DEFAULT EOS:DEFAULT"

def spdx_disable_task(d, task):
    pn = d.getVar('PN', True)
    is_native = bb.data.inherits_class('native', d) or pn.endswith('-native')
    is_blocked = pn in d.getVar('SPDX_BLACKLIST', True).split()
    current_mc = d.getVar('BB_CURRENT_MC', True)

    if (is_native and current_mc != '') or is_blocked:
        d.setVarFlag(task, 'noexec', '1')

python () {
    spdx_disable_task(d, 'do_create_spdx')
}

def collect_package_providers(d):
    from pathlib import Path
    import oe_sbom.sbom
    import oe_sbom.spdx
    import json

    deploy_dir_spdx = Path(d.getVar("DEPLOY_DIR_SPDX", True))

    providers = {}

    taskdepdata = d.getVar("BB_TASKDEPDATA", False)
    deps = sorted(set(
        dep[0] for dep in taskdepdata.values() if dep[0] != d.getVar("PN", True)
    ))
    deps.append(d.getVar("PN", True))

    for dep_pn in deps:
        recipe_data = oe_sbom.packagedata.read_pkgdata(dep_pn, d)

        for pkg in recipe_data.get("PACKAGES", "").split():

            pkg_data = oe_sbom.packagedata.read_subpkgdata_dict(pkg, d)
            rprovides = set(n for n, _ in bb.utils.explode_dep_versions2(pkg_data.get("RPROVIDES", "")).items())
            rprovides.add(pkg)

            for r in rprovides:
                providers[r] = pkg

    return providers

collect_package_providers[vardepsexclude] += "BB_TASKDEPDATA"

python do_create_runtime_spdx() {
    from datetime import datetime, timezone
    import oe_sbom.sbom
    import oe_sbom.spdx
    import oe_sbom.packagedata
    from pathlib import Path

    deploy_dir_spdx = Path(d.getVar("DEPLOY_DIR_SPDX", True))
    spdx_deploy = Path(d.getVar("SPDXRUNTIMEDEPLOY", True))
    is_native = bb.data.inherits_class("native", d) or bb.data.inherits_class("cross", d)

    creation_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    providers = collect_package_providers(d)

    if not is_native:
        bb.build.exec_func("read_subpackage_metadata", d)

        dep_package_cache = {}

        pkgdest = Path(d.getVar("PKGDEST", True))
        for package in d.getVar("PACKAGES", True).split():
            localdata = bb.data.createCopy(d)

            pkg_name = get_final_pkg_name(d, package)

            localdata.setVar("PKG", pkg_name)
            localdata.setVar('OVERRIDES', d.getVar("OVERRIDES", False) + ":" + package)

            if not oe_sbom.packagedata.packaged(package, localdata):
                continue

            pkg_spdx_path = deploy_dir_spdx / "packages" / (pkg_name + ".spdx.json")

            package_doc, package_doc_sha1 = oe_sbom.sbom.read_doc(pkg_spdx_path)

            for p in package_doc.packages:
                if p.name == pkg_name:
                    spdx_package = p
                    break
            else:
                bb.warn("Package '%s' not found in %s" % (pkg_name, pkg_spdx_path))
                spdx_package = oe_sbom.spdx.SPDXPackage()
                spdx_package.SPDXID = ' '

            runtime_doc = oe_sbom.spdx.SPDXDocument()
            runtime_doc.name = "runtime-" + pkg_name
            runtime_doc.documentNamespace = get_doc_namespace(localdata, runtime_doc)
            runtime_doc.creationInfo.created = creation_time
            runtime_doc.creationInfo.comment = "This document was created by analyzing package runtime dependencies."
            runtime_doc.creationInfo.licenseListVersion = d.getVar("SPDX_LICENSE_DATA", True)["licenseListVersion"]
            runtime_doc.creationInfo.creators.append("Tool: meta-wr-sbom")
            runtime_doc.creationInfo.creators.append("Organization: Wind River Systems, Inc.")

            package_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
            package_ref.externalDocumentId = "DocumentRef-package-" + package
            package_ref.spdxDocument = package_doc.documentNamespace
            package_ref.checksum.algorithm = "SHA1"
            package_ref.checksum.checksumValue = package_doc_sha1

            runtime_doc.externalDocumentRefs.append(package_ref)

            runtime_doc.add_relationship(
                runtime_doc.SPDXID,
                "AMENDS",
                "%s:%s" % (package_ref.externalDocumentId, package_doc.SPDXID)
            )

            deps = bb.utils.explode_dep_versions2(localdata.getVar("RDEPENDS", True) or "")
            seen_deps = set()
            for dep, _ in deps.items():
                if dep in seen_deps:
                    continue

                if dep not in providers.keys():
                    continue

                dep = providers[dep]

                if not oe_sbom.packagedata.packaged(dep, localdata):
                    continue

                dep_pkg_data = oe_sbom.packagedata.read_subpkgdata_dict(dep, d)
                dep_pkg = dep_pkg_data["PKG"]

                if dep in dep_package_cache:
                    (dep_spdx_package, dep_package_ref) = dep_package_cache[dep]
                else:
                    dep_path = deploy_dir_spdx / "packages" / ("%s.spdx.json" % dep_pkg)

                    if not os.path.exists(str(dep_path)):
                        continue

                    spdx_dep_doc, spdx_dep_sha1 = oe_sbom.sbom.read_doc(dep_path)

                    for pkg in spdx_dep_doc.packages:
                        if pkg.name == dep_pkg:
                            dep_spdx_package = pkg
                            break
                    else:
                        bb.warn("Package '%s' not found in %s" % (dep_pkg, dep_path))
                        dep_spdx_package = oe_sbom.spdx.SPDXPackage()
                        dep_spdx_package.SPDXID = ' '

                    dep_package_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
                    dep_package_ref.externalDocumentId = "DocumentRef-runtime-dependency-" + spdx_dep_doc.name
                    dep_package_ref.spdxDocument = spdx_dep_doc.documentNamespace
                    dep_package_ref.checksum.algorithm = "SHA1"
                    dep_package_ref.checksum.checksumValue = spdx_dep_sha1

                    dep_package_cache[dep] = (dep_spdx_package, dep_package_ref)

                runtime_doc.externalDocumentRefs.append(dep_package_ref)

                runtime_doc.add_relationship(
                    "%s:%s" % (dep_package_ref.externalDocumentId, dep_spdx_package.SPDXID),
                    "RUNTIME_DEPENDENCY_OF",
                    "%s:%s" % (package_ref.externalDocumentId, spdx_package.SPDXID)
                )
                seen_deps.add(dep)

            oe_sbom.sbom.write_doc(d, runtime_doc, "runtime", spdx_deploy)
}

addtask do_create_runtime_spdx after do_create_spdx before do_build do_rm_work
SSTATETASKS += "do_create_runtime_spdx"
do_create_runtime_spdx[sstate-inputdirs] = "${SPDXRUNTIMEDEPLOY}"
do_create_runtime_spdx[sstate-outputdirs] = "${DEPLOY_DIR_SPDX}"
do_create_runtime_spdx[sstate-lockfile] = "${WORKDIR}/create_runtime_spdx_sstate.lock"

python do_create_runtime_spdx_setscene () {
    sstate_setscene(d)
}
addtask do_create_runtime_spdx_setscene

do_create_runtime_spdx[dirs] = "${SPDXRUNTIMEDEPLOY}"
do_create_runtime_spdx[cleandirs] = "${SPDXRUNTIMEDEPLOY}"
do_create_runtime_spdx[rdeptask] = "do_create_spdx"
do_create_runtime_spdx[lockfiles] = "${SPDXRUNTIMEDEPLOY}/create_runtime_spdx.lock"

python () {
    spdx_disable_task(d, 'do_create_runtime_spdx')
}

def spdx_get_src(d):
    """
    save patched source of the recipe in SPDX_WORKDIR.
    """
    import shutil
    spdx_workdir = d.getVar('SPDXWORK', True)
    spdx_sysroot_native = d.getVar('STAGING_DIR_NATIVE', True)
    pn = d.getVar('PN', True)

    workdir = d.getVar("WORKDIR", True)

    try:
        # The kernel class functions require it to be on work-shared, so we dont change WORKDIR
        if not is_work_shared_spdx(d):
            # Change the WORKDIR to make do_unpack do_patch run in another dir.
            d.setVar('WORKDIR', spdx_workdir)
            # Restore the original path to recipe's native sysroot (it's relative to WORKDIR).
            d.setVar('STAGING_DIR_NATIVE', spdx_sysroot_native)

            # The changed 'WORKDIR' also caused 'B' changed, create dir 'B' for the
            # possibly requiring of the following tasks (such as some recipes's
            # do_patch required 'B' existed).
            bb.utils.mkdirhier(d.getVar('B', True))

            bb.build.exec_func('do_unpack', d)
        # Copy source of kernel to spdx_workdir
        if is_work_shared_spdx(d):
            d.setVar('WORKDIR', spdx_workdir)
            d.setVar('STAGING_DIR_NATIVE', spdx_sysroot_native)
            src_dir = spdx_workdir + "/" + d.getVar('PN', True)+ "-" + d.getVar('PV', True) + "-" + d.getVar('PR', True)
            bb.utils.mkdirhier(src_dir)
            if bb.data.inherits_class('kernel',d):
                share_src = d.getVar('STAGING_KERNEL_DIR', True)
            else:
                share_src = d.getVar('S', True)
            cmd_copy_share = "cp -rf " + share_src + "/* " + src_dir + "/"
            cmd_copy_kernel_result = os.popen(cmd_copy_share).read()
            bb.note("cmd_copy_kernel_result = " + cmd_copy_kernel_result)

            git_path = src_dir + "/.git"
            if os.path.exists(git_path):
                shutils.rmtree(git_path)

        # Make sure gcc and kernel sources are patched only once
        if not (d.getVar('SRC_URI', True) == "" or is_work_shared_spdx(d)):
            bb.build.exec_func('do_patch', d)

        # Some userland has no source.
        if not os.path.exists( spdx_workdir ):
            bb.utils.mkdirhier(spdx_workdir)
    finally:
        d.setVar("WORKDIR", workdir)

do_rootfs[recrdeptask] += "do_create_spdx do_create_runtime_spdx"

ROOTFS_POSTUNINSTALL_COMMAND =+ "image_packages_spdx ; "

def get_yocto_codename(version):
    yocto_version_to_codename = {"4.1": "Langdale", "4.0": "Kirkstone", "3.4": "Honister", "3.3": "Hardknott", "3.2": "Gatesgarth", "3.1": "Dunfell", "3.0": "Zeus", "2.7": "Warrior", "2.6": "Thud", "2.5": "Sumo", "2.4": "Rocko", "2.3": "Pyro", "2.2": "Morty", "2.1": "Krogoth", "2.0": "Jethro", "1.8": "Fido", "1.7": "Dizzy", "1.6": "Daisy", "1.5": "Dora", "1.4": "Dylan", "1.3": "Danny", "1.2": "Denzil", "1.1": "Edison", "1.0": "Bernard", "0.9": "Laverne"}

    for ver in yocto_version_to_codename.keys():
        if len(ver) > len(version):
            continue
        if ver == version[:len(ver)]:
            return yocto_version_to_codename[ver]

def get_yocto_version(bitbake_version):
    bb_version_to_yocto_version = {"2.2": "4.1", "2.0": "4.0", "1.52": "3.4", "1.50": "3.3", "1.48": "3.2", "1.46": "3.1", "1.44": "3.0", "1.42": "2.7", "1.40": "2.6", "1.38": "2.5", "1.36": "2.4", "1.34": "2.3", "1.32": "2.2", "1.30": "2.1", "1.28": "2.0", "1.26": "1.8", "1.24": "1.7", "1.22": "1.6", "1.20": "1.5", "1.18": "1.4", "1.18": "1.4", "1.16": "1.3"}

    bb_ver = bitbake_version.split('.')
    return bb_version_to_yocto_version[bb_ver[0]+'.'+bb_ver[1]]

def make_image_link(imgdeploydir, image_link_name, target_path, suffix):
    link = imgdeploydir / (image_link_name + suffix)
    if link.exists():
        os.remove(str(link))
    link.symlink_to(os.path.relpath(str(target_path), str(link.parent)))

def replace_name(name, substitutes):
    if name in substitutes.keys():
        return substitutes[name]
    else:
        return name

def is_CPE_on(d):
    return d.getVar('SBOM_CPE', True) == "1"

def is_PURL_on(d):
    return d.getVar('SBOM_PURL', True) == "1"

def is_license_on(d):
    return d.getVar('SBOM_license', True) == "1"

def is_externalDocumentRefs_on(d):
    return d.getVar('SBOM_externalDocumentRefs', True) == "1"

python image_packages_spdx() {
    import os
    import re
    import oe_sbom.spdx
    import oe_sbom.sbom
    from oe.rootfs import image_list_installed_packages
    from datetime import timezone, datetime
    from pathlib import Path

    recipe_substitutes = {}
    # replace it because CVE datasource use another package name
    recipe_substitutes["linux-yocto"] = "linux"

    distro_substitues = {}
    for distro in (d.getVar('SBOM_WRLINUX_DISTROS', True) or "").split():
        distro_substitues[distro] = "wrlinux"

    def get_pkgdata(pkg_name):
        import oe.packagedata

        pkgdata_path = os.path.join(d.getVar('PKGDATA_DIR', True), 'runtime-reverse', pkg_name)
        pkgdata = oe.packagedata.read_pkgdatafile(pkgdata_path)
        return pkgdata

    def ltss_version_validate(ltss_version):
        ltss_version_restrict = ['WRL.LTS.5.0.1', 'WRL.LTS.6.0', 'WRL.LTS.7.0', 'WRL.LTS.8.0', 'WRL.LTS.9.0', 'WRL.LTS.17', 'WRL.LTS.18', 'WRL.LTS.19']
        if ltss_version in ltss_version_restrict:
            return True
        else:
            return False

    def collect_lics(pattern, lic_string, results):
        lic_ids = re.findall(pattern, lic_string)
        for lic_id in lic_ids:
            if lic_id not in results.keys():
                results[lic_id] = {}

    def clear_spdxid_improper_char(s):
        return re.sub('[^a-zA-Z0-9.-:]', '-', s)

    creation_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    image_name = d.getVar("IMAGE_NAME", True)
    image_link_name = d.getVar("IMAGE_LINK_NAME", True)

    deploy_dir_spdx = Path(d.getVar("DEPLOY_DIR_SPDX", True))
    imgdeploydir = Path(d.getVar("IMGDEPLOYDIR", True))
    source_date_epoch = d.getVar("SOURCE_DATE_EPOCH", True)

    doc = oe_sbom.spdx.SPDXDocument()
    doc.name = image_name
    doc.documentNamespace = get_doc_namespace(d, doc)
    doc.creationInfo.created = creation_time
    doc.creationInfo.comment = "This document was created by collecting packages built into image."
    doc.creationInfo.licenseListVersion = d.getVar("SPDX_LICENSE_DATA", True)["licenseListVersion"]
    doc.creationInfo.creators.append("Tool: meta-wr-sbom")
    doc.creationInfo.creators.append("Organization: Wind River Systems, Inc.")
    if 'Yocto' in d.getVar("DISTRO_NAME", True):
        doc.comment = "DISTRO: " + "Yocto-" + get_yocto_codename(d.getVar("DISTRO_VERSION", True)) + "-" + d.getVar("DISTRO_VERSION", True)
        image_supplier = "Organization: OpenEmbedded ()"
    elif 'Wind River' in d.getVar("DISTRO_NAME", True):
        doc.comment = "DISTRO: " + "WRLinux-" + d.getVar("DISTRO_VERSION", True)
        image_supplier = "Organization: Wind River Systems, Inc."
    else:
        wr_version = d.getVar("WRLINUX_VERSION", True)
        if wr_version:
            doc.comment = "DISTRO: " + "WRLinux-" + wr_version
            image_supplier = "Organization: Wind River Systems, Inc."
        else:
            bb_version = d.getVar("BB_VERSION", True)
            yocto_version = get_yocto_version(bb_version)
            doc.comment = "DISTRO: " + "Yocto-" + get_yocto_codename(yocto_version) + "-" + yocto_version
            image_supplier = "Organization: OpenEmbedded ()"

        D_name = d.getVar("DISTRO_NAME", True).strip().replace(" ", "_")
        if D_name:
            doc.comment += "  CUSTOMIZED_DISTRO: " + D_name + '-' + d.getVar("DISTRO_VERSION", True)
        else:
            doc.comment += "  CUSTOMIZED_DISTRO: Unknown-" + d.getVar("DISTRO_VERSION", True)
    doc.comment += "  ARCH: " + d.getVar("MACHINE_ARCH", True)
    doc.comment += "  PROJECT_LABELS: " + str(d.getVar("PROJECT_LABELS", True))
    doc.comment += "  PROJECT_RELEASETIME: " + str(d.getVar("PROJECT_RELEASETIME", True))

    ltss_version = d.getVar("LTSS_VERSION", True)
    if ltss_version:
        if ltss_version_validate(ltss_version):
            doc.comment += "  LTSS_VERSION: " + str(d.getVar("LTSS_VERSION", True))
        else:
            doc.comment += "  LTSS_VERSION: mismatch"
            bb.warn("LTSS_VERSION value is not in the regular list.")
    doc.documentDescribes.append("SPDXRef-Image-" + d.getVar("IMAGE_NAME", True))

    image = oe_sbom.spdx.SPDXPackage()
    image.name = d.getVar("PN", True)
    image.versionInfo = d.getVar("EXTENDPKGV", True)
    image.SPDXID = clear_spdxid_improper_char(oe_sbom.sbom.get_image_spdxid(image_name))
    image.supplier = image_supplier

    doc.packages.append(image)

    os_package = oe_sbom.spdx.SPDXPackage()
    os_package.name, os_package.versionInfo = get_distro_type(d)
    os_package.SPDXID = clear_spdxid_improper_char(oe_sbom.sbom.get_os_spdxid(image_name))
    os_package.supplier = image_supplier

    doc.packages.append(os_package)

    doc.add_relationship(doc, "DESCRIBES", "%s" % image.SPDXID)
    doc.add_relationship(image, "CONTAINS", "%s" % os_package.SPDXID)

    spdx_package = oe_sbom.spdx.SPDXPackage()

    packages = image_list_installed_packages(d)
    recipes = {}
    externaldocrefs = set()
    user_defined_licenses = {}
    user_defined_licenses_extracted = {}
    pattern_docref_recipe = r'DocumentRef-recipe-.*\:'
    pattern_licref = r'LicenseRef-[a-zA-Z0-9.-]+'

    def collect_dep_relationships(spdx_file_path, relationship_type):
        spdx_doc, spdx_doc_sha1 = oe_sbom.sbom.read_doc(spdx_file_path)

        for r in spdx_doc.relationships:
            if r.relationshipType == relationship_type:
                if relationship_type == "RUNTIME_DEPENDENCY_OF":
                    r.relatedSpdxElement = clear_spdxid_improper_char(r.relatedSpdxElement.split(":")[1])
                    # the runtime depend packages Ref must exists in local doc
                    r.spdxElementId = clear_spdxid_improper_char(r.spdxElementId.split(":")[1])
                    doc.relationships.append(r)

                    continue

                elif relationship_type == "BUILD_DEPENDENCY_OF":
                    r.relatedSpdxElement = clear_spdxid_improper_char("%s:%s" % (r.relatedSpdxElement.replace('SPDXRef-Recipe', 'DocumentRef-recipe'), r.relatedSpdxElement))
                    related_doc_ref = r.spdxElementId.split(":")[0]
                    r.spdxElementId = clear_spdxid_improper_char(r.spdxElementId.replace("dependency-", ""))
                    for chk_dup in doc.relationships:
                        if chk_dup.spdxElementId == r.spdxElementId and chk_dup.relatedSpdxElement == r.relatedSpdxElement:
                            break
                    else:
                        doc.relationships.append(r)
                elif relationship_type == "GENERATED_FROM":
                    if r.spdxElementId.startswith("SPDXRef-Package-"):
                        related_doc_ref = r.relatedSpdxElement.split(":")[0]
                        r.relatedSpdxElement = clear_spdxid_improper_char(r.relatedSpdxElement)
                        r.spdxElementId = clear_spdxid_improper_char(r.spdxElementId)
                        doc.relationships.append(r)

                for ed in spdx_doc.externalDocumentRefs:
                    if ed.externalDocumentId == related_doc_ref:
                        ed.externalDocumentId = clear_spdxid_improper_char(ed.externalDocumentId.replace("dependency-", ""))
                        if ed.externalDocumentId not in externaldocrefs:
                            doc.externalDocumentRefs.append(ed)
                            externaldocrefs.add(ed.externalDocumentId)
                        break

    kernel_recipe = d.getVar("PREFERRED_PROVIDER_virtual/kernel", True)

    for name in sorted(packages.keys()):
        # Keep only one kernel package, filter out module packages.
        pkgdata = get_pkgdata(name)
        if pkgdata["PN"] == kernel_recipe:
            if kernel_recipe in recipes.keys():
                continue

        pkg_spdx_path = deploy_dir_spdx / "packages" / (name + ".spdx.json")
        rcp_spdx_path = deploy_dir_spdx / "recipes" / ("recipe-" + pkgdata["PN"] + ".spdx.json")
        runtime_pkg_spdx_path = deploy_dir_spdx / "runtime" / ("runtime-" + name + ".spdx.json")
        if not os.path.exists(str(pkg_spdx_path)):
            bb.warn("Unable to find package SPDX file %s" %  pkg_spdx_path)
            continue
        pkg_doc, pkg_doc_sha1 = oe_sbom.sbom.read_doc(pkg_spdx_path)

        for p in pkg_doc.packages:
            if p.name == name:
                pkg_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
                pkg_ref.externalDocumentId = clear_spdxid_improper_char("DocumentRef-package-%s" % pkg_doc.name)
                pkg_ref.spdxDocument = pkg_doc.documentNamespace
                pkg_ref.checksum.algorithm = "SHA1"
                pkg_ref.checksum.checksumValue = pkg_doc_sha1

                if is_externalDocumentRefs_on(d):
                    doc.externalDocumentRefs.append(pkg_ref)

                doc.add_relationship("%s" % os_package.SPDXID, "CONTAINS", "%s" % clear_spdxid_improper_char(p.SPDXID))
                collect_dep_relationships(pkg_spdx_path, "GENERATED_FROM")
                collect_dep_relationships(rcp_spdx_path, "BUILD_DEPENDENCY_OF")
                if not pkgdata["PN"] == kernel_recipe:
                    collect_dep_relationships(runtime_pkg_spdx_path, "RUNTIME_DEPENDENCY_OF")

                component_package = oe_sbom.spdx.SPDXPackage()
                component_package.name = p.name
                if pkgdata["PN"] == kernel_recipe:
                    component_package.name = "kernel"
                component_package.SPDXID = clear_spdxid_improper_char(p.SPDXID)

                if (not "PR" in pkgdata.keys()) or (not pkgdata["PR"]):
                    component_package.versionInfo = pkgdata["PV"]
                else:
                    component_package.versionInfo = pkgdata["PV"] + "-" + pkgdata["PR"]

                # Use downloadLocation from package spdx file, because downloadLocation
                # from recipe spdx file may refers to local path
                component_package.downloadLocation = p.downloadLocation

                if is_license_on(d):
                    # Not use license from recipe spdx file because it combine multiple
                    # package licenses into one, it is wrong for package.
                    # Use license from package spdx file may bring "DocumentRef"
                    # into licenseDeclared and licenseConcluded, it violates the spdx
                    # standard, so remove "DocumentRef"
                    component_package.licenseConcluded = re.sub(pattern_docref_recipe, "", p.licenseConcluded)
                    collect_lics(pattern_licref, component_package.licenseConcluded, user_defined_licenses)
                    component_package.licenseDeclared = re.sub(pattern_docref_recipe, "", p.licenseDeclared)
                    collect_lics(pattern_licref, component_package.licenseDeclared, user_defined_licenses)

                component_package.copyrightText = p.copyrightText
                component_package.supplier = "Organization: OpenEmbedded ()"
                source_name = replace_name(pkgdata["PN"], recipe_substitutes)
                component_package.sourceInfo = "built package from: " + source_name + " " + component_package.versionInfo

                if os.path.exists(str(rcp_spdx_path)):
                    rcp_doc, rcp_doc_sha1 = oe_sbom.sbom.read_doc(rcp_spdx_path)
                    recipe_info = rcp_doc.packages[0]
                    try:
                        component_package.comment = recipe_info.sourceInfo
                    except KeyError:
                        pass
                else:
                    bb.warn("Unable to find package SPDX file %s" %  rcp_spdx_path)

                if pkgdata["PN"] not in recipes.keys():
                    recipes[pkgdata["PN"]] = []
                recipes[pkgdata["PN"]].append(p.SPDXID)

                if is_PURL_on(d):
                    purl = oe_sbom.spdx.SPDXExternalReference()
                    purl.referenceCategory = "PACKAGE-MANAGER"
                    purl.referenceType = "purl"
                    purl.referenceLocator = ("pkg:rpm/" + os_package.name + "/" +
                        component_package.name + "@" + component_package.versionInfo +
                        "?arch=" + d.getVar("MACHINE_ARCH", True) + "&distro=" + os_package.name + "-" + os_package.versionInfo)
                    if d.getVar("PROJECT_LABELS", True):
                        purl.referenceLocator += "&labels=" + str(d.getVar("PROJECT_LABELS", True))
                    if d.getVar("LTSS_VERSION", True):
                        purl.referenceLocator += "&ltssVersion=" + str(d.getVar("LTSS_VERSION", True))
                    component_package.externalRefs.append(purl)

                doc.packages.append(component_package)
                break
            else:
                bb.warn("Unable to find package with name '%s' in SPDX file %s" % (name, pkg_spdx_path))

    if is_license_on(d) or is_CPE_on(d):
        for name in recipes.keys():
            recipe_spdx_path = deploy_dir_spdx / "recipes" / ("recipe-" + name + ".spdx.json")
            if os.path.exists(str(recipe_spdx_path)):
                recipe_doc, recipe_doc_sha1 = oe_sbom.sbom.read_doc(recipe_spdx_path)
                if is_license_on(d):
                    # append other licensing information detected section
                    for licensingInfo in recipe_doc.hasExtractedLicensingInfos:
                        if (licensingInfo.licenseId in user_defined_licenses.keys() and
                            licensingInfo.licenseId not in user_defined_licenses_extracted.keys()):
                            doc.hasExtractedLicensingInfos.append(licensingInfo)
                            user_defined_licenses_extracted[licensingInfo.licenseId] = {}

                if is_CPE_on(d):
                    # append CPEs
                    for package_r in recipe_doc.packages:
                        for externalRef in package_r.externalRefs:
                            if externalRef.referenceCategory == "SECURITY":
                                for package in doc.packages:
                                    if package.SPDXID in recipes[name]:
                                        package.externalRefs.append(externalRef)

    image_spdx_path = imgdeploydir / (image_name + ".spdx.json")

    with image_spdx_path.open("wb") as f:
        doc.to_json(f, sort_keys=True)

    make_image_link(imgdeploydir, image_link_name, image_spdx_path, ".spdx.json")
}
