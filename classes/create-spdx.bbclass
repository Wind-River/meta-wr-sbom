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

do_image_complete[depends] = "virtual/kernel:do_create_spdx"

def get_doc_namespace(d, doc):
    import uuid
    namespace_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, d.getVar(u"SPDX_UUID_NAMESPACE", True))
    return u"%s/%s-%s" % (d.getVar(u"SPDX_NAMESPACE_PREFIX", True), doc.name, unicode(uuid.uuid5(namespace_uuid, doc.name)))

def create_annotation(d, comment):
    from datetime import datetime, timezone
    import oe_sbom.spdx

    creation_time = datetime.now(tz=timezone.utc).strftime(u"%Y-%m-%dT%H:%M:%SZ")
    annotation = oe_sbom.spdx.SPDXAnnotation()
    annotation.annotationDate = creation_time
    annotation.annotationType = u"OTHER"
    annotation.annotator = u"Tool: %s - %s" % (d.getVar(u"SPDX_TOOL_NAME", True), d.getVar(u"SPDX_TOOL_VERSION", True))
    annotation.comment = comment
    return annotation

def recipe_spdx_is_native(d, recipe):
    return any(a.annotationType == u"OTHER" and
      a.annotator == u"Tool: %s - %s" % (d.getVar(u"SPDX_TOOL_NAME", True), d.getVar(u"SPDX_TOOL_VERSION", True)) and
      a.comment == u"isNative" for a in recipe.annotations)

def get_spdxdir_from_annotation(d, recipe):
    for a in recipe.annotations:
        if (a.annotationType == u"OTHER" and
          a.annotator == u"Tool: %s - %s" % (d.getVar(u"SPDX_TOOL_NAME", True), d.getVar(u"SPDX_TOOL_VERSION", True)) and
          a.comment.startswith(u"SPDXDIR:")):
              return a.comment.replace(u'SPDXDIR:', u'')

def is_work_shared_spdx(d):
    return bb.data.inherits_class(u'kernel', d) or (u'work-shared' in d.getVar(u'WORKDIR', True))

python() {
    #from __future__ import with_statement
    #from __future__ import division
    #from __future__ import absolute_import
    from io import open
    import json
    if d.getVar(u"SPDX_LICENSE_DATA", True):
        return

    with open(d.getVar(u"SPDX_LICENSES", True), u"r") as f:
        data = json.load(f)
        # Transform the license array to a dictionary
        data[u"licenses"] = dict((l[u"licenseId"], l) for l in data[u"licenses"])
        d.setVar(u"SPDX_LICENSE_DATA", data)
}

def convert_license_to_spdx(lic, document, d, existing={}):
    from pathlib import Path
    import oe_sbom.spdx

    available_licenses = d.getVar(u"AVAILABLE_LICENSES", True).split()
    license_data = d.getVar(u"SPDX_LICENSE_DATA", True)
    extracted = {}

    def add_extracted_license(ident, name, document):

        if name in extracted:
            return

        extracted_info = oe_sbom.spdx.SPDXExtractedLicensingInfo()
        extracted_info.name = name
        extracted_info.licenseId = ident
        extracted_info.extractedText = None

        if name == u"PD":
            # Special-case this.
            extracted_info.extractedText = u"Software released to the public domain"
        elif name in available_licenses:
            # This license can be found in COMMON_LICENSE_DIR or LICENSE_PATH
            for directory in [d.getVar(u'COMMON_LICENSE_DIR', True)] + d.getVar(u'LICENSE_PATH', True).split():
                try:
                    with (Path(directory) / name).open(errors=u"replace") as f:
                        extracted_info.extractedText = f.read()
                        break
                except FileNotFoundError:
                    pass
            if extracted_info.extractedText is None:
                # Error out, as the license was in available_licenses so should
                # be on disk somewhere.
                bb.error(u"Cannot find text for license %s" % name)
        else:
            # If it's not SPDX, or PD, or in available licenses, then NO_GENERIC_LICENSE must be set
            filename = d.getVarFlag(u'NO_GENERIC_LICENSE', name)
            if filename:
                filename = d.expand(u"${S}/" + filename)
                with open(filename, errors=u"replace") as f:
                    extracted_info.extractedText = f.read()
            else:
                bb.error(u"Cannot find any text for license %s" % name)

        extracted[name] = extracted_info
        document.hasExtractedLicensingInfos.append(extracted_info)

    def convert(l):
        if l == u"(" or l == u")":
            return l

        if l == u"&":
            return u"AND"

        if l == u"|":
            return u"OR"

        if l == u"CLOSED":
            return u"NONE"

        spdx_license = d.getVarFlag(u"SPDXLICENSEMAP", l) or l
        if spdx_license in license_data[u"licenses"]:
            return spdx_license

        try:
            spdx_license = existing[l]
        except KeyError:
            spdx_license = u"LicenseRef-" + l
            add_extracted_license(spdx_license, l, document)

        return spdx_license

    lic_split = lic.replace(u"(", u" ( ").replace(u")", u" ) ").split()

    return u' '.join(convert(l) for l in lic_split)

def process_sources(d):
    pn = d.getVar(u'PN', True)
    assume_provided = (d.getVar(u"ASSUME_PROVIDED", True) or u"").split()
    if pn in assume_provided:
        for p in d.getVar(u"PROVIDES", True).split():
            if p != pn:
                pn = p
                break

    # glibc-locale: do_fetch, do_unpack and do_patch tasks have been deleted,
    # so avoid archiving source here.
    if pn.startswith(u'glibc-locale'):
        return False
    if d.getVar(u'PN', True) == u"libtool-cross":
        return False
    if d.getVar(u'PN', True) == u"libgcc-initial":
        return False
    if d.getVar(u'PN', True) == u"shadow-sysroot":
        return False

    # We just archive gcc-source for all the gcc related recipes
    if d.getVar(u'BPN', True) in [u'gcc', u'libgcc']:
        bb.debug(1, u'spdx: There is bug in scan of %s is, do nothing' % pn)
        return False

    return True


def add_package_files(d, doc, spdx_pkg, topdir, get_spdxid, get_types, **_3to2kwargs):
    if 'ignore_top_level_dirs' in _3to2kwargs: ignore_top_level_dirs = _3to2kwargs['ignore_top_level_dirs']; del _3to2kwargs['ignore_top_level_dirs']
    else: ignore_top_level_dirs = []
    if 'ignore_dirs' in _3to2kwargs: ignore_dirs = _3to2kwargs['ignore_dirs']; del _3to2kwargs['ignore_dirs']
    else: ignore_dirs = []
    if 'archive' in _3to2kwargs: archive = _3to2kwargs['archive']; del _3to2kwargs['archive']
    else: archive = None
    from pathlib import Path
    import oe_sbom.spdx
    import hashlib

    source_date_epoch = d.getVar(u"SOURCE_DATE_EPOCH", True)
    if source_date_epoch:
        source_date_epoch = int(source_date_epoch)

    sha1s = []
    spdx_files = []

    file_counter = 1
    for subdir, dirs, files in os.walk(topdir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        if subdir == unicode(topdir):
            dirs[:] = [d for d in dirs if d not in ignore_top_level_dirs]

        for file in files:
            filepath = Path(subdir) / file
            filename = unicode(filepath.relative_to(topdir))

            if filepath.is_file() and not filepath.is_symlink():
                spdx_file = oe_sbom.spdx.SPDXFile()
                spdx_file.SPDXID = get_spdxid(file_counter)
                for t in get_types(filepath):
                    spdx_file.fileTypes.append(t)
                spdx_file.fileName = filename

                if archive is not None:
                    with filepath.open(u"rb") as f:
                        info = archive.gettarinfo(fileobj=f)
                        info.name = filename
                        info.uid = 0
                        info.gid = 0
                        info.uname = u"root"
                        info.gname = u"root"

                        if source_date_epoch is not None and info.mtime > source_date_epoch:
                            info.mtime = source_date_epoch

                        archive.addfile(info, f)

                sha1 = bb.utils.sha1_file(filepath)
                sha1s.append(sha1)
                spdx_file.checksums.append(oe_sbom.spdx.SPDXChecksum(
                        algorithm=u"SHA1",
                        checksumValue=sha1,
                    ))
                spdx_file.checksums.append(oe_sbom.spdx.SPDXChecksum(
                        algorithm=u"SHA256",
                        checksumValue=bb.utils.sha256_file(filepath),
                    ))

                doc.files.append(spdx_file)
                doc.add_relationship(spdx_pkg, u"CONTAINS", spdx_file)
                spdx_pkg.hasFiles.append(spdx_file.SPDXID)

                spdx_files.append(spdx_file)

                file_counter += 1

    sha1s.sort()
    verifier = hashlib.sha1()
    for v in sha1s:
        verifier.update(v.encode(u"utf-8"))
    spdx_pkg.packageVerificationCode.packageVerificationCodeValue = verifier.hexdigest()

    return spdx_files

def add_package_sources_from_debug(d, package_doc, spdx_package, package, package_files, sources, search_paths):
    from pathlib import Path
    import hashlib
    import oe_sbom.packagedata
    import oe_sbom.spdx

    debug_search_paths = [
        Path(d.getVar(u'PKGD', True)),
        Path(d.getVar(u'STAGING_DIR_TARGET', True)),
        Path(d.getVar(u'STAGING_DIR_NATIVE', True)),
        Path(d.getVar(u'STAGING_KERNEL_DIR', True)),
    ]
    topdir = d.getVar(u'TOPDIR', True)
    for path in search_paths:
        debug_search_paths.append(Path(topdir + u'/' + path))

    pkg_data = oe_sbom.packagedata.read_subpkgdata_extended(package, d)

    if pkg_data is None:
        return

    for file_path, file_data in pkg_data[u"files_info"].items():
        if not u"debugsrc" in file_data:
            continue

        for pkg_file in package_files:
            if file_path.lstrip(u"/") == pkg_file.fileName.lstrip(u"/"):
                break
        else:
            bb.fatal(u"No package file found for %s" % unicode(file_path))
            continue

        for debugsrc in file_data[u"debugsrc"]:
            ref_id = u"NOASSERTION"
            for search in debug_search_paths:
                if debugsrc.startswith(u"/usr/src/kernel"):
                    debugsrc_path = search / debugsrc.replace(u'/usr/src/kernel/', u'')
                else:
                    debugsrc_path = search / debugsrc.lstrip(u"/")
                if not debugsrc_path.exists():
                    continue

                file_sha256 = bb.utils.sha256_file(debugsrc_path)

                if file_sha256 in sources:
                    source_file = sources[file_sha256]

                    doc_ref = package_doc.find_external_document_ref(source_file.doc.documentNamespace)
                    if doc_ref is None:
                        doc_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
                        doc_ref.externalDocumentId = u"DocumentRef-dependency-" + source_file.doc.name
                        doc_ref.spdxDocument = source_file.doc.documentNamespace
                        doc_ref.checksum.algorithm = u"SHA1"
                        doc_ref.checksum.checksumValue = source_file.doc_sha1
                        package_doc.externalDocumentRefs.append(doc_ref)

                    ref_id = u"%s:%s" % (doc_ref.externalDocumentId, source_file.file.SPDXID)
                else:
                    bb.debug(1, u"Debug source %s with SHA256 %s not found in any dependency" % (unicode(debugsrc_path), file_sha256))
                break
            else:
                bb.debug(1, u"Debug source %s not found in sources at all" % (debugsrc))

            package_doc.add_relationship(pkg_file, u"GENERATED_FROM", ref_id, comment=debugsrc)

def collect_dep_recipes(d, doc, spdx_recipe):
    from pathlib import Path
    import oe_sbom.sbom
    import oe_sbom.spdx

    deploy_dir_spdx = Path(d.getVar(u"DEPLOY_DIR_SPDX", True))

    dep_recipes = []
    taskdepdata = d.getVar(u"BB_TASKDEPDATA", False)
    deps = sorted(set(
        dep[0] for dep in taskdepdata.values() if
            dep[1] == u"do_create_spdx" and dep[0] != d.getVar(u"PN", True)
    ))
    for dep_pn in deps:
        dep_recipe_path = deploy_dir_spdx / u"recipes" / (u"recipe-%s.spdx.json" % dep_pn)

        spdx_dep_doc, spdx_dep_sha1 = oe_sbom.sbom.read_doc(dep_recipe_path)

        for pkg in spdx_dep_doc.packages:
            if pkg.name == dep_pn:
                spdx_dep_recipe = pkg
                break
        else:
            continue

        dep_recipes.append(oe_sbom.sbom.DepRecipe(spdx_dep_doc, spdx_dep_sha1, spdx_dep_recipe))

        dep_recipe_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
        dep_recipe_ref.externalDocumentId = u"DocumentRef-dependency-" + spdx_dep_doc.name
        dep_recipe_ref.spdxDocument = spdx_dep_doc.documentNamespace
        dep_recipe_ref.checksum.algorithm = u"SHA1"
        dep_recipe_ref.checksum.checksumValue = spdx_dep_sha1

        doc.externalDocumentRefs.append(dep_recipe_ref)

        doc.add_relationship(
            u"%s:%s" % (dep_recipe_ref.externalDocumentId, spdx_dep_recipe.SPDXID),
            u"BUILD_DEPENDENCY_OF",
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

            if u"SOURCE" in spdx_file.fileTypes:
                for checksum in spdx_file.checksums:
                    if checksum.algorithm == u"SHA256":
                        sources[checksum.checksumValue] = oe_sbom.sbom.DepSource(dep.doc, dep.doc_sha1, dep.recipe, spdx_file)
                        break
        search_paths.append(get_spdxdir_from_annotation(d, dep.recipe))

    return sources, search_paths


python do_create_spdx() {
    #from __future__ import division
    #from __future__ import with_statement
    #from __future__ import absolute_import
    from datetime import datetime, timezone
    import oe_sbom.sbom
    import oe_sbom.spdx
    import oe_sbom.packagedata
    import uuid
    from pathlib import Path
    from contextlib import contextmanager
    import oe_sbom.cve_check

    @contextmanager
    def optional_tarfile(name, guard, mode=u"w:xz"):
        import tarfile

        if guard:
            name.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(name=name, mode=mode) as f:
                yield f
        else:
            yield None

    def get_version_from_PV(PV_str):
        if u'+git' in PV_str:
            return PV_str.split(u'+git')[0]
        else:
            return PV_str

    def get_packagegroup():
        package_bb = d.getVar(u"FILE", True)
        packagegroup = package_bb.split(u'recipes-')[1].split(u'/')[0]
        return packagegroup

    deploy_dir_spdx = Path(d.getVar(u"DEPLOY_DIR_SPDX", True))
    top_dir = Path(d.getVar(u"TOPDIR", True))
    spdx_workdir = Path(d.getVar(u"SPDXWORK", True))
    include_packaged = d.getVar(u"SPDX_INCLUDE_PACKAGED", True) == u"1"
    include_sources = d.getVar(u"SPDX_INCLUDE_SOURCES", True) == u"1"
    archive_sources = d.getVar(u"SPDX_ARCHIVE_SOURCES", True) == u"1"
    archive_packaged = d.getVar(u"SPDX_ARCHIVE_PACKAGED", True) == u"1"

    creation_time = datetime.now(tz=timezone.utc).strftime(u"%Y-%m-%dT%H:%M:%SZ")

    doc = oe_sbom.spdx.SPDXDocument()

    doc.name = u"recipe-" + d.getVar(u"PN", True)
    doc.documentNamespace = get_doc_namespace(d, doc)
    doc.creationInfo.created = creation_time
    doc.creationInfo.comment = u"This document was created by analyzing recipe files during the build."
    doc.creationInfo.licenseListVersion = d.getVar(u"SPDX_LICENSE_DATA", True)[u"licenseListVersion"]
    doc.creationInfo.creators.append(u"Tool: OpenEmbedded Core create-spdx.bbclass")
    doc.creationInfo.creators.append(u"Organization: OpenEmbedded ()")
    doc.creationInfo.creators.append(u"Person: N/A ()")

    recipe = oe_sbom.spdx.SPDXPackage()
    recipe.name = d.getVar(u"PN", True)
    recipe.versionInfo = get_version_from_PV(d.getVar(u"PV", True))
    recipe.SPDXID = oe_sbom.sbom.get_recipe_spdxid(d)
    recipe.comment = u" PackageGroup: " + get_packagegroup()
    if bb.data.inherits_class(u"native", d) or bb.data.inherits_class(u"cross", d):
        recipe.annotations.append(create_annotation(d, u"isNative"))
    recipe.annotations.append(create_annotation(d, u"SPDXDIR:%s" % d.getVar(u"PKGD", True).replace(unicode(top_dir) +u'/', u'')))


    for s in d.getVar(u'SRC_URI', True).split():
        if not s.startswith(u"file://"):
            recipe.downloadLocation = s
            break
    else:
        recipe.downloadLocation = u"NOASSERTION"

    homepage = d.getVar(u"HOMEPAGE", True)
    if homepage:
        recipe.homepage = homepage

    #license = d.getVar("LICENSE", True)
    #if license:
    #    recipe.licenseDeclared = convert_license_to_spdx(license, doc, d)
    recipe.licenseDeclared = d.getVar(u"LICENSE", True)

    summary = d.getVar(u"SUMMARY", True)
    if summary:
        recipe.summary = summary

    description = d.getVar(u"DESCRIPTION", True)
    if description:
        recipe.description = description

    # Some CVEs may be patched during the build process without incrementing the version number,
    # so querying for CVEs based on the CPE id can lead to false positives. To account for this,
    # save the CVEs fixed by patches to source information field in the SPDX.
    patched_cves = oe_sbom.cve_check.get_patched_cves(d)
    patched_cves = list(patched_cves)
    patched_cves = u' '.join(patched_cves)
    if patched_cves:
        recipe.sourceInfo = u"CVEs fixed: " + patched_cves

    cpe_ids = oe_sbom.cve_check.get_cpe_ids(d.getVar(u"CVE_PRODUCT", True), d.getVar(u"CVE_VERSION", True))
    if cpe_ids:
        for cpe_id in cpe_ids:
            cpe = oe_sbom.spdx.SPDXExternalReference()
            cpe.referenceCategory = u"SECURITY"
            cpe.referenceType = u"http://spdx.org/rdf/references/cpe23Type"
            cpe.referenceLocator = cpe_id
            recipe.externalRefs.append(cpe)

    doc.packages.append(recipe)
    doc.add_relationship(doc, u"DESCRIBES", recipe)

    if process_sources(d) and include_sources:
        recipe_archive = deploy_dir_spdx / u"recipes" / (doc.name + u".tar.xz")
        with optional_tarfile(recipe_archive, archive_sources) as archive:
            spdx_get_src(d)

            add_package_files(
                d,
                doc,
                recipe,
                spdx_workdir,
                lambda file_counter: u"SPDXRef-SourceFile-%s-%d" % (d.getVar(u"PN", True), file_counter),
                lambda filepath: [u"SOURCE"],
                ignore_dirs=[u".git"],
                ignore_top_level_dirs=[u"temp"],
                archive=archive,
            )

            if archive is not None:
                recipe.packageFileName = unicode(recipe_archive.name)

    dep_recipes = collect_dep_recipes(d, doc, recipe)

    doc_sha1 = oe_sbom.sbom.write_doc(d, doc, u"recipes")
    dep_recipes.append(oe_sbom.sbom.DepRecipe(doc, doc_sha1, recipe))

    recipe_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
    recipe_ref.externalDocumentId = u"DocumentRef-recipe-" + recipe.name
    recipe_ref.spdxDocument = doc.documentNamespace
    recipe_ref.checksum.algorithm = u"SHA1"
    recipe_ref.checksum.checksumValue = doc_sha1

    sources, search_paths = collect_dep_sources(d, dep_recipes)
    found_licenses = dict((license.name, recipe_ref.externalDocumentId + u":" + license.licenseId) for license in doc.hasExtractedLicensingInfos)

    if not recipe_spdx_is_native(d, recipe):
        bb.build.exec_func(u"read_subpackage_metadata", d)

        pkgdest = Path(d.getVar(u"PKGDEST", True))
        for package in d.getVar(u"PACKAGES", True).split():
            if not oe_sbom.packagedata.packaged(package, d):
                continue

            package_doc = oe_sbom.spdx.SPDXDocument()

            distro_ver = d.getVar(u"DISTRO_VERSION", True)
            if u'Yocto' in d.getVar(u"DISTRO_NAME", True):
                if distro_ver[:3] > u'3.0':
                    pkg_name = d.getVar(u"PKG:%s" % package, True) or package
                else:
                    pkg_name = d.getVar(u"PKG_%s" % package, True) or package
            elif u'Wind River' in d.getVar(u"DISTRO_NAME", True):
                if (distro_ver.split(u'.')[0] == u'10') and (int(distro_ver.split(u'.')[1]) > 21):
                    pkg_name = d.getVar(u"PKG:%s" % package, True) or package
                elif (distro_ver.split(u'.')[0] == u'10') and (distro_ver.split(u'.')[1] == u'21') and (int(distro_ver.split(u'.')[3]) >= 5):
                    pkg_name = d.getVar(u"PKG:%s" % package, True) or package
                else:
                    pkg_name = d.getVar(u"PKG_%s" % package, True) or package

            package_doc.name = pkg_name
            package_doc.documentNamespace = get_doc_namespace(d, package_doc)
            package_doc.creationInfo.created = creation_time
            package_doc.creationInfo.comment = u"This document was created by analyzing packages created during the build."
            package_doc.creationInfo.licenseListVersion = d.getVar(u"SPDX_LICENSE_DATA", True)[u"licenseListVersion"]
            package_doc.creationInfo.creators.append(u"Tool: OpenEmbedded Core create-spdx.bbclass")
            package_doc.creationInfo.creators.append(u"Organization: OpenEmbedded ()")
            package_doc.creationInfo.creators.append(u"Person: N/A ()")
            package_doc.externalDocumentRefs.append(recipe_ref)

            package_license = d.getVar(u"LICENSE:%s" % package, True) or d.getVar(u"LICENSE", True)

            spdx_package = oe_sbom.spdx.SPDXPackage()

            spdx_package.SPDXID = oe_sbom.sbom.get_package_spdxid(pkg_name)
            spdx_package.name = pkg_name
            spdx_package.versionInfo = d.getVar(u"PV", True)
            #spdx_package.licenseDeclared = convert_license_to_spdx(package_license, package_doc, d, found_licenses)
            spdx_package.licenseDeclared = package_license

            package_doc.packages.append(spdx_package)

            package_doc.add_relationship(spdx_package, u"GENERATED_FROM", u"%s:%s" % (recipe_ref.externalDocumentId, recipe.SPDXID))
            package_doc.add_relationship(package_doc, u"DESCRIBES", spdx_package)

            package_archive = deploy_dir_spdx / u"packages" / (package_doc.name + u".tar.xz")
            with optional_tarfile(package_archive, archive_packaged) as archive:
                package_files = add_package_files(
                    d,
                    package_doc,
                    spdx_package,
                    pkgdest / package,
                    lambda file_counter: oe_sbom.sbom.get_packaged_file_spdxid(pkg_name, file_counter),
                    lambda filepath: [u"BINARY"],
                    archive=archive,
                )

                if archive is not None:
                    spdx_package.packageFileName = unicode(package_archive.name)

            add_package_sources_from_debug(d, package_doc, spdx_package, package, package_files, sources, search_paths)

            oe_sbom.sbom.write_doc(d, package_doc, u"packages")
}
# NOTE: depending on do_unpack is a hack that is necessary to get it's dependencies for archive the source
addtask do_create_spdx after do_package do_packagedata do_unpack before do_build do_rm_work

SSTATETASKS += "do_create_spdx"
do_create_spdx[sstate-inputdirs] = "${SPDXDEPLOY}"
do_create_spdx[sstate-outputdirs] = "${DEPLOY_DIR_SPDX}"

python do_create_spdx_setscene () {
    #from __future__ import with_statement
    #from __future__ import division
    #from __future__ import absolute_import
    sstate_setscene(d)
}
addtask do_create_spdx_setscene

do_create_spdx[dirs] = "${SPDXDEPLOY} ${SPDXWORK}"
do_create_spdx[cleandirs] = "${SPDXDEPLOY} ${SPDXWORK}"
do_create_spdx[depends] += "${PATCHDEPENDENCY}"
do_create_spdx[deptask] = "do_create_spdx"

def collect_package_providers(d):
    from pathlib import Path
    import oe_sbom.sbom
    import oe_sbom.spdx
    import json

    deploy_dir_spdx = Path(d.getVar(u"DEPLOY_DIR_SPDX", True))

    providers = {}

    taskdepdata = d.getVar(u"BB_TASKDEPDATA", False)
    deps = sorted(set(
        dep[0] for dep in taskdepdata.values() if dep[0] != d.getVar(u"PN", True)
    ))
    deps.append(d.getVar(u"PN", True))

    for dep_pn in deps:
        recipe_data = oe_sbom.packagedata.read_pkgdata(dep_pn, d)

        for pkg in recipe_data.get(u"PACKAGES", u"").split():

            pkg_data = oe_sbom.packagedata.read_subpkgdata_dict(pkg, d)
            rprovides = set(n for n, _ in bb.utils.explode_dep_versions2(pkg_data.get(u"RPROVIDES", u"")).items())
            rprovides.add(pkg)

            for r in rprovides:
                providers[r] = pkg

    return providers

collect_package_providers[vardepsexclude] += "BB_TASKDEPDATA"

python do_create_runtime_spdx() {
    #from __future__ import division
    #from __future__ import absolute_import
    from datetime import datetime, timezone
    import oe_sbom.sbom
    import oe_sbom.spdx
    import oe_sbom.packagedata
    from pathlib import Path

    deploy_dir_spdx = Path(d.getVar(u"DEPLOY_DIR_SPDX", True))
    spdx_deploy = Path(d.getVar(u"SPDXRUNTIMEDEPLOY", True))
    is_native = bb.data.inherits_class(u"native", d) or bb.data.inherits_class(u"cross", d)

    creation_time = datetime.now(tz=timezone.utc).strftime(u"%Y-%m-%dT%H:%M:%SZ")

    providers = collect_package_providers(d)

    if not is_native:
        bb.build.exec_func(u"read_subpackage_metadata", d)

        dep_package_cache = {}

        pkgdest = Path(d.getVar(u"PKGDEST", True))
        for package in d.getVar(u"PACKAGES", True).split():
            localdata = bb.data.createCopy(d)

            distro_ver = d.getVar(u"DISTRO_VERSION", True)
            if u'Yocto' in d.getVar(u"DISTRO_NAME", True):
                if distro_ver[:3] > u'3.0':
                    pkg_name = d.getVar(u"PKG:%s" % package, True) or package
                else:
                    pkg_name = d.getVar(u"PKG_%s" % package, True) or package
            elif u'Wind River' in d.getVar(u"DISTRO_NAME", True):
                if (distro_ver.split(u'.')[0] == u'10') and (int(distro_ver.split(u'.')[1]) > 21):
                    pkg_name = d.getVar(u"PKG:%s" % package, True) or package
                elif (distro_ver.split(u'.')[0] == u'10') and (distro_ver.split(u'.')[1] == u'21') and (int(distro_ver.split(u'.')[3]) >= 5):
                    pkg_name = d.getVar(u"PKG:%s" % package, True) or package
                else:
                    pkg_name = d.getVar(u"PKG_%s" % package, True) or package

            localdata.setVar(u"PKG", pkg_name)
            localdata.setVar(u'OVERRIDES', d.getVar(u"OVERRIDES", False) + u":" + package)

            if not oe_sbom.packagedata.packaged(package, localdata):
                continue

            pkg_spdx_path = deploy_dir_spdx / u"packages" / (pkg_name + u".spdx.json")

            package_doc, package_doc_sha1 = oe_sbom.sbom.read_doc(pkg_spdx_path)

            for p in package_doc.packages:
                if p.name == pkg_name:
                    spdx_package = p
                    break
            else:
                bb.fatal(u"Package '%s' not found in %s" % (pkg_name, pkg_spdx_path))

            runtime_doc = oe_sbom.spdx.SPDXDocument()
            runtime_doc.name = u"runtime-" + pkg_name
            runtime_doc.documentNamespace = get_doc_namespace(localdata, runtime_doc)
            runtime_doc.creationInfo.created = creation_time
            runtime_doc.creationInfo.comment = u"This document was created by analyzing package runtime dependencies."
            runtime_doc.creationInfo.licenseListVersion = d.getVar(u"SPDX_LICENSE_DATA", True)[u"licenseListVersion"]
            runtime_doc.creationInfo.creators.append(u"Tool: OpenEmbedded Core create-spdx.bbclass")
            runtime_doc.creationInfo.creators.append(u"Organization: OpenEmbedded ()")
            runtime_doc.creationInfo.creators.append(u"Person: N/A ()")

            package_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
            package_ref.externalDocumentId = u"DocumentRef-package-" + package
            package_ref.spdxDocument = package_doc.documentNamespace
            package_ref.checksum.algorithm = u"SHA1"
            package_ref.checksum.checksumValue = package_doc_sha1

            runtime_doc.externalDocumentRefs.append(package_ref)

            runtime_doc.add_relationship(
                runtime_doc.SPDXID,
                u"AMENDS",
                u"%s:%s" % (package_ref.externalDocumentId, package_doc.SPDXID)
            )

            deps = bb.utils.explode_dep_versions2(localdata.getVar(u"RDEPENDS", True) or u"")
            seen_deps = set()
            for dep, _ in deps.items():
                if dep in seen_deps:
                    continue

                dep = providers[dep]

                if not oe_sbom.packagedata.packaged(dep, localdata):
                    continue

                dep_pkg_data = oe_sbom.packagedata.read_subpkgdata_dict(dep, d)
                dep_pkg = dep_pkg_data[u"PKG"]

                if dep in dep_package_cache:
                    (dep_spdx_package, dep_package_ref) = dep_package_cache[dep]
                else:
                    dep_path = deploy_dir_spdx / u"packages" / (u"%s.spdx.json" % dep_pkg)

                    spdx_dep_doc, spdx_dep_sha1 = oe_sbom.sbom.read_doc(dep_path)

                    for pkg in spdx_dep_doc.packages:
                        if pkg.name == dep_pkg:
                            dep_spdx_package = pkg
                            break
                    else:
                        bb.fatal(u"Package '%s' not found in %s" % (dep_pkg, dep_path))

                    dep_package_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
                    dep_package_ref.externalDocumentId = u"DocumentRef-runtime-dependency-" + spdx_dep_doc.name
                    dep_package_ref.spdxDocument = spdx_dep_doc.documentNamespace
                    dep_package_ref.checksum.algorithm = u"SHA1"
                    dep_package_ref.checksum.checksumValue = spdx_dep_sha1

                    dep_package_cache[dep] = (dep_spdx_package, dep_package_ref)

                runtime_doc.externalDocumentRefs.append(dep_package_ref)

                runtime_doc.add_relationship(
                    u"%s:%s" % (dep_package_ref.externalDocumentId, dep_spdx_package.SPDXID),
                    u"RUNTIME_DEPENDENCY_OF",
                    u"%s:%s" % (package_ref.externalDocumentId, spdx_package.SPDXID)
                )
                seen_deps.add(dep)

            oe_sbom.sbom.write_doc(d, runtime_doc, u"runtime", spdx_deploy)
}

addtask do_create_runtime_spdx after do_create_spdx before do_build do_rm_work
SSTATETASKS += "do_create_runtime_spdx"
do_create_runtime_spdx[sstate-inputdirs] = "${SPDXRUNTIMEDEPLOY}"
do_create_runtime_spdx[sstate-outputdirs] = "${DEPLOY_DIR_SPDX}"

python do_create_runtime_spdx_setscene () {
    #from __future__ import with_statement
    #from __future__ import division
    #from __future__ import absolute_import
    sstate_setscene(d)
}
addtask do_create_runtime_spdx_setscene

do_create_runtime_spdx[dirs] = "${SPDXRUNTIMEDEPLOY}"
do_create_runtime_spdx[cleandirs] = "${SPDXRUNTIMEDEPLOY}"
do_create_runtime_spdx[rdeptask] = "do_create_spdx"

def spdx_get_src(d):
    u"""
    save patched source of the recipe in SPDX_WORKDIR.
    """
    import shutil
    spdx_workdir = d.getVar(u'SPDXWORK', True)
    spdx_sysroot_native = d.getVar(u'STAGING_DIR_NATIVE', True)
    pn = d.getVar(u'PN', True)

    workdir = d.getVar(u"WORKDIR", True)

    try:
        # The kernel class functions require it to be on work-shared, so we dont change WORKDIR
        if not is_work_shared_spdx(d):
            # Change the WORKDIR to make do_unpack do_patch run in another dir.
            d.setVar(u'WORKDIR', spdx_workdir)
            # Restore the original path to recipe's native sysroot (it's relative to WORKDIR).
            d.setVar(u'STAGING_DIR_NATIVE', spdx_sysroot_native)

            # The changed 'WORKDIR' also caused 'B' changed, create dir 'B' for the
            # possibly requiring of the following tasks (such as some recipes's
            # do_patch required 'B' existed).
            bb.utils.mkdirhier(d.getVar(u'B', True))

            bb.build.exec_func(u'do_unpack', d)
        # Copy source of kernel to spdx_workdir
        if is_work_shared_spdx(d):
            d.setVar(u'WORKDIR', spdx_workdir)
            d.setVar(u'STAGING_DIR_NATIVE', spdx_sysroot_native)
            src_dir = spdx_workdir + u"/" + d.getVar(u'PN', True)+ u"-" + d.getVar(u'PV', True) + u"-" + d.getVar(u'PR', True)
            bb.utils.mkdirhier(src_dir)
            if bb.data.inherits_class(u'kernel',d):
                share_src = d.getVar(u'STAGING_KERNEL_DIR', True)
            else:
                share_src = d.getVar(u'S', True)
            cmd_copy_share = u"cp -rf " + share_src + u"/* " + src_dir + u"/"
            cmd_copy_kernel_result = os.popen(cmd_copy_share).read()
            bb.note(u"cmd_copy_kernel_result = " + cmd_copy_kernel_result)

            git_path = src_dir + u"/.git"
            if os.path.exists(git_path):
                shutils.rmtree(git_path)

        # Make sure gcc and kernel sources are patched only once
        if not (d.getVar(u'SRC_URI', True) == u"" or is_work_shared_spdx(d)):
            bb.build.exec_func(u'do_patch', d)

        # Some userland has no source.
        if not os.path.exists( spdx_workdir ):
            bb.utils.mkdirhier(spdx_workdir)
    finally:
        d.setVar(u"WORKDIR", workdir)

do_rootfs[recrdeptask] += "do_create_spdx do_create_runtime_spdx"

ROOTFS_POSTUNINSTALL_COMMAND =+ "image_combine_spdx ; "
python image_combine_spdx() {
    #from __future__ import with_statement
    #from __future__ import division
    #from __future__ import absolute_import
    import os
    import oe_sbom.spdx
    import oe_sbom.sbom
    import io
    import json
    from oe.rootfs import image_list_installed_packages
    from datetime import timezone, datetime
    from pathlib import Path
    import tarfile

    def get_yocto_codename(version):
        yocto_version_to_codename = {u"4.1": u"Langdale", u"4.0": u"Kirkstone", u"3.4": u"Honister", u"3.3": u"Hardknott", u"3.2": u"Gatesgarth", u"3.1": u"Dunfell", u"3.0": u"Zeus", u"2.7": u"Warrior", u"2.6": u"Thud", u"2.5": u"Sumo", u"2.4": u"Rocko", u"2.3": u"Pyro", u"2.2": u"Morty", u"2.1": u"Krogoth", u"2.0": u"Jethro", u"1.8": u"Fido", u"1.7": u"Dizzy", u"1.6": u"Daisy", u"1.5": u"Dora", u"1.4": u"Dylan", u"1.3": u"Danny", u"1.2": u"Denzil", u"1.1": u"Edison", u"1.0": u"Bernard", u"0.9": u"Laverne"}
        for ver in yocto_version_to_codename.keys():
            if len(ver) > len(version):
                continue
            if ver == version[:len(ver)]:
                return yocto_version_to_codename[ver]

    creation_time = datetime.now(tz=timezone.utc).strftime(u"%Y-%m-%dT%H:%M:%SZ")
    image_name = d.getVar(u"IMAGE_NAME", True)
    image_link_name = d.getVar(u"IMAGE_LINK_NAME", True)

    deploy_dir_spdx = Path(d.getVar(u"DEPLOY_DIR_SPDX", True))
    imgdeploydir = Path(d.getVar(u"IMGDEPLOYDIR", True))
    source_date_epoch = d.getVar(u"SOURCE_DATE_EPOCH", True)

    doc = oe_sbom.spdx.SPDXDocument()
    doc.name = image_name
    doc.documentNamespace = get_doc_namespace(d, doc)
    doc.creationInfo.created = creation_time
    doc.creationInfo.comment = u"This document was created by analyzing the source of the Yocto recipe during the build."
    doc.creationInfo.licenseListVersion = d.getVar(u"SPDX_LICENSE_DATA", True)[u"licenseListVersion"]
    doc.creationInfo.creators.append(u"Tool: OpenEmbedded Core create-spdx.bbclass")
    doc.creationInfo.creators.append(u"Organization: OpenEmbedded ()")
    doc.creationInfo.creators.append(u"Person: N/A ()")
    if u'Yocto' in d.getVar(u"DISTRO_NAME", True):
        doc.comment = u"DISTRO: " + u"Yocto-" + get_yocto_codename(d.getVar(u"DISTRO_VERSION", True)) + u"-" + d.getVar(u"DISTRO_VERSION", True) + u"  ARCH: " + d.getVar(u"MACHINE_ARCH", True)
    elif u'Wind River' in d.getVar(u"DISTRO_NAME", True):
        doc.comment = u"DISTRO: " + u"WRLinux-" + d.getVar(u"DISTRO_VERSION", True) + u"  ARCH: " + d.getVar(u"MACHINE_ARCH", True)
    doc.documentDescribes.append(u"SPDXRef-Image-" + d.getVar(u"IMAGE_NAME", True))

    image = oe_sbom.spdx.SPDXPackage()
    image.name = d.getVar(u"PN", True)
    image.versionInfo = d.getVar(u"PV", True)
    image.SPDXID = oe_sbom.sbom.get_image_spdxid(image_name)

    doc.packages.append(image)

    spdx_package = oe_sbom.spdx.SPDXPackage()

    packages = image_list_installed_packages(d)

    for name in sorted(packages.keys()):
        pkg_spdx_path = deploy_dir_spdx / u"packages" / (name + u".spdx.json")
        pkg_doc, pkg_doc_sha1 = oe_sbom.sbom.read_doc(pkg_spdx_path)

        for p in pkg_doc.packages:
            if p.name == name:
                pkg_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
                pkg_ref.externalDocumentId = u"DocumentRef-%s" % pkg_doc.name
                pkg_ref.spdxDocument = pkg_doc.documentNamespace
                pkg_ref.checksum.algorithm = u"SHA1"
                pkg_ref.checksum.checksumValue = pkg_doc_sha1

                doc.externalDocumentRefs.append(pkg_ref)
                doc.add_relationship(image, u"CONTAINS", u"%s:%s" % (pkg_ref.externalDocumentId, p.SPDXID))
                break
        else:
            bb.fatal(u"Unable to find package with name '%s' in SPDX file %s" % (name, pkg_spdx_path))

        runtime_spdx_path = deploy_dir_spdx / u"runtime" / (u"runtime-" + name + u".spdx.json")
        runtime_doc, runtime_doc_sha1 = oe_sbom.sbom.read_doc(runtime_spdx_path)

        runtime_ref = oe_sbom.spdx.SPDXExternalDocumentRef()
        runtime_ref.externalDocumentId = u"DocumentRef-%s" % runtime_doc.name
        runtime_ref.spdxDocument = runtime_doc.documentNamespace
        runtime_ref.checksum.algorithm = u"SHA1"
        runtime_ref.checksum.checksumValue = runtime_doc_sha1

        # "OTHER" isn't ideal here, but I can't find a relationship that makes sense
        doc.externalDocumentRefs.append(runtime_ref)
        doc.add_relationship(
            image,
            u"OTHER",
            u"%s:%s" % (runtime_ref.externalDocumentId, runtime_doc.SPDXID),
            comment=u"Runtime dependencies for %s" % name
        )

    recipe_spdx_path = os.path.join(deploy_dir_spdx, u"recipes")
    for filename in os.listdir(recipe_spdx_path):
        if filename.endswith(u"spdx.json") and u"-native" not in filename:
            with open(os.path.join(recipe_spdx_path, filename)) as f:
                recipe_spdx = json.load(f)
                if u'packages' in recipe_spdx.keys():
                    doc.packages.extend(recipe_spdx[u"packages"])
                #if 'files' in recipe_spdx.keys():
                #    doc.files.extend(recipe_spdx["files"])
                #if 'relationships' in recipe_spdx.keys():
                #    doc.relationships.extend(recipe_spdx["relationships"])
    image_spdx_path = imgdeploydir / (image_name + u".spdx.json")

    with image_spdx_path.open(u"wb") as f:
        doc.to_json(f, sort_keys=True)

    image_spdx_link = imgdeploydir / (image_link_name + u".spdx.json")
    image_spdx_link.symlink_to(os.path.relpath(image_spdx_path, image_spdx_link.parent))

    num_threads = int(d.getVar(u"BB_NUMBER_THREADS", True))

    visited_docs = set()

    index = {u"documents": []}

    spdx_tar_path = imgdeploydir / (image_name + u".spdx.tar.xz")
    with tarfile.open(name=spdx_tar_path, mode=u"w:xz") as tar:
        def collect_spdx_document(path, tar, deploy_dir_spdx, source_date_epoch, index):
            #nonlocal tar
            #nonlocal deploy_dir_spdx
            #nonlocal source_date_epoch
            #nonlocal index

            if path in visited_docs:
                return

            visited_docs.add(path)

            with path.open(u"rb") as f:
                doc, sha1 = oe_sbom.sbom.read_doc(f)
                f.seek(0)

                if doc.documentNamespace in visited_docs:
                    return

                bb.note(u"Adding SPDX document %s" % path)
                visited_docs.add(doc.documentNamespace)
                info = tar.gettarinfo(fileobj=f)

                info.name = doc.name + u".spdx.json"
                info.uid = 0
                info.gid = 0
                info.uname = u"root"
                info.gname = u"root"

                if source_date_epoch is not None and info.mtime > int(source_date_epoch):
                    info.mtime = int(source_date_epoch)

                tar.addfile(info, f)

                index[u"documents"].append({
                    u"filename": info.name,
                    u"documentNamespace": doc.documentNamespace,
                    u"sha1": sha1,
                })

            for ref in doc.externalDocumentRefs:
                ref_path = deploy_dir_spdx / u"by-namespace" / ref.spdxDocument.replace(u"/", u"_")
                collect_spdx_document(ref_path, tar, deploy_dir_spdx, source_date_epoch, index)

        collect_spdx_document(image_spdx_path, tar, deploy_dir_spdx, source_date_epoch, index)

        index[u"documents"].sort(key=lambda x: x[u"filename"])

        index_str = io.BytesIO(json.dumps(index, sort_keys=True).encode(u"utf-8"))

        info = tarfile.TarInfo()
        info.name = u"index.json"
        info.size = len(index_str.getvalue())
        info.uid = 0
        info.gid = 0
        info.uname = u"root"
        info.gname = u"root"

        tar.addfile(info, fileobj=index_str)

    def make_image_link(target_path, suffix):
        link = imgdeploydir / (image_link_name + suffix)
        link.symlink_to(os.path.relpath(target_path, link.parent))

    make_image_link(spdx_tar_path, u".spdx.tar.xz")

    spdx_index_path = imgdeploydir / (image_name + u".spdx.index.json")
    with spdx_index_path.open(u"w") as f:
        json.dump(index, f, sort_keys=True)

    make_image_link(spdx_index_path, u".spdx.index.json")
}

