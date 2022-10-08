#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: GPL-2.0-only
#

from __future__ import with_statement
from __future__ import division
from __future__ import absolute_import
import collections

DepRecipe = collections.namedtuple("DepRecipe", ("doc", "doc_sha1", "recipe"))
DepSource = collections.namedtuple("DepSource", ("doc", "doc_sha1", "recipe", "file"))


def get_recipe_spdxid(d):
    return "SPDXRef-%s-%s" % ("Recipe", d.getVar("PN", True))


def get_package_spdxid(pkg):
    return "SPDXRef-Package-%s" % pkg


def get_source_file_spdxid(d, idx):
    return "SPDXRef-SourceFile-%s-%d" % (d.getVar("PN", True), idx)


def get_packaged_file_spdxid(pkg, idx):
    return "SPDXRef-PackagedFile-%s-%d" % (pkg, idx)


def get_image_spdxid(img):
    return "SPDXRef-Image-%s" % img


def write_doc(d, spdx_doc, subdir, spdx_deploy=None):

    if spdx_deploy is None:
        spdx_deploy = d.getVar("SPDXDEPLOY", True)

    dest = spdx_deploy + '/' + subdir + '/' + (spdx_doc.name + ".spdx.json")

    def os_mkdir(str_dir):
        if not os.path.exists(os.path.abspath(os.path.dirname(str_dir))):
            os_mkdir(os.path.abspath(os.path.dirname(str_dir)))

        if not os.path.exists(str_dir):
            os.mkdir(str_dir)

    os_mkdir(os.path.dirname(dest))

    with open(dest, "wb") as f:
        doc_sha1 = spdx_doc.to_json(f, sort_keys=True)

    l = spdx_deploy + "/by-namespace/" + spdx_doc.documentNamespace.replace("/", "_")
    os_mkdir(os.path.dirname(l))
    os.symlink(os.path.relpath(dest, os.path.dirname(l)), l)

    return doc_sha1


def read_doc(fn):
    import hashlib
    import oe_sbom.spdx
    import io
    import contextlib

    @contextlib.contextmanager
    def get_file():
        if isinstance(fn, file):
            yield fn
        else:
            with open(fn, "rb") as f:
                yield f

    with get_file() as f:
        sha1 = hashlib.sha1()
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha1.update(chunk)

        f.seek(0)
        doc = oe_sbom.spdx.SPDXDocument.from_json(f)

    return (doc, sha1.hexdigest())
