#
# SPDX-License-Identifier: GPL-2.0-only
#

from __future__ import with_statement
from __future__ import division
from __future__ import absolute_import
import collections

DepRecipe = collections.namedtuple(u"DepRecipe", (u"doc", u"doc_sha1", u"recipe"))
DepSource = collections.namedtuple(u"DepSource", (u"doc", u"doc_sha1", u"recipe", u"file"))


def get_recipe_spdxid(d):
    return u"SPDXRef-%s-%s" % (u"Recipe", d.getVar(u"PN", True))


def get_package_spdxid(pkg):
    return u"SPDXRef-Package-%s" % pkg


def get_source_file_spdxid(d, idx):
    return u"SPDXRef-SourceFile-%s-%d" % (d.getVar(u"PN", True), idx)


def get_packaged_file_spdxid(pkg, idx):
    return u"SPDXRef-PackagedFile-%s-%d" % (pkg, idx)


def get_image_spdxid(img):
    return u"SPDXRef-Image-%s" % img


def write_doc(d, spdx_doc, subdir, spdx_deploy=None):
    from pathlib import Path

    if spdx_deploy is None:
        spdx_deploy = Path(d.getVar(u"SPDXDEPLOY", True))

    dest = spdx_deploy / subdir / (spdx_doc.name + u".spdx.json")
    dest.parent.mkdir(exist_ok=True, parents=True)
    with dest.open(u"wb") as f:
        doc_sha1 = spdx_doc.to_json(f, sort_keys=True)

    l = spdx_deploy / u"by-namespace" / spdx_doc.documentNamespace.replace(u"/", u"_")
    l.parent.mkdir(exist_ok=True, parents=True)
    l.symlink_to(os.path.relpath(dest, l.parent))

    return doc_sha1


def read_doc(fn):
    import hashlib
    import oe_sbom.spdx
    import io
    import contextlib

    @contextlib.contextmanager
    def get_file():
        if isinstance(fn, io.IOBase):
            yield fn
        else:
            with fn.open(u"rb") as f:
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
