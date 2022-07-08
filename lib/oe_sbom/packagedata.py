#
# SPDX-License-Identifier: GPL-2.0-only
#

from __future__ import with_statement
from __future__ import absolute_import
import codecs
import os
from io import open

def packaged(pkg, d):
    return os.access(get_subpkgedata_fn(pkg, d) + u'.packaged', os.R_OK)

def read_pkgdatafile(fn, d):
    pkgdata = {}

    def decode(unicode):
        c = codecs.getdecoder(u"unicode_escape")
        return c(unicode)[0]

    if os.access(fn, os.R_OK):
        import re
        with open(fn, u'r') as f:
            lines = f.readlines()

        distro_ver = d.getVar(u"DISTRO_VERSION", True)
        if u'Yocto' in d.getVar(u"DISTRO_NAME", True):
            if distro_ver[:3] > u'3.3':
                r = re.compile(ur"(^.+?):\s+(.*)")
            else:
                r = re.compile(u"([^:]+):\s*(.*)")
        elif u'Wind River' in d.getVar(u"DISTRO_NAME", True):
            if (distro_ver.split(u'.')[0] == u'10') and (distro_ver.split(u'.')[1] > u'21'):
                r = re.compile(ur"(^.+?):\s+(.*)")
            else:
                r = re.compile(u"([^:]+):\s*(.*)")

        for l in lines:
            m = r.match(l)
            if m:
                pkgdata[m.group(1)] = decode(m.group(2))

    return pkgdata

def get_subpkgedata_fn(pkg, d):
    return d.expand(u'${PKGDATA_DIR}/runtime/%s' % pkg)

def has_subpkgdata(pkg, d):
    return os.access(get_subpkgedata_fn(pkg, d), os.R_OK)

def read_subpkgdata(pkg, d):
    return read_pkgdatafile(get_subpkgedata_fn(pkg, d), d)

def has_pkgdata(pn, d):
    fn = d.expand(u'${PKGDATA_DIR}/%s' % pn)
    return os.access(fn, os.R_OK)

def read_pkgdata(pn, d):
    fn = d.expand(u'${PKGDATA_DIR}/%s' % pn)
    return read_pkgdatafile(fn, d)

#
# Collapse FOO_pkg variables into FOO
#
def read_subpkgdata_dict(pkg, d):
    ret = {}
    subd = read_pkgdatafile(get_subpkgedata_fn(pkg, d), d)
    for var in subd:
        distro_ver = d.getVar(u"DISTRO_VERSION", True)
        if u'Yocto' in d.getVar(u"DISTRO_NAME", True):
            if distro_ver[:3] > u'3.3':
                newvar = var.replace(u":" + pkg, u"")
                if newvar == var and var + u":" + pkg in subd:
                    continue
            else:
                newvar = var.replace(u"_" + pkg, u"")
                if newvar == var and var + u"_" + pkg in subd:
                    continue
        if u'Wind River' in d.getVar(u"DISTRO_NAME", True):
            if (distro_ver.split(u'.')[0] == u'10') and (distro_ver.split(u'.')[1] > u'21'):
                newvar = var.replace(u":" + pkg, u"")
                if newvar == var and var + u":" + pkg in subd:
                    continue
            else:
                newvar = var.replace(u"_" + pkg, u"")
                if newvar == var and var + u"_" + pkg in subd:
                    continue
        ret[newvar] = subd[var]
    return ret

def read_subpkgdata_extended(pkg, d):
    import json

    fn = d.expand(u"${PKGDATA_DIR}/extended/%s.json" % pkg)
    try:
        with open(fn, u"rt", encoding=u"utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def _pkgmap(d):
    u"""Return a dictionary mapping package to recipe name."""

    pkgdatadir = d.getVar(u"PKGDATA_DIR")

    pkgmap = {}
    try:
        files = os.listdir(pkgdatadir)
    except OSError:
        bb.warn(u"No files in %s?" % pkgdatadir)
        files = []

    for pn in [f for f in files if not os.path.isdir(os.path.join(pkgdatadir, f))]:
        try:
            pkgdata = read_pkgdatafile(os.path.join(pkgdatadir, pn), d)
        except OSError:
            continue

        packages = pkgdata.get(u"PACKAGES") or u""
        for pkg in packages.split():
            pkgmap[pkg] = pn

    return pkgmap

def pkgmap(d):
    u"""Return a dictionary mapping package to recipe name.
    Cache the mapping in the metadata"""

    pkgmap_data = d.getVar(u"__pkgmap_data", False)
    if pkgmap_data is None:
        pkgmap_data = _pkgmap(d)
        d.setVar(u"__pkgmap_data", pkgmap_data)

    return pkgmap_data

def recipename(pkg, d):
    u"""Return the recipe name for the given binary package name."""

    return pkgmap(d).get(pkg)
