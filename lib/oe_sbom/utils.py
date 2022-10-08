#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: GPL-2.0-only
#
def sha1_file(filename):
    """
    Return the hex string representation of the SHA1 checksum of the filename
    """
    try:
        import hashlib
    except ImportError:
        return None

    s = hashlib.sha1()
    with open(filename, "rb") as f:
        for line in f:
            s.update(line)
    return s.hexdigest()
