from __future__ import with_statement
from __future__ import absolute_import
import oe.path
from io import open

class NotFoundError(bb.BBHandledException):
    def __init__(self, path):
        self.path = path

    def __str__(self):
        return u"Error: %s not found." % self.path

class CmdError(bb.BBHandledException):
    def __init__(self, command, exitstatus, output):
        self.command = command
        self.status = exitstatus
        self.output = output

    def __str__(self):
        return u"Command Error: '%s' exited with %d  Output:\n%s" % \
                (self.command, self.status, self.output)


def runcmd(args, dir = None):
    import pipes

    if dir:
        olddir = os.path.abspath(os.curdir)
        if not os.path.exists(dir):
            raise NotFoundError(dir)
        os.chdir(dir)
        # print("cwd: %s -> %s" % (olddir, dir))

    try:
        args = [ pipes.quote(unicode(arg)) for arg in args ]
        cmd = u" ".join(args)
        # print("cmd: %s" % cmd)
        (exitstatus, output) = oe.utils.getstatusoutput(cmd)
        if exitstatus != 0:
            raise CmdError(cmd, exitstatus >> 8, output)
        return output

    finally:
        if dir:
            os.chdir(olddir)

class PatchError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return u"Patch Error: %s" % self.msg

class PatchSet(object):
    defaults = {
        u"strippath": 1
    }

    def __init__(self, dir, d):
        self.dir = dir
        self.d = d
        self.patches = []
        self._current = None

    def current(self):
        return self._current

    def Clean(self):
        u"""
        Clean out the patch set.  Generally includes unapplying all
        patches and wiping out all associated metadata.
        """
        raise NotImplementedError()

    def Import(self, patch, force):
        if not patch.get(u"file"):
            if not patch.get(u"remote"):
                raise PatchError(u"Patch file must be specified in patch import.")
            else:
                patch[u"file"] = bb.fetch2.localpath(patch[u"remote"], self.d)

        for param in PatchSet.defaults:
            if not patch.get(param):
                patch[param] = PatchSet.defaults[param]

        if patch.get(u"remote"):
            patch[u"file"] = self.d.expand(bb.fetch2.localpath(patch[u"remote"], self.d))

        patch[u"filemd5"] = bb.utils.md5_file(patch[u"file"])

    def Push(self, force):
        raise NotImplementedError()

    def Pop(self, force):
        raise NotImplementedError()

    def Refresh(self, remote = None, all = None):
        raise NotImplementedError()

    @staticmethod
    def getPatchedFiles(patchfile, striplevel, srcdir=None):
        u"""
        Read a patch file and determine which files it will modify.
        Params:
            patchfile: the patch file to read
            striplevel: the strip level at which the patch is going to be applied
            srcdir: optional path to join onto the patched file paths
        Returns:
            A list of tuples of file path and change mode ('A' for add,
            'D' for delete or 'M' for modify)
        """

        def patchedpath(patchline):
            filepth = patchline.split()[1]
            if filepth.endswith(u'/dev/null'):
                return u'/dev/null'
            filesplit = filepth.split(os.sep)
            if striplevel > len(filesplit):
                bb.error(u'Patch %s has invalid strip level %d' % (patchfile, striplevel))
                return None
            return os.sep.join(filesplit[striplevel:])

        for encoding in [u'utf-8', u'latin-1']:
            try:
                copiedmode = False
                filelist = []
                with open(patchfile) as f:
                    for line in f:
                        if line.startswith(u'--- '):
                            patchpth = patchedpath(line)
                            if not patchpth:
                                break
                            if copiedmode:
                                addedfile = patchpth
                            else:
                                removedfile = patchpth
                        elif line.startswith(u'+++ '):
                            addedfile = patchedpath(line)
                            if not addedfile:
                                break
                        elif line.startswith(u'*** '):
                            copiedmode = True
                            removedfile = patchedpath(line)
                            if not removedfile:
                                break
                        else:
                            removedfile = None
                            addedfile = None

                        if addedfile and removedfile:
                            if removedfile == u'/dev/null':
                                mode = u'A'
                            elif addedfile == u'/dev/null':
                                mode = u'D'
                            else:
                                mode = u'M'
                            if srcdir:
                                fullpath = os.path.abspath(os.path.join(srcdir, addedfile))
                            else:
                                fullpath = addedfile
                            filelist.append((fullpath, mode))
            except UnicodeDecodeError:
                continue
            break
        else:
            raise PatchError(u'Unable to decode %s' % patchfile)

        return filelist


class PatchTree(PatchSet):
    def __init__(self, dir, d):
        PatchSet.__init__(self, dir, d)
        self.patchdir = os.path.join(self.dir, u'patches')
        self.seriespath = os.path.join(self.dir, u'patches', u'series')
        bb.utils.mkdirhier(self.patchdir)

    def _appendPatchFile(self, patch, strippath):
        with open(self.seriespath, u'a') as f:
            f.write(os.path.basename(patch) + u"," + strippath + u"\n")
        shellcmd = [u"cat", patch, u">" , self.patchdir + u"/" + os.path.basename(patch)]
        runcmd([u"sh", u"-c", u" ".join(shellcmd)], self.dir)

    def _removePatch(self, p):
        patch = {}
        patch[u'file'] = p.split(u",")[0]
        patch[u'strippath'] = p.split(u",")[1]
        self._applypatch(patch, False, True)

    def _removePatchFile(self, all = False):
        if not os.path.exists(self.seriespath):
            return
        with open(self.seriespath, u'r+') as f:
            patches = f.readlines()
        if all:
            for p in reversed(patches):
                self._removePatch(os.path.join(self.patchdir, p.strip()))
            patches = []
        else:
            self._removePatch(os.path.join(self.patchdir, patches[-1].strip()))
            patches.pop()
        with open(self.seriespath, u'w') as f:
            for p in patches:
                f.write(p)
         
    def Import(self, patch, force = None):
        u""""""
        PatchSet.Import(self, patch, force)

        if self._current is not None:
            i = self._current + 1
        else:
            i = 0
        self.patches.insert(i, patch)

    def _applypatch(self, patch, force = False, reverse = False, run = True):
        shellcmd = [u"cat", patch[u'file'], u"|", u"patch", u"-p", patch[u'strippath']]
        if reverse:
            shellcmd.append(u'-R')

        if not run:
            return u"sh" + u"-c" + u" ".join(shellcmd)

        if not force:
            shellcmd.append(u'--dry-run')

        try:
            output = runcmd([u"sh", u"-c", u" ".join(shellcmd)], self.dir)

            if force:
                return

            shellcmd.pop(len(shellcmd) - 1)
            output = runcmd([u"sh", u"-c", u" ".join(shellcmd)], self.dir)
        except CmdError, err:
            raise bb.BBHandledException(u"Applying '%s' failed:\n%s" %
                                        (os.path.basename(patch[u'file']), err.output))

        if not reverse:
            self._appendPatchFile(patch[u'file'], patch[u'strippath'])

        return output

    def Push(self, force = False, all = False, run = True):
        bb.note(u"self._current is %s" % self._current)
        bb.note(u"patches is %s" % self.patches)
        if all:
            for i in self.patches:
                bb.note(u"applying patch %s" % i)
                self._applypatch(i, force)
                self._current = i
        else:
            if self._current is not None:
                next = self._current + 1
            else:
                next = 0

            bb.note(u"applying patch %s" % self.patches[next])
            ret = self._applypatch(self.patches[next], force)

            self._current = next
            return ret

    def Pop(self, force = None, all = None):
        if all:
            self._removePatchFile(True)
            self._current = None
        else:
            self._removePatchFile(False)

        if self._current == 0:
            self._current = None

        if self._current is not None:
            self._current = self._current - 1

    def Clean(self):
        u""""""
        self.Pop(all=True)

class GitApplyTree(PatchTree):
    patch_line_prefix = u'%% original patch'
    ignore_commit_prefix = u'%% ignore'

    def __init__(self, dir, d):
        PatchTree.__init__(self, dir, d)
        self.commituser = d.getVar(u'PATCH_GIT_USER_NAME', True)
        self.commitemail = d.getVar(u'PATCH_GIT_USER_EMAIL', True)

    @staticmethod
    def extractPatchHeader(patchfile):
        u"""
        Extract just the header lines from the top of a patch file
        """
        for encoding in [u'utf-8', u'latin-1']:
            lines = []
            try:
                with open(patchfile, u'r', encoding=encoding) as f:
                    for line in f:
                        if line.startswith(u'Index: ') or line.startswith(u'diff -') or line.startswith(u'---'):
                            break
                        lines.append(line)
            except UnicodeDecodeError:
                continue
            break
        else:
            raise PatchError(u'Unable to find a character encoding to decode %s' % patchfile)
        return lines

    @staticmethod
    def decodeAuthor(line):
        from email.header import decode_header
        authorval = line.split(u':', 1)[1].strip().replace(u'"', u'')
        result =  decode_header(authorval)[0][0]
        if hasattr(result, u'decode'):
            result = result.decode(u'utf-8')
        return result

    @staticmethod
    def interpretPatchHeader(headerlines):
        import re
        author_re = re.compile(u'[\S ]+ <\S+@\S+\.\S+>')
        from_commit_re = re.compile(u'^From [a-z0-9]{40} .*')
        outlines = []
        author = None
        date = None
        subject = None
        for line in headerlines:
            if line.startswith(u'Subject: '):
                subject = line.split(u':', 1)[1]
                # Remove any [PATCH][oe-core] etc.
                subject = re.sub(ur'\[.+?\]\s*', u'', subject)
                continue
            elif line.startswith(u'From: ') or line.startswith(u'Author: '):
                authorval = GitApplyTree.decodeAuthor(line)
                # git is fussy about author formatting i.e. it must be Name <email@domain>
                if author_re.match(authorval):
                    author = authorval
                    continue
            elif line.startswith(u'Date: '):
                if date is None:
                    dateval = line.split(u':', 1)[1].strip()
                    # Very crude check for date format, since git will blow up if it's not in the right
                    # format. Without e.g. a python-dateutils dependency we can't do a whole lot more
                    if len(dateval) > 12:
                        date = dateval
                continue
            elif not author and line.lower().startswith(u'signed-off-by: '):
                authorval = GitApplyTree.decodeAuthor(line)
                # git is fussy about author formatting i.e. it must be Name <email@domain>
                if author_re.match(authorval):
                    author = authorval
            elif from_commit_re.match(line):
                # We don't want the From <commit> line - if it's present it will break rebasing
                continue
            outlines.append(line)

        if not subject:
            firstline = None
            for line in headerlines:
                line = line.strip()
                if firstline:
                    if line:
                        # Second line is not blank, the first line probably isn't usable
                        firstline = None
                    break
                elif line:
                    firstline = line
            if firstline and not firstline.startswith((u'#', u'Index:', u'Upstream-Status:')) and len(firstline) < 100:
                subject = firstline

        return outlines, author, date, subject

    @staticmethod
    def gitCommandUserOptions(cmd, commituser=None, commitemail=None, d=None):
        if d:
            commituser = d.getVar(u'PATCH_GIT_USER_NAME', True)
            commitemail = d.getVar(u'PATCH_GIT_USER_EMAIL', True)
        if commituser:
            cmd += [u'-c', u'user.name="%s"' % commituser]
        if commitemail:
            cmd += [u'-c', u'user.email="%s"' % commitemail]

    @staticmethod
    def prepareCommit(patchfile, commituser=None, commitemail=None):
        u"""
        Prepare a git commit command line based on the header from a patch file
        (typically this is useful for patches that cannot be applied with "git am" due to formatting)
        """
        import tempfile
        # Process patch header and extract useful information
        lines = GitApplyTree.extractPatchHeader(patchfile)
        outlines, author, date, subject = GitApplyTree.interpretPatchHeader(lines)
        if not author or not subject or not date:
            try:
                shellcmd = [u"git", u"log", u"--format=email", u"--follow", u"--diff-filter=A", u"--", patchfile]
                out = runcmd([u"sh", u"-c", u" ".join(shellcmd)], os.path.dirname(patchfile))
            except CmdError:
                out = None
            if out:
                _, newauthor, newdate, newsubject = GitApplyTree.interpretPatchHeader(out.splitlines())
                if not author:
                    # If we're setting the author then the date should be set as well
                    author = newauthor
                    date = newdate
                elif not date:
                    # If we don't do this we'll get the current date, at least this will be closer
                    date = newdate
                if not subject:
                    subject = newsubject
        if subject and outlines and not outlines[0].strip() == subject:
            outlines.insert(0, u'%s\n\n' % subject.strip())

        # Write out commit message to a file
        with tempfile.NamedTemporaryFile(u'w', delete=False) as tf:
            tmpfile = tf.name
            for line in outlines:
                tf.write(line)
        # Prepare git command
        cmd = [u"git"]
        GitApplyTree.gitCommandUserOptions(cmd, commituser, commitemail)
        cmd += [u"commit", u"-F", tmpfile]
        # git doesn't like plain email addresses as authors
        if author and u'<' in author:
            cmd.append(u'--author="%s"' % author)
        if date:
            cmd.append(u'--date="%s"' % date)
        return (tmpfile, cmd)

    @staticmethod
    def extractPatches(tree, startcommit, outdir, paths=None):
        import tempfile
        import shutil
        import re
        tempdir = tempfile.mkdtemp(prefix=u'oepatch')
        try:
            shellcmd = [u"git", u"format-patch", startcommit, u"-o", tempdir]
            if paths:
                shellcmd.append(u'--')
                shellcmd.extend(paths)
            out = runcmd([u"sh", u"-c", u" ".join(shellcmd)], tree)
            if out:
                for srcfile in out.split():
                    for encoding in [u'utf-8', u'latin-1']:
                        patchlines = []
                        outfile = None
                        try:
                            with open(srcfile, u'r', encoding=encoding) as f:
                                for line in f:
                                    checkline = line
                                    if checkline.startswith(u'Subject: '):
                                        checkline = re.sub(ur'\[.+?\]\s*', u'', checkline[9:])
                                    if checkline.startswith(GitApplyTree.patch_line_prefix):
                                        outfile = line.split()[-1].strip()
                                        continue
                                    if checkline.startswith(GitApplyTree.ignore_commit_prefix):
                                        continue
                                    patchlines.append(line)
                        except UnicodeDecodeError:
                            continue
                        break
                    else:
                        raise PatchError(u'Unable to find a character encoding to decode %s' % srcfile)

                    if not outfile:
                        outfile = os.path.basename(srcfile)
                    with open(os.path.join(outdir, outfile), u'w') as of:
                        for line in patchlines:
                            of.write(line)
        finally:
            shutil.rmtree(tempdir)

    def _applypatch(self, patch, force = False, reverse = False, run = True):
        import shutil

        def _applypatchhelper(shellcmd, patch, force = False, reverse = False, run = True):
            if reverse:
                shellcmd.append(u'-R')

            shellcmd.append(patch[u'file'])

            if not run:
                return u"sh" + u"-c" + u" ".join(shellcmd)

            return runcmd([u"sh", u"-c", u" ".join(shellcmd)], self.dir)

        # Add hooks which add a pointer to the original patch file name in the commit message
        reporoot = (runcmd(u"git rev-parse --show-toplevel".split(), self.dir) or u'').strip()
        if not reporoot:
            raise Exception(u"Cannot get repository root for directory %s" % self.dir)
        hooks_dir = os.path.join(reporoot, u'.git', u'hooks')
        hooks_dir_backup = hooks_dir + u'.devtool-orig'
        if os.path.lexists(hooks_dir_backup):
            raise Exception(u"Git hooks backup directory already exists: %s" % hooks_dir_backup)
        if os.path.lexists(hooks_dir):
            shutil.move(hooks_dir, hooks_dir_backup)
        os.mkdir(hooks_dir)
        commithook = os.path.join(hooks_dir, u'commit-msg')
        applyhook = os.path.join(hooks_dir, u'applypatch-msg')
        with open(commithook, u'w') as f:
            # NOTE: the formatting here is significant; if you change it you'll also need to
            # change other places which read it back
            f.write(u'echo >> $1\n')
            f.write(u'echo "%s: $PATCHFILE" >> $1\n' % GitApplyTree.patch_line_prefix)
        os.chmod(commithook, 0755)
        shutil.copy2(commithook, applyhook)
        try:
            patchfilevar = u'PATCHFILE="%s"' % os.path.basename(patch[u'file'])
            try:
                shellcmd = [patchfilevar, u"git", u"--work-tree=%s" % reporoot]
                self.gitCommandUserOptions(shellcmd, self.commituser, self.commitemail)
                shellcmd += [u"am", u"-3", u"--keep-cr", u"-p%s" % patch[u'strippath']]
                return _applypatchhelper(shellcmd, patch, force, reverse, run)
            except CmdError:
                # Need to abort the git am, or we'll still be within it at the end
                try:
                    shellcmd = [u"git", u"--work-tree=%s" % reporoot, u"am", u"--abort"]
                    runcmd([u"sh", u"-c", u" ".join(shellcmd)], self.dir)
                except CmdError:
                    pass
                # git am won't always clean up after itself, sadly, so...
                shellcmd = [u"git", u"--work-tree=%s" % reporoot, u"reset", u"--hard", u"HEAD"]
                runcmd([u"sh", u"-c", u" ".join(shellcmd)], self.dir)
                # Also need to take care of any stray untracked files
                shellcmd = [u"git", u"--work-tree=%s" % reporoot, u"clean", u"-f"]
                runcmd([u"sh", u"-c", u" ".join(shellcmd)], self.dir)

                # Fall back to git apply
                shellcmd = [u"git", u"--git-dir=%s" % reporoot, u"apply", u"-p%s" % patch[u'strippath']]
                try:
                    output = _applypatchhelper(shellcmd, patch, force, reverse, run)
                except CmdError:
                    # Fall back to patch
                    output = PatchTree._applypatch(self, patch, force, reverse, run)
                # Add all files
                shellcmd = [u"git", u"add", u"-f", u"-A", u"."]
                output += runcmd([u"sh", u"-c", u" ".join(shellcmd)], self.dir)
                # Exclude the patches directory
                shellcmd = [u"git", u"reset", u"HEAD", self.patchdir]
                output += runcmd([u"sh", u"-c", u" ".join(shellcmd)], self.dir)
                # Commit the result
                (tmpfile, shellcmd) = self.prepareCommit(patch[u'file'], self.commituser, self.commitemail)
                try:
                    shellcmd.insert(0, patchfilevar)
                    output += runcmd([u"sh", u"-c", u" ".join(shellcmd)], self.dir)
                finally:
                    os.remove(tmpfile)
                return output
        finally:
            shutil.rmtree(hooks_dir)
            if os.path.lexists(hooks_dir_backup):
                shutil.move(hooks_dir_backup, hooks_dir)


class QuiltTree(PatchSet):
    def _runcmd(self, args, run = True):
        quiltrc = self.d.getVar(u'QUILTRCFILE', True)
        if not run:
            return [u"quilt"] + [u"--quiltrc"] + [quiltrc] + args
        runcmd([u"quilt"] + [u"--quiltrc"] + [quiltrc] + args, self.dir)

    def _quiltpatchpath(self, file):
        return os.path.join(self.dir, u"patches", os.path.basename(file))


    def __init__(self, dir, d):
        PatchSet.__init__(self, dir, d)
        self.initialized = False
        p = os.path.join(self.dir, u'patches')
        if not os.path.exists(p):
            os.makedirs(p)

    def Clean(self):
        try:
            self._runcmd([u"pop", u"-a", u"-f"])
            oe.path.remove(os.path.join(self.dir, u"patches",u"series"))
        except Exception:
            pass
        self.initialized = True

    def InitFromDir(self):
        # read series -> self.patches
        seriespath = os.path.join(self.dir, u'patches', u'series')
        if not os.path.exists(self.dir):
            raise NotFoundError(self.dir)
        if os.path.exists(seriespath):
            with open(seriespath, u'r') as f:
                for line in f.readlines():
                    patch = {}
                    parts = line.strip().split()
                    patch[u"quiltfile"] = self._quiltpatchpath(parts[0])
                    patch[u"quiltfilemd5"] = bb.utils.md5_file(patch[u"quiltfile"])
                    if len(parts) > 1:
                        patch[u"strippath"] = parts[1][2:]
                    self.patches.append(patch)

            # determine which patches are applied -> self._current
            try:
                output = runcmd([u"quilt", u"applied"], self.dir)
            except CmdError:
                import sys
                if sys.exc_value.output.strip() == u"No patches applied":
                    return
                else:
                    raise
            output = [val for val in output.split(u'\n') if not val.startswith(u'#')]
            for patch in self.patches:
                if os.path.basename(patch[u"quiltfile"]) == output[-1]:
                    self._current = self.patches.index(patch)
        self.initialized = True

    def Import(self, patch, force = None):
        if not self.initialized:
            self.InitFromDir()
        PatchSet.Import(self, patch, force)
        oe.path.symlink(patch[u"file"], self._quiltpatchpath(patch[u"file"]), force=True)
        with open(os.path.join(self.dir, u"patches", u"series"), u"a") as f:
            f.write(os.path.basename(patch[u"file"]) + u" -p" + patch[u"strippath"] + u"\n")
        patch[u"quiltfile"] = self._quiltpatchpath(patch[u"file"])
        patch[u"quiltfilemd5"] = bb.utils.md5_file(patch[u"quiltfile"])

        # TODO: determine if the file being imported:
        #      1) is already imported, and is the same
        #      2) is already imported, but differs

        self.patches.insert(self._current or 0, patch)


    def Push(self, force = False, all = False, run = True):
        # quilt push [-f]

        args = [u"push"]
        if force:
            args.append(u"-f")
        if all:
            args.append(u"-a")
        if not run:
            return self._runcmd(args, run)

        self._runcmd(args)

        if self._current is not None:
            self._current = self._current + 1
        else:
            self._current = 0

    def Pop(self, force = None, all = None):
        # quilt pop [-f]
        args = [u"pop"]
        if force:
            args.append(u"-f")
        if all:
            args.append(u"-a")

        self._runcmd(args)

        if self._current == 0:
            self._current = None

        if self._current is not None:
            self._current = self._current - 1

    def Refresh(self, **kwargs):
        if kwargs.get(u"remote"):
            patch = self.patches[kwargs[u"patch"]]
            if not patch:
                raise PatchError(u"No patch found at index %s in patchset." % kwargs[u"patch"])
            (type, host, path, user, pswd, parm) = bb.fetch.decodeurl(patch[u"remote"])
            if type == u"file":
                import shutil
                if not patch.get(u"file") and patch.get(u"remote"):
                    patch[u"file"] = bb.fetch2.localpath(patch[u"remote"], self.d)

                shutil.copyfile(patch[u"quiltfile"], patch[u"file"])
            else:
                raise PatchError(u"Unable to do a remote refresh of %s, unsupported remote url scheme %s." % (os.path.basename(patch[u"quiltfile"]), type))
        else:
            # quilt refresh
            args = [u"refresh"]
            if kwargs.get(u"quiltfile"):
                args.append(os.path.basename(kwargs[u"quiltfile"]))
            elif kwargs.get(u"patch"):
                args.append(os.path.basename(self.patches[kwargs[u"patch"]][u"quiltfile"]))
            self._runcmd(args)

class Resolver(object):
    def __init__(self, patchset, terminal):
        raise NotImplementedError()

    def Resolve(self):
        raise NotImplementedError()

    def Revert(self):
        raise NotImplementedError()

    def Finalize(self):
        raise NotImplementedError()

class NOOPResolver(Resolver):
    def __init__(self, patchset, terminal):
        self.patchset = patchset
        self.terminal = terminal

    def Resolve(self):
        olddir = os.path.abspath(os.curdir)
        os.chdir(self.patchset.dir)
        try:
            self.patchset.Push()
        except Exception:
            import sys
            os.chdir(olddir)
            raise

# Patch resolver which relies on the user doing all the work involved in the
# resolution, with the exception of refreshing the remote copy of the patch
# files (the urls).
class UserResolver(Resolver):
    def __init__(self, patchset, terminal):
        self.patchset = patchset
        self.terminal = terminal

    # Force a push in the patchset, then drop to a shell for the user to
    # resolve any rejected hunks
    def Resolve(self):
        olddir = os.path.abspath(os.curdir)
        os.chdir(self.patchset.dir)
        try:
            self.patchset.Push(False)
        except CmdError, v:
            # Patch application failed
            patchcmd = self.patchset.Push(True, False, False)

            t = self.patchset.d.getVar(u'T', True)
            if not t:
                bb.msg.fatal(u"Build", u"T not set")
            bb.utils.mkdirhier(t)
            import random
            rcfile = u"%s/bashrc.%s.%s" % (t, unicode(os.getpid()), random.random())
            with open(rcfile, u"w") as f:
                f.write(u"echo '*** Manual patch resolution mode ***'\n")
                f.write(u"echo 'Dropping to a shell, so patch rejects can be fixed manually.'\n")
                f.write(u"echo 'Run \"quilt refresh\" when patch is corrected, press CTRL+D to exit.'\n")
                f.write(u"echo ''\n")
                f.write(u" ".join(patchcmd) + u"\n")
            os.chmod(rcfile, 0775)

            self.terminal(u"bash --rcfile " + rcfile, u'Patch Rejects: Please fix patch rejects manually', self.patchset.d)

            # Construct a new PatchSet after the user's changes, compare the
            # sets, checking patches for modifications, and doing a remote
            # refresh on each.
            oldpatchset = self.patchset
            self.patchset = oldpatchset.__class__(self.patchset.dir, self.patchset.d)

            for patch in self.patchset.patches:
                oldpatch = None
                for opatch in oldpatchset.patches:
                    if opatch[u"quiltfile"] == patch[u"quiltfile"]:
                        oldpatch = opatch

                if oldpatch:
                    patch[u"remote"] = oldpatch[u"remote"]
                    if patch[u"quiltfile"] == oldpatch[u"quiltfile"]:
                        if patch[u"quiltfilemd5"] != oldpatch[u"quiltfilemd5"]:
                            bb.note(u"Patch %s has changed, updating remote url %s" % (os.path.basename(patch[u"quiltfile"]), patch[u"remote"]))
                            # user change?  remote refresh
                            self.patchset.Refresh(remote=True, patch=self.patchset.patches.index(patch))
                        else:
                            # User did not fix the problem.  Abort.
                            raise PatchError(u"Patch application failed, and user did not fix and refresh the patch.")
        except Exception:
            os.chdir(olddir)
            raise
        os.chdir(olddir)


def patch_path(url, fetch, workdir, expand=True):
    u"""Return the local path of a patch, or None if this isn't a patch"""

    local = fetch.localpath(url)
    base, ext = os.path.splitext(os.path.basename(local))
    if ext in (u'.gz', u'.bz2', u'.xz', u'.Z'):
        if expand:
            local = os.path.join(workdir, base)
        ext = os.path.splitext(base)[1]

    urldata = fetch.ud[url]
    if u"apply" in urldata.parm:
        apply = oe.types.boolean(urldata.parm[u"apply"])
        if not apply:
            return
    elif ext not in (u".diff", u".patch"):
        return

    return local

def src_patches(d, all=False, expand=True):
    workdir = d.getVar(u'WORKDIR', True)
    fetch = bb.fetch2.Fetch([], d)
    patches = []
    sources = []
    for url in fetch.urls:
        local = patch_path(url, fetch, workdir, expand)
        if not local:
            if all:
                local = fetch.localpath(url)
                sources.append(local)
            continue

        urldata = fetch.ud[url]
        parm = urldata.parm
        patchname = parm.get(u'pname') or os.path.basename(local)

        apply, reason = should_apply(parm, d)
        if not apply:
            if reason:
                bb.note(u"Patch %s %s" % (patchname, reason))
            continue

        patchparm = {u'patchname': patchname}
        if u"striplevel" in parm:
            striplevel = parm[u"striplevel"]
        elif u"pnum" in parm:
            #bb.msg.warn(None, "Deprecated usage of 'pnum' url parameter in '%s', please use 'striplevel'" % url)
            striplevel = parm[u"pnum"]
        else:
            striplevel = u'1'
        patchparm[u'striplevel'] = striplevel

        patchdir = parm.get(u'patchdir')
        if patchdir:
            patchparm[u'patchdir'] = patchdir

        localurl = bb.fetch.encodeurl((u'file', u'', local, u'', u'', patchparm))
        patches.append(localurl)

    if all:
        return sources

    return patches


def should_apply(parm, d):
    if u"mindate" in parm or u"maxdate" in parm:
        pn = d.getVar(u'PN', True)
        srcdate = d.getVar(u'SRCDATE_%s' % pn, True)
        if not srcdate:
            srcdate = d.getVar(u'SRCDATE', True)

        if srcdate == u"now":
            srcdate = d.getVar(u'DATE', True)

        if u"maxdate" in parm and parm[u"maxdate"] < srcdate:
            return False, u'is outdated'

        if u"mindate" in parm and parm[u"mindate"] > srcdate:
            return False, u'is predated'


    if u"minrev" in parm:
        srcrev = d.getVar(u'SRCREV', True)
        if srcrev and srcrev < parm[u"minrev"]:
            return False, u'applies to later revisions'

    if u"maxrev" in parm:
        srcrev = d.getVar(u'SRCREV', True)
        if srcrev and srcrev > parm[u"maxrev"]:
            return False, u'applies to earlier revisions'

    if u"rev" in parm:
        srcrev = d.getVar(u'SRCREV', True)
        if srcrev and parm[u"rev"] not in srcrev:
            return False, u"doesn't apply to revision"

    if u"notrev" in parm:
        srcrev = d.getVar(u'SRCREV', True)
        if srcrev and parm[u"notrev"] in srcrev:
            return False, u"doesn't apply to revision"

    return True, None

