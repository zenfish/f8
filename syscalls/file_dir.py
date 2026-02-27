"""Directory syscalls: chdir, fchdir, mkdir, rmdir, getdirentries64, getattrlistbulk."""

from . import SyscallHandler, register


@register
class FileDirHandler(SyscallHandler):
    categories = ["file"]
    syscalls = [
        "chdir", "fchdir", "mkdir", "rmdir",
        "getdirentries64", "getattrlistbulk",
    ]

    dtrace = r'''
/* ============================================ */
/* DIRECTORY OPERATIONS                         */
/* ============================================ */

syscall::mkdir:entry
/TRACED/
{
    self->mkdir_path = copyinstr(arg0);
    self->mkdir_mode = arg1;
    self->mkdir_ts = walltimestamp/1000;
}

syscall::mkdir:return
/TRACED && self->mkdir_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d mkdir %d %d %d \"%s\" 0%o\n",
        pid, tid, (int)arg1, errno, self->mkdir_ts, self->mkdir_path, self->mkdir_mode);
    self->mkdir_path = NULL;
}

syscall::rmdir:entry
/TRACED/
{
    self->rmdir_path = copyinstr(arg0);
    self->rmdir_ts = walltimestamp/1000;
}

syscall::rmdir:return
/TRACED && self->rmdir_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d rmdir %d %d %d \"%s\"\n",
        pid, tid, (int)arg1, errno, self->rmdir_ts, self->rmdir_path);
    self->rmdir_path = NULL;
}

syscall::chdir:entry
/TRACED/
{
    self->chdir_path = copyinstr(arg0);
    self->chdir_ts = walltimestamp/1000;
}

syscall::chdir:return
/TRACED && self->chdir_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d chdir %d %d %d \"%s\"\n",
        pid, tid, (int)arg1, errno, self->chdir_ts, self->chdir_path);
    self->chdir_path = NULL;
}

syscall::fchdir:entry
/TRACED/
{
    self->fchdir_fd = arg0;
    self->fchdir_ts = walltimestamp/1000;
}

syscall::fchdir:return
/TRACED && self->fchdir_ts/
{
    printf("MACTRACE_SYSCALL %d %d fchdir %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->fchdir_ts, self->fchdir_fd);
    self->fchdir_ts = 0;
}

syscall::getdirentries64:entry
/TRACED/
{
    self->getdents_fd = arg0;
    self->getdents_ts = walltimestamp/1000;
}

syscall::getdirentries64:return
/TRACED && self->getdents_ts/
{
    printf("MACTRACE_SYSCALL %d %d getdirentries64 %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->getdents_ts, self->getdents_fd);
    self->getdents_ts = 0;
}

syscall::getattrlistbulk:entry
/TRACED/
{
    self->gab_fd = arg0;
    self->gab_ts = walltimestamp/1000;
}

syscall::getattrlistbulk:return
/TRACED && self->gab_ts/
{
    printf("MACTRACE_SYSCALL %d %d getattrlistbulk %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->gab_ts, self->gab_fd);
    self->gab_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall in ("chdir", "rmdir"):
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
        elif syscall == "fchdir":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
        elif syscall == "mkdir":
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
            if len(args) >= 2:
                result["mode"] = args[1]
        elif syscall in ("getdirentries64", "getattrlistbulk"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
        return result
