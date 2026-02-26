"""Stat/access syscalls: stat64, lstat64, fstat64, fstatat64, access, faccessat."""

from . import SyscallHandler, register


@register
class FileStatHandler(SyscallHandler):
    syscalls = [
        "stat64", "lstat64", "fstat64", "fstatat64",
        "access", "faccessat",
    ]

    dtrace = r'''
/* ============================================ */
/* FILE STAT / ACCESS                           */
/* ============================================ */

syscall::stat64:entry
/TRACED/
{
    self->stat_path = copyinstr(arg0);
    self->stat_is_lstat = 0;
    self->stat_ts = walltimestamp/1000;
}

syscall::lstat64:entry
/TRACED/
{
    self->stat_path = copyinstr(arg0);
    self->stat_is_lstat = 1;
    self->stat_ts = walltimestamp/1000;
}

syscall::stat64:return,
syscall::lstat64:return
/TRACED && self->stat_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d %s %d %d %d \"%s\"\n",
        pid, tid, self->stat_is_lstat ? "lstat64" : "stat64",
        (int)arg1, errno, self->stat_ts, self->stat_path);
    self->stat_path = NULL;
}

syscall::fstat64:entry
/TRACED/
{
    self->fstat_fd = arg0;
    self->fstat_ts = walltimestamp/1000;
}

syscall::fstat64:return
/TRACED && self->fstat_ts/
{
    printf("MACTRACE_SYSCALL %d %d fstat64 %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->fstat_ts, self->fstat_fd);
    self->fstat_ts = 0;
}

syscall::fstatat64:entry
/TRACED/
{
    self->fstatat_fd = arg0;
    self->fstatat_path = copyinstr(arg1);
    self->fstatat_flag = arg3;
    self->fstatat_ts = walltimestamp/1000;
}

syscall::fstatat64:return
/TRACED && self->fstatat_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d fstatat64 %d %d %d %d \"%s\" 0x%x\n",
        pid, tid, (int)arg1, errno, self->fstatat_ts, self->fstatat_fd, self->fstatat_path, self->fstatat_flag);
    self->fstatat_path = NULL;
}

syscall::access:entry
/TRACED/
{
    self->access_path = copyinstr(arg0);
    self->access_mode = arg1;
    self->access_ts = walltimestamp/1000;
}

syscall::access:return
/TRACED && self->access_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d access %d %d %d \"%s\" %d\n",
        pid, tid, (int)arg1, errno, self->access_ts, self->access_path, self->access_mode);
    self->access_path = NULL;
}

syscall::faccessat:entry
/TRACED/
{
    self->faccessat_fd = arg0;
    self->faccessat_path = copyinstr(arg1);
    self->faccessat_mode = arg2;
    self->faccessat_ts = walltimestamp/1000;
}

syscall::faccessat:return
/TRACED && self->faccessat_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d faccessat %d %d %d %d \"%s\" %d\n",
        pid, tid, (int)arg1, errno, self->faccessat_ts,
        self->faccessat_fd, self->faccessat_path, self->faccessat_mode);
    self->faccessat_path = NULL;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall in ("stat64", "lstat64"):
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
        elif syscall == "fstat64":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
        elif syscall == "fstatat64":
            if len(args) >= 1:
                result["dirfd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["path"] = self.clean_str(args[1])
            if len(args) >= 3:
                result["flag"] = args[2]
        elif syscall == "access":
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
            if len(args) >= 2:
                result["mode"] = self.parse_int(args[1])
        elif syscall == "faccessat":
            if len(args) >= 1:
                result["dirfd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["path"] = self.clean_str(args[1])
            if len(args) >= 3:
                result["mode"] = self.parse_int(args[2])
        return result
