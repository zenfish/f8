"""Permission/truncate syscalls: chmod, fchmod, truncate, ftruncate."""

from . import SyscallHandler, register


@register
class FilePermHandler(SyscallHandler):
    syscalls = ["chmod", "fchmod", "truncate", "ftruncate"]

    dtrace = r'''
/* ============================================ */
/* FILE PERMISSIONS / TRUNCATE                  */
/* ============================================ */

syscall::chmod:entry
/TRACED/
{
    self->chmod_path = copyinstr(arg0);
    self->chmod_mode = arg1;
    self->chmod_ts = walltimestamp/1000;
}

syscall::chmod:return
/TRACED && self->chmod_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d chmod %d %d %d \"%s\" 0%o\n",
        pid, tid, (int)arg1, errno, self->chmod_ts, self->chmod_path, self->chmod_mode);
    self->chmod_path = NULL;
}

syscall::fchmod:entry
/TRACED/
{
    self->fchmod_fd = arg0;
    self->fchmod_mode = arg1;
    self->fchmod_ts = walltimestamp/1000;
}

syscall::fchmod:return
/TRACED && self->fchmod_ts/
{
    printf("MACTRACE_SYSCALL %d %d fchmod %d %d %d %d 0%o\n",
        pid, tid, (int)arg1, errno, self->fchmod_ts, self->fchmod_fd, self->fchmod_mode);
    self->fchmod_ts = 0;
}

syscall::truncate:entry
/TRACED/
{
    self->trunc_path = copyinstr(arg0);
    self->trunc_len = arg1;
    self->trunc_ts = walltimestamp/1000;
}

syscall::truncate:return
/TRACED && self->trunc_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d truncate %d %d %d \"%s\" %d\n",
        pid, tid, (int)arg1, errno, self->trunc_ts, self->trunc_path, self->trunc_len);
    self->trunc_path = NULL;
}

syscall::ftruncate:entry
/TRACED/
{
    self->ftrunc_fd = arg0;
    self->ftrunc_len = arg1;
    self->ftrunc_ts = walltimestamp/1000;
}

syscall::ftruncate:return
/TRACED && self->ftrunc_ts/
{
    printf("MACTRACE_SYSCALL %d %d ftruncate %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->ftrunc_ts, self->ftrunc_fd, self->ftrunc_len);
    self->ftrunc_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall == "chmod":
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
            if len(args) >= 2:
                result["mode"] = args[1]
        elif syscall == "fchmod":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["mode"] = args[1]
        elif syscall == "truncate":
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
            if len(args) >= 2:
                result["length"] = self.parse_int(args[1])
        elif syscall == "ftruncate":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["length"] = self.parse_int(args[1])
        return result
