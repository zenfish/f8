"""File open syscalls: open, openat (+ _nocancel variants)."""

from . import SyscallHandler, register
from ._constants import parse_open_flags


@register
class FileOpenHandler(SyscallHandler):
    syscalls = [
        "open", "open_nocancel",
        "openat", "openat_nocancel",
    ]

    dtrace = r'''
/* ============================================ */
/* FILE OPEN                                    */
/* ============================================ */

syscall::open:entry,
syscall::open_nocancel:entry
/TRACED/
{
    self->open_path = copyinstr(arg0);
    self->open_flags = arg1;
    self->open_mode = arg2;
    self->open_ts = walltimestamp/1000;
}

syscall::open:return,
syscall::open_nocancel:return
/TRACED && self->open_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d open %d %d %d \"%s\" 0x%x 0%o\n",
        pid, tid, (int)arg1, errno, self->open_ts, 
        self->open_path, self->open_flags, self->open_mode);
    self->open_path = NULL;
}

syscall::openat:entry,
syscall::openat_nocancel:entry
/TRACED/
{
    self->openat_fd = arg0;
    self->openat_path = copyinstr(arg1);
    self->openat_flags = arg2;
    self->openat_mode = arg3;
    self->openat_ts = walltimestamp/1000;
}

syscall::openat:return,
syscall::openat_nocancel:return
/TRACED && self->openat_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d openat %d %d %d %d \"%s\" 0x%x 0%o\n",
        pid, tid, (int)arg1, errno, self->openat_ts,
        self->openat_fd, self->openat_path, self->openat_flags, self->openat_mode);
    self->openat_path = NULL;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall in ("open", "open_nocancel"):
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
            if len(args) >= 2:
                flags = self.parse_int(args[1])
                result["flags"] = parse_open_flags(flags)
                result["flags_raw"] = flags
            if len(args) >= 3:
                result["mode"] = args[2]
        elif syscall in ("openat", "openat_nocancel"):
            if len(args) >= 1:
                result["dirfd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["path"] = self.clean_str(args[1])
            if len(args) >= 3:
                flags = self.parse_int(args[2])
                result["flags"] = parse_open_flags(flags)
            if len(args) >= 4:
                result["mode"] = args[3]
        return result

    def update_fd_info(self, event, fd_tracker):
        if event.return_value >= 0 and "path" in event.args:
            fd_tracker.set_file(event.pid, event.return_value, event.args["path"])
