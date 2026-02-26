"""File close syscall."""

from . import SyscallHandler, register


@register
class FileCloseHandler(SyscallHandler):
    syscalls = ["close", "close_nocancel"]

    dtrace = r'''
syscall::close:entry,
syscall::close_nocancel:entry
/TRACED/
{
    self->close_fd = arg0;
    self->close_ts = walltimestamp/1000;
}

syscall::close:return,
syscall::close_nocancel:return
/TRACED && self->close_ts/
{
    printf("MACTRACE_SYSCALL %d %d close %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->close_ts, self->close_fd);
    self->close_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if len(args) >= 1:
            result["fd"] = self.parse_int(args[0])
        return result

    def update_fd_info(self, event, fd_tracker):
        fd = event.args.get("fd")
        if fd is not None:
            fd_tracker.remove(event.pid, fd)
