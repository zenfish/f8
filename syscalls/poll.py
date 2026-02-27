"""Polling/multiplexing syscalls: select, poll, kevent, kqueue."""

from . import SyscallHandler, register


@register
class PollHandler(SyscallHandler):
    categories = ["poll"]
    syscalls = [
        "select", "select_nocancel",
        "poll", "poll_nocancel",
        "kevent", "kevent64",
        "kqueue",
    ]

    dtrace = r'''
/* ============================================ */
/* POLLING / SELECT                             */
/* ============================================ */

syscall::select:entry,
syscall::select_nocancel:entry
/TRACED/
{
    self->sel_nfds = arg0;
    self->sel_ts = walltimestamp/1000;
}

syscall::select:return,
syscall::select_nocancel:return
/TRACED && self->sel_ts/
{
    printf("MACTRACE_SYSCALL %d %d select %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->sel_ts, self->sel_nfds);
    self->sel_ts = 0;
}

syscall::poll:entry,
syscall::poll_nocancel:entry
/TRACED/
{
    self->poll_nfds = arg1;
    self->poll_timeout = arg2;
    self->poll_ts = walltimestamp/1000;
}

syscall::poll:return,
syscall::poll_nocancel:return
/TRACED && self->poll_ts/
{
    printf("MACTRACE_SYSCALL %d %d poll %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->poll_ts, self->poll_nfds, self->poll_timeout);
    self->poll_ts = 0;
}

syscall::kevent:entry,
syscall::kevent64:entry
/TRACED/
{
    self->kev_fd = arg0;
    self->kev_ts = walltimestamp/1000;
}

syscall::kevent:return,
syscall::kevent64:return
/TRACED && self->kev_ts/
{
    printf("MACTRACE_SYSCALL %d %d kevent %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->kev_ts, self->kev_fd);
    self->kev_ts = 0;
}

syscall::kqueue:return
/TRACED/
{
    printf("MACTRACE_SYSCALL %d %d kqueue %d %d %d\n",
        pid, tid, (int)arg1, errno, walltimestamp/1000);
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall in ("select", "select_nocancel"):
            if len(args) >= 1:
                result["nfds"] = self.parse_int(args[0])
        elif syscall in ("poll", "poll_nocancel"):
            if len(args) >= 1:
                result["nfds"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["timeout"] = self.parse_int(args[1])
        elif syscall in ("kevent", "kevent64"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
        # kqueue: no args
        return result
