"""Vectored read/write syscalls: readv, writev, preadv, pwritev (+ _nocancel variants).

Scatter/gather I/O used by databases (PostgreSQL, MySQL), high-performance
servers, and the OS itself. Captures fd, iov count, and total bytes
transferred (return value). For preadv/pwritev, also captures offset.

When --iovec is enabled, the saved iov pointer (self->*_iov) is used by
the unrolled capture probes generated in _build_iovec_capture_probes().
"""

from . import SyscallHandler, register


@register
class FileRWVecHandler(SyscallHandler):
    categories = ["file"]
    syscalls = [
        "readv", "readv_nocancel",
        "writev", "writev_nocancel",
        "preadv",
        "pwritev",
    ]

    dtrace = r'''
/* ============================================ */
/* VECTORED FILE READ / WRITE                   */
/* ============================================ */

syscall::readv:entry,
syscall::readv_nocancel:entry
/TRACED/
{
    self->readv_fd = arg0;
    self->readv_iov = arg1;
    self->readv_iovcnt = (int)arg2;
    self->readv_ts = walltimestamp/1000;
}

syscall::readv:return,
syscall::readv_nocancel:return
/TRACED && self->readv_ts/
{
    printf("F8_SYSCALL %d %d readv %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->readv_ts,
        self->readv_fd, self->readv_iovcnt);
    self->readv_ts = 0;
}

syscall::writev:entry,
syscall::writev_nocancel:entry
/TRACED/
{
    self->writev_fd = arg0;
    self->writev_iov = arg1;
    self->writev_iovcnt = (int)arg2;
    self->writev_ts = walltimestamp/1000;
}

syscall::writev:return,
syscall::writev_nocancel:return
/TRACED && self->writev_ts/
{
    printf("F8_SYSCALL %d %d writev %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->writev_ts,
        self->writev_fd, self->writev_iovcnt);
    self->writev_ts = 0;
}

syscall::preadv:entry
/TRACED/
{
    self->preadv_fd = arg0;
    self->preadv_iov = arg1;
    self->preadv_iovcnt = (int)arg2;
    self->preadv_off = arg3;
    self->preadv_ts = walltimestamp/1000;
}

syscall::preadv:return
/TRACED && self->preadv_ts/
{
    printf("F8_SYSCALL %d %d preadv %d %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->preadv_ts,
        self->preadv_fd, self->preadv_iovcnt, self->preadv_off);
    self->preadv_ts = 0;
}

syscall::pwritev:entry
/TRACED/
{
    self->pwritev_fd = arg0;
    self->pwritev_iov = arg1;
    self->pwritev_iovcnt = (int)arg2;
    self->pwritev_off = arg3;
    self->pwritev_ts = walltimestamp/1000;
}

syscall::pwritev:return
/TRACED && self->pwritev_ts/
{
    printf("F8_SYSCALL %d %d pwritev %d %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->pwritev_ts,
        self->pwritev_fd, self->pwritev_iovcnt, self->pwritev_off);
    self->pwritev_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall in ("readv", "readv_nocancel", "writev", "writev_nocancel"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["iovcnt"] = self.parse_int(args[1])
        elif syscall in ("preadv", "pwritev"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["iovcnt"] = self.parse_int(args[1])
            if len(args) >= 3:
                result["offset"] = self.parse_int(args[2])
        return result
