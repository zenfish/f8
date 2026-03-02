"""Read/write syscalls: read, write, pread, pwrite (+ _nocancel variants)."""

from . import SyscallHandler, register


@register
class FileRWHandler(SyscallHandler):
    categories = ["file"]
    syscalls = [
        "read", "read_nocancel",
        "write", "write_nocancel",
        "pread", "pread_nocancel",
        "pwrite", "pwrite_nocancel",
    ]

    dtrace = r'''
/* ============================================ */
/* FILE READ / WRITE                            */
/* ============================================ */

syscall::read:entry,
syscall::read_nocancel:entry
/TRACED/
{
    self->read_fd = arg0;
    self->read_size = arg2;
    self->read_ts = walltimestamp/1000;
}

syscall::read:return,
syscall::read_nocancel:return
/TRACED && self->read_ts/
{
    printf("F8_SYSCALL %d %d read %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->read_ts, self->read_fd, self->read_size);
    self->read_ts = 0;
}

syscall::pread:entry,
syscall::pread_nocancel:entry
/TRACED/
{
    self->pread_fd = arg0;
    self->pread_size = arg2;
    self->pread_off = arg3;
    self->pread_ts = walltimestamp/1000;
}

syscall::pread:return,
syscall::pread_nocancel:return
/TRACED && self->pread_ts/
{
    printf("F8_SYSCALL %d %d pread %d %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->pread_ts, 
        self->pread_fd, self->pread_size, self->pread_off);
    self->pread_ts = 0;
}

syscall::write:entry,
syscall::write_nocancel:entry
/TRACED/
{
    self->write_fd = arg0;
    self->write_size = arg2;
    self->write_ts = walltimestamp/1000;
}

syscall::write:return,
syscall::write_nocancel:return
/TRACED && self->write_ts/
{
    printf("F8_SYSCALL %d %d write %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->write_ts, self->write_fd, self->write_size);
    self->write_ts = 0;
}

syscall::pwrite:entry,
syscall::pwrite_nocancel:entry
/TRACED/
{
    self->pwrite_fd = arg0;
    self->pwrite_size = arg2;
    self->pwrite_off = arg3;
    self->pwrite_ts = walltimestamp/1000;
}

syscall::pwrite:return,
syscall::pwrite_nocancel:return
/TRACED && self->pwrite_ts/
{
    printf("F8_SYSCALL %d %d pwrite %d %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->pwrite_ts,
        self->pwrite_fd, self->pwrite_size, self->pwrite_off);
    self->pwrite_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall in ("read", "read_nocancel", "write", "write_nocancel"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["count"] = self.parse_int(args[1])
        elif syscall in ("pread", "pread_nocancel", "pwrite", "pwrite_nocancel"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["count"] = self.parse_int(args[1])
            if len(args) >= 3:
                result["offset"] = self.parse_int(args[2])
        return result
