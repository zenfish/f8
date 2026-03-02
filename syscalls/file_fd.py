"""File descriptor syscalls: dup, dup2, fcntl, ioctl, fsync."""

from . import SyscallHandler, register
from ._constants import parse_fcntl_cmd


@register
class FileFdHandler(SyscallHandler):
    categories = ["file"]
    syscalls = [
        "dup", "dup2",
        "fcntl", "fcntl_nocancel",
        "ioctl",
        "fsync", "fsync_nocancel",
    ]

    dtrace = r'''
/* ============================================ */
/* FILE DESCRIPTOR OPS                          */
/* ============================================ */

syscall::dup:entry
/TRACED/
{
    self->dup_fd = arg0;
    self->dup_ts = walltimestamp/1000;
}

syscall::dup:return
/TRACED && self->dup_ts/
{
    printf("F8_SYSCALL %d %d dup %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->dup_ts, self->dup_fd);
    self->dup_ts = 0;
}

syscall::dup2:entry
/TRACED/
{
    self->dup2_old = arg0;
    self->dup2_new = arg1;
    self->dup2_ts = walltimestamp/1000;
}

syscall::dup2:return
/TRACED && self->dup2_ts/
{
    printf("F8_SYSCALL %d %d dup2 %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->dup2_ts, self->dup2_old, self->dup2_new);
    self->dup2_ts = 0;
}

syscall::fcntl:entry,
syscall::fcntl_nocancel:entry
/TRACED/
{
    self->fcntl_fd = arg0;
    self->fcntl_cmd = arg1;
    self->fcntl_arg = arg2;
    self->fcntl_ts = walltimestamp/1000;
}

syscall::fcntl:return,
syscall::fcntl_nocancel:return
/TRACED && self->fcntl_ts/
{
    printf("F8_SYSCALL %d %d fcntl %d %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->fcntl_ts, 
        self->fcntl_fd, self->fcntl_cmd, self->fcntl_arg);
    self->fcntl_ts = 0;
}

syscall::ioctl:entry
/TRACED/
{
    self->ioctl_fd = arg0;
    self->ioctl_req = arg1;
    self->ioctl_ts = walltimestamp/1000;
}

syscall::ioctl:return
/TRACED && self->ioctl_ts/
{
    printf("F8_SYSCALL %d %d ioctl %d %d %d %d 0x%lx\n",
        pid, tid, (int)arg1, errno, self->ioctl_ts, self->ioctl_fd, self->ioctl_req);
    self->ioctl_ts = 0;
}

syscall::fsync:entry,
syscall::fsync_nocancel:entry
/TRACED/
{
    self->fsync_fd = arg0;
    self->fsync_ts = walltimestamp/1000;
}

syscall::fsync:return,
syscall::fsync_nocancel:return
/TRACED && self->fsync_ts/
{
    printf("F8_SYSCALL %d %d fsync %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->fsync_ts, self->fsync_fd);
    self->fsync_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall == "dup":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
        elif syscall == "dup2":
            if len(args) >= 1:
                result["oldfd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["newfd"] = self.parse_int(args[1])
        elif syscall in ("fcntl", "fcntl_nocancel"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                cmd = self.parse_int(args[1])
                result["cmd"] = parse_fcntl_cmd(cmd)
                result["cmd_raw"] = cmd
            if len(args) >= 3:
                result["arg"] = self.parse_int(args[2])
        elif syscall == "ioctl":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["request"] = args[1]
        elif syscall in ("fsync", "fsync_nocancel"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
        return result
