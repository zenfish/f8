"""Simple info/IPC syscalls: getpid, getppid, getuid, geteuid, getgid, getegid, pipe."""

from . import SyscallHandler, register


@register
class InfoHandler(SyscallHandler):
    categories = ["process"]
    syscalls = [
        "getpid", "getppid",
        "getuid", "geteuid",
        "getgid", "getegid",
        "pipe",
    ]

    dtrace = r'''
/* ============================================ */
/* PROCESS INFO / IPC                           */
/* ============================================ */

syscall::pipe:return
/TRACED/
{
    printf("MACTRACE_SYSCALL %d %d pipe %d %d %d\n",
        pid, tid, (int)arg1, errno, walltimestamp/1000);
}

syscall::getpid:return
/TRACED/
{
    printf("MACTRACE_SYSCALL %d %d getpid %d %d %d\n",
        pid, tid, (int)arg1, errno, walltimestamp/1000);
}

syscall::getppid:return
/TRACED/
{
    printf("MACTRACE_SYSCALL %d %d getppid %d %d %d\n",
        pid, tid, (int)arg1, errno, walltimestamp/1000);
}

syscall::getuid:return
/TRACED/
{
    printf("MACTRACE_SYSCALL %d %d getuid %d %d %d\n",
        pid, tid, (int)arg1, errno, walltimestamp/1000);
}

syscall::geteuid:return
/TRACED/
{
    printf("MACTRACE_SYSCALL %d %d geteuid %d %d %d\n",
        pid, tid, (int)arg1, errno, walltimestamp/1000);
}

syscall::getgid:return
/TRACED/
{
    printf("MACTRACE_SYSCALL %d %d getgid %d %d %d\n",
        pid, tid, (int)arg1, errno, walltimestamp/1000);
}

syscall::getegid:return
/TRACED/
{
    printf("MACTRACE_SYSCALL %d %d getegid %d %d %d\n",
        pid, tid, (int)arg1, errno, walltimestamp/1000);
}
'''

    def parse_args(self, syscall, args):
        # These syscalls have no meaningful args beyond the return value
        return {}
