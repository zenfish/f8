"""macOS Mandatory Access Control (MAC) syscalls: __mac_*."""

from . import SyscallHandler, register


@register
class MacHandler(SyscallHandler):
    categories = ["mac", "process"]
    syscalls = [
        "__mac_execve", "__mac_syscall",
        "__mac_get_file", "__mac_set_file",
        "__mac_get_link", "__mac_set_link",
        "__mac_get_proc", "__mac_set_proc",
        "__mac_get_fd", "__mac_set_fd",
        "__mac_get_pid",
    ]

    dtrace = r'''
/* ============================================ */
/* MAC (Mandatory Access Control)               */
/* ============================================ */

syscall::__mac_execve:entry
/TRACED/
{
    self->mac_execve_path = copyinstr(arg0);
    self->mac_execve_ts = walltimestamp/1000;
}

syscall::__mac_execve:return
/TRACED && self->mac_execve_path != NULL/
{
    printf("F8_SYSCALL %d %d __mac_execve %d %d %d \"%s\"\n",
        pid, tid, (int)arg1, errno, self->mac_execve_ts, self->mac_execve_path);
    self->mac_execve_path = NULL;
}

syscall::__mac_syscall:entry
/TRACED/
{
    self->mac_syscall_policy = copyinstr(arg0);
    self->mac_syscall_call = arg1;
    self->mac_syscall_ts = walltimestamp/1000;
}

syscall::__mac_syscall:return
/TRACED && self->mac_syscall_ts/
{
    printf("F8_SYSCALL %d %d __mac_syscall %d %d %d \"%s\" %d\n",
        pid, tid, (int)arg1, errno, self->mac_syscall_ts, 
        self->mac_syscall_policy != NULL ? self->mac_syscall_policy : "", self->mac_syscall_call);
    self->mac_syscall_ts = 0;
}

syscall::__mac_get_file:entry,
syscall::__mac_set_file:entry
/TRACED/
{
    self->mac_file_path = copyinstr(arg0);
    self->mac_file_ts = walltimestamp/1000;
}

syscall::__mac_get_file:return,
syscall::__mac_set_file:return
/TRACED && self->mac_file_path != NULL/
{
    printf("F8_SYSCALL %d %d %s %d %d %d \"%s\"\n",
        pid, tid, probefunc, (int)arg1, errno, self->mac_file_ts, self->mac_file_path);
    self->mac_file_path = NULL;
}

syscall::__mac_get_link:entry,
syscall::__mac_set_link:entry
/TRACED/
{
    self->mac_link_path = copyinstr(arg0);
    self->mac_link_ts = walltimestamp/1000;
}

syscall::__mac_get_link:return,
syscall::__mac_set_link:return
/TRACED && self->mac_link_path != NULL/
{
    printf("F8_SYSCALL %d %d %s %d %d %d \"%s\"\n",
        pid, tid, probefunc, (int)arg1, errno, self->mac_link_ts, self->mac_link_path);
    self->mac_link_path = NULL;
}

syscall::__mac_get_proc:entry,
syscall::__mac_set_proc:entry
/TRACED/
{
    self->mac_proc_ts = walltimestamp/1000;
}

syscall::__mac_get_proc:return,
syscall::__mac_set_proc:return
/TRACED && self->mac_proc_ts/
{
    printf("F8_SYSCALL %d %d %s %d %d %d\n",
        pid, tid, probefunc, (int)arg1, errno, self->mac_proc_ts);
    self->mac_proc_ts = 0;
}

syscall::__mac_get_fd:entry,
syscall::__mac_set_fd:entry
/TRACED/
{
    self->mac_fd_fd = arg0;
    self->mac_fd_ts = walltimestamp/1000;
}

syscall::__mac_get_fd:return,
syscall::__mac_set_fd:return
/TRACED && self->mac_fd_ts/
{
    printf("F8_SYSCALL %d %d %s %d %d %d %d\n",
        pid, tid, probefunc, (int)arg1, errno, self->mac_fd_ts, self->mac_fd_fd);
    self->mac_fd_ts = 0;
}

syscall::__mac_get_pid:entry
/TRACED/
{
    self->mac_pid_pid = arg0;
    self->mac_pid_ts = walltimestamp/1000;
}

syscall::__mac_get_pid:return
/TRACED && self->mac_pid_ts/
{
    printf("F8_SYSCALL %d %d __mac_get_pid %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->mac_pid_ts, self->mac_pid_pid);
    self->mac_pid_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall == "__mac_execve":
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
        elif syscall == "__mac_syscall":
            if len(args) >= 1:
                result["policy"] = self.clean_str(args[0])
            if len(args) >= 2:
                result["call"] = self.parse_int(args[1])
        elif syscall in ("__mac_get_file", "__mac_set_file",
                         "__mac_get_link", "__mac_set_link"):
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
        elif syscall in ("__mac_get_fd", "__mac_set_fd"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
        elif syscall == "__mac_get_pid":
            if len(args) >= 1:
                result["pid"] = self.parse_int(args[0])
        # __mac_get_proc, __mac_set_proc: no args
        return result
