"""Process lifecycle syscalls: fork, execve, posix_spawn, exit, wait4."""

from . import SyscallHandler, register


@register
class ProcessHandler(SyscallHandler):
    categories = ["process"]
    syscalls = [
        "fork", "execve", "posix_spawn", "exit",
        "wait4", "wait4_nocancel",
    ]

    dtrace = r'''
/* ============================================ */
/* PROCESS LIFECYCLE                            */
/* ============================================ */

syscall::fork:return
/TRACED/
{
    printf("F8_SYSCALL %d %d %s %d %d %d\n",
        pid, tid, probefunc, (int)arg1, errno, walltimestamp/1000);
}

syscall::fork:return
/arg1 == 0 && (progenyof($target_pid) || ppid == $target_pid)/
{
    self->is_child = 1;
    printf("F8_FORK_CHILD %d %d %d %d\n", ppid, pid, tid, walltimestamp/1000);
}

syscall::execve:entry
/TRACED/
{
    self->exec_path = copyinstr(arg0);
    self->exec_ts = walltimestamp/1000;
}

syscall::execve:return
/TRACED && self->exec_path != NULL/
{
    printf("F8_SYSCALL %d %d execve %d %d %d \"%s\"\n",
        pid, tid, (int)arg1, errno, self->exec_ts, self->exec_path);
    self->exec_path = NULL;
}

syscall::posix_spawn:entry
/TRACED/
{
    self->spawn_path = copyinstr(arg1);
    self->spawn_ts = walltimestamp/1000;
}

syscall::posix_spawn:return
/TRACED && self->spawn_path != NULL/
{
    printf("F8_SYSCALL %d %d posix_spawn %d %d %d \"%s\"\n",
        pid, tid, (int)arg1, errno, self->spawn_ts, self->spawn_path);
    self->spawn_path = NULL;
}

syscall::exit:entry
/TRACED/
{
    printf("F8_EXIT %d %d %d %d\n", pid, ppid, (int)arg0, walltimestamp/1000);
    self->is_child = 0;
}

syscall::wait4:entry,
syscall::wait4_nocancel:entry
/TRACED/
{
    self->wait_pid = arg0;
    self->wait_opts = arg2;
    self->wait_ts = walltimestamp/1000;
}

syscall::wait4:return,
syscall::wait4_nocancel:return
/TRACED && self->wait_ts/
{
    printf("F8_SYSCALL %d %d wait4 %d %d %d %d 0x%x\n",
        pid, tid, (int)arg1, errno, self->wait_ts, self->wait_pid, self->wait_opts);
    self->wait_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall in ("execve",):
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
        elif syscall == "posix_spawn":
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
        elif syscall in ("wait4", "wait4_nocancel"):
            if len(args) >= 1:
                result["pid"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["options"] = args[1]
        # fork: no extra args to parse
        return result
