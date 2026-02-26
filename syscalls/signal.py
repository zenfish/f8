"""Signal syscalls: kill, sigaction, sigprocmask."""

from . import SyscallHandler, register
from ._constants import signal_name


@register
class SignalHandler(SyscallHandler):
    syscalls = ["kill", "sigaction", "sigprocmask"]

    # Only kill has explicit DTrace probes (sigaction/sigprocmask are
    # captured by the catch-all counter but have no rich arg capture)
    dtrace = r'''
/* ============================================ */
/* SIGNALS                                      */
/* ============================================ */

syscall::kill:entry
/TRACED/
{
    self->kill_pid = arg0;
    self->kill_sig = arg1;
    self->kill_ts = walltimestamp/1000;
}

syscall::kill:return
/TRACED && self->kill_ts/
{
    printf("MACTRACE_SYSCALL %d %d kill %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->kill_ts, self->kill_pid, self->kill_sig);
    self->kill_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall == "kill":
            if len(args) >= 1:
                result["pid"] = self.parse_int(args[0])
            if len(args) >= 2:
                sig = self.parse_int(args[1])
                result["signal"] = sig
                result["signal_str"] = signal_name(sig)
        # sigaction, sigprocmask: no rich arg parsing yet
        return result
