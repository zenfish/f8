"""NECP (Network Extension Control Policy) syscalls."""

from . import SyscallHandler, register


@register
class NetNecpHandler(SyscallHandler):
    categories = ["network"]
    syscalls = [
        "necp_open", "necp_client_action",
        "necp_session_open", "necp_session_action",
    ]

    dtrace = r'''
/* ============================================ */
/* NECP (Network Extension Control Policy)      */
/* ============================================ */

syscall::necp_open:entry
/TRACED/
{
    self->necp_open_flags = arg0;
    self->necp_open_ts = walltimestamp/1000;
}

syscall::necp_open:return
/TRACED && self->necp_open_ts/
{
    printf("F8_SYSCALL %d %d necp_open %d %d %d 0x%x\n",
        pid, tid, (int)arg1, errno, self->necp_open_ts, self->necp_open_flags);
    self->necp_open_ts = 0;
}

syscall::necp_client_action:entry
/TRACED/
{
    self->necp_ca_fd = arg0;
    self->necp_ca_action = arg1;
    self->necp_ca_ts = walltimestamp/1000;
}

syscall::necp_client_action:return
/TRACED && self->necp_ca_ts/
{
    printf("F8_SYSCALL %d %d necp_client_action %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->necp_ca_ts, self->necp_ca_fd, self->necp_ca_action);
    self->necp_ca_ts = 0;
}

syscall::necp_session_open:entry
/TRACED/
{
    self->necp_so_flags = arg0;
    self->necp_so_ts = walltimestamp/1000;
}

syscall::necp_session_open:return
/TRACED && self->necp_so_ts/
{
    printf("F8_SYSCALL %d %d necp_session_open %d %d %d 0x%x\n",
        pid, tid, (int)arg1, errno, self->necp_so_ts, self->necp_so_flags);
    self->necp_so_ts = 0;
}

syscall::necp_session_action:entry
/TRACED/
{
    self->necp_sa_fd = arg0;
    self->necp_sa_action = arg1;
    self->necp_sa_ts = walltimestamp/1000;
}

syscall::necp_session_action:return
/TRACED && self->necp_sa_ts/
{
    printf("F8_SYSCALL %d %d necp_session_action %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->necp_sa_ts, self->necp_sa_fd, self->necp_sa_action);
    self->necp_sa_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall == "necp_open":
            if len(args) >= 1:
                result["flags"] = args[0]
        elif syscall == "necp_client_action":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["action"] = self.parse_int(args[1])
        elif syscall == "necp_session_open":
            if len(args) >= 1:
                result["flags"] = args[0]
        elif syscall == "necp_session_action":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["action"] = self.parse_int(args[1])
        return result
