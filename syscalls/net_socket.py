"""Socket creation/config syscalls: socket, socketpair, listen, shutdown, setsockopt, getsockopt."""

from . import SyscallHandler, register
from ._constants import AF_NAMES, SOCK_NAMES, SHUT_NAMES, parse_sockopt_level, parse_sockopt_name


@register
class NetSocketHandler(SyscallHandler):
    categories = ["network"]
    syscalls = [
        "socket", "socketpair", "listen", "shutdown",
        "setsockopt", "getsockopt",
    ]

    dtrace = r'''
/* ============================================ */
/* SOCKET CREATION / CONFIG                     */
/* ============================================ */

syscall::socket:entry
/TRACED/
{
    self->sock_domain = arg0;
    self->sock_type = arg1;
    self->sock_proto = arg2;
    self->sock_ts = walltimestamp/1000;
}

syscall::socket:return
/TRACED && self->sock_ts/
{
    printf("MACTRACE_SYSCALL %d %d socket %d %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->sock_ts,
        self->sock_domain, self->sock_type, self->sock_proto);
    self->sock_ts = 0;
}

syscall::socketpair:entry
/TRACED/
{
    self->spair_domain = arg0;
    self->spair_type = arg1;
    self->spair_proto = arg2;
    self->spair_ts = walltimestamp/1000;
}

syscall::socketpair:return
/TRACED && self->spair_ts/
{
    printf("MACTRACE_SYSCALL %d %d socketpair %d %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->spair_ts,
        self->spair_domain, self->spair_type, self->spair_proto);
    self->spair_ts = 0;
}

syscall::listen:entry
/TRACED/
{
    self->listen_fd = arg0;
    self->listen_backlog = arg1;
    self->listen_ts = walltimestamp/1000;
}

syscall::listen:return
/TRACED && self->listen_ts/
{
    printf("MACTRACE_SYSCALL %d %d listen %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->listen_ts, self->listen_fd, self->listen_backlog);
    self->listen_ts = 0;
}

syscall::shutdown:entry
/TRACED/
{
    self->shut_fd = arg0;
    self->shut_how = arg1;
    self->shut_ts = walltimestamp/1000;
}

syscall::shutdown:return
/TRACED && self->shut_ts/
{
    printf("MACTRACE_SYSCALL %d %d shutdown %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->shut_ts, self->shut_fd, self->shut_how);
    self->shut_ts = 0;
}

syscall::setsockopt:entry
/TRACED/
{
    self->sso_fd = arg0;
    self->sso_level = arg1;
    self->sso_opt = arg2;
    self->sso_ts = walltimestamp/1000;
}

syscall::setsockopt:return
/TRACED && self->sso_ts/
{
    printf("MACTRACE_SYSCALL %d %d setsockopt %d %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->sso_ts,
        self->sso_fd, self->sso_level, self->sso_opt);
    self->sso_ts = 0;
}

syscall::getsockopt:entry
/TRACED/
{
    self->gso_fd = arg0;
    self->gso_level = arg1;
    self->gso_opt = arg2;
    self->gso_ts = walltimestamp/1000;
}

syscall::getsockopt:return
/TRACED && self->gso_ts/
{
    printf("MACTRACE_SYSCALL %d %d getsockopt %d %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->gso_ts,
        self->gso_fd, self->gso_level, self->gso_opt);
    self->gso_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall == "socket":
            if len(args) >= 1:
                domain = self.parse_int(args[0])
                result["domain"] = AF_NAMES.get(domain, f"AF_{domain}")
            if len(args) >= 2:
                stype = self.parse_int(args[1])
                result["type"] = SOCK_NAMES.get(stype, f"SOCK_{stype}")
            if len(args) >= 3:
                result["protocol"] = self.parse_int(args[2])
        elif syscall == "socketpair":
            if len(args) >= 1:
                domain = self.parse_int(args[0])
                result["domain"] = AF_NAMES.get(domain, f"AF_{domain}")
            if len(args) >= 2:
                stype = self.parse_int(args[1])
                result["type"] = SOCK_NAMES.get(stype, f"SOCK_{stype}")
            if len(args) >= 3:
                result["protocol"] = self.parse_int(args[2])
        elif syscall == "listen":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["backlog"] = self.parse_int(args[1])
        elif syscall == "shutdown":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                how = self.parse_int(args[1])
                result["how"] = how
                result["how_str"] = SHUT_NAMES.get(how, f"SHUT_{how}")
        elif syscall in ("setsockopt", "getsockopt"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                level = self.parse_int(args[1])
                result["level"] = level
                result["level_str"] = parse_sockopt_level(level)
            if len(args) >= 3:
                optname = self.parse_int(args[2])
                result["optname"] = optname
                result["optname_str"] = parse_sockopt_name(
                    level if len(args) >= 2 else -1, optname)
        return result

    def update_fd_info(self, event, fd_tracker):
        syscall = event.syscall
        if syscall == "socket" and event.return_value >= 0:
            domain = event.args.get("domain", "?")
            stype = event.args.get("type", "?")
            fd_tracker.set_socket(event.pid, event.return_value, f"socket({domain}/{stype})")
        elif syscall in ("listen", "shutdown", "setsockopt", "getsockopt"):
            fd = event.args.get("fd")
            if fd is not None:
                fd_tracker.mark_socket(event.pid, fd)
