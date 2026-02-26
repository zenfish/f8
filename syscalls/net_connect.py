"""Socket connect/bind/accept — with sockaddr capture via MACTRACE_SOCKADDR."""

from . import SyscallHandler, register


@register
class NetConnectHandler(SyscallHandler):
    syscalls = [
        "connect", "connect_nocancel",
        "bind",
        "accept", "accept_nocancel",
    ]

    dtrace = r'''
/* ============================================ */
/* SOCKET CONNECT / BIND / ACCEPT               */
/* ============================================ */

syscall::connect:entry,
syscall::connect_nocancel:entry
/TRACED/
{
    self->conn_fd = arg0;
    self->conn_addr = arg1;
    self->conn_len = arg2;
    self->conn_ts = walltimestamp/1000;
}

syscall::connect:return,
syscall::connect_nocancel:return
/TRACED && self->conn_ts && self->conn_len > 0 && self->conn_len <= 128/
{
    this->sa = (struct sockaddr *)copyin(self->conn_addr, self->conn_len);
    this->family = this->sa->sa_family;
    
    printf("MACTRACE_SOCKADDR %d %d connect %d %d %d %d %d ",
        pid, tid, (int)arg1, errno, self->conn_ts, self->conn_fd, this->family);
    tracemem(this->sa, 128, self->conn_len);
    printf("\n");
    self->conn_ts = 0;
}

syscall::connect:return,
syscall::connect_nocancel:return
/TRACED && self->conn_ts && (self->conn_len == 0 || self->conn_len > 128)/
{
    printf("MACTRACE_SYSCALL %d %d connect %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->conn_ts, self->conn_fd);
    self->conn_ts = 0;
}

syscall::bind:entry
/TRACED/
{
    self->bind_fd = arg0;
    self->bind_addr = arg1;
    self->bind_len = arg2;
    self->bind_ts = walltimestamp/1000;
}

syscall::bind:return
/TRACED && self->bind_ts && self->bind_len > 0 && self->bind_len <= 128/
{
    this->sa = (struct sockaddr *)copyin(self->bind_addr, self->bind_len);
    this->family = this->sa->sa_family;
    
    printf("MACTRACE_SOCKADDR %d %d bind %d %d %d %d %d ",
        pid, tid, (int)arg1, errno, self->bind_ts, self->bind_fd, this->family);
    tracemem(this->sa, 128, self->bind_len);
    printf("\n");
    self->bind_ts = 0;
}

syscall::bind:return
/TRACED && self->bind_ts && (self->bind_len == 0 || self->bind_len > 128)/
{
    printf("MACTRACE_SYSCALL %d %d bind %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->bind_ts, self->bind_fd);
    self->bind_ts = 0;
}

syscall::accept:entry,
syscall::accept_nocancel:entry
/TRACED/
{
    self->accept_fd = arg0;
    self->accept_addr = arg1;
    self->accept_lenp = arg2;
    self->accept_ts = walltimestamp/1000;
}

syscall::accept:return,
syscall::accept_nocancel:return
/TRACED && self->accept_ts && self->accept_addr != 0 && arg1 >= 0/
{
    this->addrlen = *(socklen_t *)copyin(self->accept_lenp, sizeof(socklen_t));
    this->sa = (struct sockaddr *)copyin(self->accept_addr, 
        this->addrlen > 128 ? 128 : this->addrlen);
    this->family = this->sa->sa_family;
    
    printf("MACTRACE_SOCKADDR %d %d accept %d %d %d %d %d ",
        pid, tid, (int)arg1, errno, self->accept_ts, self->accept_fd, this->family);
    tracemem(this->sa, 128, this->addrlen > 128 ? 128 : this->addrlen);
    printf("\n");
    self->accept_ts = 0;
}

syscall::accept:return,
syscall::accept_nocancel:return
/TRACED && self->accept_ts && (self->accept_addr == 0 || arg1 < 0)/
{
    printf("MACTRACE_SYSCALL %d %d accept %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->accept_ts, self->accept_fd);
    self->accept_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        """Parse fallback MACTRACE_SYSCALL args (when sockaddr capture fails)."""
        result = {}
        if syscall in ("connect", "connect_nocancel", "bind"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["addrlen"] = self.parse_int(args[1])
        elif syscall in ("accept", "accept_nocancel"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
        return result

    def update_fd_info(self, event, fd_tracker):
        syscall = event.syscall
        if syscall in ("connect", "connect_nocancel"):
            fd = event.args.get("fd")
            if fd is not None:
                fd_tracker.mark_socket(event.pid, fd)
                addr = event.args.get("display") or event.args.get("address")
                if addr:
                    fd_tracker.set_socket(event.pid, fd, addr)
                elif event.args.get("path"):
                    fd_tracker.set_socket(event.pid, fd, event.args["path"])
        elif syscall in ("accept", "accept_nocancel"):
            if event.return_value >= 0:
                addr = event.args.get("display") or event.args.get("address")
                desc = f"from {addr}" if addr else None
                fd_tracker.set_socket(event.pid, event.return_value, desc)
        elif syscall == "bind":
            fd = event.args.get("fd")
            if fd is not None:
                fd_tracker.mark_socket(event.pid, fd)
