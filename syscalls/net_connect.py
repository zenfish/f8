"""Socket connect/bind/accept — with sockaddr capture via F8_SOCKADDR."""

from . import SyscallHandler, register


@register
class NetConnectHandler(SyscallHandler):
    categories = ["network"]
    syscalls = [
        "connect", "connect_nocancel",
        "connectx",
        "disconnectx",
        "bind",
        "accept", "accept_nocancel",
        "peeloff",
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
    
    printf("F8_SOCKADDR %d %d connect %d %d %d %d %d ",
        pid, tid, (int)arg1, errno, self->conn_ts, self->conn_fd, this->family);
    tracemem(this->sa, 128, self->conn_len);
    printf("\n");
    self->conn_ts = 0;
}

syscall::connect:return,
syscall::connect_nocancel:return
/TRACED && self->conn_ts && (self->conn_len == 0 || self->conn_len > 128)/
{
    printf("F8_SYSCALL %d %d connect %d %d %d %d\n",
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
    
    printf("F8_SOCKADDR %d %d bind %d %d %d %d %d ",
        pid, tid, (int)arg1, errno, self->bind_ts, self->bind_fd, this->family);
    tracemem(this->sa, 128, self->bind_len);
    printf("\n");
    self->bind_ts = 0;
}

syscall::bind:return
/TRACED && self->bind_ts && (self->bind_len == 0 || self->bind_len > 128)/
{
    printf("F8_SYSCALL %d %d bind %d %d %d %d\n",
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
    
    printf("F8_SOCKADDR %d %d accept %d %d %d %d %d ",
        pid, tid, (int)arg1, errno, self->accept_ts, self->accept_fd, this->family);
    tracemem(this->sa, 128, this->addrlen > 128 ? 128 : this->addrlen);
    printf("\n");
    self->accept_ts = 0;
}

syscall::accept:return,
syscall::accept_nocancel:return
/TRACED && self->accept_ts && (self->accept_addr == 0 || arg1 < 0)/
{
    printf("F8_SYSCALL %d %d accept %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->accept_ts, self->accept_fd);
    self->accept_ts = 0;
}

/* ── connectx (extended connect with endpoints) ── */

syscall::connectx:entry
/TRACED/
{
    self->connx_fd = arg0;
    self->connx_endpoints = arg1;
    self->connx_flags = arg3;
    self->connx_ts = walltimestamp/1000;
}

syscall::connectx:return
/TRACED && self->connx_ts && self->connx_endpoints != 0/
{
    /* sa_endpoints_t: srcif(4) + pad(4) + srcaddr_ptr(8) + srcaddrlen(4) + pad(4) + dstaddr_ptr(8) + dstaddrlen(4) */
    this->ep = (uint8_t *)copyin(self->connx_endpoints, 40);

    /* Extract destination sockaddr pointer and length (offsets for arm64 LP64) */
    this->dstaddr = *(uintptr_t *)(this->ep + 24);
    this->dstlen  = *(uint32_t *)(this->ep + 32);

    /* Emit sockaddr if destination is available */
    this->sa = (struct sockaddr *)copyin(this->dstaddr,
        this->dstlen > 128 ? 128 : this->dstlen);
    this->family = this->sa->sa_family;

    printf("F8_SOCKADDR %d %d connectx %d %d %d %d %d ",
        pid, tid, (int)arg1, errno, self->connx_ts, self->connx_fd, this->family);
    tracemem(this->sa, 128, this->dstlen > 128 ? 128 : this->dstlen);
    printf("\n");
    self->connx_ts = 0;
}

syscall::connectx:return
/TRACED && self->connx_ts && self->connx_endpoints == 0/
{
    printf("F8_SYSCALL %d %d connectx %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->connx_ts, self->connx_fd);
    self->connx_ts = 0;
}

/* ── disconnectx (close a connectx association) ── */

syscall::disconnectx:entry
/TRACED/
{
    self->dconnx_fd = arg0;
    self->dconnx_aid = arg1;
    self->dconnx_cid = arg2;
    self->dconnx_ts = walltimestamp/1000;
}

syscall::disconnectx:return
/TRACED && self->dconnx_ts/
{
    printf("F8_SYSCALL %d %d disconnectx %d %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->dconnx_ts,
        self->dconnx_fd, (int)self->dconnx_aid, (int)self->dconnx_cid);
    self->dconnx_ts = 0;
}

/* ── peeloff (SCTP: separate stream into new socket) ── */

syscall::peeloff:entry
/TRACED/
{
    self->peel_fd = arg0;
    self->peel_aid = arg1;
    self->peel_ts = walltimestamp/1000;
}

syscall::peeloff:return
/TRACED && self->peel_ts/
{
    printf("F8_SYSCALL %d %d peeloff %d %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->peel_ts,
        self->peel_fd, (int)self->peel_aid);
    self->peel_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        """Parse fallback F8_SYSCALL args (when sockaddr capture fails)."""
        result = {}
        if syscall in ("connect", "connect_nocancel", "connectx", "disconnectx", "bind"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["addrlen"] = self.parse_int(args[1])
        elif syscall in ("accept", "accept_nocancel"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
        elif syscall == "disconnectx":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["associd"] = self.parse_int(args[1])
            if len(args) >= 3:
                result["connid"] = self.parse_int(args[2])
        elif syscall == "peeloff":
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["associd"] = self.parse_int(args[1])
        return result

    def update_fd_info(self, event, fd_tracker):
        syscall = event.syscall
        if syscall in ("connect", "connect_nocancel", "connectx", "disconnectx"):
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
        elif syscall == "peeloff":
            if event.return_value >= 0:
                fd_tracker.set_socket(event.pid, event.return_value, "peeloff")
        elif syscall == "bind":
            fd = event.args.get("fd")
            if fd is not None:
                fd_tracker.mark_socket(event.pid, fd)
