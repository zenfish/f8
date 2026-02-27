"""Network I/O: sendto, recvfrom, sendmsg, recvmsg (+ sockaddr capture)."""

from . import SyscallHandler, register


@register
class NetIOHandler(SyscallHandler):
    categories = ["network"]
    syscalls = [
        "sendto", "sendto_nocancel",
        "recvfrom", "recvfrom_nocancel",
        "sendmsg", "sendmsg_nocancel",
        "recvmsg", "recvmsg_nocancel",
        "sendmsg_x", "recvmsg_x",
        "sendfile",
    ]

    dtrace = r'''
/* ============================================ */
/* NETWORK I/O                                  */
/* ============================================ */

syscall::sendto:entry,
syscall::sendto_nocancel:entry
/TRACED/
{
    self->sendto_fd = arg0;
    self->sendto_len = arg2;
    self->sendto_flags = arg3;
    self->sendto_addr = arg4;
    self->sendto_addrlen = arg5;
    self->sendto_ts = walltimestamp/1000;
}

syscall::sendto:return,
syscall::sendto_nocancel:return
/TRACED && self->sendto_ts && self->sendto_addr != 0 && self->sendto_addrlen > 0/
{
    this->sa = (struct sockaddr *)copyin(self->sendto_addr, 
        self->sendto_addrlen > 128 ? 128 : self->sendto_addrlen);
    this->family = this->sa->sa_family;
    
    printf("MACTRACE_SOCKADDR %d %d sendto %d %d %d %d %d %d 0x%x ",
        pid, tid, (int)arg1, errno, self->sendto_ts,
        self->sendto_fd, self->sendto_len, this->family, self->sendto_flags);
    tracemem(this->sa, 128, self->sendto_addrlen > 128 ? 128 : self->sendto_addrlen);
    printf("\n");
    self->sendto_ts = 0;
}

syscall::sendto:return,
syscall::sendto_nocancel:return
/TRACED && self->sendto_ts && (self->sendto_addr == 0 || self->sendto_addrlen == 0)/
{
    printf("MACTRACE_SYSCALL %d %d sendto %d %d %d %d %d 0x%x\n",
        pid, tid, (int)arg1, errno, self->sendto_ts,
        self->sendto_fd, self->sendto_len, self->sendto_flags);
    self->sendto_ts = 0;
}

syscall::recvfrom:entry,
syscall::recvfrom_nocancel:entry
/TRACED/
{
    self->recvfrom_fd = arg0;
    self->recvfrom_len = arg2;
    self->recvfrom_flags = arg3;
    self->recvfrom_addr = arg4;
    self->recvfrom_lenp = arg5;
    self->recvfrom_ts = walltimestamp/1000;
}

syscall::recvfrom:return,
syscall::recvfrom_nocancel:return
/TRACED && self->recvfrom_ts && self->recvfrom_addr != 0 && arg1 >= 0/
{
    this->addrlen = *(socklen_t *)copyin(self->recvfrom_lenp, sizeof(socklen_t));
    this->sa = (struct sockaddr *)copyin(self->recvfrom_addr,
        this->addrlen > 128 ? 128 : this->addrlen);
    this->family = this->sa->sa_family;
    
    printf("MACTRACE_SOCKADDR %d %d recvfrom %d %d %d %d %d %d 0x%x ",
        pid, tid, (int)arg1, errno, self->recvfrom_ts,
        self->recvfrom_fd, self->recvfrom_len, this->family, self->recvfrom_flags);
    tracemem(this->sa, 128, this->addrlen > 128 ? 128 : this->addrlen);
    printf("\n");
    self->recvfrom_ts = 0;
}

syscall::recvfrom:return,
syscall::recvfrom_nocancel:return
/TRACED && self->recvfrom_ts && (self->recvfrom_addr == 0 || arg1 < 0)/
{
    printf("MACTRACE_SYSCALL %d %d recvfrom %d %d %d %d %d 0x%x\n",
        pid, tid, (int)arg1, errno, self->recvfrom_ts,
        self->recvfrom_fd, self->recvfrom_len, self->recvfrom_flags);
    self->recvfrom_ts = 0;
}

syscall::sendmsg:entry,
syscall::sendmsg_nocancel:entry
/TRACED/
{
    self->sendmsg_fd = arg0;
    self->sendmsg_flags = arg2;
    self->sendmsg_ts = walltimestamp/1000;
}

syscall::sendmsg:return,
syscall::sendmsg_nocancel:return
/TRACED && self->sendmsg_ts/
{
    printf("MACTRACE_SYSCALL %d %d sendmsg %d %d %d %d 0x%x\n",
        pid, tid, (int)arg1, errno, self->sendmsg_ts, self->sendmsg_fd, self->sendmsg_flags);
    self->sendmsg_ts = 0;
}

syscall::recvmsg:entry,
syscall::recvmsg_nocancel:entry
/TRACED/
{
    self->recvmsg_fd = arg0;
    self->recvmsg_flags = arg2;
    self->recvmsg_ts = walltimestamp/1000;
}

syscall::recvmsg:return,
syscall::recvmsg_nocancel:return
/TRACED && self->recvmsg_ts/
{
    printf("MACTRACE_SYSCALL %d %d recvmsg %d %d %d %d 0x%x\n",
        pid, tid, (int)arg1, errno, self->recvmsg_ts, self->recvmsg_fd, self->recvmsg_flags);
    self->recvmsg_ts = 0;
}

/* ── sendmsg_x / recvmsg_x (batch multi-message I/O) ── */

syscall::sendmsg_x:entry
/TRACED/
{
    self->sendmsgx_fd = arg0;
    self->sendmsgx_cnt = arg2;
    self->sendmsgx_flags = arg3;
    self->sendmsgx_ts = walltimestamp/1000;
}

syscall::sendmsg_x:return
/TRACED && self->sendmsgx_ts/
{
    printf("MACTRACE_SYSCALL %d %d sendmsg_x %d %d %d %d %d 0x%x\n",
        pid, tid, (int)arg1, errno, self->sendmsgx_ts,
        self->sendmsgx_fd, self->sendmsgx_cnt, self->sendmsgx_flags);
    self->sendmsgx_ts = 0;
}

syscall::recvmsg_x:entry
/TRACED/
{
    self->recvmsgx_fd = arg0;
    self->recvmsgx_cnt = arg2;
    self->recvmsgx_flags = arg3;
    self->recvmsgx_ts = walltimestamp/1000;
}

syscall::recvmsg_x:return
/TRACED && self->recvmsgx_ts/
{
    printf("MACTRACE_SYSCALL %d %d recvmsg_x %d %d %d %d %d 0x%x\n",
        pid, tid, (int)arg1, errno, self->recvmsgx_ts,
        self->recvmsgx_fd, self->recvmsgx_cnt, self->recvmsgx_flags);
    self->recvmsgx_ts = 0;
}

/* ── sendfile (zero-copy file → socket) ── */

syscall::sendfile:entry
/TRACED/
{
    self->sf_filefd = arg0;
    self->sf_sockfd = arg1;
    self->sf_offset = arg2;
    self->sf_nbytesp = arg3;
    self->sf_flags = arg5;
    self->sf_ts = walltimestamp/1000;
}

syscall::sendfile:return
/TRACED && self->sf_ts && self->sf_nbytesp != 0/
{
    /* Read actual bytes sent from *nbytes (off_t = 8 bytes) */
    this->sent = *(int64_t *)copyin(self->sf_nbytesp, 8);
    printf("MACTRACE_SYSCALL %d %d sendfile %d %d %d %d %d %lld %lld 0x%x\n",
        pid, tid, (int)arg1, errno, self->sf_ts,
        self->sf_filefd, self->sf_sockfd, (long long)self->sf_offset,
        (long long)this->sent, self->sf_flags);
    self->sf_ts = 0;
}

syscall::sendfile:return
/TRACED && self->sf_ts && self->sf_nbytesp == 0/
{
    printf("MACTRACE_SYSCALL %d %d sendfile %d %d %d %d %d %lld 0 0x%x\n",
        pid, tid, (int)arg1, errno, self->sf_ts,
        self->sf_filefd, self->sf_sockfd, (long long)self->sf_offset, self->sf_flags);
    self->sf_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        """Parse fallback MACTRACE_SYSCALL args (when sockaddr capture fails or not applicable)."""
        result = {}
        if syscall in ("sendto", "sendto_nocancel", "recvfrom", "recvfrom_nocancel"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["len"] = self.parse_int(args[1])
            if len(args) >= 3:
                result["flags"] = args[2]
        elif syscall in ("sendmsg", "sendmsg_nocancel", "recvmsg", "recvmsg_nocancel"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["flags"] = args[1]
        elif syscall in ("sendmsg_x", "recvmsg_x"):
            if len(args) >= 1:
                result["fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["msg_count"] = self.parse_int(args[1])
            if len(args) >= 3:
                result["flags"] = args[2]
        elif syscall == "sendfile":
            if len(args) >= 1:
                result["file_fd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["socket_fd"] = self.parse_int(args[1])
            if len(args) >= 3:
                result["offset"] = self.parse_int(args[2])
            if len(args) >= 4:
                result["bytes_sent"] = self.parse_int(args[3])
            if len(args) >= 5:
                result["flags"] = args[4]
        return result

    def update_fd_info(self, event, fd_tracker):
        fd = event.args.get("fd")
        if fd is not None:
            fd_tracker.mark_socket(event.pid, fd)
        # sendfile uses two fds
        if event.syscall == "sendfile":
            sock_fd = event.args.get("socket_fd")
            if sock_fd is not None:
                fd_tracker.mark_socket(event.pid, sock_fd)
