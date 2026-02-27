"""Socket address query: getpeername, getsockname (with sockaddr capture)."""

from . import SyscallHandler, register


@register
class NetPeerHandler(SyscallHandler):
    categories = ["network"]
    syscalls = ["getpeername", "getsockname"]

    dtrace = r'''
/* ============================================ */
/* SOCKET ADDRESS QUERY                         */
/* ============================================ */

syscall::getpeername:entry
/TRACED/
{
    self->gpn_fd = arg0;
    self->gpn_addr = arg1;
    self->gpn_lenp = arg2;
    self->gpn_ts = walltimestamp/1000;
}

syscall::getpeername:return
/TRACED && self->gpn_ts && errno == 0/
{
    this->addrlen = *(socklen_t *)copyin(self->gpn_lenp, sizeof(socklen_t));
    this->sa = (struct sockaddr *)copyin(self->gpn_addr,
        this->addrlen > 128 ? 128 : this->addrlen);
    this->family = this->sa->sa_family;
    
    printf("MACTRACE_SOCKADDR %d %d getpeername %d %d %d %d %d ",
        pid, tid, (int)arg1, errno, self->gpn_ts, self->gpn_fd, this->family);
    tracemem(this->sa, 128, this->addrlen > 128 ? 128 : this->addrlen);
    printf("\n");
    self->gpn_ts = 0;
}

syscall::getpeername:return
/TRACED && self->gpn_ts && errno != 0/
{
    printf("MACTRACE_SYSCALL %d %d getpeername %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->gpn_ts, self->gpn_fd);
    self->gpn_ts = 0;
}

syscall::getsockname:entry
/TRACED/
{
    self->gsn_fd = arg0;
    self->gsn_addr = arg1;
    self->gsn_lenp = arg2;
    self->gsn_ts = walltimestamp/1000;
}

syscall::getsockname:return
/TRACED && self->gsn_ts && errno == 0/
{
    this->addrlen = *(socklen_t *)copyin(self->gsn_lenp, sizeof(socklen_t));
    this->sa = (struct sockaddr *)copyin(self->gsn_addr,
        this->addrlen > 128 ? 128 : this->addrlen);
    this->family = this->sa->sa_family;
    
    printf("MACTRACE_SOCKADDR %d %d getsockname %d %d %d %d %d ",
        pid, tid, (int)arg1, errno, self->gsn_ts, self->gsn_fd, this->family);
    tracemem(this->sa, 128, this->addrlen > 128 ? 128 : this->addrlen);
    printf("\n");
    self->gsn_ts = 0;
}

syscall::getsockname:return
/TRACED && self->gsn_ts && errno != 0/
{
    printf("MACTRACE_SYSCALL %d %d getsockname %d %d %d %d\n",
        pid, tid, (int)arg1, errno, self->gsn_ts, self->gsn_fd);
    self->gsn_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        """Parse fallback MACTRACE_SYSCALL args (error case)."""
        result = {}
        if len(args) >= 1:
            result["fd"] = self.parse_int(args[0])
        return result

    def update_fd_info(self, event, fd_tracker):
        fd = event.args.get("fd")
        if fd is not None:
            fd_tracker.mark_socket(event.pid, fd)
