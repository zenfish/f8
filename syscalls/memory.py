"""Memory management syscalls: mmap, munmap, mprotect."""

from . import SyscallHandler, register
from ._constants import parse_prot_flags, parse_mmap_flags


@register
class MemoryHandler(SyscallHandler):
    categories = ["memory"]
    syscalls = ["mmap", "munmap", "mprotect"]

    dtrace = r'''
/* ============================================ */
/* MEMORY OPERATIONS                            */
/* ============================================ */

syscall::mmap:entry
/TRACED/
{
    self->mmap_len = arg1;
    self->mmap_prot = arg2;
    self->mmap_flags = arg3;
    self->mmap_fd = arg4;
    self->mmap_off = arg5;
    self->mmap_ts = walltimestamp/1000;
}

syscall::mmap:return
/TRACED && self->mmap_ts/
{
    printf("F8_SYSCALL %d %d mmap %p %d %d 0x%x %d 0x%x %d %d\n",
        pid, tid, arg1, errno, self->mmap_ts,
        self->mmap_len, self->mmap_prot, self->mmap_flags, self->mmap_fd, self->mmap_off);
    self->mmap_ts = 0;
}

syscall::munmap:entry
/TRACED/
{
    self->munmap_addr = arg0;
    self->munmap_len = arg1;
    self->munmap_ts = walltimestamp/1000;
}

syscall::munmap:return
/TRACED && self->munmap_ts/
{
    printf("F8_SYSCALL %d %d munmap %d %d %d 0x%lx %d\n",
        pid, tid, (int)arg1, errno, self->munmap_ts, self->munmap_addr, self->munmap_len);
    self->munmap_ts = 0;
}

syscall::mprotect:entry
/TRACED/
{
    self->mprot_addr = arg0;
    self->mprot_len = arg1;
    self->mprot_prot = arg2;
    self->mprot_ts = walltimestamp/1000;
}

syscall::mprotect:return
/TRACED && self->mprot_ts/
{
    printf("F8_SYSCALL %d %d mprotect %d %d %d 0x%lx %d %d\n",
        pid, tid, (int)arg1, errno, self->mprot_ts,
        self->mprot_addr, self->mprot_len, self->mprot_prot);
    self->mprot_ts = 0;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall == "mmap":
            if len(args) >= 1:
                result["length"] = self.parse_hex(args[0])
            if len(args) >= 2:
                prot = self.parse_int(args[1])
                result["prot"] = prot
                result["prot_str"] = parse_prot_flags(prot)
            if len(args) >= 3:
                flags = self.parse_hex(args[2])
                result["flags"] = flags
                result["flags_str"] = parse_mmap_flags(flags)
            if len(args) >= 4:
                result["fd"] = self.parse_hex(args[3])
            if len(args) >= 5:
                result["offset"] = self.parse_hex(args[4])
        elif syscall == "munmap":
            if len(args) >= 1:
                result["addr"] = args[0]
            if len(args) >= 2:
                result["length"] = self.parse_int(args[1])
        elif syscall == "mprotect":
            if len(args) >= 1:
                result["addr"] = args[0]
            if len(args) >= 2:
                result["length"] = self.parse_int(args[1])
            if len(args) >= 3:
                prot = self.parse_int(args[2])
                result["prot"] = prot
                result["prot_str"] = parse_prot_flags(prot)
        return result
