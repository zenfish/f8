"""Link/rename/unlink syscalls: link, symlink, readlink, unlink, rename."""

from . import SyscallHandler, register


@register
class FileLinkHandler(SyscallHandler):
    syscalls = ["unlink", "rename", "link", "symlink", "readlink"]

    dtrace = r'''
/* ============================================ */
/* FILE LINK / RENAME / UNLINK                  */
/* ============================================ */

syscall::unlink:entry
/TRACED/
{
    self->unlink_path = copyinstr(arg0);
    self->unlink_ts = walltimestamp/1000;
}

syscall::unlink:return
/TRACED && self->unlink_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d unlink %d %d %d \"%s\"\n",
        pid, tid, (int)arg1, errno, self->unlink_ts, self->unlink_path);
    self->unlink_path = NULL;
}

syscall::rename:entry
/TRACED/
{
    self->rename_old = copyinstr(arg0);
    self->rename_new = copyinstr(arg1);
    self->rename_ts = walltimestamp/1000;
}

syscall::rename:return
/TRACED && self->rename_old != NULL/
{
    printf("MACTRACE_SYSCALL %d %d rename %d %d %d \"%s\" \"%s\"\n",
        pid, tid, (int)arg1, errno, self->rename_ts, self->rename_old, self->rename_new);
    self->rename_old = NULL;
    self->rename_new = NULL;
}

syscall::link:entry
/TRACED/
{
    self->link_old = copyinstr(arg0);
    self->link_new = copyinstr(arg1);
    self->link_ts = walltimestamp/1000;
}

syscall::link:return
/TRACED && self->link_old != NULL/
{
    printf("MACTRACE_SYSCALL %d %d link %d %d %d \"%s\" \"%s\"\n",
        pid, tid, (int)arg1, errno, self->link_ts, self->link_old, self->link_new);
    self->link_old = NULL;
}

syscall::symlink:entry
/TRACED/
{
    self->sym_old = copyinstr(arg0);
    self->sym_new = copyinstr(arg1);
    self->sym_ts = walltimestamp/1000;
}

syscall::symlink:return
/TRACED && self->sym_old != NULL/
{
    printf("MACTRACE_SYSCALL %d %d symlink %d %d %d \"%s\" \"%s\"\n",
        pid, tid, (int)arg1, errno, self->sym_ts, self->sym_old, self->sym_new);
    self->sym_old = NULL;
}

syscall::readlink:entry
/TRACED/
{
    self->readlink_path = copyinstr(arg0);
    self->readlink_ts = walltimestamp/1000;
}

syscall::readlink:return
/TRACED && self->readlink_path != NULL/
{
    printf("MACTRACE_SYSCALL %d %d readlink %d %d %d \"%s\"\n",
        pid, tid, (int)arg1, errno, self->readlink_ts, self->readlink_path);
    self->readlink_path = NULL;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall in ("unlink", "readlink"):
            if len(args) >= 1:
                result["path"] = self.clean_str(args[0])
        elif syscall in ("rename", "link", "symlink"):
            if len(args) >= 1:
                result["oldpath"] = self.clean_str(args[0])
            if len(args) >= 2:
                result["newpath"] = self.clean_str(args[1])
        return result
