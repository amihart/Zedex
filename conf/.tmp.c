#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
int main()
{
    #ifdef __NR_read
    printf("|__NR_read| %i\n", __NR_read);
    #endif
    #ifdef __NR_write
    printf("|__NR_write| %i\n", __NR_write);
    #endif
    #ifdef __NR_open
    printf("|__NR_open| %i\n", __NR_open);
    #endif
    #ifdef __NR_stat
    printf("|__NR_stat| %i\n", __NR_stat);
    #endif
    #ifdef __NR_fstat
    printf("|__NR_fstat| %i\n", __NR_fstat);
    #endif
    #ifdef __NR_lstat
    printf("|__NR_lstat| %i\n", __NR_lstat);
    #endif
    #ifdef __NR_poll
    printf("|__NR_poll| %i\n", __NR_poll);
    #endif
    #ifdef __NR_rt_sigaction
    printf("|__NR_rt_sigaction| %i\n", __NR_rt_sigaction);
    #endif
    #ifdef __NR_rt_sigprocmask
    printf("|__NR_rt_sigprocmask| %i\n", __NR_rt_sigprocmask);
    #endif
    #ifdef __NR_pread64
    printf("|__NR_pread64| %i\n", __NR_pread64);
    #endif
    #ifdef __NR_pwrite64
    printf("|__NR_pwrite64| %i\n", __NR_pwrite64);
    #endif
    #ifdef __NR_readv
    printf("|__NR_readv| %i\n", __NR_readv);
    #endif
    #ifdef __NR_writev
    printf("|__NR_writev| %i\n", __NR_writev);
    #endif
    #ifdef __NR_access
    printf("|__NR_access| %i\n", __NR_access);
    #endif
    #ifdef __NR_pipe
    printf("|__NR_pipe| %i\n", __NR_pipe);
    #endif
    #ifdef __NR_select
    printf("|__NR_select| %i\n", __NR_select);
    #endif
    #ifdef __NR_mincore
    printf("|__NR_mincore| %i\n", __NR_mincore);
    #endif
    #ifdef __NR_shmat
    printf("|__NR_shmat| %i\n", __NR_shmat);
    #endif
    #ifdef __NR_shmctl
    printf("|__NR_shmctl| %i\n", __NR_shmctl);
    #endif
    #ifdef __NR_nanosleep
    printf("|__NR_nanosleep| %i\n", __NR_nanosleep);
    #endif
    #ifdef __NR_getitimer
    printf("|__NR_getitimer| %i\n", __NR_getitimer);
    #endif
    #ifdef __NR_setitimer
    printf("|__NR_setitimer| %i\n", __NR_setitimer);
    #endif
    #ifdef __NR_sendfile
    printf("|__NR_sendfile| %i\n", __NR_sendfile);
    #endif
    #ifdef __NR_connect
    printf("|__NR_connect| %i\n", __NR_connect);
    #endif
    #ifdef __NR_accept
    printf("|__NR_accept| %i\n", __NR_accept);
    #endif
    #ifdef __NR_sendto
    printf("|__NR_sendto| %i\n", __NR_sendto);
    #endif
    #ifdef __NR_recvfrom
    printf("|__NR_recvfrom| %i\n", __NR_recvfrom);
    #endif
    #ifdef __NR_sendmsg
    printf("|__NR_sendmsg| %i\n", __NR_sendmsg);
    #endif
    #ifdef __NR_recvmsg
    printf("|__NR_recvmsg| %i\n", __NR_recvmsg);
    #endif
    #ifdef __NR_bind
    printf("|__NR_bind| %i\n", __NR_bind);
    #endif
    #ifdef __NR_getsockname
    printf("|__NR_getsockname| %i\n", __NR_getsockname);
    #endif
    #ifdef __NR_getpeername
    printf("|__NR_getpeername| %i\n", __NR_getpeername);
    #endif
    #ifdef __NR_socketpair
    printf("|__NR_socketpair| %i\n", __NR_socketpair);
    #endif
    #ifdef __NR_setsockopt
    printf("|__NR_setsockopt| %i\n", __NR_setsockopt);
    #endif
    #ifdef __NR_getsockopt
    printf("|__NR_getsockopt| %i\n", __NR_getsockopt);
    #endif
    #ifdef __NR_clone
    printf("|__NR_clone| %i\n", __NR_clone);
    #endif
    #ifdef __NR_execve
    printf("|__NR_execve| %i\n", __NR_execve);
    #endif
    #ifdef __NR_wait4
    printf("|__NR_wait4| %i\n", __NR_wait4);
    #endif
    #ifdef __NR_uname
    printf("|__NR_uname| %i\n", __NR_uname);
    #endif
    #ifdef __NR_semop
    printf("|__NR_semop| %i\n", __NR_semop);
    #endif
    #ifdef __NR_shmdt
    printf("|__NR_shmdt| %i\n", __NR_shmdt);
    #endif
    #ifdef __NR_msgsnd
    printf("|__NR_msgsnd| %i\n", __NR_msgsnd);
    #endif
    #ifdef __NR_msgrcv
    printf("|__NR_msgrcv| %i\n", __NR_msgrcv);
    #endif
    #ifdef __NR_msgctl
    printf("|__NR_msgctl| %i\n", __NR_msgctl);
    #endif
    #ifdef __NR_truncate
    printf("|__NR_truncate| %i\n", __NR_truncate);
    #endif
    #ifdef __NR_getdents
    printf("|__NR_getdents| %i\n", __NR_getdents);
    #endif
    #ifdef __NR_getcwd
    printf("|__NR_getcwd| %i\n", __NR_getcwd);
    #endif
    #ifdef __NR_chdir
    printf("|__NR_chdir| %i\n", __NR_chdir);
    #endif
    #ifdef __NR_rename
    printf("|__NR_rename| %i\n", __NR_rename);
    #endif
    #ifdef __NR_mkdir
    printf("|__NR_mkdir| %i\n", __NR_mkdir);
    #endif
    #ifdef __NR_rmdir
    printf("|__NR_rmdir| %i\n", __NR_rmdir);
    #endif
    #ifdef __NR_creat
    printf("|__NR_creat| %i\n", __NR_creat);
    #endif
    #ifdef __NR_link
    printf("|__NR_link| %i\n", __NR_link);
    #endif
    #ifdef __NR_unlink
    printf("|__NR_unlink| %i\n", __NR_unlink);
    #endif
    #ifdef __NR_symlink
    printf("|__NR_symlink| %i\n", __NR_symlink);
    #endif
    #ifdef __NR_readlink
    printf("|__NR_readlink| %i\n", __NR_readlink);
    #endif
    #ifdef __NR_chmod
    printf("|__NR_chmod| %i\n", __NR_chmod);
    #endif
    #ifdef __NR_chown
    printf("|__NR_chown| %i\n", __NR_chown);
    #endif
    #ifdef __NR_lchown
    printf("|__NR_lchown| %i\n", __NR_lchown);
    #endif
    #ifdef __NR_gettimeofday
    printf("|__NR_gettimeofday| %i\n", __NR_gettimeofday);
    #endif
    #ifdef __NR_getrlimit
    printf("|__NR_getrlimit| %i\n", __NR_getrlimit);
    #endif
    #ifdef __NR_getrusage
    printf("|__NR_getrusage| %i\n", __NR_getrusage);
    #endif
    #ifdef __NR_sysinfo
    printf("|__NR_sysinfo| %i\n", __NR_sysinfo);
    #endif
    #ifdef __NR_times
    printf("|__NR_times| %i\n", __NR_times);
    #endif
    #ifdef __NR_syslog
    printf("|__NR_syslog| %i\n", __NR_syslog);
    #endif
    #ifdef __NR_getgroups
    printf("|__NR_getgroups| %i\n", __NR_getgroups);
    #endif
    #ifdef __NR_setgroups
    printf("|__NR_setgroups| %i\n", __NR_setgroups);
    #endif
    #ifdef __NR_setresuid
    printf("|__NR_setresuid| %i\n", __NR_setresuid);
    #endif
    #ifdef __NR_getresuid
    printf("|__NR_getresuid| %i\n", __NR_getresuid);
    #endif
    #ifdef __NR_getresgid
    printf("|__NR_getresgid| %i\n", __NR_getresgid);
    #endif
    #ifdef __NR_rt_sigpending
    printf("|__NR_rt_sigpending| %i\n", __NR_rt_sigpending);
    #endif
    #ifdef __NR_sigtimedwait
    printf("|__NR_sigtimedwait| %i\n", __NR_sigtimedwait);
    #endif
    #ifdef __NR_rt_sigqueueinfo
    printf("|__NR_rt_sigqueueinfo| %i\n", __NR_rt_sigqueueinfo);
    #endif
    #ifdef __NR_rt_sigsuspend
    printf("|__NR_rt_sigsuspend| %i\n", __NR_rt_sigsuspend);
    #endif
    #ifdef __NR_sigaltstack
    printf("|__NR_sigaltstack| %i\n", __NR_sigaltstack);
    #endif
    #ifdef __NR_utime
    printf("|__NR_utime| %i\n", __NR_utime);
    #endif
    #ifdef __NR_mknod
    printf("|__NR_mknod| %i\n", __NR_mknod);
    #endif
    #ifdef __NR_uselib
    printf("|__NR_uselib| %i\n", __NR_uselib);
    #endif
    #ifdef __NR_ustat
    printf("|__NR_ustat| %i\n", __NR_ustat);
    #endif
    #ifdef __NR_statfs
    printf("|__NR_statfs| %i\n", __NR_statfs);
    #endif
    #ifdef __NR_fstatfs
    printf("|__NR_fstatfs| %i\n", __NR_fstatfs);
    #endif
    #ifdef __NR_sched_setparam
    printf("|__NR_sched_setparam| %i\n", __NR_sched_setparam);
    #endif
    #ifdef __NR_sched_getparam
    printf("|__NR_sched_getparam| %i\n", __NR_sched_getparam);
    #endif
    #ifdef __NR_sched_setscheduler
    printf("|__NR_sched_setscheduler| %i\n", __NR_sched_setscheduler);
    #endif
    #ifdef __NR_sched_rr_get_interval
    printf("|__NR_sched_rr_get_interval| %i\n", __NR_sched_rr_get_interval);
    #endif
    #ifdef __NR_modify_ldt
    printf("|__NR_modify_ldt| %i\n", __NR_modify_ldt);
    #endif
    #ifdef __NR_pivot_root
    printf("|__NR_pivot_root| %i\n", __NR_pivot_root);
    #endif
    #ifdef __NR_sysctl
    printf("|__NR_sysctl| %i\n", __NR_sysctl);
    #endif
    #ifdef __NR_arch_prctl
    printf("|__NR_arch_prctl| %i\n", __NR_arch_prctl);
    #endif
    #ifdef __NR_adjtimex
    printf("|__NR_adjtimex| %i\n", __NR_adjtimex);
    #endif
    #ifdef __NR_setrlimit
    printf("|__NR_setrlimit| %i\n", __NR_setrlimit);
    #endif
    #ifdef __NR_chroot
    printf("|__NR_chroot| %i\n", __NR_chroot);
    #endif
    #ifdef __NR_acct
    printf("|__NR_acct| %i\n", __NR_acct);
    #endif
    #ifdef __NR_settimeofday
    printf("|__NR_settimeofday| %i\n", __NR_settimeofday);
    #endif
    #ifdef __NR_mount
    printf("|__NR_mount| %i\n", __NR_mount);
    #endif
    #ifdef __NR_umount2
    printf("|__NR_umount2| %i\n", __NR_umount2);
    #endif
    #ifdef __NR_swapon
    printf("|__NR_swapon| %i\n", __NR_swapon);
    #endif
    #ifdef __NR_swapoff
    printf("|__NR_swapoff| %i\n", __NR_swapoff);
    #endif
    #ifdef __NR_reboot
    printf("|__NR_reboot| %i\n", __NR_reboot);
    #endif
    #ifdef __NR_sethostname
    printf("|__NR_sethostname| %i\n", __NR_sethostname);
    #endif
    #ifdef __NR_setdomainname
    printf("|__NR_setdomainname| %i\n", __NR_setdomainname);
    #endif
    #ifdef __NR_iopl
    printf("|__NR_iopl| %i\n", __NR_iopl);
    #endif
    #ifdef __NR_init_module
    printf("|__NR_init_module| %i\n", __NR_init_module);
    #endif
    #ifdef __NR_delete_module
    printf("|__NR_delete_module| %i\n", __NR_delete_module);
    #endif
    #ifdef __NR_quotactl
    printf("|__NR_quotactl| %i\n", __NR_quotactl);
    #endif
    #ifdef __NR_setxattr
    printf("|__NR_setxattr| %i\n", __NR_setxattr);
    #endif
    #ifdef __NR_lsetxaddr
    printf("|__NR_lsetxaddr| %i\n", __NR_lsetxaddr);
    #endif
    #ifdef __NR_fsetxaddr
    printf("|__NR_fsetxaddr| %i\n", __NR_fsetxaddr);
    #endif
    #ifdef __NR_getxaddr
    printf("|__NR_getxaddr| %i\n", __NR_getxaddr);
    #endif
    #ifdef __NR_lgetxattr
    printf("|__NR_lgetxattr| %i\n", __NR_lgetxattr);
    #endif
    #ifdef __NR_fgetxaddr
    printf("|__NR_fgetxaddr| %i\n", __NR_fgetxaddr);
    #endif
    #ifdef __NR_listxattr
    printf("|__NR_listxattr| %i\n", __NR_listxattr);
    #endif
    #ifdef __NR_llistxattr
    printf("|__NR_llistxattr| %i\n", __NR_llistxattr);
    #endif
    #ifdef __NR_flistxattr
    printf("|__NR_flistxattr| %i\n", __NR_flistxattr);
    #endif
    #ifdef __NR_removexattr
    printf("|__NR_removexattr| %i\n", __NR_removexattr);
    #endif
    #ifdef __NR_lremovexattr
    printf("|__NR_lremovexattr| %i\n", __NR_lremovexattr);
    #endif
    #ifdef __NR_fremovexattr
    printf("|__NR_fremovexattr| %i\n", __NR_fremovexattr);
    #endif
    #ifdef __NR_time
    printf("|__NR_time| %i\n", __NR_time);
    #endif
    #ifdef __NR_futex
    printf("|__NR_futex| %i\n", __NR_futex);
    #endif
    #ifdef __NR_sched_setaffinity
    printf("|__NR_sched_setaffinity| %i\n", __NR_sched_setaffinity);
    #endif
    #ifdef __NR_sched_getaffinity
    printf("|__NR_sched_getaffinity| %i\n", __NR_sched_getaffinity);
    #endif
    #ifdef __NR_set_thread_area
    printf("|__NR_set_thread_area| %i\n", __NR_set_thread_area);
    #endif
    #ifdef __NR_io_setup
    printf("|__NR_io_setup| %i\n", __NR_io_setup);
    #endif
    #ifdef __NR_io_getevents
    printf("|__NR_io_getevents| %i\n", __NR_io_getevents);
    #endif
    #ifdef __NR_io_submit
    printf("|__NR_io_submit| %i\n", __NR_io_submit);
    #endif
    #ifdef __NR_io_cancel
    printf("|__NR_io_cancel| %i\n", __NR_io_cancel);
    #endif
    #ifdef __NR_get_thread_area
    printf("|__NR_get_thread_area| %i\n", __NR_get_thread_area);
    #endif
    #ifdef __NR_getdents64
    printf("|__NR_getdents64| %i\n", __NR_getdents64);
    #endif
    #ifdef __NR_set_tid_address
    printf("|__NR_set_tid_address| %i\n", __NR_set_tid_address);
    #endif
    #ifdef __NR_semtimedop
    printf("|__NR_semtimedop| %i\n", __NR_semtimedop);
    #endif
    #ifdef __NR_timer_create
    printf("|__NR_timer_create| %i\n", __NR_timer_create);
    #endif
    #ifdef __NR_timer_settime
    printf("|__NR_timer_settime| %i\n", __NR_timer_settime);
    #endif
    #ifdef __NR_timer_gettime
    printf("|__NR_timer_gettime| %i\n", __NR_timer_gettime);
    #endif
    #ifdef __NR_clock_settime
    printf("|__NR_clock_settime| %i\n", __NR_clock_settime);
    #endif
    #ifdef __NR_clock_gettime
    printf("|__NR_clock_gettime| %i\n", __NR_clock_gettime);
    #endif
    #ifdef __NR_clock_getres
    printf("|__NR_clock_getres| %i\n", __NR_clock_getres);
    #endif
    #ifdef __NR_clock_nanosleep
    printf("|__NR_clock_nanosleep| %i\n", __NR_clock_nanosleep);
    #endif
    #ifdef __NR_epoll_wait
    printf("|__NR_epoll_wait| %i\n", __NR_epoll_wait);
    #endif
    #ifdef __NR_epoll_ctl
    printf("|__NR_epoll_ctl| %i\n", __NR_epoll_ctl);
    #endif
    #ifdef __NR_utimes
    printf("|__NR_utimes| %i\n", __NR_utimes);
    #endif
    #ifdef __NR_mbind
    printf("|__NR_mbind| %i\n", __NR_mbind);
    #endif
    #ifdef __NR_set_mempolicy
    printf("|__NR_set_mempolicy| %i\n", __NR_set_mempolicy);
    #endif
    #ifdef __NR_get_mempolicy
    printf("|__NR_get_mempolicy| %i\n", __NR_get_mempolicy);
    #endif
    #ifdef __NR_mq_open
    printf("|__NR_mq_open| %i\n", __NR_mq_open);
    #endif
    #ifdef __NR_mq_unlink
    printf("|__NR_mq_unlink| %i\n", __NR_mq_unlink);
    #endif
    #ifdef __NR_mq_timedsend
    printf("|__NR_mq_timedsend| %i\n", __NR_mq_timedsend);
    #endif
    #ifdef __NR_mq_timedreceive
    printf("|__NR_mq_timedreceive| %i\n", __NR_mq_timedreceive);
    #endif
    #ifdef __NR_mq_notify
    printf("|__NR_mq_notify| %i\n", __NR_mq_notify);
    #endif
    #ifdef __NR_mq_getsetattr
    printf("|__NR_mq_getsetattr| %i\n", __NR_mq_getsetattr);
    #endif
    #ifdef __NR_kexec_load
    printf("|__NR_kexec_load| %i\n", __NR_kexec_load);
    #endif
    #ifdef __NR_waitid
    printf("|__NR_waitid| %i\n", __NR_waitid);
    #endif
    #ifdef __NR_add_key
    printf("|__NR_add_key| %i\n", __NR_add_key);
    #endif
    #ifdef __NR_request_key
    printf("|__NR_request_key| %i\n", __NR_request_key);
    #endif
    #ifdef __NR_inotify_add_watch
    printf("|__NR_inotify_add_watch| %i\n", __NR_inotify_add_watch);
    #endif
    #ifdef __NR_migrate_pages
    printf("|__NR_migrate_pages| %i\n", __NR_migrate_pages);
    #endif
    #ifdef __NR_openat
    printf("|__NR_openat| %i\n", __NR_openat);
    #endif
    #ifdef __NR_mkdirat
    printf("|__NR_mkdirat| %i\n", __NR_mkdirat);
    #endif
    #ifdef __NR_mknodat
    printf("|__NR_mknodat| %i\n", __NR_mknodat);
    #endif
    #ifdef __NR_fchownat
    printf("|__NR_fchownat| %i\n", __NR_fchownat);
    #endif
    #ifdef __NR_futimesat
    printf("|__NR_futimesat| %i\n", __NR_futimesat);
    #endif
    #ifdef __NR_newfstatat
    printf("|__NR_newfstatat| %i\n", __NR_newfstatat);
    #endif
    #ifdef __NR_unlinkat
    printf("|__NR_unlinkat| %i\n", __NR_unlinkat);
    #endif
    #ifdef __NR_renameat
    printf("|__NR_renameat| %i\n", __NR_renameat);
    #endif
    #ifdef __NR_linkat
    printf("|__NR_linkat| %i\n", __NR_linkat);
    #endif
    #ifdef __NR_symlinkat
    printf("|__NR_symlinkat| %i\n", __NR_symlinkat);
    #endif
    #ifdef __NR_readlinkat
    printf("|__NR_readlinkat| %i\n", __NR_readlinkat);
    #endif
    #ifdef __NR_fchmodat
    printf("|__NR_fchmodat| %i\n", __NR_fchmodat);
    #endif
    #ifdef __NR_faccessat
    printf("|__NR_faccessat| %i\n", __NR_faccessat);
    #endif
    #ifdef __NR_pselect6
    printf("|__NR_pselect6| %i\n", __NR_pselect6);
    #endif
    #ifdef __NR_ppoll
    printf("|__NR_ppoll| %i\n", __NR_ppoll);
    #endif
    #ifdef __NR_set_robust_list
    printf("|__NR_set_robust_list| %i\n", __NR_set_robust_list);
    #endif
    #ifdef __NR_get_robust_list
    printf("|__NR_get_robust_list| %i\n", __NR_get_robust_list);
    #endif
    #ifdef __NR_splice
    printf("|__NR_splice| %i\n", __NR_splice);
    #endif
    #ifdef __NR_vmsplice
    printf("|__NR_vmsplice| %i\n", __NR_vmsplice);
    #endif
    #ifdef __NR_move_pages
    printf("|__NR_move_pages| %i\n", __NR_move_pages);
    #endif
    #ifdef __NR_utimensat
    printf("|__NR_utimensat| %i\n", __NR_utimensat);
    #endif
    #ifdef __NR_epoll_pwait
    printf("|__NR_epoll_pwait| %i\n", __NR_epoll_pwait);
    #endif
    #ifdef __NR_signalfd
    printf("|__NR_signalfd| %i\n", __NR_signalfd);
    #endif
    #ifdef __NR_timerfd_settime
    printf("|__NR_timerfd_settime| %i\n", __NR_timerfd_settime);
    #endif
    #ifdef __NR_timerfd_gettime
    printf("|__NR_timerfd_gettime| %i\n", __NR_timerfd_gettime);
    #endif
    #ifdef __NR_accept4
    printf("|__NR_accept4| %i\n", __NR_accept4);
    #endif
    #ifdef __NR_signalfd4
    printf("|__NR_signalfd4| %i\n", __NR_signalfd4);
    #endif
    #ifdef __NR_pipe2
    printf("|__NR_pipe2| %i\n", __NR_pipe2);
    #endif
    #ifdef __NR_preadv
    printf("|__NR_preadv| %i\n", __NR_preadv);
    #endif
    #ifdef __NR_pwritev
    printf("|__NR_pwritev| %i\n", __NR_pwritev);
    #endif
    #ifdef __NR_rt_tgsigqueueinfo
    printf("|__NR_rt_tgsigqueueinfo| %i\n", __NR_rt_tgsigqueueinfo);
    #endif
    #ifdef __NR_perf_event_open
    printf("|__NR_perf_event_open| %i\n", __NR_perf_event_open);
    #endif
    #ifdef __NR_recvmmsg
    printf("|__NR_recvmmsg| %i\n", __NR_recvmmsg);
    #endif
    #ifdef __NR_prlimit64
    printf("|__NR_prlimit64| %i\n", __NR_prlimit64);
    #endif
    #ifdef __NR_name_to_handle_at
    printf("|__NR_name_to_handle_at| %i\n", __NR_name_to_handle_at);
    #endif
    #ifdef __NR_open_by_handle_at
    printf("|__NR_open_by_handle_at| %i\n", __NR_open_by_handle_at);
    #endif
    #ifdef __NR_clock_adjtime
    printf("|__NR_clock_adjtime| %i\n", __NR_clock_adjtime);
    #endif
    #ifdef __NR_sendmmsg
    printf("|__NR_sendmmsg| %i\n", __NR_sendmmsg);
    #endif
    #ifdef __NR_setns
    printf("|__NR_setns| %i\n", __NR_setns);
    #endif
    #ifdef __NR_getcpu
    printf("|__NR_getcpu| %i\n", __NR_getcpu);
    #endif
    #ifdef __NR_process_vm_readv
    printf("|__NR_process_vm_readv| %i\n", __NR_process_vm_readv);
    #endif
    #ifdef __NR_process_vm_writev
    printf("|__NR_process_vm_writev| %i\n", __NR_process_vm_writev);
    #endif
    #ifdef __NR_finit_module
    printf("|__NR_finit_module| %i\n", __NR_finit_module);
    #endif
    #ifdef __NR_sched_setattr
    printf("|__NR_sched_setattr| %i\n", __NR_sched_setattr);
    #endif
    #ifdef __NR_sched_getattr
    printf("|__NR_sched_getattr| %i\n", __NR_sched_getattr);
    #endif
    #ifdef __NR_renameat2
    printf("|__NR_renameat2| %i\n", __NR_renameat2);
    #endif
    #ifdef __NR_seccomp
    printf("|__NR_seccomp| %i\n", __NR_seccomp);
    #endif
    #ifdef __NR_getrandom
    printf("|__NR_getrandom| %i\n", __NR_getrandom);
    #endif
    #ifdef __NR_memfd_create
    printf("|__NR_memfd_create| %i\n", __NR_memfd_create);
    #endif
    #ifdef __NR_kexec_file_load
    printf("|__NR_kexec_file_load| %i\n", __NR_kexec_file_load);
    #endif
    #ifdef __NR_bpf
    printf("|__NR_bpf| %i\n", __NR_bpf);
    #endif
    #ifdef __NR_stub_execveat
    printf("|__NR_stub_execveat| %i\n", __NR_stub_execveat);
    #endif
    #ifdef __NR_copy_file_range
    printf("|__NR_copy_file_range| %i\n", __NR_copy_file_range);
    #endif
    #ifdef __NR_preadb2
    printf("|__NR_preadb2| %i\n", __NR_preadb2);
    #endif
    #ifdef __NR_pwritev2
    printf("|__NR_pwritev2| %i\n", __NR_pwritev2);
    #endif
    return 0;
}
