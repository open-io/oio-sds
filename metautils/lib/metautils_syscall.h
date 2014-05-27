#ifndef __REDCURRANT__metautils_syscalls__h
# define __REDCURRANT__metautils_syscalls__h 1
# include <sys/types.h>

struct pollfd;
struct sockaddr;

struct metautils_syscalls_vtable_s {
	int (*open) (const char *, int, int);
	int (*shutdown) (int, int);
	int (*close) (int);
	int (*unlink) (const char *);

	int (*socket) (int, int, int);
	int (*connect) (int, const struct sockaddr *, socklen_t);
	int (*accept) (int, struct sockaddr *, socklen_t *);
	int (*accept4) (int, struct sockaddr *, socklen_t *, int);

	int (*poll) (struct pollfd *, int, int);
	ssize_t (*write) (int, const void *, size_t);
	ssize_t (*read) (int , void *, size_t);

	int (*getsockopt) (int, int, int, void *, socklen_t *);
	int (*setsockopt) (int, int, int, const void *, socklen_t);
};

void metautils_set_vtable_syscall(struct metautils_syscalls_vtable_s *vtable);
struct metautils_syscalls_vtable_s* metautils_get_vtable_syscall(void);

// Wrappers

int metautils_syscall_open (const char *, int, int);
int metautils_syscall_close (int);
int metautils_syscall_shutdown (int, int);
int metautils_syscall_unlink (const char *);
int metautils_syscall_socket (int, int, int);
int metautils_syscall_connect (int, const struct sockaddr *, socklen_t);
int metautils_syscall_accept (int, struct sockaddr *, socklen_t *);
#ifdef HAVE_ACCEPT4
int metautils_syscall_accept4 (int, struct sockaddr *, socklen_t *, int);
#endif
ssize_t metautils_syscall_write (int, const void *, size_t);
ssize_t metautils_syscall_read (int , void *, size_t);
int metautils_syscall_poll (struct pollfd *, int, int);
int metautils_syscall_getsockopt (int, int, int, void *, socklen_t *);
int metautils_syscall_setsockopt (int, int, int, const void *, socklen_t);

#endif // __REDCURRANT__metautils_syscalls__h
