#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "crawler.test.binredir"
#endif


#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>


#include "binredir.h"



struct SBinRedir {
	pid_t pid;
	int read_fd;
	time_t last_time_stamp;
};



void binredir_exec(char* cmdline)
{
	system(cmdline);
}


TBinRedir* binredir_launch(char* cmdline)
{
	char write_buf[100];
	int enter_value = 13;
	TBinRedir* b = NULL;
	sprintf(write_buf,"%c",enter_value);

	int read_fd[2];
	int pid;

	char** argv = g_strsplit(cmdline, " ", 0);

	pipe(read_fd);
	pid = fork();

	if (pid == -1){
		g_error("Failed on create process: (%d) %s\n", errno, strerror(errno));
		exit(1);
	} 

	if (pid == 0) {		
		//child process
		close(read_fd[0]);      //close stdin of read pipe
		 dup2(read_fd[1], STDERR_FILENO); // Redirect stderr into writing end of pipe

		// Now that we have copies where needed, we can close all the child's 
		// other references to the pipes.
		close(read_fd[1]);      //close stdin of read pipe

		fprintf(stderr, "launch...%s\n", cmdline);

		// First argument of command is nearly always the executable name
		execv(argv[0], argv);

		// Shouldn't reach here
		fprintf(stderr, "execl Failed, cannont execute [%s]: (%d) %s\n", cmdline, errno, strerror(errno));
		exit(1);

	} else {		
		close(read_fd[1]);  // Don't need writing end of the stderr pipe in parent.

		fprintf(stdout, "Child pid (%s): %d\n", cmdline, pid);

		b = g_malloc0(sizeof(TBinRedir));
		b->pid      = pid;
		b->read_fd  = read_fd[0];
		time(&(b->last_time_stamp));
	}

	return b;
}


int binredir_stop(TBinRedir** handle)
{
	TBinRedir* b = *handle;
	int status;
	
	kill(b->pid, SIGQUIT);

	close(b->read_fd);

	waitpid(b->pid, &status, 0);	

	g_free(*handle);
	*handle = NULL;

	return 0;
}

// TODO: mettre un select avant le read, avec timeout...
int binredir_get(TBinRedir* handle, char* buff, int size, int timeout_sec)
{
	char* text = (char*) buff;
	int nb = 0;
	fd_set rfds;
	struct timeval tv;
	int retval;
	time_t current_time_stamp;

	text[0] = '\0';

	if (handle == 0) {
		fprintf(stdout, "handle == 0");
		return -1;
	}

	FD_ZERO(&rfds);
	FD_SET(handle->read_fd, &rfds);

	// timeout
	tv.tv_sec  = timeout_sec;   
	tv.tv_usec = 0;

	retval = select(handle->read_fd+1, &rfds, NULL, NULL, &tv);
	/* Donrely on the value of tv now! */

	if (retval == -1) {
		perror("select()");
	} else if (retval == 0) {
		//timeout
		nb = -1;
	} else if (retval) {
		if (FD_ISSET(handle->read_fd, &rfds)) {
			nb = read(handle->read_fd,  text, size);
			if (nb  == -1) {
				perror(" read error: ");
				exit(1);
			} else {
				text[nb] = '\0';
			}
		}
	} //else printf("No data within X seconds.\n");

	// TODO: check if pid is alive and not zombie --> timeout "no response"

	if (nb == 0) {
		text[nb] = '\0';

		// timeout ??
		time(&current_time_stamp);
		if (timeout_sec  > difftime(current_time_stamp, handle->last_time_stamp)) {
			// timeout
			nb = -1;			
		}
	} else {
		// reinit timeout
		time(&(handle->last_time_stamp));
	}

	return nb;
}

