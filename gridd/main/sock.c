#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "server.pool"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <metautils/lib/metautils.h>

#include "./sock.h"
#include "./server_internals.h"
#include "./srvalert.h"


#define FAMILY(S) ((struct sockaddr*)(S))->sa_family
#define ADDRLEN(A) (((struct sockaddr*)(A))->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

#include <poll.h>

gint
format_addr (struct sockaddr *sa, gchar *h, gsize hL, gchar *p, gsize pL, GError **err)
{
	if (!sa) {
		GSETERROR(err,"Invalid parameter");
		return 0;
	}

	memset (h, 0x00, hL);
	memset (p, 0x00, pL);

	*h = '?';
	*p = '?';

	/*no reverse resolution, only numeric addresses*/
	if (0 != getnameinfo (sa, ADDRLEN(sa), h, hL, p, pL, NI_NUMERICHOST|NI_NUMERICSERV)) {
		GSETERROR(err, "Cannot format the address (%s)", strerror(errno));
		return 0;
	}

	return 1;
}


gint
resolve (struct sockaddr_storage *sa, const gchar *h, const gchar *p, GError **err)
{
	gint retCode;
	struct addrinfo *ai=0, aiHint;

	if (!sa) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	memset(&aiHint, 0x00, sizeof(struct addrinfo));
	aiHint.ai_family = PF_UNSPEC;
	aiHint.ai_socktype = SOCK_STREAM;
	retCode = getaddrinfo (h, p, &aiHint, &ai);
	if (retCode != 0) {
		GSETERROR(err,"Cannot resolve [%s]:%s (%s)", (h?h:"0.0.0.0"), (p?p:"NOPORT"), gai_strerror(retCode));
		return 0;
	}
	if (!ai) {
		GSETERROR(err,"Cannot resolve [%s]:%s (%s)", (h?h:"0.0.0.0"), (p?p:"NOPORT"), "Unknown error");
		return 0;
	}

	memcpy (sa, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);
	return 1;
}


gint
accept_make(ACCEPT_POOL *s, GError **err)
{
	struct accept_pool_s *ap=NULL;

	if (!s) {
		GSETERROR(err,"Invalid parameter");
		goto error_param;
	}

	ap = g_try_malloc0 (sizeof(struct accept_pool_s));
	if (!ap) {
		GSETERROR(err,"Memory allocation error");
		goto error_pool;
	}

	g_static_rec_mutex_init(&(ap->mut));

	ap->count = 0;
	ap->size = 2;
	ap->srv = g_try_malloc0 (ap->size * sizeof(gint));
	if (!ap->srv) {
		GSETERROR(err,"Memory allocation failure");
		goto error_array;
	} else {
		int i;
		for (i=0; i<ap->size ;i++)
			ap->srv[i]=-1;
	}
	*s = ap;

	return 1;

error_array:
	g_free(ap);
error_pool:
error_param:
	return 0;
}


static const char*
_get_family_name (int f)
{
	switch (f) {
		case PF_LOCAL: return "PF_LOCAL";
		case PF_INET: return "PF_INET";
		case PF_INET6: return "PF_INET6";
		case PF_UNSPEC: return "PF_UNSPEC";
	}
	return "?";
}


static gint
accept_add_any (ACCEPT_POOL ap, int srv, GError **err)
{
	gint rc = 0;
	if (!ap || srv<0)
	{
		GSETERROR (err, "Invalid parameter");
		return 0;
	}

	g_static_rec_mutex_lock (&(ap->mut));

	/*allocates an array if it is necessary*/
	if (!ap->srv) {
		GSETERROR(err, "AcceptPool not initialized (should not happen)");
		goto exitLabel;
	}

	/*make the arrays grows if it is too small*/
	if (ap->size <= ap->count) {
		gint *newSrv, newSize;
		newSize = ap->size + 2;
		newSrv = g_try_realloc (ap->srv, sizeof(gint) * newSize);
		if (!newSrv)
		{
			GSETERROR(err, "Memory allocation error (%s)", strerror(errno));
			goto exitLabel;
		}
		memset (newSrv+ap->size, 0x00, sizeof(gint) * 2);
		ap->size = newSize;
		ap->srv = newSrv;
	}

	ap->srv [ap->count++] = srv;

	rc = 1;
exitLabel:
	g_static_rec_mutex_unlock (&(ap->mut));
	return rc;
}




struct working_parameter_s
{
	char buf[2048];
	int  buf_len;
	struct {
		char *ptr;
		int   size;
	} path;
	mode_t mode;
};

static void
parse_option_mode( struct working_parameter_s *pParam, char *pV )
{
	char *pVEnd=NULL;
	guint64 u64, max;

	switch (sizeof(mode_t)) {
		case 1: max = G_MAXUINT8; break;
		case 2: max = G_MAXUINT16; break;
		case 4: max = G_MAXUINT32; break;
		case 8: max = G_MAXUINT64; break;
		default: abort();
	}

	errno=0;
	u64 = g_ascii_strtoull( pV, &pVEnd, 8);
	if (errno!=0) {
		WARN("Invalid mode found for UNIX socket [%s] : %s", pParam->path.ptr, strerror(errno));
	} else if (!u64 && pVEnd==pV) {
		WARN("Invalid mode found for UNIX socket [%s] : not an integer", pParam->path.ptr);
	} else if (u64>max) {
		WARN("Invalid mode found for UNIX socket [%s] : out of range", pParam->path.ptr);
	} else {
		pParam->mode = u64;
		pParam->mode |= S_IRUSR|S_IWUSR;
		NOTICE("UNIX socket [%s] will have permissions [%o]", pParam->path.ptr, pParam->mode);
	}
}

static void
parse_one_option( struct working_parameter_s *pParam, char *pStr, int len )
{
	char *pEq;
	pEq = g_strstr_len( pStr, len, "=" );
	if (!pEq) {
		ERROR("Invalid UNIX socket argument format. Must be key=value");
		return;
	} else {
		char *pK, *pV;
		pV = pEq+1;
		pK = pStr;
		*pEq = '\0';
		DEBUG("UNIX socket option found: k=[%s] v=[%s]", pK, pV);
		if (0==g_ascii_strcasecmp(pK,"mode")) {
			parse_option_mode( pParam, pV );
		} else {
			ERROR("Unrecongnized UNIX socket option [%s] with value [%s]", pK, pV);
		}
	}
}

static void
parse_socket_options( struct working_parameter_s *pParam )
{
	char *pStart, *pEnd;
	
	/*find options beginning*/
	pStart = g_strstr_len( pParam->buf, pParam->buf_len, "?" );
	if (!pStart) {
		if (g_strstr_len( pParam->buf, pParam->buf_len, "&" )) {
			WARN("It is unusual to have '?' in a path, without a '&', check UNIX socket paths");
		}
		return;
	}
	*pStart = '\0';
	pStart++;

	while (*pStart) {
		pEnd = g_strstr_len( pStart, strlen(pStart), "&" );
		if (pEnd) {
			*pEnd='\0';
			DEBUG("Found argument pair [%s]", pStart);
			parse_one_option( pParam, pStart, pEnd-pStart );
			pStart = pEnd+1;
		} else {
			DEBUG("Found argument pair [%s]", pStart);
			parse_one_option( pParam, pStart, strlen(pStart) );
			break;
		}
	}
}

static void
init_socket_options_defaults( const gchar *l, struct working_parameter_s *pParam)
{
	char *pStr;
	memset( pParam, 0x00, sizeof(struct working_parameter_s) );
	pParam->buf_len = g_strlcpy( pParam->buf, l, sizeof(pParam->buf)-1 );
	
	pParam->mode = 0644;
	for (pStr=pParam->buf; *pStr=='/' ;pStr++) {
		char c = *(pStr+1);
		if (!c || c!='/')
			break;
	}
	pParam->path.ptr = pStr;
	pParam->path.size = strlen( pParam->path.ptr );
}

static int
check_socket_is_absent( struct working_parameter_s *pParam, GError **err )
{
	struct sockaddr_un sun;
	int attempts, fd, rc;
	struct stat lStat;

	for (attempts=3; attempts>0 ; attempts--) {
		if (-1==stat( pParam->path.ptr, &lStat )) {

			switch (errno) {
				case ENOTDIR:
				case EACCES:
				case ELOOP:
					GSETERROR(err,"cannot access the socket path : %s", strerror(errno));
					return -1;
				default:
					return 0;
			}

		} else {

			if (!S_ISSOCK(lStat.st_mode)) {
				GSETERROR(err,"path %s exists and is not a socket, remove it and restart the server", pParam->path.ptr);
				return -1;
			}

			if (-1==(fd = socket(PF_LOCAL, SOCK_STREAM, 0))) {
				GSETERROR(err,"socket error : %s", strerror(errno));
				return -1;
			}


			/*try to connect*/
			sun.sun_family = PF_LOCAL;
			strncpy(sun.sun_path, pParam->path.ptr, sizeof(sun.sun_path));
			rc = connect(fd,(struct sockaddr*)&sun,sizeof(sun));
			metautils_pclose(&fd);
			if (!rc) {
				GSETERROR(err,"Server socket already up at [%s]", pParam->path.ptr);
				return -1;
			} else if (-1==unlink(pParam->path.ptr)) {
				GSETERROR(err,"Cannot remove the socket at [%s] : %s", pParam->path.ptr, strerror(errno));
				return -1;
			} /*else the socket has been unlinked, we retry to connect*/
			NOTICE("Socket %s unlinked", pParam->path.ptr);

		}
	}

	GSETERROR(err, "Supposed socket [%s] could not be removed", pParam->path.ptr);
	return -1;
}

gint
accept_add_local (ACCEPT_POOL ap, const gchar *l, GError **err)
{
	struct working_parameter_s wrkParam;
	struct sockaddr_un sun;
	int srv = -1;
	
	if (!l || !(*l))
	{
		GSETERROR(err,"invalid parameter");
		goto errorLabel;
	}

	/*parse the URL*/
	init_socket_options_defaults( l, &wrkParam );
	parse_socket_options( &wrkParam );

	/*try to stat the file*/
	if (-1 == check_socket_is_absent( &wrkParam, err )) {
		GSETERROR(err,"A socket seems already present at [%s]", wrkParam.path.ptr);
	}

	/*open and bind the socket*/

	if (-1==(srv=socket(PF_UNIX, SOCK_STREAM, 0)))
	{
		GSETERROR(err,"Cannot open a new socket PF_UNIX : %s", strerror(errno));
		goto errorLabel;
	}
	
	if (!sock_set_reuseaddr(srv, TRUE)) {
		GSETERROR(err,"Cannot set SO_REUSEADDR on %d [%s] (%s)", srv, l, strerror(errno));
		goto errorLabel;
	}

	fcntl(srv, F_SETFL, O_NONBLOCK|fcntl(srv, F_GETFL));

	sun.sun_family = PF_LOCAL;
	strncpy(sun.sun_path, wrkParam.path.ptr, sizeof(sun.sun_path));

	if (-1==bind (srv, (struct sockaddr*) &sun, sizeof(struct sockaddr_un)))
	{
		GSETERROR(err,"cannot bind srv=%d to %s (%s)", srv, l, strerror(errno));
		goto errorLabel;
	}
	
	if (-1==listen (srv,AP_BACKLOG))
	{
		GSETERROR(err,"cannot listen to inbound connections : %s",  strerror(errno));
		goto errorLabel;
	}
	
	if (!accept_add_any(ap,srv,err))
	{
		GSETERROR(err,"Cannot monitor the local server");
		goto errorLabel;
	}

	/*change socket rights*/
	if (0 != chmod(wrkParam.path.ptr,wrkParam.mode)) {
		int errsav = errno;
		ERROR("Failed to set mode [%o] on UNIX socket [%s] : %s", wrkParam.mode, wrkParam.path.ptr, strerror(errsav));
		SRV_SEND_WARNING("server","UNIX socket might be not accessible : failed to set mode [%o] on UNIX socket [%s] (%s)",
			wrkParam.mode, wrkParam.path.ptr, strerror(errsav));
	}
	
	INFO("socket srv=%d %s now monitored", srv, _get_family_name(FAMILY(&sun)));

	return 1;
errorLabel:
	if (srv>=0)
		metautils_pclose(&srv);
	return 0;
}


gint
accept_add_inet (ACCEPT_POOL ap, const gchar *h, const gchar *p, GError **err)
{
	struct sockaddr_storage sa;
	gint srv = -1;

	if (!ap || !p)
	{
		GSETERROR (err, "Invalid parameter");
		goto errorLabel;
	}

	if (!h || !(*h))
		h = "0.0.0.0";

	if (!resolve (&sa, h, p, err))
	{
		GSETERROR(err,"Cannot resolve [%s]:%s", h, p);
		goto errorLabel;
	}

	/*create the server socket*/
	if (-1 == (srv = socket (FAMILY(&sa), SOCK_STREAM, 0)))
	{
		GSETERROR(err,"Cannot open a %s socket (%s)", _get_family_name(FAMILY(&sa)), strerror(errno));
		goto errorLabel;
	}

	if (!sock_set_reuseaddr(srv, TRUE)) {
		GSETERROR(err,"Cannot set SO_REUSEADDR on %d [%s]:%s (%s)", srv, h, p, strerror(errno));
		goto errorLabel;
	}

	fcntl(srv, F_SETFL, O_NONBLOCK|fcntl(srv, F_GETFL));

	if (-1 == bind (srv, (struct sockaddr*)(&sa), sizeof(struct sockaddr_in)))
	{
		GSETERROR(err,"Cannot bind %d on [%s]:%s (%s)", srv, h, p, strerror(errno));
		goto errorLabel;
	}

	if (-1 == listen (srv,AP_BACKLOG))
	{
		GSETERROR(err,"Cannot listen on %d [%s]:%s (%s)", srv, h, p, strerror(errno));
		goto errorLabel;
	}

	if (!accept_add_any(ap,srv,err))
	{
		GSETERROR(err,"Cannot monitor %s srv=%d", _get_family_name(FAMILY(&sa)), srv);
		goto errorLabel;
	}

	return 1;
errorLabel:
	if (srv>=0)
		metautils_pclose(&srv);
	return 0;
}


static int
UNSAFE_accept_many_server(struct pollfd *pfd, int max,
		struct sockaddr *sa, socklen_t *saSize, GError **err)
{
	int nbEvents = poll(pfd, max, 2000);

	/* timeout or error */
	if (nbEvents == 0)
		return -1;
	if (nbEvents < 0) {
		if (errno != EINTR && errno != EAGAIN)
			GSETERROR(err,"poll error : %s", strerror(errno));
		return -1;
	}

	/* events! */
	for (int i=0; i<max ;i++) {
		if (!pfd[i].revents)
			continue;
		if (pfd[i].revents & POLLIN) {
			int clt = accept_nonblock(pfd[i].fd, sa, saSize);
			if (clt >= 0)
				return clt;
			if (errno != EAGAIN && errno != EINTR)
				GSETERROR(err,"accept error : %s", strerror(errno));
			return -1;
		}
	}

	return -1;
}

static int
UNSAFE_accept_do(ACCEPT_POOL ap, struct sockaddr *sa, socklen_t *saSize, GError **err)
{
	if (ap->count <= 0) {
		GSETERROR(err,"No server configured");
		return -1;
	}

	struct pollfd *pfd = g_alloca(ap->count * sizeof(struct pollfd));
	for (int i=0; i<ap->count ;i++) {
		pfd[i].fd = ap->srv[i];
		pfd[i].events = POLLIN;
		pfd[i].revents = 0;
	}

	g_static_rec_mutex_lock (&(ap->mut));
	int clt = UNSAFE_accept_many_server(pfd, ap->count, sa, saSize, err);
	g_static_rec_mutex_unlock (&(ap->mut));

	return clt;
}


gint
accept_add (ACCEPT_POOL ap, const gchar *url, GError **err)
{
	if (!ap || !url || !(*url)) {
		GSETERROR(err,"Invalid parameter");
		return 0;
	}

	if (*url=='/') {
		return accept_add_local (ap,url,err);
	} else {
		char *colon;
		if (!(colon=strrchr(url,':'))) {
			/*url supposed to be only a port*/
			return accept_add_inet (ap, NULL, url, err);
		}
		else {
			/*url supposed to be host:port*/
			/**@todo TODO manage ipv6 addresses format*/
			*colon = '\0';
			return accept_add_inet (ap, url, colon+1, err);
		}
	}
	return 0;
}


gint
accept_do (ACCEPT_POOL ap, addr_info_t *cltaddr, GError **err)
{
	struct sockaddr_storage sa;
	socklen_t saSize;
	int clt;

	errno=0;

	if (!ap) {
		GSETERROR(err,"Invalid parameter");
		return -1;
	}

	if (!ap->srv || ap->count<=0) {
		GSETERROR(err, "Empty server socket pool");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	saSize = sizeof(sa);
	clt = UNSAFE_accept_do (ap, (struct sockaddr*) &sa, &saSize, err);

	if (clt < 0)
		return -1;

	if (cltaddr != NULL) {
		memset(cltaddr, 0, sizeof(addr_info_t));
		addrinfo_from_sockaddr(cltaddr, (struct sockaddr*)&sa, saSize);
	}

	/*Set all the helpful socket options*/
	if (gridd_flags & GRIDD_FLAG_NOLINGER)
		sock_set_linger_default(clt);
	if (gridd_flags & GRIDD_FLAG_KEEPALIVE)
		sock_set_keepalive(clt, TRUE);
	if (gridd_flags & GRIDD_FLAG_QUICKACK)
		sock_set_tcpquickack(clt, TRUE);

	return clt;
}


static void
remove_unix_socket( int fd )
{
	struct sockaddr_storage ss;
	socklen_t ss_size = sizeof(ss);

	errno=0;
	memset( &ss, 0x00, sizeof(ss));

	if (0 != getsockname(fd, (struct sockaddr*)&ss, &ss_size)) {
		ERROR("getsockname error : %s", strerror(errno));
	} else if (ss.ss_family == PF_LOCAL) {
		struct stat sock_stats;
		char *path = ((struct sockaddr_un*) &ss)->sun_path;

		/*we do not touch something else than a socket*/
		memset(&sock_stats, 0x00, sizeof(sock_stats));
		if (0 != stat(path, &sock_stats)) {
			/*socket not found, this is not really a problem*/
			NOTICE("Listen socket (%s) not found : %s", path, strerror(errno));
			return;
		} else {
			if (!S_ISSOCK(sock_stats.st_mode)) {
				ERROR("Listen socket (%s) is not a socket, not removed", path);
				return;
			}
		}

		/*remove ... now!*/
		if (0 != unlink(path)) {
			ERROR("Listen socket (%s) cannot be removed : %s", path, strerror(errno));
		} else {
			NOTICE("Socket %s removed", path);
		}
	}
}

gint
accept_close_servers (ACCEPT_POOL ap, GError **err)
{
	int *pSrv = NULL; 
	int max=0, nb_errors=0;

	if (!ap) {
		GSETERROR(err,"Invalid parameter");
		return 0;
	}

	g_static_rec_mutex_lock (&(ap->mut));
	if (ap->srv) {
		pSrv = ap->srv;
		max = ap->count;
	}
	ap->srv = NULL;
	ap->count = 0;
	g_static_rec_mutex_unlock (&(ap->mut));

	if (pSrv) {
		int i;
		for (i=0; i<max ;i++) {
			int fd = pSrv[ i ];
			if (fd>=0) {
				remove_unix_socket( fd );
				errno=0;
				metautils_pclose(&fd);
			}
			pSrv[ i ] = -1;
		}
	}

	g_free(pSrv);
	return nb_errors;
}

gsize
accept_pool_to_string( ACCEPT_POOL ap, gchar *dst, gsize dst_size )
{
	gchar *fmt1=",[%s]:%s", *fmt0="[%s]:%s";
	struct sockaddr_storage ss;
	socklen_t ss_size;
	gsize writen_size=0;

	g_static_rec_mutex_lock (&(ap->mut));
	if (ap->srv) {
		int i,max;
		char host[64], port[6], *fmt=fmt0;

		for (i=0,max=ap->count; i<max ;i++) {
			gint writen;
			ss_size = sizeof(ss);
			if (0!=getsockname(ap->srv[i], (struct sockaddr*)&ss, &ss_size))
				continue;
			if (!format_addr((struct sockaddr*)&ss, host, sizeof(host), port, sizeof(port), NULL))
				continue;
			writen = g_snprintf( dst+writen_size, dst_size-writen_size, fmt, host, port);
			fmt = fmt1;
			if (writen>0)
				writen_size += writen;
		}
	}
	g_static_rec_mutex_unlock (&(ap->mut));

	return writen_size;
}

gboolean
wait_for_socket(int fd, long ms)
{
	struct pollfd pfd;

retry:
	pfd.fd = fd;
	pfd.events = POLLIN|POLLERR|POLLHUP;
	pfd.revents = 0;
	int rc = poll(&pfd, 1, ms);
	if (rc < 0 && errno == EINTR)
		goto retry;
	return rc != 0;
}

