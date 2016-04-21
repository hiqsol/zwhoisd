#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <pwd.h>

extern int errno;
extern uint32_t hashlittle( const void *key, size_t length, uint32_t initval);

int                 daemon_mode = 0;
int                 thread_mode = 0;
int                 ipv6_mode   = 0;

char                path2templates[256];
char                path2data[256];
size_t              path2data_len;
char                path2log[256];
char                path2pid[256];
char                username[16];
int                 listen_sock;
struct sockaddr_in  listen_sin4;
struct sockaddr_in6 listen_sin6;
struct iovec        tpl[3];
struct sf_hdtr      hdtr;

#define TPL_NOTFOUND        0
#define TPL_HEADER          1
#define TPL_FOOTER          2

#define REQUEST_BUF_SIZE    256

static void
print_usage (void) {
    fprintf(stderr, "Usage: zwhoisd -t /path/to/templates/ -w /path/to/whois/data/ -l /path/to/log/file -a listen_addr [-p /path/to/pidfile] [-u user] [-d] [-m] \n\t-d - daemon mode\n\t-m - multithreaded mode\n");
}

static int
parse_args (int argc, char *argv[]) {
  int       ch;
  size_t    len;

  while ((ch = getopt(argc, argv, "t:w:l:a:p:u:dm")) != -1) {
    switch (ch) {
      case 'd' :
        daemon_mode = 1;
        break;
      case 'm' :
        thread_mode = 1;
        break;
      case 't' :
        len = strlen(optarg);
        if(sizeof(path2templates) < len + 2)
          return(-1);
        memcpy(path2templates, optarg, len + 1);
        if(path2templates[len - 1] != '/') {        // add trailing '/'
          path2templates[len] = '/';
          path2templates[len + 1] = '\0';
        }
        break;
      case 'w' :
        path2data_len = strlen(optarg);
        if(sizeof(path2data) < path2data_len + 2)
          return(-1);
        memcpy(path2data, optarg, path2data_len + 1);
        if(path2data[path2data_len - 1] != '/') {
          path2data[path2data_len++] = '/';
          path2data[path2data_len] = '\0';
        }
        break;
      case 'l' :
        strncpy(path2log, optarg, sizeof(path2log));
        break;
      case 'a' :
        if (inet_pton(AF_INET,  optarg, &(listen_sin4.sin_addr)) == 1)
            break;
        if (inet_pton(AF_INET6, optarg, &(listen_sin6.sin6_addr)) != 1)
            return(-1);
        ipv6_mode = 1;
        break;
      case 'p' :
        strncpy(path2pid, optarg, sizeof(path2pid));
        break;
      case 'u' :
        strncpy(username, optarg, sizeof(username));
        break;
    }
  }
  return(0);
}

int
print2log(const char * format, ...) {
  FILE          *fd_log;
  static struct timeval    currtime;
  static char   time_buf[32];
  va_list       ap;

  fd_log = fopen(path2log, "a");
  if(fd_log == NULL)
    return(errno);

  if(gettimeofday(&currtime, NULL))
    return(errno);
  if(! ctime_r(&currtime.tv_sec, time_buf))
    return(-1);
  time_buf[24] = '\0';        // clear '\n'

  if (!daemon_mode)
    fprintf(stderr, "%s\t", time_buf);
  if (0 >= fprintf(fd_log, "%s\t", time_buf))
    return(-1);
  va_start(ap, format);
  if (!daemon_mode)
    vfprintf(stderr, format, ap);
  if (0 >= vfprintf(fd_log, format, ap)) {
    va_end(ap);
    return(-1);
  }

  fclose(fd_log);
  va_end(ap);
  return(0);
}

int
load_tpl(struct iovec *tpl_ref, char *name) {
  char          tpl_path[256];
  size_t        path_len;
  size_t        name_len;
  int           tpl_fd, ret;
  struct stat   sb;
  void          *tpl_data;

  memcpy(tpl_path, path2templates, 256);
  path_len = strlen(tpl_path);
  name_len = strlen(name);
  if(name_len == 0 || path_len + name_len >= 255) {
    print2log("path_len %u + name_len %u >= 255\n", path_len, name_len);
    return(-1);
  }
  memcpy(&(tpl_path[path_len]), name, name_len);
  tpl_path[path_len+name_len] = '\0';

  tpl_fd = open(tpl_path, O_RDONLY);
  if(tpl_fd == -1) {
    print2log("Can't open template %s: %s\n", tpl_path, strerror(errno));
    return(-1);
  }

  ret = fstat(tpl_fd, &sb);
  if(ret == -1) {
    print2log("Can't stat template %s: %s\n", tpl_path, strerror(errno));
    return(-1);
  }
  if(sb.st_size > 0) {
    tpl_data = malloc(sb.st_size);
    if(tpl_data == NULL) {
      print2log("Can't malloc %u bytes for template %s\n", sb.st_size, tpl_path);
      return(-1);
    }
    ret = read(tpl_fd, tpl_data, sb.st_size);
    if(ret != sb.st_size) {
      print2log("Can't read %u bytes for template %s - got only %u\n", sb.st_size, tpl_path, ret);
      free(tpl_data);
      return(-1);
    }
    if(tpl_ref->iov_base != NULL)
      free(tpl_ref->iov_base);
    tpl_ref->iov_base = tpl_data;
    tpl_ref->iov_len = ret;
  } else {                // empty template, not a problem
    if(tpl_ref->iov_base != NULL) {
      free(tpl_ref->iov_base);
      tpl_ref->iov_base = NULL;
    }
    tpl_ref->iov_len = 0;
  }

  return(0);
}

int
basic_init() {
  int           err, fd;
  int           sockopt = 1;
  struct accept_filter_arg    accf_arg;
  struct rlimit flim;
  FILE          *f_pid;
  struct passwd *pw_info;

  if(*path2templates == '\0') {
    fprintf(stderr, "Path to templates is not specified\n");
    return(-1);
  }
  if(*path2data == '\0') {
    fprintf(stderr, "Path to whois data is not specified\n");
    return(-1);
  }
  if(*path2log == '\0') {
    fprintf(stderr, "Path to log file is not specified\n");
    return(-1);
  }

// try to open logfile
  if((err = print2log("zwhoisd\n"))) {
    if(err > 0)
      fprintf(stderr, "Fail to log: %s\n", strerror(err));
    return(-1);
  }

// load templates
  if(load_tpl(&(tpl[TPL_NOTFOUND]), "notfound"))
    return(-1);
  if(load_tpl(&(tpl[TPL_HEADER]), "header"))
    return(-1);
  if(load_tpl(&(tpl[TPL_FOOTER]), "footer"))
    return(-1);
  if(tpl[TPL_HEADER].iov_len > 0) {
    hdtr.headers = &(tpl[TPL_HEADER]);
    hdtr.hdr_cnt = 1;
  }
  if(tpl[TPL_FOOTER].iov_len > 0) {
    hdtr.trailers = &(tpl[TPL_FOOTER]);
    hdtr.trl_cnt = 1;
  }

// daemonize
  if(daemon_mode) {
    if(getppid() != 1) {
      signal(SIGTTOU, SIG_IGN);
      signal(SIGTTIN, SIG_IGN);
      signal(SIGTSTP, SIG_IGN);
    }
    if(fork() != 0)
      exit(0);
    setsid();
    getrlimit(RLIMIT_NOFILE, &flim);
    for(fd = 0; fd < flim.rlim_max; fd++)
      close(fd);
    chdir("/");
  }

// open socket
  listen_sock = socket(ipv6_mode ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
  if(listen_sock == -1) {
    print2log("Fail to create socket: %s\n", strerror(errno));
    return(-1);
  }

  err = setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));
  if(err == -1) {
    print2log("Fail to set 'SO_REUSEADDR' option on socket on socket: %s\n", strerror(errno));
    return(-1);
  }

  if (ipv6_mode) {
    listen_sin6.sin6_family = AF_INET6;
    listen_sin6.sin6_port = htons(43);
    err = bind(listen_sock, (struct sockaddr *)&listen_sin6, sizeof(listen_sin6));
  } else {
    listen_sin4.sin_family = AF_INET;
    listen_sin4.sin_port = htons(43);
    err = bind(listen_sock, (struct sockaddr *)&listen_sin4, sizeof(listen_sin4));
  }
  if(err == -1) {
    print2log("Fail to bind socket: %s\n", strerror(errno));
    return(-1);
  }

  err = listen(listen_sock, -1);
  if(err == -1) {
    print2log("Fail to listen socket: %s\n", strerror(errno));
    return(-1);
  }

  bzero(&accf_arg, sizeof(accf_arg));
  strcpy(accf_arg.af_name, "dataready");
  err = setsockopt(listen_sock, SOL_SOCKET, SO_ACCEPTFILTER, &accf_arg, sizeof(accf_arg));
  if(err == -1) {
    print2log("Fail to set 'dataready' accept filter on socket: %s\n", strerror(errno));
    return(-1);
  }

// write pid
  if(path2pid[0] != '\0') {
    f_pid = fopen(path2pid, "w");
    if(f_pid == NULL) {
      print2log("Fail to open pidfile '%s': '%s'\n", path2pid, strerror(errno));
    } else {
      err = fprintf(f_pid, "%u\n", getpid());
      if(err < 0)
        print2log("Fail to write pid: %s\n", strerror(errno));
      fclose(f_pid);
    }
  }

// change gid/uid
  if(username[0] != '\0') {
    errno = 0;
    pw_info = getpwnam(username);
    if(pw_info == NULL) {
      print2log("Can not get uid for login '%s': %s\n", username, strerror(errno));
      print2log("Exiting\n");
      exit(1);
    }
    err = setgid(pw_info->pw_gid);
    if(err == -1) {
      print2log("Can not set gid %hu for login '%s': %s\n", pw_info->pw_gid, username, strerror(errno));
      print2log("Exiting\n");
      exit(1);
    }
    err = setuid(pw_info->pw_uid);
    if(err == -1) {
      print2log("Can not set uid %hu for login '%s': %s\n", pw_info->pw_uid, username, strerror(errno));
      print2log("Exiting\n");
      exit(1);
    }
  }

  return(0);
}

void
not_found(int conn) {
  int    ret;

  ret = write(conn, tpl[TPL_NOTFOUND].iov_base, tpl[TPL_NOTFOUND].iov_len);
  if(ret == -1) {
    print2log("Error while writing 'notfound' template: %s\n", strerror(errno));
  }
}

/* request[] must match /=?[a-zA-Z0-9.-]+\r\n/ */
const char ascii[256] = {
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, '-','.', 0,
  '0','1','2','3','4','5','6','7','8','9', 0,  0,  0,  0,  0,  0,
   0, 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o',
  'p','q','r','s','t','u','v','w','x','y','z', 0,  0,  0,  0,  0,
   0, 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o',
  'p','q','r','s','t','u','v','w','x','y','z', 0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
};

#define DOMAIN_STRLEN        7
#define NAMESERVER_STRLEN    11
int
process_request(int conn, char *request, ssize_t request_size) {
  char          domain_path[256];
  char          domain_name[REQUEST_BUF_SIZE];
  int           i, path_size, dom_fd, ret;
  uint32_t      hash_val;
  struct stat   sb;
  off_t         sbytes;

  bzero(domain_name, REQUEST_BUF_SIZE);

  while(request[request_size - 1] == '\n' || request[request_size - 1] == '\r') {
    request_size -= 1;
    if(request_size <= 0) {
      return -1;
    }
  }

  if(request_size > NAMESERVER_STRLEN) {
    if(0 == strncmp(request, "nameserver ", NAMESERVER_STRLEN)) {
      return(0);
    }
  }

  if(request_size > DOMAIN_STRLEN) {
    if(0 == strncmp(request, "domain ", DOMAIN_STRLEN)) {
      request += DOMAIN_STRLEN;
      request_size -= DOMAIN_STRLEN;
    }
  }

  while(request[0] == '.' || request[0] == ' ') {    // remove all leading dots and spaces
    request++;
    request_size--;
    if(request_size <= 0)
      return(-1);
  }

  if(request[0] == '=') {
    request++;
    request_size--;
  }

  while(request[request_size - 1] == '.') {        // remove all trailing dots
    request_size--;
    if(request_size <= 0)
      return(-1);
  }

  for(i = 0; i < request_size; i++) {
    if(ascii[request[i]] == 0)                // wrong character
      return(-1);
    domain_name[i] = ascii[request[i]];
  }

  hash_val = hashlittle(domain_name, request_size, 1928374650);
  hash_val &= 0xfff;            // use 12 bits of hash value (0..4095)

  path_size = snprintf(domain_path, sizeof(domain_path), "%s%04u/%s", path2data, hash_val, domain_name);
  if(path_size == sizeof(domain_path) - 1 || path_size <= 0) {
    print2log("Too long path size '%s' for domain '%s' (hash_val %04hu)\n", domain_path, domain_name, hash_val);
    return(-1);
  }

// open file with whois data for requested domain, obtained fd will be used in sendfile()
  dom_fd = open(domain_path, O_RDONLY);
  if(dom_fd == -1) {            // no such record for this domain
    print2log("No record for '%s' (hash_val %04hu): %s\n", domain_name, hash_val, strerror(errno));
    not_found(conn);
    return(0);
  }

  ret = sendfile(dom_fd, conn, 0, 0, &hdtr, &sbytes, 0);
  if(ret == -1) {
    print2log("Fail to sendfile() data for domain '%s' (hash_val %04hu): %s\n", domain_name, hash_val, strerror(errno));
  } else {
//    print2log("Sent %llu bytes by sendfile() for domain '%s' (hash_val %04hu)\n", sbytes, domain_name, hash_val);
  }
  close(dom_fd);
  return(0);
}

int
main_loop(void) {
  int       conn, err;
  ssize_t   size;
  struct    sockaddr_in6 remote_sin;
  socklen_t sin_size = sizeof(remote_sin);
  char      request[REQUEST_BUF_SIZE];

  for(;;) {
    conn = accept(listen_sock, (struct sockaddr *)&remote_sin, &sin_size);
    if(conn == -1) {
      print2log("Accept return error: %s\n", strerror(errno));
      if(errno == ECONNABORTED || errno == EINTR)
        continue;
      return(-1);
    }

    err = fcntl(conn, F_SETFL, O_NONBLOCK);
    if(err == -1) {
      print2log("Fail to set non-blocking mode on file descriptor: %s\n", strerror(errno));
    }

    bzero(request, REQUEST_BUF_SIZE);
    size = read(conn, request, REQUEST_BUF_SIZE);
    if(size <= 2) {
      if(size != 0) {
        print2log("Read %lld bytes\n", size);
      }
    } else {
      err = process_request(conn, request, size);
      if(err == -1) {
        if(request[size - 1] == '\n')
          request[size - 1] = '\0';
        if(request[size - 2] == '\r')
          request[size - 2] = '\0';
        print2log("Error on processing request '%s' (%lld bytes)\n", request, size);
        not_found(conn);
      }
    }

    err = close(conn);
    if(err == -1) {
      print2log("Fail to close socket: %s\n", strerror(errno));
    }
  }
  return(0);
}

int
start_threads() {
  return(0);
}

int
main(int argc, char *argv[]) {
  bzero(&listen_sin4, sizeof(listen_sin4));
  bzero(&listen_sin6, sizeof(listen_sin6));

  if (parse_args(argc, argv) < 0) {
    print_usage();
    exit(1);
  }
  if (basic_init() != 0) {
    print_usage();
    exit(0);
  }

  if (thread_mode)
    start_threads();
  else
    main_loop();
}

