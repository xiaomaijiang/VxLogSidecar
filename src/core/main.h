#include <apr_network_io.h>

typedef struct watcher_conf_t
{
    char *host;
    char *url_path;
    char *startup_script_path;
    char *shutdown_script_path;
    char *conf_path;
    char *pid_path;
    int interval;
    apr_port_t port;
} watcher_conf_t;
