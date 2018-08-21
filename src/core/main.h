#include <apr_network_io.h>

typedef struct watcher_conf_t
{
    char *url;
    char *startup_script_path;
    char *shutdown_script_path;
    char *conf_path;
    char *pid_path;
    int interval;
} watcher_conf_t;
