#include "main.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iniparser.h"
#include "http_parser.h"
#include <assert.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_time.h>
#include <apr_network_io.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_thread_proc.h>
#include "boot.h"
#include <zlog.h>
#include <apr_getopt.h>
#define CRLF_STR "\r\n"

watcher_conf_t watcher_conf;

apr_status_t rv;
umr_boot_t boot;
apr_socket_t *s;

dictionary *ini;
char *config_path;

zlog_category_t *log_category;

static apr_status_t do_connect(apr_socket_t **sock, apr_pool_t *mp)
{
    apr_sockaddr_t *sa;
    apr_socket_t *s;
    apr_status_t rv;

    rv = apr_sockaddr_info_get(&sa, watcher_conf.host, APR_INET, watcher_conf.port, 0, mp);
    if (apr_sockaddr_info_get(&sa, watcher_conf.host, APR_INET, watcher_conf.port, 0, mp) != APR_SUCCESS)
    {
        return rv;
    }

    rv = apr_socket_create(&s, sa->family, SOCK_STREAM, APR_PROTO_TCP, mp);
    if (rv != APR_SUCCESS)
    {
        return rv;
    }
    apr_socket_opt_set(s, APR_SO_NONBLOCK, 1);
    apr_socket_timeout_set(s, APR_USEC_PER_SEC * 30);

    rv = apr_socket_connect(s, sa);
    if (rv != APR_SUCCESS)
    {
        return rv;
    }

    apr_socket_opt_set(s, APR_SO_NONBLOCK, 0);
    apr_socket_timeout_set(s, APR_USEC_PER_SEC * 30);

    *sock = s;
    return APR_SUCCESS;
}

int on_body(http_parser *parse, const char *at, size_t length)
{
    if (parse->status_code == 200)
    {

        apr_status_t rv;
        apr_file_t *conf_file = NULL;

        apr_size_t nbytes = 4096;
        char *str = apr_pcalloc(boot.mp, nbytes + 1);
        if (rv = apr_file_open(&conf_file, watcher_conf.conf_path,
                               APR_FOPEN_READ | APR_FOPEN_WRITE | APR_FOPEN_CREATE,
                               APR_UREAD | APR_UWRITE | APR_GREAD, boot.mp) == APR_SUCCESS)
        {
            apr_file_read(conf_file, str, &nbytes);

            apr_file_close(conf_file);
            if (apr_strnatcmp(str, at) != 0)
            {
                zlog_info(log_category, "start VxLog");
                system(watcher_conf.shutdown_script_path);
                zlog_info(log_category, "config is changed,upgrade local VxLOG config");
                if (rv = apr_file_open(&conf_file, watcher_conf.conf_path,
                                       APR_FOPEN_READ | APR_FOPEN_WRITE | APR_FOPEN_TRUNCATE,
                                       APR_UREAD | APR_UWRITE | APR_GREAD, boot.mp) == APR_SUCCESS)
                {
                    rv = apr_file_write(conf_file, at, &length);
                    zlog_info(log_category, "Upgrade local config success");
                }
                else
                {
                    zlog_info(log_category, "Upgrade local config failed");
                }
                apr_file_close(conf_file);
            }
        }
    }

    return 0;
}

static apr_status_t do_client_task(apr_socket_t *sock, char *filepath, apr_pool_t *mp)
{
    apr_status_t rv;
    const char *req_hdr = apr_pstrcat(mp, "GET ", filepath, " HTTP/1.0" CRLF_STR CRLF_STR, NULL);
    apr_size_t len = strlen(req_hdr);
    rv = apr_socket_send(sock, req_hdr, &len);
    if (rv != APR_SUCCESS)
    {
        return rv;
    }
    while (1)
    {
        char buf[4096];
        apr_size_t len = sizeof(buf);

        apr_status_t rv = apr_socket_recv(sock, buf, &len);
        if (rv == APR_EOF || len == 0)
        {
            http_parser_settings settings;
            memset(&settings, 0, sizeof(settings));
            settings.on_body = on_body;
            http_parser parser;
            http_parser_init(&parser, HTTP_RESPONSE);
            size_t nparsed = http_parser_execute(&parser, &settings, buf, 4096);
            break;
        }
    }

    return rv;
}

static void *APR_THREAD_FUNC config_update(apr_thread_t *thd, void *data)
{
    while (1)
    {
        rv = do_connect(&s, boot.mp);

        if (rv == APR_SUCCESS)
        {
            rv = do_client_task(s, watcher_conf.url_path, boot.mp);
            if (rv != APR_SUCCESS)
            {
                zlog_info(log_category, "Request latest VxLog Config failed");
            }
            apr_socket_close(s);
        }
        else
        {
            zlog_info(log_category, "Connect Server fail");
        }

        apr_sleep(watcher_conf.interval * APR_USEC_PER_SEC);
    }
}

static void *APR_THREAD_FUNC vxlog_monit(apr_thread_t *thd, void *data)
{
    while (1)
    {
        apr_sleep(60 * APR_USEC_PER_SEC);
        apr_status_t rv;
        apr_file_t *pid_file = NULL;

        if (rv = apr_file_open(&pid_file, watcher_conf.pid_path,
                               APR_FOPEN_READ,
                               APR_UREAD | APR_UWRITE | APR_GREAD, boot.mp) != APR_SUCCESS)
        {
            zlog_info(log_category, "VxLog is not started ,start VxLOG");
            system(watcher_conf.startup_script_path);
        }
    }
}

void args_init_callback(char ch, const char *optarg)
{
    switch (ch)
    {
    case 'c':
        config_path = optarg;
        zlog_info(log_category, apr_pstrcat(boot.mp, "Config Path is :", config_path, NULL));
        break;
    case 'd':
        break;
    default:
        break;
    }
}

void init_config()
{
    ini = iniparser_load(config_path);
    iniparser_dump(ini, stderr);

    watcher_conf.host = iniparser_getstring(ini, "main:host", NULL);
    watcher_conf.port = iniparser_getint(ini, "main:port", NULL);
    watcher_conf.url_path = iniparser_getstring(ini, "main:url", NULL);
    watcher_conf.startup_script_path = iniparser_getstring(ini, "main:startup_script_path", NULL);
    watcher_conf.shutdown_script_path = iniparser_getstring(ini, "main:shutdown_scirpt_path", NULL);
    watcher_conf.conf_path = iniparser_getstring(ini, "main:vxlog_config_path", NULL);
    watcher_conf.pid_path = iniparser_getstring(ini, "main:vxlog_pid_path", NULL);
    watcher_conf.interval = iniparser_getint(ini, "main:interval", NULL);
}

int main(int argc, const char *const *argv, const char *const *env)
{
    int rc;

    rc = zlog_init("zlog.conf");
    if (rc)
    {
        printf("init failed\n");
        return -1;
    }
    log_category = zlog_get_category("sidecar");

    boot_app(&boot, argc, argv, env);
    args_init(boot.mp, "c:", argc, argv, args_init_callback);

    if (config_path == NULL)
    {
        zlog_info(log_category, "Please Specified the config path");
        exit(-1);
    }

    zlog_info(log_category, "init config properties");

    init_config();
    apr_thread_t *thd_arr[2];
    apr_threadattr_t *thd_attr;
    apr_threadattr_create(&thd_attr, boot.mp);
    apr_thread_create(&thd_arr[0], thd_attr, config_update, 0, boot.mp);
    apr_thread_create(&thd_arr[1], thd_attr, vxlog_monit, 1, boot.mp);

    int i;
    for (i = 0; i < 2; i++)
    {
        rv = apr_thread_join(&rv, thd_arr[i]);
        assert(rv == APR_SUCCESS);
    }

    iniparser_freedict(ini);
    zlog_fini();

    return 0;
}
