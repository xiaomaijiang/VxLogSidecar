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

#define CRLF_STR "\r\n"

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

watcher_conf_t watcher_conf;

apr_status_t rv;
apr_pool_t *mp;
apr_socket_t *s;

dictionary *ini;

void exit_action()
{
    iniparser_freedict(ini);
    apr_terminate();
}

static apr_status_t do_connect(apr_socket_t **sock, apr_pool_t *mp)
{
    apr_sockaddr_t *sa;
    apr_socket_t *s;
    apr_status_t rv;

    rv = apr_sockaddr_info_get(&sa, watcher_conf.host, APR_INET, watcher_conf.port, 0, mp);
    if (rv != APR_SUCCESS)
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

int on_body(http_parser *_, const char *at, size_t length)
{
    printf("Body: %s\n", at);
    apr_status_t rv;
    apr_file_t *conf_file = NULL;

    apr_size_t nbytes = 256;
    char *str = apr_pcalloc(mp, nbytes + 1);

    if (rv = apr_file_open(&conf_file, watcher_conf.conf_path,
                           APR_FOPEN_READ | APR_FOPEN_WRITE | APR_FOPEN_CREATE,
                           APR_UREAD | APR_UWRITE | APR_GREAD, mp) == APR_SUCCESS)
    {
        rv = apr_file_read(conf_file, str, &nbytes);

        apr_file_close(conf_file);
        if (rv != APR_SUCCESS)
        {
            printf("读取本地配置文件异常\n");
        }
        else
        {
            if (strcmp(str, at) == 0)
            {
                // printf("远程配置文件和本地配置文件相等，不做任何操作\n");
            }
            else
            {
                printf("停止客户端\n");
                system(watcher_conf.shutdown_script_path);

                printf("配置文件变更，更新配置文件内容:%s,%s\n", str, at);
                if (rv = apr_file_open(&conf_file, watcher_conf.conf_path,
                                       APR_FOPEN_READ | APR_FOPEN_WRITE | APR_FOPEN_TRUNCATE,
                                       APR_UREAD | APR_UWRITE | APR_GREAD, mp) == APR_SUCCESS)
                {
                    rv = apr_file_write(conf_file, at, &length);
                    printf("配置文件更新成功\n");
                }
                else
                {
                    printf("更新配置文件失败\n");
                }
                apr_file_close(conf_file);

                // printf("启动客户端\n");
                // system(watcher_conf.startup_script_path);
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
        rv = do_connect(&s, mp);

        if (rv == APR_SUCCESS)
        {
            rv = do_client_task(s, watcher_conf.url_path, mp);
            if (rv != APR_SUCCESS)
            {
                printf("请求客户端最新配置失败\n");
            }
        }
        else
        {
            printf("请求服务器失败，服务没有开启\n");
        }
        apr_sleep(watcher_conf.interval * APR_USEC_PER_SEC);
        apr_socket_close(s);
    }
}

static void *APR_THREAD_FUNC vxlog_monit(apr_thread_t *thd, void *data)
{
    while (1)
    {
        apr_status_t rv;
        apr_file_t *pid_file = NULL;

        if (rv = apr_file_open(&pid_file, watcher_conf.pid_path,
                               APR_FOPEN_READ,
                               APR_UREAD | APR_UWRITE | APR_GREAD, mp) != APR_SUCCESS)
        {
            printf("客户端未启动，启动客户端\n");
            system(watcher_conf.startup_script_path);
        }

        apr_sleep(60 * APR_USEC_PER_SEC);
    }
}
int main(int argc, char const *argv[])
{
    if (argc != 2)
    {
        printf("请指定配置文件路径\n");
        exit(-1);
    }

    printf("初始化配置信息\n");
    ini = iniparser_load(argv[1]);
    iniparser_dump(ini, stderr);

    watcher_conf.host = iniparser_getstring(ini, "main:host", NULL);
    watcher_conf.port = iniparser_getint(ini, "main:port", NULL);
    watcher_conf.url_path = iniparser_getstring(ini, "main:url", NULL);
    watcher_conf.startup_script_path = iniparser_getstring(ini, "main:startup_script_path", NULL);
    watcher_conf.shutdown_script_path = iniparser_getstring(ini, "main:shutdown_scirpt_path", NULL);
    watcher_conf.conf_path = iniparser_getstring(ini, "main:vxlog_config_path", NULL);
    watcher_conf.pid_path = iniparser_getstring(ini, "main:vxlog_pid_path", NULL);
    watcher_conf.interval = iniparser_getint(ini, "main:interval", NULL);

    atexit(exit_action);

    apr_initialize();
    apr_pool_create(&mp, NULL);
    apr_thread_t *thd_arr[2];
    apr_threadattr_t *thd_attr;
    apr_threadattr_create(&thd_attr, mp);
    apr_thread_create(&thd_arr[0], thd_attr, config_update, 0, mp);
    apr_thread_create(&thd_arr[1], thd_attr, vxlog_monit, 1, mp);

    int i;
    for (i = 0; i < 2; i++)
    {
        rv = apr_thread_join(&rv, thd_arr[i]);
        assert(rv == APR_SUCCESS);
    }
    return 0;
}
