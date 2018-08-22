#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"
#include "boot.h"
#include "iniparser.h"
#include <assert.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_thread_proc.h>
#include <zlog.h>
#include <curl/curl.h>

watcher_conf_t watcher_conf;

apr_status_t rv;
umr_boot_t boot;
dictionary *ini;
char *config_path;
zlog_category_t *log_category;

CURL *curl;
CURLcode res;

apr_file_t *conf_file = NULL;

size_t static config_get_callback(void *buffer,
                                  size_t size,
                                  size_t nmemb,
                                  void *userp)
{
    apr_size_t nbytes = 4096;
    size_t size_cal = (size_t)(size * nmemb);

    char *str = apr_pcalloc(boot.mp, nbytes + 1);

    if (rv = apr_file_open(&conf_file, watcher_conf.conf_path,
                           APR_FOPEN_READ | APR_FOPEN_CREATE,
                           APR_FPROT_UREAD, boot.mp) == APR_SUCCESS)
    {
        apr_file_read(conf_file, str, &nbytes);

        apr_file_close(conf_file);

        if (apr_strnatcmp(str, (char *)buffer) != 0)
        {
            zlog_info(log_category, "Exec VxLog start script");
            system(watcher_conf.shutdown_script_path);

            zlog_info(log_category, "config is changed,upgrade local VxLOG config");
            if (rv = apr_file_open(&conf_file, watcher_conf.conf_path,
                                   APR_FOPEN_READ | APR_FOPEN_WRITE | APR_FOPEN_TRUNCATE,
                                   APR_FPROT_UREAD | APR_FPROT_UWRITE, boot.mp) == APR_SUCCESS)
            {
                rv = apr_file_write(conf_file, (char *)buffer, &size_cal);
                apr_file_close(conf_file);
                zlog_info(log_category, "Upgrade local config success");
            }
            else
            {
                zlog_info(log_category, "Upgrade local config failed");
            }
        }
    }
    return ((size_t)(size * nmemb));
}

static void *APR_THREAD_FUNC config_update(apr_thread_t *thd, void *data)
{
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, watcher_conf.url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, config_get_callback);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    while (1)
    {
        if (curl)
        {
            res = curl_easy_perform(curl);
            if (res != CURLE_OK)
            {
                zlog_error(log_category, apr_psprintf(boot.mp, "curl_easy_perform() failed: %s", curl_easy_strerror(res)));
            }
        }
        else
        {
            zlog_info(log_category, "Init Curl fail");
            exit(-1);
        }

        apr_sleep(watcher_conf.interval * APR_USEC_PER_SEC);
    }
    curl_easy_cleanup(curl);
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
    default:
        break;
    }
}

void init_config()
{
    ini = iniparser_load(config_path);
    iniparser_dump(ini, stderr);

    watcher_conf.url = iniparser_getstring(ini, "main:url", NULL);
    watcher_conf.startup_script_path = iniparser_getstring(ini, "main:startup_script_path", NULL);
    watcher_conf.shutdown_script_path = iniparser_getstring(ini, "main:shutdown_scirpt_path", NULL);
    watcher_conf.conf_path = iniparser_getstring(ini, "main:vxlog_config_path", NULL);
    watcher_conf.pid_path = iniparser_getstring(ini, "main:vxlog_pid_path", NULL);
    watcher_conf.interval = iniparser_getint(ini, "main:interval", NULL);
}

int main(int argc, const char *const *argv, const char *const *env)
{
    if (zlog_init("zlog.conf"))
    {
        printf("init zlog failed\n");
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
