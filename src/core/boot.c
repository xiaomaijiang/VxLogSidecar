#include <apr_general.h>
#include <apr_getopt.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_time.h>

#include "boot.h"

void exit_action()
{
    apr_terminate();
}

void boot_app(umr_boot_t *umr_boot, int argc, const char *const *argv, const char *const *env)
{
    if (apr_app_initialize(&argc, &argv, &env) != APR_SUCCESS)
    {
        printf("init apr app fail");
        exit(-1);
    }

    if (apr_initialize() != APR_SUCCESS)
    {
        printf("init apr fail\n");
        exit(-1);
    }

    apr_pool_create(&umr_boot->mp, NULL);
    atexit(exit_action);
}

void args_init(apr_pool_t *mp, const char *arg_configs, int argc, const char *const *argv, void (*callback)())
{
    apr_getopt_t *opt;
    apr_status_t rv;
    char ch;
    const char *optarg;

    if (apr_getopt_init(&opt, mp, argc, argv) == APR_SUCCESS)
    {
        while (apr_getopt(opt, arg_configs, &ch, &optarg) == APR_SUCCESS)
        {
            (*callback)(ch, optarg);
        }
    }
    else
    {
        printf("init args failed");
    }
}

void repl_console(apr_pool_t *mp, void (*callback)())
{
    apr_file_t *in;
    apr_file_t *out;
    apr_status_t rv;

    char buf[4096];
    apr_file_open_stdin(&in, mp);
    apr_file_open_stdout(&out, mp);
    apr_size_t length = sizeof(buf);
    while ((rv = apr_file_read(in, buf, &length)) == APR_SUCCESS)
    {
        callback(out, buf);
    }
}

char *print_time(apr_pool_t *pool, const apr_time_exp_t *xt)
{
    return apr_psprintf(pool,
                        "%04d-%02d-%02d %02d:%02d:%02d.%06d %+05d [%d %s]%s",
                        xt->tm_year + 1900,
                        xt->tm_mon + 1,
                        xt->tm_mday,
                        xt->tm_hour,
                        xt->tm_min,
                        xt->tm_sec,
                        xt->tm_usec,
                        xt->tm_gmtoff,
                        xt->tm_yday + 1,
                        apr_day_snames[xt->tm_wday],
                        (xt->tm_isdst ? " DST" : ""));
}