#include <apr_general.h>
#include <apr_strings.h>
#include <apr_time.h>

typedef struct umr_boot_t
{
    apr_pool_t *mp;
} umr_boot_t;

/**
 * umr entry point
 **/
void boot_app(umr_boot_t *umr_boot, int argc, const char *const *argv, const char *const *env);

/**
 * init args such as -c xxx -v xxx
 * args_init(umr_boot.mp, "c:d:", argc, argv, args_init_callback);
 void args_init_callback(char ch, const char *optarg)
 {
    switch (ch)
    {
    case 'c':
        break;
    case 'd':
        break;
    default:
        break;
    }
}**/
void args_init(apr_pool_t *mp, const char *arg_configs, int argc, const char *const *argv, void (*callback)());

void repl_console(apr_pool_t *mp, void (*callback)());

char *print_time(apr_pool_t *pool, const apr_time_exp_t *xt);