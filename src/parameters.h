
#ifndef PARAMETERS_H
#define PARAMETERS_H

#ifndef PARAMETERS_CONFIG
#define PARAMETERS_CONFIG "./config/config.conf"
#endif

struct Parameters
{
    char *token;
    char *zone_id;
    char *dns_record_id;
    int update_interval;
    char *domain;
    char *bind_template;
    char *bind_template_noproxy;
    char *healthcheck_url;
};

extern char * get_env(const char *name, const char *buf);

extern char * get_env_and_print(const char *name, const char *buf);

extern char * str_replace(char *str, const char *pattern, const char *newvalue);

extern char * replace_bind(char *bind_template, const char *ip, const char *domain);

extern struct Parameters get_parameters();

#endif /* PARAMETERS_H */