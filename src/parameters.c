#include "parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log_utils.h"
#include "mjson.h"

char * get_env(const char *name, const char *buf)
{
    TRACE_START();
    LOG_DEBUG("Obteniendo variable %s", name);
    char *valor;
    LOG_DEBUG("buscando %s",name);
    
    if (mjson_get_string(buf, strlen(buf), name, &valor, 256) < 0)
    {
        LOG_ERROR("valor de variable %s no existe", name);
        exit(1);
    }
    LOG_DEBUG("Valor de variable %s: %s", name, valor);
    TRACE_END();
    return valor;
}

char * get_env_and_print(const char *name, const char *buf)
{
    TRACE_START();
    char *value = get_env(name, buf);
    LOG_INFO("%s: %s", name, value);
    TRACE_END();
    return value;
}

char* str_replace(char *str, const char *pattern, const char *newvalue)
{
    TRACE_START();
    LOG_DEBUG("Remplazando %s con %s en %s", pattern, newvalue, str);

    size_t pattern_len = strlen(pattern);
    size_t newvalue_len = strlen(newvalue);
    size_t str_len = strlen(str);
    size_t count = 0;

    LOG_DEBUG("tamaño del patron: %zu", pattern_len);
    LOG_DEBUG("tamaño del nuevo valor: %zu", newvalue_len);
    LOG_DEBUG("tamaño de la cadena: %zu", str_len);

    char *ptr = str;
    
    while ((ptr = strstr(ptr, pattern)) != NULL)
    {
        count++;
        ptr += pattern_len;
    }

    LOG_DEBUG("Buscando %zu ocurrencias", count);

    size_t new_str_len = str_len + count * (newvalue_len - pattern_len);

    LOG_DEBUG("Tmaño de la nueva cadena: %zu", new_str_len);

    LOG_DEBUG("Asignando %zu bytes", new_str_len + 1)
    char *new_str = (char*) malloc(new_str_len + 1);
    char *to_ret = new_str;
    
    char *ptr2 = str;
    ptr = str;
    size_t remaining = str_len - (ptr2 - str);

    while ((ptr = strstr(ptr2, pattern)) != NULL)
    {
        size_t len = ptr - ptr2;
        LOG_DEBUG("Copiando subcadena, %zu bytes", len);
        memcpy(new_str, ptr2, len);
        LOG_DEBUG("Copiando nuevo valor, %zu bytes", newvalue_len);
        memcpy(new_str + len, newvalue, newvalue_len);
        new_str += len + newvalue_len;
        ptr2 = ptr + pattern_len;
        remaining = str_len - (ptr2 - str);
        LOG_DEBUG("Restante: %zu", remaining);
    }
    LOG_DEBUG("Copiando restante, %zu +1 bytes", remaining);
    memcpy(new_str, ptr2, remaining + 1);

    TRACE_END();
    return to_ret;
}

char * replace_bind(char *bind_template, const char *ip, const char *domain)
{
    TRACE_START();
    char *a = str_replace(bind_template, "%ip%", ip);
    char *b = str_replace(a, "%domain%", domain);
    char *c = str_replace(b, ";", "\n");
    LOG_DEBUG("Liberando a y b");
    free(a);
    free(b);
    TRACE_END();
    return c;
}

struct Parameters get_parameters()
{
    TRACE_START();
    FILE *fconf;
    char lconf[256];

    fconf = fopen(PARAMETERS_CONFIG, "r");
    if (fconf == NULL)
    {
        LOG_ERROR("El archivo config.conf no existe");
        exit(1);
    }
    fgets(lconf,256,fconf);
    close(fconf);

    struct Parameters parameters;
    parameters.token = get_env("$.TOKEN",lconf);
    parameters.zone_id = get_env_and_print("$.ZONEID",lconf);
    parameters.dns_record_id = get_env_and_print("$.DNS_RECORD_ID",lconf);
    parameters.update_interval = atoi(get_env_and_print("$.UPDATE_INTERVAL",lconf));
    parameters.domain = get_env_and_print("$.DOMAIN",lconf);
    parameters.bind_template = get_env_and_print("$.BIND_TEMPLATE",lconf);
    parameters.bind_template_noproxy = get_env_and_print("$.BIND_TEMPLATE_NOPROXY",lconf);
    parameters.healthcheck_url = get_env_and_print("$.HEALTHCHECK_URL",lconf);

    TRACE_END();
    return parameters;
}