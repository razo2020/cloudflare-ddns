#include "sub.h"
#include "log_utils.h"
#include "errors.h"
#include "mjson.h"

#define IP_HAYSTACK "\nip="

int sub_get_ip(char *ip)
{
    TRACE_START();
    struct RequestResult result = request("GET", "https://cloudflare.com/cdn-cgi/trace", NULL, 0);
    struct Response res = result.response;
    CATCH(result);
    LOG_DEBUG("Dirección del contenido: %p", res.content);

    size_t ip_haystack_len = strlen(IP_HAYSTACK);

    char *haystack = strstr(res.content, IP_HAYSTACK);
    if (haystack == NULL)
    {
        LOG_ERROR("Error al analizar la respuesta: %s no se encontro", IP_HAYSTACK);
        return ERROR_GET_IP_HAYSTACK_NOT_FOUND;
    }
    LOG_DEBUG("haystack address: %p", haystack);

    char *end = strstr(haystack + ip_haystack_len, "\n");
    if (end == NULL)
    {
        LOG_ERROR("Error al analizar la respuesta: \\n no se encontro");
        return ERROR_GET_IP_NEWLINE_NOT_FOUND;
    }
    LOG_DEBUG("haystack end address: %p", end);

    size_t len = end - haystack - ip_haystack_len;
    LOG_DEBUG("copying %ld bytes", len);
    memcpy(ip, haystack + ip_haystack_len, len);
    ip[len] = '\0';


    // size_t index = 0;
    // size_t ip_index = 0;
    // size_t haystack_len = strlen(IP_HAYSTACK);
    // while (index < res.content_size - haystack_len)
    // {
    //     if (strncmp(IP_HAYSTACK, res.content + index, haystack_len) == 0)
    //     {
    //         index += haystack_len;
    //         while (res.content[index] != '\n')
    //         {
    //             ip[ip_index++] = res.content[index++];
    //         }
    //         ip[ip_index] = '\0';
    //         break;
    //     }
    //     index++;
    // }
    request_result_cleanup(&result);
    TRACE_END();

    return NO_ERROR;
}

int sub_handle_zones(const struct Parameters params, const CloudFlare cloudflare, const struct Response response)
{
    TRACE_START();
    const char *buf;
    int len;

    LOG_DEBUG("finding $.result");
    if (mjson_find(response.content, response.content_size, "$.result", &buf, &len) != MJSON_TOK_ARRAY)
    {
        LOG_ERROR("Error al analizar json: $.result is not an array");
        return ERROR_HANDLE_ZONES_RESULT_NOT_ARRAY;
    }

    int next = 0;
    int koff = 0;
    int klen = 0;
    char selector[128];

    const char *itemBuf;
    int itemLen = 0;

    char typeBuf[256];
    char idBuf[256];
    char nameBuf[256];

    char url[256];

    while (1)
    {
        next = mjson_next(buf, len, next, &koff, &klen, NULL, NULL, NULL);
        LOG_DEBUG("next: %d", koff);
        if (next == 0)
        {
            break;
        }

        snprintf(selector, 128, "$[%d]", koff);
        LOG_DEBUG("selector: %s", selector);
        if (mjson_find(buf, len, selector, &itemBuf, &itemLen) != MJSON_TOK_OBJECT)
        {
            LOG_ERROR("Error al analizar json: %s no es un objeto", selector);
            return ERROR_HANDLE_ZONES_SELECTOR_NOT_OBJECT;
        }

        if (mjson_get_string(itemBuf, itemLen, "$.type", typeBuf, 256) < 0)
        {
            LOG_ERROR("Error al analizar json: $.type no es una cadena");
            return ERROR_HANDLE_ZONES_TYPE_NOT_STRING;
        }

        if (mjson_get_string(itemBuf, itemLen, "$.id", idBuf, 256) < 0)
        {
            LOG_ERROR("Error al analizar json: $.id no es una cadena");
            return ERROR_HANDLE_ZONES_ID_NOT_STRING;
        }

        if (mjson_get_string(itemBuf, itemLen, "$.name", nameBuf, 256) < 0)
        {
            LOG_ERROR("Error al analizar json: $.name no es una cadena");
            return ERROR_HANDLE_ZONES_NAME_NOT_STRING;
        }

        if (mjson_get_string(itemBuf, itemLen, "$.content", nameBuf, 256) < 0)
        {
            LOG_ERROR("Error al analizar json: $.content no es una cadena");
            return ERROR_HANDLE_ZONES_CONTENT_NOT_STRING;
        }

        if (strcmp(typeBuf, "A") == 0 && strcmp(idBuf, params.dns_record_id))
        {
            LOG_INFO("DDNS tipo=%s id=%s name=%s", typeBuf, idBuf, nameBuf);
        }
        else
        {
            LOG_INFO("DDNS tipo=%s id=%s name=%s", typeBuf, idBuf, nameBuf);
        }
    }

    TRACE_END();
    return NO_ERROR;
}

int health_check(char *url)
{
    int err = NO_ERROR;
    TRACE_START();
    if (strlen(url) > 0) {
        LOG_INFO("Health check")
        struct RequestResult result = request("GET", url, NULL, 0);
        err = result.error_code;
        request_result_cleanup(&result);
    } else {
        LOG_INFO("Health check url not set, skipping");
    }
    TRACE_END();
    return err;
}