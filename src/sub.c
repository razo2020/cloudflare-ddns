#include "sub.h"
#include "log_utils.h"
#include "errors.h"
#include "mjson.h"

#define IP_HAYSTACK "\nip="

int sub_get_ip(char *ip)
{
    TRACE_START();
    struct RequestResult result = request("GET", "https://cloudflare.com/cdn-cgi/trace", NULL, 0, NULL);
    struct Response res = result.response;
    CATCH(result);
    LOG_DEBUG("Contenido de la dirección: %p", res.content);

    size_t ip_haystack_len = strlen(IP_HAYSTACK);

    char *haystack = strstr(res.content, IP_HAYSTACK);
    if (haystack == NULL)
    {
        LOG_ERROR("Error al analizar la respuesta: %s no se encontro", IP_HAYSTACK);
        return ERROR_GET_IP_HAYSTACK_NOT_FOUND;
    }
    LOG_DEBUG("Seleccion inicial en la direccion: %p", haystack);

    char *end = strstr(haystack + ip_haystack_len, "\n");
    if (end == NULL)
    {
        LOG_ERROR("Error al analizar la respuesta: \\n no se encontro");
        return ERROR_GET_IP_NEWLINE_NOT_FOUND;
    }
    LOG_DEBUG("Seleccion final en la direccion: %p", end);

    size_t len = end - haystack - ip_haystack_len;
    LOG_DEBUG("Copiando %ld bytes", len);
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

int sub_handle_zones(struct Parameters params, const CloudFlare cloudflare, const struct Response response, char *ip)
{
    TRACE_START();
    const char *buf;
    int len;

    LOG_DEBUG("Buscando $.result");
    if (mjson_find(response.content, response.content_size, "$.result", &buf, &len) != MJSON_TOK_ARRAY)
    {
        LOG_ERROR("Error al analizar json: $.result no es un arreglo");
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
    char contentBuf[256];
    char url[256];

    while (1)
    {
        next = mjson_next(buf, len, next, &koff, &klen, NULL, NULL, NULL);
        LOG_DEBUG("Siguiente: %d", koff);
        if (next == 0)
        {
            if (params.dns_record_id == NULL)
            {  
                snprintf(url, 256, "https://api.cloudflare.com/client/v4/zones/%s/dns_records", params.zone_id);
                char *data[256];
                snprintf(data, 256, "{\"content\": \"%s\",\"name\": \"%s\", \"proxied\": true,\"type\": \"A\",\"tags\": [],\"ttl\": 1,\"comment\": \"Actualización automatica\"}", ip, params.domain);

                struct RequestResult rr = cloudflare_request(cloudflare, "POST", url, data);
                CATCH(rr);
                struct Response mem = rr.response;
                
                LOG_DEBUG("Buscando $.result");
                if (mjson_find(mem.content, mem.content_size, "$.result", &itemBuf, &itemLen) != MJSON_TOK_OBJECT)
                {
                    LOG_ERROR("Error al analizar json: $.result no es un objeto");
                    return ERROR_HANDLE_ZONES_SELECTOR_NOT_OBJECT;
                }

                sub_ddns_valores("$.type", itemBuf, itemLen,typeBuf);
                sub_ddns_valores("$.id", itemBuf, itemLen,idBuf);
                sub_ddns_valores("$.name", itemBuf, itemLen,nameBuf);
                sub_ddns_valores("$.content", itemBuf, itemLen,contentBuf);
                params.dns_record_id = idBuf;
                LOG_INFO("Se creo:\nDDNS tipo=%s id=%s name=%s content=%s", typeBuf, idBuf, nameBuf, contentBuf);
                request_result_cleanup(&rr);
            }
            
            break;
        }

        snprintf(selector, 128, "$[%d]", koff);
        LOG_DEBUG("selector: %s", selector);
        if (mjson_find(buf, len, selector, &itemBuf, &itemLen) != MJSON_TOK_OBJECT)
        {
            LOG_ERROR("Error al analizar json: %s no es un objeto", selector);
            return ERROR_HANDLE_ZONES_SELECTOR_NOT_OBJECT;
        }

        sub_ddns_valores("$.type", itemBuf, itemLen,typeBuf);
        sub_ddns_valores("$.id", itemBuf, itemLen,idBuf);
        sub_ddns_valores("$.name", itemBuf, itemLen,nameBuf);
        sub_ddns_valores("$.content", itemBuf, itemLen,contentBuf);
        LOG_INFO("DDNS tipo=%s id=%s name=%s content=%s", typeBuf, idBuf, nameBuf, contentBuf);

        if (strcmp(typeBuf, "A") == 0 && strcmp(idBuf, params.dns_record_id))
        {
            snprintf(url, 256, "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", params.zone_id, params.dns_record_id);
            char *data[256];
            snprintf(data, 256, "{\"content\": \"%s\", \"comment\": \"Actualización automatica\"}", ip);
           
            struct RequestResult rr = cloudflare_request(cloudflare, "PATCH", url, data);
            CATCH(rr);
            struct Response mem = rr.response;
            
            LOG_DEBUG("Buscando $.result");
            if (mjson_find(mem.content, mem.content_size, "$.result", &itemBuf, &itemLen) != MJSON_TOK_OBJECT)
            {
                LOG_ERROR("Error al analizar json: $.result no es un objeto");
                return ERROR_HANDLE_ZONES_SELECTOR_NOT_OBJECT;
            }

            sub_ddns_valores("$.content", itemBuf, itemLen, contentBuf);
            LOG_INFO("DDNS Actualizado tipo=%s id=%s name=%s content=%s", typeBuf, idBuf, nameBuf, contentBuf);
            request_result_cleanup(&rr);
        }
    }

    TRACE_END();
    return NO_ERROR;
}

int sub_ddns_valores(const char *name, const char *buf, int len, char * valor)
{
    TRACE_START();
    LOG_DEBUG("Obteniendo variable %s", name);
    if (mjson_get_string(buf, len, name, &valor, 256) < 0)
    {
        LOG_ERROR("Error al analizar json: %s no es una cadena", name);
        return ERROR_HANDLE_ZONES_TYPE_NOT_STRING;
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
        struct RequestResult result = request("GET", url, NULL, 0, NULL);
        err = result.error_code;
        request_result_cleanup(&result);
    } else {
        LOG_INFO("URL de verificación de estado no configurada, omitiendo");
    }
    TRACE_END();
    return err;
}