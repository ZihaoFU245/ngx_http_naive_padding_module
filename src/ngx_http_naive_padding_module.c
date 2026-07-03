
/*
 * Copyright(c) 2026 ZihaoFU245
 *
 * NaiveProxy CONNECT padding filter for HTTP/2 and HTTP/3 tunnels.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_NAIVE_PADDING_K_FIRST          8
#define NGX_HTTP_NAIVE_PADDING_HEADER_SIZE      3
#define NGX_HTTP_NAIVE_PADDING_MAX_PAYLOAD      65535
#define NGX_HTTP_NAIVE_PADDING_MAX_PADDING      255
#define NGX_HTTP_NAIVE_PADDING_RESPONSE_MIN     30
#define NGX_HTTP_NAIVE_PADDING_RESPONSE_MAX     62


typedef struct {
    ngx_flag_t  enable;
} ngx_http_naive_padding_loc_conf_t;


typedef struct {
    size_t      payload_size;
    size_t      padding_size;
    ngx_uint_t  request_count;
    ngx_uint_t  response_count;
    ngx_uint_t  read_state;
    unsigned    active:1;
    unsigned    header_sent:1;
} ngx_http_naive_padding_ctx_t;


enum {
    ngx_http_naive_padding_read_header_b0 = 0,
    ngx_http_naive_padding_read_header_b1,
    ngx_http_naive_padding_read_header_b2,
    ngx_http_naive_padding_read_payload,
    ngx_http_naive_padding_read_discard
};


static ngx_int_t ngx_http_naive_padding_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_naive_padding_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_naive_padding_request_body_filter(
    ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_naive_padding_init(ngx_conf_t *cf);
static void *ngx_http_naive_padding_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_naive_padding_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_http_naive_padding_supported(ngx_http_request_t *r);
static ngx_int_t ngx_http_naive_padding_has_header(ngx_http_request_t *r);
static ngx_http_naive_padding_ctx_t *ngx_http_naive_padding_get_ctx(
    ngx_http_request_t *r, ngx_uint_t create);
static ngx_int_t ngx_http_naive_padding_add_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_naive_padding_decode_request(
    ngx_http_request_t *r, ngx_http_naive_padding_ctx_t *ctx,
    ngx_chain_t *in, ngx_chain_t **out);
static ngx_int_t ngx_http_naive_padding_encode_response(
    ngx_http_request_t *r, ngx_http_naive_padding_ctx_t *ctx,
    ngx_chain_t *in, ngx_chain_t **out);
static ngx_int_t ngx_http_naive_padding_append_copy(ngx_http_request_t *r,
    ngx_chain_t ***ll, u_char *pos, size_t size, ngx_uint_t flush);
static ngx_int_t ngx_http_naive_padding_append_raw(ngx_http_request_t *r,
    ngx_chain_t ***ll, ngx_buf_t *src, u_char *pos, u_char *last,
    ngx_uint_t last_buf);
static ngx_int_t ngx_http_naive_padding_append_last(ngx_http_request_t *r,
    ngx_chain_t ***ll);
static ngx_int_t ngx_http_naive_padding_append_buf(ngx_http_request_t *r,
    ngx_chain_t ***ll, ngx_buf_t *b);


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
static ngx_http_request_body_filter_pt   ngx_http_next_request_body_filter;


static ngx_command_t  ngx_http_naive_padding_commands[] = {

    { ngx_string("naive_padding"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_naive_padding_loc_conf_t, enable),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_naive_padding_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_naive_padding_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_naive_padding_create_loc_conf, /* create location configuration */
    ngx_http_naive_padding_merge_loc_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_naive_padding_module = {
    NGX_MODULE_V1,
    &ngx_http_naive_padding_module_ctx,    /* module context */
    ngx_http_naive_padding_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_naive_padding_header_filter(ngx_http_request_t *r)
{
    ngx_http_naive_padding_ctx_t  *ctx;

    if (r->headers_out.status != NGX_HTTP_OK) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_naive_padding_get_ctx(r, 1);
    if (ctx != NULL && ctx->active && !ctx->header_sent) {
        if (ngx_http_naive_padding_add_header(r) != NGX_OK) {
            return NGX_ERROR;
        }

        ctx->header_sent = 1;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_naive_padding_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                       rc;
    ngx_chain_t                    *out;
    ngx_http_naive_padding_ctx_t   *ctx;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_naive_padding_module);
    if (ctx == NULL || !ctx->active
        || ctx->response_count >= NGX_HTTP_NAIVE_PADDING_K_FIRST)
    {
        return ngx_http_next_body_filter(r, in);
    }

    out = NULL;
    rc = ngx_http_naive_padding_encode_response(r, ctx, in, &out);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_next_body_filter(r, out);
}


static ngx_int_t
ngx_http_naive_padding_request_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in)
{
    ngx_int_t                       rc;
    ngx_chain_t                    *out;
    ngx_http_naive_padding_ctx_t   *ctx;

    ctx = ngx_http_naive_padding_get_ctx(r, 1);

    if (in == NULL) {
        if (ctx != NULL && ctx->active && r->request_body != NULL) {
            r->request_body->filter_need_buffering = 1;
        }

        return ngx_http_next_request_body_filter(r, in);
    }

    if (ctx == NULL || !ctx->active
        || ctx->request_count >= NGX_HTTP_NAIVE_PADDING_K_FIRST)
    {
        return ngx_http_next_request_body_filter(r, in);
    }

    out = NULL;
    rc = ngx_http_naive_padding_decode_request(r, ctx, in, &out);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_next_request_body_filter(r, out);
}


static ngx_int_t
ngx_http_naive_padding_supported(ngx_http_request_t *r)
{
    ngx_http_naive_padding_loc_conf_t  *conf;

    if (r != r->main || r->method != NGX_HTTP_CONNECT) {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_naive_padding_module);
    if (conf->enable != 1) {
        return NGX_DECLINED;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        return NGX_OK;
    }
#endif

#if (NGX_HTTP_V3)
    if (r->http_version == NGX_HTTP_VERSION_30) {
        return NGX_OK;
    }
#endif

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_naive_padding_has_header(ngx_http_request_t *r)
{
    u_char            *key;
    ngx_uint_t         i;
    ngx_list_part_t   *part;
    ngx_table_elt_t   *header;

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                return NGX_DECLINED;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        key = (header[i].lowcase_key != NULL) ? header[i].lowcase_key
                                              : header[i].key.data;

        if (header[i].key.len == sizeof("padding") - 1
            && ngx_strncasecmp(key, (u_char *) "padding",
                               sizeof("padding") - 1)
               == 0)
        {
            return NGX_OK;
        }
    }
}


static ngx_http_naive_padding_ctx_t *
ngx_http_naive_padding_get_ctx(ngx_http_request_t *r, ngx_uint_t create)
{
    ngx_http_naive_padding_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_naive_padding_module);
    if (ctx != NULL || !create) {
        return ctx;
    }

    if (ngx_http_naive_padding_supported(r) != NGX_OK
        || ngx_http_naive_padding_has_header(r) != NGX_OK)
    {
        return NULL;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_naive_padding_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->active = 1;
    ngx_http_set_ctx(r, ctx, ngx_http_naive_padding_module);

    return ctx;
}


static ngx_int_t
ngx_http_naive_padding_add_header(ngx_http_request_t *r)
{
    static u_char    codes[] = { '!', '"', '#', '$', '&', '\'', '(', ')',
                                 '*', '+', ',', ';', '<', '>', '?', '@',
                                 'X' };
    size_t           first, i;
    uint64_t         bits;
    ngx_uint_t       len, n;
    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    len = NGX_HTTP_NAIVE_PADDING_RESPONSE_MIN
          + (ngx_random()
             % (NGX_HTTP_NAIVE_PADDING_RESPONSE_MAX
                - NGX_HTTP_NAIVE_PADDING_RESPONSE_MIN + 1));

    h->value.data = ngx_pnalloc(r->pool, len);
    if (h->value.data == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->next = NULL;
    ngx_str_set(&h->key, "padding");
    h->value.len = len;

    first = 16;
    bits = ngx_random();
    n = 7;

    for (i = 0; i < first; i++) {
        h->value.data[i] = codes[bits & 0x0f];
        bits >>= 4;

        if (--n == 0) {
            bits = ngx_random();
            n = 7;
        }
    }

    for (i = first; i < (size_t) len; i++) {
        h->value.data[i] = codes[16];
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_naive_padding_decode_request(ngx_http_request_t *r,
    ngx_http_naive_padding_ctx_t *ctx, ngx_chain_t *in, ngx_chain_t **out)
{
    size_t          n;
    ngx_buf_t      *b;
    ngx_chain_t    *cl;
    ngx_chain_t   **ll;
    ngx_uint_t      last, last_forwarded;

    ll = out;
    last = 0;
    last_forwarded = 0;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;

        if (b->last_buf) {
            last = 1;
        }

        while (b->pos < b->last) {

            if (ctx->request_count >= NGX_HTTP_NAIVE_PADDING_K_FIRST) {
                if (ngx_http_naive_padding_append_raw(r, &ll, b, b->pos,
                                                      b->last, b->last_buf)
                    != NGX_OK)
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b->pos = b->last;
                last_forwarded = b->last_buf;
                break;
            }

            switch (ctx->read_state) {

            case ngx_http_naive_padding_read_header_b0:
                ctx->payload_size = (size_t) *b->pos++ << 8;
                ctx->read_state = ngx_http_naive_padding_read_header_b1;
                break;

            case ngx_http_naive_padding_read_header_b1:
                ctx->payload_size |= *b->pos++;
                ctx->read_state = ngx_http_naive_padding_read_header_b2;
                break;

            case ngx_http_naive_padding_read_header_b2:
                ctx->padding_size = *b->pos++;

                if (ctx->payload_size != 0) {
                    ctx->read_state = ngx_http_naive_padding_read_payload;

                } else if (ctx->padding_size != 0) {
                    ctx->read_state = ngx_http_naive_padding_read_discard;

                } else {
                    ctx->request_count++;
                    ctx->read_state = ngx_http_naive_padding_read_header_b0;
                }

                break;

            case ngx_http_naive_padding_read_payload:
                n = ngx_min((size_t) (b->last - b->pos), ctx->payload_size);

                if (ngx_http_naive_padding_append_copy(r, &ll, b->pos, n,
                                                       b->flush)
                    != NGX_OK)
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b->pos += n;
                ctx->payload_size -= n;

                if (ctx->payload_size == 0) {
                    ctx->read_state = ctx->padding_size
                                      ? ngx_http_naive_padding_read_discard
                                      : ngx_http_naive_padding_read_header_b0;

                    if (ctx->padding_size == 0) {
                        ctx->request_count++;
                    }
                }

                break;

            case ngx_http_naive_padding_read_discard:
                n = ngx_min((size_t) (b->last - b->pos), ctx->padding_size);

                while (n) {
                    if (*b->pos != '\0') {
                        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                      "naive padding request contained "
                                      "non-zero padding");
                        return NGX_HTTP_BAD_REQUEST;
                    }

                    b->pos++;
                    n--;
                    ctx->padding_size--;
                }

                if (ctx->padding_size == 0) {
                    ctx->request_count++;
                    ctx->read_state = ngx_http_naive_padding_read_header_b0;
                }

                break;

            default:
                return NGX_HTTP_BAD_REQUEST;
            }
        }
    }

    if (last && !last_forwarded) {
        if (ctx->read_state != ngx_http_naive_padding_read_header_b0
            || ctx->payload_size != 0 || ctx->padding_size != 0)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "naive padding request ended with incomplete frame");
            return NGX_HTTP_BAD_REQUEST;
        }

        if (ngx_http_naive_padding_append_last(r, &ll) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_naive_padding_encode_response(ngx_http_request_t *r,
    ngx_http_naive_padding_ctx_t *ctx, ngx_chain_t *in, ngx_chain_t **out)
{
    size_t          payload_size, padding_size;
    u_char         *p, *pos, *last;
    ngx_buf_t      *b, *nb;
    ngx_chain_t    *cl;
    ngx_chain_t   **ll;

    ll = out;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;
        pos = b->pos;
        last = b->last;

        if (pos == last) {
            if (ngx_http_naive_padding_append_buf(r, &ll, b) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        while (pos < last) {

            if (ctx->response_count >= NGX_HTTP_NAIVE_PADDING_K_FIRST) {
                b->pos = pos;

                if (ngx_http_naive_padding_append_buf(r, &ll, b) != NGX_OK) {
                    return NGX_ERROR;
                }

                break;
            }

            payload_size = ngx_min((size_t) (last - pos),
                                   (size_t) NGX_HTTP_NAIVE_PADDING_MAX_PAYLOAD);
            padding_size = ngx_random()
                           % (NGX_HTTP_NAIVE_PADDING_MAX_PADDING + 1);

            nb = ngx_create_temp_buf(r->pool,
                                     NGX_HTTP_NAIVE_PADDING_HEADER_SIZE
                                     + payload_size + padding_size);
            if (nb == NULL) {
                return NGX_ERROR;
            }

            p = nb->last;
            *p++ = (u_char) (payload_size >> 8);
            *p++ = (u_char) payload_size;
            *p++ = (u_char) padding_size;
            p = ngx_cpymem(p, pos, payload_size);

            if (padding_size) {
                ngx_memzero(p, padding_size);
                p += padding_size;
            }

            nb->last = p;
            nb->flush = b->flush;

            pos += payload_size;
            b->pos = pos;
            ctx->response_count++;

            if (b->last_buf && pos == last) {
                nb->last_buf = 1;
            }

            if (ngx_http_naive_padding_append_buf(r, &ll, nb) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_naive_padding_append_copy(ngx_http_request_t *r, ngx_chain_t ***ll,
    u_char *pos, size_t size, ngx_uint_t flush)
{
    ngx_buf_t  *b;

    if (size == 0) {
        return NGX_OK;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, pos, size);
    b->flush = flush;

    return ngx_http_naive_padding_append_buf(r, ll, b);
}


static ngx_int_t
ngx_http_naive_padding_append_raw(ngx_http_request_t *r, ngx_chain_t ***ll,
    ngx_buf_t *src, u_char *pos, u_char *last, ngx_uint_t last_buf)
{
    ngx_buf_t  *b;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    *b = *src;
    b->pos = pos;
    b->last = last;
    b->last_buf = last_buf;

    return ngx_http_naive_padding_append_buf(r, ll, b);
}


static ngx_int_t
ngx_http_naive_padding_append_last(ngx_http_request_t *r, ngx_chain_t ***ll)
{
    ngx_buf_t  *b;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last_buf = 1;

    return ngx_http_naive_padding_append_buf(r, ll, b);
}


static ngx_int_t
ngx_http_naive_padding_append_buf(ngx_http_request_t *r, ngx_chain_t ***ll,
    ngx_buf_t *b)
{
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    **ll = cl;
    *ll = &cl->next;

    return NGX_OK;
}


static void *
ngx_http_naive_padding_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_naive_padding_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_naive_padding_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_naive_padding_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_naive_padding_loc_conf_t *prev = parent;
    ngx_http_naive_padding_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_naive_padding_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_naive_padding_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_naive_padding_body_filter;

    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_naive_padding_request_body_filter;

    return NGX_OK;
}
