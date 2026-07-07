
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
#define NGX_HTTP_NAIVE_PADDING_H2_END_MIN       48
#define NGX_HTTP_NAIVE_PADDING_H2_END_MAX       72


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
    ngx_chain_t *in, ngx_chain_t **out, ngx_uint_t *h2_end_stream);
static ngx_int_t ngx_http_naive_padding_append_buf(ngx_http_request_t *r,
    ngx_chain_t ***ll, ngx_buf_t *b);
#if (NGX_HTTP_V2)
static ngx_int_t ngx_http_naive_padding_h2_send_end_stream(
    ngx_http_request_t *r);
static ngx_int_t ngx_http_naive_padding_h2_end_stream_handler(
    ngx_http_v2_connection_t *h2c, ngx_http_v2_out_frame_t *frame);
#endif


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
#if (HEADERS_MORE)
    u_char                       *key;
    ngx_uint_t                    i;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
#endif
    ngx_http_naive_padding_ctx_t  *ctx;

    if (r->method != NGX_HTTP_CONNECT) {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.status != NGX_HTTP_OK
#if (HEADERS_MORE)
        && r->headers_out.status != NGX_HTTP_NOT_ALLOWED
#endif
    )
    {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_naive_padding_get_ctx(r, 1);
    if (ctx == NULL || !ctx->active) {
        return ngx_http_next_header_filter(r);
    }

    /*
     * Use `./configure ... --with-cc-opt='-DHEADERS_MORE=1 ...'
     * to compile with clear 'Proxy-Authenticate' support. 
     * This is for users who don't want to compile openResty's
     * headers more module.
     */
    
#if (HEADERS_MORE)
    if (r->headers_out.status == NGX_HTTP_NOT_ALLOWED)
    {
        ngx_http_clear_content_length(r);

        for (header = r->headers_out.proxy_authenticate; header;
             header = header->next)
        {
            header->hash = 0;
        }

        r->headers_out.proxy_authenticate = NULL;

        part = &r->headers_out.headers.part;
        header = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (header[i].hash == 0
                || header[i].key.len != sizeof("Proxy-Authenticate") - 1)
            {
                continue;
            }

            key = (header[i].lowcase_key != NULL) ? header[i].lowcase_key
                                                  : header[i].key.data;

            if (ngx_strncasecmp(key, (u_char *) "Proxy-Authenticate",
                                sizeof("Proxy-Authenticate") - 1)
                == 0)
            {
                header[i].hash = 0;
            }
        }

        return ngx_http_next_header_filter(r);
    }
#endif

    if (!ctx->header_sent) {
        ngx_http_clear_content_length(r);

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
    ngx_chain_t                    *cl;
    ngx_chain_t                    *out;
    ngx_chain_t                   **ll;
    ngx_uint_t                      h2_end_stream;
    ngx_http_naive_padding_ctx_t   *ctx;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_naive_padding_module);
    if (ctx == NULL || !ctx->active) {
        return ngx_http_next_body_filter(r, in);
    }

#if (NGX_HTTP_V2)
    if (ctx->response_count >= NGX_HTTP_NAIVE_PADDING_K_FIRST
        && (r->http_version != NGX_HTTP_VERSION_20 || r->stream == NULL))
    {
        return ngx_http_next_body_filter(r, in);
    }

    if (r->http_version == NGX_HTTP_VERSION_20 && r->stream != NULL) {
        h2_end_stream = 0;

        for (cl = in; cl; cl = cl->next) {
            if (cl->buf->last_buf) {
                h2_end_stream = 1;
                break;
            }
        }

        if (ctx->response_count >= NGX_HTTP_NAIVE_PADDING_K_FIRST) {
            if (!h2_end_stream) {
                return ngx_http_next_body_filter(r, in);
            }

            out = NULL;
            ll = &out;

            for (cl = in; cl; cl = cl->next) {
                cl->buf->last_buf = 0;
                cl->buf->last_in_chain = 0;

                if (ngx_buf_size(cl->buf) == 0
                    && !ngx_buf_special(cl->buf))
                {
                    continue;
                }

                if (ngx_http_naive_padding_append_buf(r, &ll, cl->buf)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

            in = out;
            goto forward;
        }

    } else {
        h2_end_stream = 0;
    }
#else
    h2_end_stream = 0;

    if (ctx->response_count >= NGX_HTTP_NAIVE_PADDING_K_FIRST) {
        return ngx_http_next_body_filter(r, in);
    }
#endif

    out = NULL;
    rc = ngx_http_naive_padding_encode_response(r, ctx, in, &out,
                                                 h2_end_stream
                                                 ? &h2_end_stream : NULL);
    if (rc != NGX_OK) {
        return rc;
    }

    in = out;

forward:

    rc = ngx_http_next_body_filter(r, in);
    if (rc != NGX_OK) {
        return rc;
    }

#if (NGX_HTTP_V2)
    if (h2_end_stream) {
        rc = ngx_http_naive_padding_h2_send_end_stream(r);
        if (rc == NGX_DECLINED) {
            ngx_buf_t  *b;

            out = NULL;
            ll = &out;

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            b->last_buf = 1;

            if (ngx_http_naive_padding_append_buf(r, &ll, b) != NGX_OK) {
                return NGX_ERROR;
            }

            return ngx_http_next_body_filter(r, out);
        }

        return rc;
    }
#endif

    return NGX_OK;
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

    if (ngx_http_naive_padding_supported(r) != NGX_OK) {
        return NULL;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_naive_padding_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    if (ngx_http_naive_padding_has_header(r) == NGX_OK) {
        ctx->active = 1;
    }

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
    enum {
        ngx_http_naive_padding_read_header_b0 = 0,
        ngx_http_naive_padding_read_header_b1,
        ngx_http_naive_padding_read_header_b2,
        ngx_http_naive_padding_read_payload,
        ngx_http_naive_padding_read_discard
    };

    size_t          n;
    ngx_buf_t      *b, *nb;
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
                nb = ngx_alloc_buf(r->pool);
                if (nb == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                *nb = *b;
                nb->tag = 0;
                nb->shadow = NULL;
                nb->recycled = 0;
                nb->last_shadow = 0;
                nb->pos = b->pos;
                nb->last = b->last;
                if (!nb->last_buf) {
                    nb->last_in_chain = 0;
                }

                if (ngx_http_naive_padding_append_buf(r, &ll, nb) != NGX_OK) {
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

                nb = ngx_alloc_buf(r->pool);
                if (nb == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                *nb = *b;
                nb->tag = 0;
                nb->shadow = NULL;
                nb->recycled = 0;
                nb->last_shadow = 0;
                nb->pos = b->pos;
                nb->last = b->pos + n;
                nb->last_buf = 0;
                nb->last_in_chain = 0;

                if (ngx_http_naive_padding_append_buf(r, &ll, nb) != NGX_OK) {
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

                b->pos += n;
                ctx->padding_size -= n;

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

        nb = ngx_calloc_buf(r->pool);
        if (nb == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        nb->last_buf = 1;

        if (ngx_http_naive_padding_append_buf(r, &ll, nb) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_naive_padding_encode_response(ngx_http_request_t *r,
    ngx_http_naive_padding_ctx_t *ctx, ngx_chain_t *in, ngx_chain_t **out,
    ngx_uint_t *h2_end_stream)
{
    enum {
        ngx_http_naive_padding_encode_add_header = 0,
        ngx_http_naive_padding_encode_body,
        ngx_http_naive_padding_encode_add_tail
    } state;

    size_t          n, payload_size, padding_size;
    u_char         *body_pos, *body_last, *pos, *last, *tail_pos;
    ngx_buf_t      *b, *nb;
    ngx_chain_t    *cl;
    ngx_chain_t   **ll;
    ngx_uint_t      body_last_buf, final_buf, mutable, tail_last_buf;

    ll = out;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;
        pos = b->pos;
        last = b->last;

        if (pos == last) {
            if (b->last_buf && h2_end_stream != NULL) {
                *h2_end_stream = 1;
                goto h2_end_stream;
            }

            if (ngx_http_naive_padding_append_buf(r, &ll, b) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        while (pos < last) {

            if (ctx->response_count >= NGX_HTTP_NAIVE_PADDING_K_FIRST) {
                b->pos = pos;

                if (b->last_buf && h2_end_stream != NULL) {
                    b->last_buf = 0;
                    b->last_in_chain = 0;
                    *h2_end_stream = 1;
                }

                if (ngx_http_naive_padding_append_buf(r, &ll, b) != NGX_OK) {
                    return NGX_ERROR;
                }
                break;
            }

            payload_size = ngx_min((size_t) (last - pos),
                                   (size_t) NGX_HTTP_NAIVE_PADDING_MAX_PAYLOAD);
            padding_size = ngx_random()
                           % (NGX_HTTP_NAIVE_PADDING_MAX_PADDING + 1);

            body_pos = pos;
            body_last = pos + payload_size;
            final_buf = b->last_buf && body_last == last;
            mutable = b->temporary && b->shadow == NULL && !b->recycled
                      && !b->last_shadow && !b->in_file;
            state = ngx_http_naive_padding_encode_add_header;

            for ( ;; ) {
                switch (state) {

                case ngx_http_naive_padding_encode_add_header:
                    /*
                     * Prefer in-place header space immediately before b->pos.
                     * For later chunks from the same buffer, bytes before pos
                     * may already be referenced by output links.
                     */
                    if (body_pos == b->pos && mutable
                        && (size_t) (body_pos - b->start)
                           >= NGX_HTTP_NAIVE_PADDING_HEADER_SIZE)
                    {
                        body_pos -= NGX_HTTP_NAIVE_PADDING_HEADER_SIZE;
                        body_pos[0] = (u_char) (payload_size >> 8);
                        body_pos[1] = (u_char) payload_size;
                        body_pos[2] = (u_char) padding_size;

                    } else {
                        nb = ngx_create_temp_buf(r->pool,
                            NGX_HTTP_NAIVE_PADDING_HEADER_SIZE);
                        if (nb == NULL) {
                            return NGX_ERROR;
                        }

                        *nb->last++ = (u_char) (payload_size >> 8);
                        *nb->last++ = (u_char) payload_size;
                        *nb->last++ = (u_char) padding_size;

                        if (ngx_http_naive_padding_append_buf(r, &ll, nb)
                            != NGX_OK)
                        {
                            return NGX_ERROR;
                        }
                    }

                    state = ngx_http_naive_padding_encode_body;
                    continue;

                case ngx_http_naive_padding_encode_body:
                    /*
                     * The payload body is a cloned ngx_buf_t span.  No payload
                     * bytes are copied into padding-owned storage.
                     */
                    body_last_buf = final_buf && padding_size == 0
                                    && h2_end_stream == NULL;

                    nb = ngx_alloc_buf(r->pool);
                    if (nb == NULL) {
                        return NGX_ERROR;
                    }

                    *nb = *b;
                    nb->tag = 0;
                    nb->shadow = NULL;
                    nb->recycled = 0;
                    nb->last_shadow = 0;
                    nb->pos = body_pos;
                    nb->last = body_last;
                    nb->last_buf = body_last_buf;
                    if (!body_last_buf) {
                        nb->last_in_chain = 0;
                    }

                    if (ngx_http_naive_padding_append_buf(r, &ll, nb)
                        != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    pos = body_last;
                    b->pos = pos;
                    ctx->response_count++;

                    state = ngx_http_naive_padding_encode_add_tail;
                    continue;

                case ngx_http_naive_padding_encode_add_tail:
                    /*
                     * Tail bytes can use spare space at b->last only when this
                     * padding frame consumed the original end of b.  Otherwise
                     * the tail must be a separate zero buffer to preserve chain
                     * order before the next payload chunk.
                     */
                    tail_last_buf = final_buf && h2_end_stream == NULL;

                    if (padding_size == 0) {
                        break;
                    }

                    if (pos == last && mutable && b->last < b->end)
                    {
                        n = ngx_min(padding_size,
                                    (size_t) (b->end - b->last));
                        tail_pos = b->last;
                        ngx_memzero(tail_pos, n);
                        b->last += n;
                        padding_size -= n;

                        nb = ngx_alloc_buf(r->pool);
                        if (nb == NULL) {
                            return NGX_ERROR;
                        }

                        *nb = *b;
                        nb->tag = 0;
                        nb->shadow = NULL;
                        nb->recycled = 0;
                        nb->last_shadow = 0;
                        nb->pos = tail_pos;
                        nb->last = tail_pos + n;
                        nb->last_buf = tail_last_buf && padding_size == 0;
                        if (!nb->last_buf) {
                            nb->last_in_chain = 0;
                        }

                        if (ngx_http_naive_padding_append_buf(r, &ll, nb)
                            != NGX_OK)
                        {
                            return NGX_ERROR;
                        }
                    }

                    if (padding_size) {
                        nb = ngx_create_temp_buf(r->pool, padding_size);
                        if (nb == NULL) {
                            return NGX_ERROR;
                        }

                        ngx_memzero(nb->last, padding_size);
                        nb->last += padding_size;
                        nb->flush = b->flush;
                        nb->last_buf = tail_last_buf;

                        if (ngx_http_naive_padding_append_buf(r, &ll, nb)
                            != NGX_OK)
                        {
                            return NGX_ERROR;
                        }
                    }

                    break;
                }

                break;
            }

            if (final_buf && h2_end_stream != NULL) {
                *h2_end_stream = 1;
                goto h2_end_stream;
            }
        }
    }

    return NGX_OK;

h2_end_stream:

    return NGX_OK;
}


#if (NGX_HTTP_V2)

static ngx_int_t
ngx_http_naive_padding_h2_send_end_stream(ngx_http_request_t *r)
{
    u_char                    *p;
    size_t                     frame_size, range, total_size;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_v2_stream_t      *stream;
    ngx_http_v2_connection_t  *h2c;
    ngx_http_v2_out_frame_t   *frame;

    if (r->http_version != NGX_HTTP_VERSION_20 || r->stream == NULL
        || !r->header_sent)
    {
        return NGX_DECLINED;
    }

    stream = r->stream;
    h2c = stream->connection;

    if (stream->out_closed || stream->rst_sent || h2c->connection->error) {
        return NGX_DECLINED;
    }

    total_size = NGX_HTTP_NAIVE_PADDING_H2_END_MIN;
    range = NGX_HTTP_NAIVE_PADDING_H2_END_MAX
            - NGX_HTTP_NAIVE_PADDING_H2_END_MIN + 1;
    total_size += ngx_random() % range;
    frame_size = total_size - NGX_HTTP_V2_FRAME_HEADER_SIZE;

    if (frame_size < 2 || frame_size - 1 > 255) {
        return NGX_DECLINED;
    }

    if (h2c->send_window < frame_size
        || stream->send_window < (ssize_t) frame_size)
    {
        return NGX_DECLINED;
    }

    frame = ngx_pcalloc(r->pool, sizeof(ngx_http_v2_out_frame_t));
    if (frame == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, total_size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->tag = (ngx_buf_tag_t) &ngx_http_v2_module;
    b->memory = 1;
    b->flush = 1;
    b->last_buf = 1;

    p = b->last;
    p = ngx_http_v2_write_len_and_type(p, frame_size, NGX_HTTP_V2_DATA_FRAME);
    *p++ = NGX_HTTP_V2_END_STREAM_FLAG | NGX_HTTP_V2_PADDED_FLAG;
    p = ngx_http_v2_write_sid(p, stream->node->id);
    *p++ = (u_char) (frame_size - 1);
    ngx_memzero(p, frame_size - 1);
    p += frame_size - 1;
    b->last = p;

    cl->buf = b;
    cl->next = NULL;

    frame->first = cl;
    frame->last = cl;
    frame->handler = ngx_http_naive_padding_h2_end_stream_handler;
    frame->stream = stream;
    frame->length = frame_size;
    frame->blocked = 0;
    frame->fin = 1;

    ngx_http_v2_queue_frame(h2c, frame);
    h2c->send_window -= frame_size;
    stream->send_window -= frame_size;
    stream->queued++;

    stream->blocked = 1;
    if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
        r->connection->error = 1;
        return NGX_ERROR;
    }
    stream->blocked = 0;

    if (stream->queued) {
        r->connection->buffered |= NGX_HTTP_V2_BUFFERED;
        r->connection->write->active = 1;
        r->connection->write->ready = 0;
        return NGX_OK;
    }

    r->connection->buffered &= ~NGX_HTTP_V2_BUFFERED;

    return NGX_OK;
}


static ngx_int_t
ngx_http_naive_padding_h2_end_stream_handler(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_out_frame_t *frame)
{
    ngx_event_t          *wev;
    ngx_chain_t          *cl;
    ngx_connection_t     *fc;
    ngx_http_request_t   *r;
    ngx_http_v2_stream_t *stream;

    if (frame->first->buf->pos != frame->first->buf->last) {
        return NGX_AGAIN;
    }

    stream = frame->stream;
    r = stream->request;
    cl = frame->first;

    r->connection->sent += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;
    r->header_size += NGX_HTTP_V2_FRAME_HEADER_SIZE;
    h2c->total_bytes += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;
    h2c->payload_bytes += frame->length;

    if (frame->fin) {
        stream->out_closed = 1;
    }

    ngx_free_chain(r->pool, cl);

    frame->next = stream->free_frames;
    stream->free_frames = frame;
    stream->queued--;

    fc = r->connection;
    if (stream->queued == 0 && !h2c->connection->buffered) {
        fc->buffered &= ~NGX_HTTP_V2_BUFFERED;
    }

    if (!stream->waiting && !stream->blocked) {
        wev = fc->write;
        wev->active = 0;
        wev->ready = 1;

        if (fc->error || !wev->delayed) {
            ngx_post_event(wev, &ngx_posted_events);
        }
    }

    return NGX_OK;
}

#endif


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
