#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <stdio.h>   /* sprintf() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <string.h>   /* memcpy */

/* 使用者可在编译选项中自行设置宏，没设置的话就用缺省值 */
#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')
#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define PUTC(c, ch)         do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)
#define PUTS(c, s, len)     memcpy(lept_context_push(c, len), s, len)

typedef struct {
    const char* json;
    /* 解析一个字符串之前，这个缓冲区的大小是不能预知的。
    因此，采用动态数组（dynamic array）这种数据结构 
    一个动态的堆栈（stack）数据结构,stack是 当前堆栈空间起始的地址,
    size 是当前的堆栈容量，top 是栈顶的位置 */
    char* stack;
    size_t size, top;
}lept_context;

/* 返回指向压入数据起始的指针*/
static void* lept_context_push(lept_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0) {
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        }
        while (c->top + size >= c->size)
            c->size += c->size >> 1;
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void lept_parse_whitespace(lept_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static lept_parse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type) {
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i + 1]; i++)
        if (c->json[i] != literal[i + 1])
            return LEPT_PARSE_INVALID_VALUE;

    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v) {
    /*  number = [ "-" ] int [ frac ] [ exp ]
        int = "0" / digit1-9 *digit
        frac = "." 1*digit
        exp = ("e" / "E") ["-" / "+"] 1*digit 
    */

    const char* p = c->json;
    if (*p == '-') p++;
    if (*p == '0') p++;
    else {
        if (!ISDIGIT1TO9(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++;ISDIGIT(*p);p++);
    }
    if (*p == '.') {
        p++;
        if(!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++;ISDIGIT(*p);p++);
    }
    if(*p == 'e' || *p == 'E') {
        p++;
        if(*p == '+' || *p == '-') p++;
        if(!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++;ISDIGIT(*p);p++);
    }

    errno = 0;
    v->n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL))
        return LEPT_PARSE_NUMBER_TOO_BIG;
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static const char* lept_parse_hex4(const char* p, unsigned* u) {
    *u = 0;
    for(int i = 0; i < 4;  i++) {
        char ch = *p++;
        *u <<= 4;
        if (ch >= '0' && ch <= '9')
            *u |= ch - '0';
        else if (ch >= 'A' && ch <= 'F')
            *u |= ch - 'A' + 10;
        else if (ch >= 'a' && ch <= 'f')
            *u |= ch - 'a' + 10;    
        else
            return NULL;
    }
    return p;
}

static void lept_encode_utf8(lept_context* c, unsigned u) {
    if (u <= 0x7F) {
        PUTC(c, u & 0xFF);
    } else if (u <= 0x7FF) {
        PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
        PUTC(c, 0x80 | ( u       & 0x3F));
    } else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    } else {
        assert(u <= 0x10FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
}

#define STRING_ERROR(ret)   do { c->top = head; return ret; } while(0)

/* 解析 JSON 字符串，把结果写入 str 和 len */
/* str 指向 c->stack 中的元素，需要在 c->stack  */
static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
    size_t head = c->top;
    unsigned u, u2;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for(;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                *len = c->top - head;
                *str = lept_context_pop(c, *len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\\':
                /* 转义序列的解析 */
                switch (*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/' ); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                        /* eg: \uD834\uDD1E -> 0x1D11E -> 0xE2, 0x82, 0xAC */
                        if (!(p = lept_parse_hex4(p, &u)))
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        if (u >= 0xD800 && u <= 0xDBFF) { /* surrogate pair */
                            if (*p++ != '\\')
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (*p++ != 'u')
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (!(p = lept_parse_hex4(p, &u2)))
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\0':
                STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20) { 
                    /* 不合法的字符串 */
                    STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                }
                PUTC(c, ch);
        }
    }
}

static int lept_parse_string(lept_context* c, lept_value* v) {
    int ret;
    char* s;
    size_t len;
    if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK)
        lept_set_string(v, s, len);
    return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v);

static int lept_parse_array(lept_context* c, lept_value* v) {
    size_t size = 0;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    if (*c->json == ']') {
        c->json++;
        // v->type = LEPT_ARRAY;
        // v->esize = 0;
        // v->e = NULL;
        lept_set_array(v, 0);
        return LEPT_PARSE_OK;
    }
    for(;;) {
        lept_value e;
        lept_init(&e);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK)
            break;
        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        }
        else if (*c->json == ']') {
            c->json++;
            // v->type = LEPT_ARRAY;
            lept_set_array(v, size);
            v->esize = size;
            // size *= sizeof(lept_value);
            // memcpy(v->e = (lept_value*)malloc(size), lept_context_pop(c, size), size);
            memcpy(v->e, lept_context_pop(c, size * sizeof(lept_value)), size *  sizeof(lept_value));
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    /* Pop and free values on the stack */
    for (int i = 0; i < size; i++)
        lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
    return ret;
}

static int lept_parse_object(lept_context* c, lept_value* v) {
    size_t size = 0;
    lept_member m;
    int ret;
    EXPECT(c, '{');
    lept_parse_whitespace(c);
    if (*c->json == '}') {
        c->json++;
        lept_set_object(v, 0);
        // v->type = LEPT_OBJECT;
        // v->msize = 0;
        // v->m = NULL;
        return LEPT_PARSE_OK;
    }
    m.k = NULL;
    for(;;) {
        char* str;
        lept_init(&m.v);
        /* parse key to m.k, m.klen */
        if (*c->json != '"') {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }
        if ((ret = lept_parse_string_raw(c, &str, &m.klen)) != LEPT_PARSE_OK)
            break;
        memcpy(m.k = (char*)malloc(m.klen+1), str, m.klen);
        m.k[m.klen] = '\0';
        /* parse ws colon ws */
        lept_parse_whitespace(c);
        if (*c->json != ':') {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        lept_parse_whitespace(c);
        /* parse value */
        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK)
            break;
        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        m.k = NULL; /* ownership is transferred to member on stack */
        /* parse ws [comma | right-curly-brace] ws */
        lept_parse_whitespace(c);
        if (*c->json == ',') {
           c->json++;
           lept_parse_whitespace(c); 
        } else if (*c->json == '}') {
            // size_t s = sizeof(lept_member) * size;
            c->json++;
            // v->type = LEPT_OBJECT;
            lept_set_object(v, size);
            v->msize = size;
            // memcpy(v->m = (lept_member*)malloc(s), lept_context_pop(c, s), s);
            memcpy(v->m, lept_context_pop(c, sizeof(lept_member) * size), sizeof(lept_member) * size);
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    /* Pop and free members on the stack */
    free(m.k);
    for (int i  = 0; i < size; i++) {
        lept_member* m = (lept_member*)lept_context_pop(c, sizeof(lept_member));
        free(m->k);
        lept_free(&m->v);
    }
    v->type = LEPT_NULL;
    return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 't':  return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f':  return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case 'n':  return lept_parse_literal(c, v, "null", LEPT_NULL);
        default:   return lept_parse_number(c, v);
        case '"':  return lept_parse_string(c, v);
        case '[':  return lept_parse_array(c, v);
        case '{':  return lept_parse_object(c,v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
    }
}

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    v->type = LEPT_NULL;
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

#if 0
// Unoptimized
static void lept_stringify_string(lept_context* c, const char* s, size_t len) {
    size_t i;
    assert(s != NULL);
    PUTC(c, '"');
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
            case '\"': PUTS(c, "\\\"", 2); break;
            case '\\': PUTS(c, "\\\\", 2); break;
            case '\b': PUTS(c, "\\b",  2); break;
            case '\f': PUTS(c, "\\f",  2); break;
            case '\n': PUTS(c, "\\n",  2); break;
            case '\r': PUTS(c, "\\r",  2); break;
            case '\t': PUTS(c, "\\t",  2); break;
            default:
                if (ch < 0x20) {
                    char buffer[7];
                    sprintf(buffer, "\\u%04X", ch);
                    PUTS(c, buffer, 6);
                }
                else
                    PUTC(c, s[i]);
        }
    }
    PUTC(c, '"');
}
#else
static void lept_stringify_string(lept_context* c, const char* s, size_t len) {
    static const char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    size_t i, size;
    char* head, *p;
    assert(s != NULL);
    /* 预先分配足够的内存，每次加入字符就不用做lept_context_push中的条件检查了 */
    p = head = lept_context_push(c, size = len * 6 + 2); /* "\u00xx..." */
    *p++ = '"';
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
            case '\"': *p++ = '\\'; *p++ = '\"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\b': *p++ = '\\'; *p++ = 'b';  break;
            case '\f': *p++ = '\\'; *p++ = 'f';  break;
            case '\n': *p++ = '\\'; *p++ = 'n';  break;
            case '\r': *p++ = '\\'; *p++ = 'r';  break;
            case '\t': *p++ = '\\'; *p++ = 't';  break;
            default:
                if (ch < 0x20) {
                    /* 自行编写十六进位输出，避免了 printf() 内解析格式的开销 */
                    *p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
                    *p++ = hex_digits[ch >> 4];
                    *p++ = hex_digits[ch & 15];
                }
                else
                    *p++ = s[i];
        }
    }
    *p++ = '"';
    c->top -= size - (p - head);
}
#endif

static void lept_stringify_value(lept_context* c, const lept_value* v) {
    size_t i;
    switch (v->type) {
        case LEPT_NULL:   PUTS(c, "null",  4); break;
        case LEPT_FALSE:  PUTS(c, "false", 5); break;
        case LEPT_TRUE:   PUTS(c, "true",  4); break;
        case LEPT_NUMBER:
            {
                char* buffer = lept_context_push(c, 32);
                int length = sprintf(buffer, "%.17g", v->n);
                c->top -= 32 - length;
            }
            break;
        case LEPT_STRING:lept_stringify_string(c, v->s, v->len);break;
        case LEPT_ARRAY:
            PUTC(c, '[');
            for (i = 0; i < v->esize; i++) {
                if (i > 0)
                    PUTC(c, ',');
                lept_stringify_value(c, &v->e[i]);
            }
            PUTC(c, ']');
            break;
        case LEPT_OBJECT:
        PUTC(c, '{');
            for (i = 0; i < v->msize; i++) {
                if (i > 0)
                    PUTC(c, ',');
                lept_stringify_string(c, v->m[i].k, v->m[i].klen);
                PUTC(c, ':');
                lept_stringify_value(c, &v->m[i].v);
            }
            PUTC(c, '}');
            break;
        default: assert(0 && "invalid type");
    }
}

char* lept_stringify(const lept_value* v, size_t* length) {
    lept_context c;
    assert(v != NULL);
    c.stack = (char*)malloc(c.size = LEPT_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    lept_stringify_value(&c, v);
    if (length)
        *length = c.top;
    PUTC(&c, '\0');
    return c.stack;
}

void lept_free(lept_value* v) {
    assert(v != NULL);
    if (v->type == LEPT_STRING) {
        free(v->s);
    }
    if (v->type == LEPT_ARRAY) {
        for (int i = 0; i < v->esize; i++)
            lept_free(&v->e[i]);
        free(v->e);
    }
    if (v->type == LEPT_OBJECT) {
        for (int i = 0; i < v->msize; i++) {
            free(v->m[i].k);
            lept_free(&v->m[i].v);
        }
        free(v->m);
    }
    v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

int lept_get_boolean(const lept_value* v) {
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b) {
    lept_free(v);
    v->type = (b ? LEPT_TRUE : LEPT_FALSE);
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}

void lept_set_number(lept_value* v, double n) {
    lept_free(v);
    v->n = n;
    v->type = LEPT_NUMBER;
}

const char* lept_get_string(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->s;
}

size_t lept_get_string_length(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->len;
}

void lept_set_string(lept_value* v, const char* s, size_t len) {
    /* 非空指针（有具体的字符串）或是零长度的字符串都是合法的 */
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->s = (char*)malloc(len+1);
    memcpy(v->s, s, len);
    v->s[len] = '\0';
    v->len = len;
    v->type = LEPT_STRING;
}
// TODO array 相关函数
void lept_set_array(lept_value* v, size_t capacity) {
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_ARRAY;
    v->ecapacity = capacity;
    v->esize = 0;
    v->e = capacity > 0 ? (lept_value*)malloc(sizeof(lept_value) * capacity) : NULL;
}

size_t lept_get_array_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->esize;
}

size_t lept_get_array_capacity(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->ecapacity;
}

void lept_reserve_array(lept_value* v, size_t capacity) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->ecapacity < capacity) {
        v->ecapacity = capacity;
        v->e = (lept_value*)realloc(v->e, sizeof(lept_value) * capacity);
    }
}

void lept_shrink_array(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->ecapacity > v->esize) {
        v->ecapacity = v->esize;
        v->e = (lept_value*)realloc(v->e, sizeof(lept_value) * v->ecapacity);
    }
}

void lept_clear_array(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    for (size_t i = 0; i < v->esize; i++) {
        lept_free(&v->e[i]);
    }
    v->esize = 0;
}

lept_value* lept_get_array_element(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->esize);
    return &(v->e[index]);
}

/* 在数组末端压入一个元素，返回新的元素指针 */
lept_value* lept_pushback_array_element(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->esize == v->ecapacity) {
        lept_reserve_array(v, v->ecapacity == 0 ? 1 : v->ecapacity * 2);
    }
    lept_init(&v->e[v->esize]);
    return &v->e[v->esize++];
}

void lept_popback_array_element(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY && v->esize > 0);
    lept_free(&v->e[--v->esize]);
}

/* 在 index 位置插入一个元素 */
lept_value* lept_insert_array_element(lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY && index <= v->esize);
    if (v->esize == v->ecapacity) {
        lept_reserve_array(v, v->ecapacity == 0 ? 1 : v->ecapacity * 2);
    }
    memcpy(&v->e[index + 1], &v->e[index], (v->esize - index) * sizeof(lept_value));
    lept_init(&v->e[index]);
    v->esize++;
    return &v->e[index];
}

/* 删去在 index 位置开始共 count 个元素（不改容量）*/
/* 回收空间，然后将index后面count个元素移到index处，然后将空闲的count个元素重新初始化 */
void lept_erase_array_element(lept_value* v, size_t index, size_t count) {
    assert(v != NULL && v->type == LEPT_ARRAY && index + count <= v->esize);
    size_t i;
    for (i = index; i < index + count; i++) {
        lept_free(&v->e[i]);
    }
    memcpy(&v->e[index], &v->e[index + count], (v->esize - index -count ) * sizeof(lept_value));
    for (i = v->esize - count; i < v->esize; i++) {
        lept_init(&v->e[i]);
    }
    v->esize -= count;
}

// TODO object 相关函数
void lept_set_object(lept_value* v, size_t capacity) {
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_OBJECT;
    v->mcapacity = capacity;
    v->msize = 0;
    v->m = capacity > 0 ? (lept_member*)malloc(sizeof(lept_member) * capacity) : NULL;
}

size_t lept_get_object_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->msize;
}

size_t lept_get_object_capacity(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->mcapacity;
}

void lept_reserve_object(lept_value* v, size_t capacity) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->mcapacity < capacity) {
        v->mcapacity = capacity;
        v->m = (lept_member*)realloc(v->m, sizeof(lept_member) * capacity);
    }
}

void lept_shrink_object(lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->mcapacity > v->msize) {
        v->mcapacity = v->msize;
        v->m = (lept_member*)realloc(v->m, sizeof(lept_member) * v->mcapacity);
    }  
}
void lept_clear_object(lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    for(size_t i = 0; i < v->msize; i++) {
        v->m[i].klen = 0;
        free(v->m[i].k);
        v->m[i].k = NULL;
        lept_free(&v->m[i].v);

    }
    v->msize = 0;
}

const char* lept_get_object_key(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->msize);
    return v->m[index].k;
}

size_t lept_get_object_key_length(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->msize);
    return v->m[index].klen;
}

lept_value* lept_get_object_value(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->msize);
    return &v->m[index].v;
}

size_t lept_find_object_index(const lept_value* v, const char* key, size_t klen) {
    assert(v != NULL && v->type == LEPT_OBJECT && key != NULL);
    for (size_t i = 0; i < v->msize; i++) {
        if (v->m[i].klen ==  klen && memcmp(v->m[i].k, key, klen) == 0)
            return i;
    }
    return LEPT_KEY_NOT_EXIST;
}

lept_value* lept_find_object_value(lept_value* v, const char* key, size_t klen) {
    size_t index = lept_find_object_index(v, key, klen);
    return index != LEPT_KEY_NOT_EXIST ? &v->m[index].v : NULL;
}

/* 先搜寻是否存在现有的键，若存在则直接返回该值的指针，不存在时才新增 */
lept_value* lept_set_object_value(lept_value* v, const char* key, size_t klen) {
    assert(v != NULL && v->type == LEPT_OBJECT && key != NULL);
    lept_value* ret = NULL;
    if ((ret = lept_find_object_value(v, key, klen)) != NULL)
        return ret;
    if (v->msize == v->mcapacity) {
        lept_reserve_object(v,v->mcapacity == 0 ? 1 : (v->mcapacity << 1));
    }
    size_t i = v->msize;

    v->m[i].k = (char*)malloc(klen + 1);
    memcpy(v->m[i].k, key, klen);
    v->m[i].k[klen] = '\0';
    v->m[i].klen = klen;
    lept_init(&v->m[i].v);
    v->msize++;
    return &v->m[i].v;
}

void lept_remove_object_value(lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT && index < v->msize);

    free(v->m[index].k);
    v->m[index].k = NULL;
    lept_free(&v->m[index].v);

    memcpy(&v->m[index], &v->m[index + 1], (v->msize - index -1) * sizeof(lept_member));
    v->m[--v->msize].k = NULL;
    v->m[v->msize].klen = 0;
    lept_init(&v->m[v->msize].v);
}

// TODO json 比较 复制 移动 交换 函数
int lept_is_equal(const lept_value* lhs, const lept_value* rhs) {
    size_t i;
    assert(lhs != NULL && rhs != NULL);
    if (lhs->type != rhs->type)
        return 0;
    switch (lhs->type) {
        case LEPT_NUMBER:
            return lhs->n == rhs->n;
        case LEPT_STRING:
            return lhs->len == rhs->len && memcmp(lhs->s, rhs->s, lhs->len) == 0;
        case LEPT_ARRAY:
            if (lhs->esize != rhs->esize)
                return 0;
            for (i = 0; i < lhs->esize; i++)
                if (!lept_is_equal(&lhs->e[i], &rhs->e[i]))
                    return 0;
            return 1;
        case LEPT_OBJECT:
            if (lhs->msize != rhs->msize)
                return 0;
            for (i = 0; i < lhs->msize; i++)  {
                lept_value* tmp = lept_find_object_value(rhs, lhs->m[i].k, lhs->m[i].klen);
                if (!lept_is_equal(&lhs->m[i].v, tmp))
                    return 0;
            }
            return 1;
        default:
            return 1;
    }
}

void lept_copy(lept_value* dst, const lept_value* src) {
    size_t i;
    assert(dst != NULL && src != NULL && dst != src);
    switch (src->type) {
        case LEPT_STRING:
            lept_set_string(dst, src->s, src->len);
            break;
        case LEPT_ARRAY:
            lept_set_array(dst, src->esize);
            // dst->type = LEPT_ARRAY;
            // dst->e = (lept_value*)malloc(sizeof(lept_value) * src->esize);
            for (i = 0; i < src->esize; i++)
                lept_copy(&dst->e[i], &src->e[i]);
            dst->esize = src->esize;
            break;
        case LEPT_OBJECT:
            lept_set_object(dst, src->msize);
            // dst->type = LEPT_OBJECT;
            // dst->m = (lept_member*)malloc(sizeof(lept_member) * src->msize);
            for (i = 0; i < src->msize; i++) {
                // dst->m[i].k = (char*)malloc(src->m[i].klen);
                // memcpy(dst->m[i].k, src->m[i].k, src->m[i].klen);
                // dst->m[i].klen = src->m[i].klen;
                lept_set_object_value(dst, src->m[i].k, src->m[i].klen);
                lept_copy(&dst->m[i].v, &src->m[i].v);
            }
            dst->msize = src->msize;
            break;
        default:
            lept_free(dst);
            memcpy(dst, src, sizeof(lept_value));
            break;
    }
}

void lept_move(lept_value* dst, lept_value* src) {
    assert(dst != NULL && src != NULL && dst != src);
    lept_free(dst);
    memcpy(dst, src, sizeof(lept_value));
    lept_init(src);
}

void lept_swap(lept_value* lhs, lept_value* rhs) {
    assert(lhs != NULL && rhs != NULL);
    if (lhs != rhs) {
        lept_value tmp;
        memcpy(&tmp, lhs, sizeof(lept_value));
        memcpy(lhs, rhs, sizeof(lept_value));
        memcpy(rhs, &tmp, sizeof(lept_value));
    }
}