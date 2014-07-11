#ifndef HC_metautils_bits__h
#define HC_metautils_bits__h 1
#include <glib.h>

/*
 * A place for all the macros playing with integer bits
 */

#define BUFSIZE(B)       (B),sizeof(B)
#define BUFLEN(B)        (B),sizeof(B)-1

#define ZERO(A) memset((A), 0x00, sizeof(A));

// Return -1 if A<B, 0 if A==B, 1 if A>B
#define CMP(a,b) (((a) > (b)) - ((a) < (b)))

// Return -1 if A<0, 0 if A==0, 1 if A>0
#define SIGN(v) CMP(v,0)
#define BOOL(C) ((C)!=0)

# define MACRO_COND(C,A,B) ((B) ^ (((A)^(B)) & -BOOL(C)))
# define MACRO_MAX(A,B)    ((A) ^ (((A)^(B)) & -((A)<(B))))
# define MACRO_MIN(A,B)    ((B) ^ (((A)^(B)) & -((A)<(B))))

// Might slightly speed up the code using branch predictions
# ifdef __GNUC__
#  define likely(x)       __builtin_expect(BOOL(x),1)
#  define unlikely(x)     __builtin_expect(BOOL(x),0)
# else
#  define likely(x)       (x)
#  define unlikely(x)     (x)
# endif

struct hash_len_s
{
	guint32 h;
	guint32 l;
};

static inline guint32
djb_hash_buf3(register guint32 h, const guint8 * b, register gsize bs)
{
	for (register gsize i = 0; i < bs; ++i)
		h = ((h << 5) + h) ^ (guint32) (b[i]);
	return h;
}

static inline guint32
djb_hash_buf(const guint8 * b, register gsize bs)
{
	return djb_hash_buf3(5381, b, bs);
}

static inline struct hash_len_s
djb_hash_str(const gchar * b)
{
	struct hash_len_s hl = {.h = 5381,.l = 0 };
	for (; b[hl.l]; ++hl.l)
		hl.h = ((hl.h << 5) + hl.h) ^ (guint32) (b[hl.l]);
	return hl;
}

static inline int
FUNC_SIGN(register int v)
{
    return SIGN(v);
}

static inline guint
FUNC_CLAMP(register guint v, register guint lo, register guint hi)
{
	v = MACRO_MIN(v,hi);
	return MACRO_MAX(v,lo);
}

static inline guint
FUNC_MAX(register guint v0, register guint v1)
{
	return MACRO_MAX(v0,v1);
}

static inline guint
FUNC_MIN(register guint v0, register guint v1)
{
	return MACRO_MIN(v0,v1);
}

static inline guint
FUNC_COND(register guint c, register guint v0, register guint v1)
{
	return MACRO_COND(c,v0,v1);
}

static inline guint64
guint_to_guint64(guint u)
{
	guint64 u64 = u;
	return u64;
}

#define metautils_pfree0(pp,repl) do { \
	if (NULL != *(pp)) \
		g_free(*pp); \
	*(pp) = (repl); \
} while (0)

#define metautils_pfree(pp,repl) do { \
	if (NULL != (pp)) \
		metautils_pfree0(pp,repl); \
} while (0)

#endif // HC_metautils_bits__h
