#include <openssl/crypto.h>
#include <openssl/des.h>

#ifdef des_cbc_encrypt
#undef des_cbc_encrypt
#endif
void
des_cbc_encrypt(void *i, void *o, long l, DES_key_schedule k, void *iv, int e)
{
	DES_cbc_encrypt(i,o,l,&k,iv,e);
}

#ifdef des_key_sched
#undef des_key_sched
#endif
void
des_key_sched(const_DES_cblock *k, DES_key_schedule ks)
{
	DES_key_sched(k, &ks);
}

#ifdef des_ncbc_encrypt
#undef des_ncbc_encrypt
#endif
void
des_ncbc_encrypt(const unsigned char *i, unsigned char *o, long l, DES_key_schedule k, DES_cblock *iv, int e)
{
	DES_ncbc_encrypt(i, o, l, &k, iv, e);
}

