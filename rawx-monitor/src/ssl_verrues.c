/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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

