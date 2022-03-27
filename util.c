/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012 Luke Dashjr
 * Copyright 2012-2020 pooler
 * Copyright 2017 Pieter Wuille
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define _GNU_SOURCE
#include "cpuminer-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#if defined(WIN32)
#include <winsock2.h>
#include <mstcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif
#include "compat.h"
#include "miner.h"
#include "elist.h"

struct header_info {
	char		*lp_path;
	char		*reason;
	char		*stratum_url;
	size_t		content_length;
};

struct data_buffer {
	void			*buf;
	size_t			len;
	size_t			allocated;
	struct header_info	*headers;
};

struct tq_ent {
	void			*data;
	struct list_head	q_node;
};

struct thread_q {
	struct list_head	q;

	bool frozen;

	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	char *f;
	int len;
	time_t now;
	struct tm tm, *tm_p;

	time(&now);

	pthread_mutex_lock(&applog_lock);
	tm_p = localtime(&now);
	memcpy(&tm, tm_p, sizeof(tm));
	pthread_mutex_unlock(&applog_lock);

	len = 40 + strlen(fmt) + 2;
	f = alloca(len);
	sprintf(f, "%s\n", fmt);
	pthread_mutex_lock(&applog_lock);
	vfprintf(stderr, f, ap);	/* atomic write to stderr */
	fflush(stderr);
	pthread_mutex_unlock(&applog_lock);

	va_end(ap);
}

static void databuf_free(struct data_buffer *db)
{
	if (!db)
		return;

	free(db->buf);

	memset(db, 0, sizeof(*db));
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
	struct data_buffer *db = user_data;
	size_t len = size * nmemb;
	size_t newalloc, reqalloc;
	void *newmem;
	static const unsigned char zero = 0;
	static const size_t max_realloc_increase = 8 * 1024 * 1024;
	static const size_t initial_alloc = 16 * 1024;

	/* minimum required allocation size */
	reqalloc = db->len + len + 1;

	if (reqalloc > db->allocated) {
		if (db->len > 0) {
			newalloc = db->allocated * 2;
		} else {
			if (db->headers->content_length > 0)
				newalloc = db->headers->content_length + 1;
			else
				newalloc = initial_alloc;
		}

		if (db->headers->content_length == 0) {
			/* limit the maximum buffer increase */
			if (newalloc - db->allocated > max_realloc_increase)
				newalloc = db->allocated + max_realloc_increase;
		}

		/* ensure we have a big enough allocation */
		if (reqalloc > newalloc)
			newalloc = reqalloc;

		newmem = realloc(db->buf, newalloc);
		if (!newmem)
			return 0;

		db->buf = newmem;
		db->allocated = newalloc;
	}

	memcpy(db->buf + db->len, ptr, len); /* append new data */
	memcpy(db->buf + db->len + len, &zero, 1); /* null terminate */

	db->len += len;

	return len;
}

static size_t resp_hdr_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct header_info *hi = user_data;
	size_t remlen, slen, ptrlen = size * nmemb;
	char *rem, *val = NULL, *key = NULL;
	void *tmp;

	val = calloc(1, ptrlen);
	key = calloc(1, ptrlen);
	if (!key || !val)
		goto out;

	tmp = memchr(ptr, ':', ptrlen);
	if (!tmp || (tmp == ptr))	/* skip empty keys / blanks */
		goto out;
	slen = tmp - ptr;
	if ((slen + 1) == ptrlen)	/* skip key w/ no value */
		goto out;
	memcpy(key, ptr, slen);		/* store & nul term key */
	key[slen] = 0;

	rem = ptr + slen + 1;		/* trim value's leading whitespace */
	remlen = ptrlen - slen - 1;
	while ((remlen > 0) && (isspace(*rem))) {
		remlen--;
		rem++;
	}

	memcpy(val, rem, remlen);	/* store value, trim trailing ws */
	val[remlen] = 0;
	while ((*val) && (isspace(val[strlen(val) - 1]))) {
		val[strlen(val) - 1] = 0;
	}
	if (!*val)			/* skip blank value */
		goto out;

	if (!strcasecmp("X-Long-Polling", key)) {
		hi->lp_path = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Reject-Reason", key)) {
		hi->reason = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Stratum", key)) {
		hi->stratum_url = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("Content-Length", key))
		hi->content_length = strtoul(val, NULL, 10);

out:
	free(key);
	free(val);
	return ptrlen;
}

void memrev(unsigned char *p, size_t len)
{
	unsigned char c, *q;
	for (q = p + len - 1; p < q; p++, q--) {
		c = *p;
		*p = *q;
		*q = c;
	}
}

void bin2hex(char *s, const unsigned char *p, size_t len)
{
	int i;
	for (i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);
}

char *abin2hex(const unsigned char *p, size_t len)
{
	char *s = malloc((len * 2) + 1);
	if (!s)
		return NULL;
	bin2hex(s, p, len);
	return s;
}

bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	if(hexstr == NULL)
		return false;

	size_t hexstr_len = strlen(hexstr);
	if((hexstr_len % 2) != 0) {
		applog(LOG_ERR, "hex2bin str truncated");
		return false;
	}

	size_t bin_len = hexstr_len / 2;
	if (bin_len > len) {
		applog(LOG_ERR, "hex2bin buffer too small");
		return false;
	}

	memset(p, 0, len);

	size_t i = 0;
	while (i < hexstr_len) {
		char c = hexstr[i];
		unsigned char nibble;
		if(c >= '0' && c <= '9') {
			nibble = (c - '0');
		} else if (c >= 'A' && c <= 'F') {
			nibble = (10 + (c - 'A'));
		} else if (c >= 'a' && c <= 'f') {
			nibble = (10 + (c - 'a'));
		} else {
			applog(LOG_ERR, "hex2bin invalid hex");
			return false;
		}
		p[(i / 2)] |= (nibble << ((1 - (i % 2)) * 4));
		i++;
	}

	return true;
}

int varint_encode(unsigned char *p, uint64_t n)
{
	int i;
	if (n < 0xfd) {
		p[0] = n;
		return 1;
	}
	if (n <= 0xffff) {
		p[0] = 0xfd;
		p[1] = n & 0xff;
		p[2] = n >> 8;
		return 3;
	}
	if (n <= 0xffffffff) {
		p[0] = 0xfe;
		for (i = 1; i < 5; i++) {
			p[i] = n & 0xff;
			n >>= 8;
		}
		return 5;
	}
	p[0] = 0xff;
	for (i = 1; i < 9; i++) {
		p[i] = n & 0xff;
		n >>= 8;
	}
	return 9;
}

static const char b58digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool b58dec(unsigned char *bin, size_t binsz, const char *b58)
{
	size_t i, j;
	uint64_t t;
	uint32_t c;
	uint32_t *outi;
	size_t outisz = (binsz + 3) / 4;
	int rem = binsz % 4;
	uint32_t remmask = 0xffffffff << (8 * rem);
	size_t b58sz = strlen(b58);
	bool rc = false;

	outi = calloc(outisz, sizeof(*outi));

	for (i = 0; i < b58sz; ++i) {
		for (c = 0; b58digits[c] != b58[i]; c++)
			if (!b58digits[c])
				goto out;
		for (j = outisz; j--; ) {
			t = (uint64_t)outi[j] * 58 + c;
			c = t >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c || outi[0] & remmask)
			goto out;
	}

	j = 0;
	switch (rem) {
		case 3:
			*(bin++) = (outi[0] >> 16) & 0xff;
		case 2:
			*(bin++) = (outi[0] >> 8) & 0xff;
		case 1:
			*(bin++) = outi[0] & 0xff;
			++j;
		default:
			break;
	}
	for (; j < outisz; ++j) {
		be32enc((uint32_t *)bin, outi[j]);
		bin += sizeof(uint32_t);
	}

	rc = true;
out:
	free(outi);
	return rc;
}

static int b58check(unsigned char *bin, size_t binsz, const char *b58)
{
	unsigned char buf[32];
	int i;

	sha256d(buf, bin, binsz - 4);
	if (memcmp(&bin[binsz - 4], buf, 4))
		return -1;

	/* Check number of zeros is correct AFTER verifying checksum
	 * (to avoid possibility of accessing the string beyond the end) */
	for (i = 0; bin[i] == '\0' && b58[i] == '1'; ++i);
	if (bin[i] == '\0' || b58[i] == '1')
		return -3;

	return bin[0];
}

static uint32_t bech32_polymod_step(uint32_t pre) {
	uint8_t b = pre >> 25;
	return ((pre & 0x1FFFFFF) << 5) ^
		(-((b >> 0) & 1) & 0x3b6a57b2UL) ^
		(-((b >> 1) & 1) & 0x26508e6dUL) ^
		(-((b >> 2) & 1) & 0x1ea119faUL) ^
		(-((b >> 3) & 1) & 0x3d4233ddUL) ^
		(-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const int8_t bech32_charset_rev[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
	 1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
	 1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

static bool bech32_decode(char *hrp, uint8_t *data, size_t *data_len, const char *input) {
	uint32_t chk = 1;
	size_t i;
	size_t input_len = strlen(input);
	size_t hrp_len;
	int have_lower = 0, have_upper = 0;
	if (input_len < 8 || input_len > 90) {
		return false;
	}
	*data_len = 0;
	while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
		++(*data_len);
	}
	hrp_len = input_len - (1 + *data_len);
	if (1 + *data_len >= input_len || *data_len < 6) {
		return false;
	}
	*(data_len) -= 6;
	for (i = 0; i < hrp_len; ++i) {
		int ch = input[i];
		if (ch < 33 || ch > 126) {
			return false;
		}
		if (ch >= 'a' && ch <= 'z') {
			have_lower = 1;
		} else if (ch >= 'A' && ch <= 'Z') {
			have_upper = 1;
			ch = (ch - 'A') + 'a';
		}
		hrp[i] = ch;
		chk = bech32_polymod_step(chk) ^ (ch >> 5);
	}
	hrp[i] = 0;
	chk = bech32_polymod_step(chk);
	for (i = 0; i < hrp_len; ++i) {
		chk = bech32_polymod_step(chk) ^ (input[i] & 0x1f);
	}
	++i;
	while (i < input_len) {
		int v = (input[i] & 0x80) ? -1 : bech32_charset_rev[(int)input[i]];
		if (input[i] >= 'a' && input[i] <= 'z') have_lower = 1;
		if (input[i] >= 'A' && input[i] <= 'Z') have_upper = 1;
		if (v == -1) {
			return false;
		}
		chk = bech32_polymod_step(chk) ^ v;
		if (i + 6 < input_len) {
			data[i - (1 + hrp_len)] = v;
		}
		++i;
	}
	if (have_lower && have_upper) {
		return false;
	}
	return chk == 1;
}

static bool convert_bits(uint8_t *out, size_t *outlen, int outbits, const uint8_t *in, size_t inlen, int inbits, int pad) {
	uint32_t val = 0;
	int bits = 0;
	uint32_t maxv = (((uint32_t)1) << outbits) - 1;
	while (inlen--) {
		val = (val << inbits) | *(in++);
		bits += inbits;
		while (bits >= outbits) {
			bits -= outbits;
			out[(*outlen)++] = (val >> bits) & maxv;
		}
	}
	if (pad) {
		if (bits) {
			out[(*outlen)++] = (val << (outbits - bits)) & maxv;
		}
	} else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
		return false;
	}
	return true;
}

static bool segwit_addr_decode(int *witver, uint8_t *witdata, size_t *witdata_len, const char *addr) {
	uint8_t data[84];
	char hrp_actual[84];
	size_t data_len;
	if (!bech32_decode(hrp_actual, data, &data_len, addr)) return false;
	if (data_len == 0 || data_len > 65) return false;
	if (data[0] > 16) return false;
	*witdata_len = 0;
	if (!convert_bits(witdata, witdata_len, 8, data + 1, data_len - 1, 5, 0)) return false;
	if (*witdata_len < 2 || *witdata_len > 40) return false;
	if (data[0] == 0 && *witdata_len != 20 && *witdata_len != 32) return false;
	*witver = data[0];
	return true;
}

static size_t bech32_to_script(uint8_t *out, size_t outsz, const char *addr) {
	uint8_t witprog[40];
	size_t witprog_len;
	int witver;

	if (!segwit_addr_decode(&witver, witprog, &witprog_len, addr))
		return 0;
	if (outsz < witprog_len + 2)
		return 0;
	out[0] = witver ? (0x50 + witver) : 0;
	out[1] = witprog_len;
	memcpy(out + 2, witprog, witprog_len);
	return witprog_len + 2;
}

size_t address_to_script(unsigned char *out, size_t outsz, const char *addr)
{
	unsigned char addrbin[25];
	int addrver;
	size_t rv;

	if (!b58dec(addrbin, sizeof(addrbin), addr))
		return bech32_to_script(out, outsz, addr);
	addrver = b58check(addrbin, sizeof(addrbin), addr);
	if (addrver < 0)
		return 0;
	switch (addrver) {
		case 5:    /* Bitcoin script hash */
		case 196:  /* Testnet script hash */
			if (outsz < (rv = 23))
				return rv;
			out[ 0] = 0xa9;  /* OP_HASH160 */
			out[ 1] = 0x14;  /* push 20 bytes */
			memcpy(&out[2], &addrbin[1], 20);
			out[22] = 0x87;  /* OP_EQUAL */
			return rv;
		default:
			if (outsz < (rv = 25))
				return rv;
			out[ 0] = 0x76;  /* OP_DUP */
			out[ 1] = 0xa9;  /* OP_HASH160 */
			out[ 2] = 0x14;  /* push 20 bytes */
			memcpy(&out[3], &addrbin[1], 20);
			out[23] = 0x88;  /* OP_EQUALVERIFY */
			out[24] = 0xac;  /* OP_CHECKSIG */
			return rv;
	}
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract(struct timeval *result, struct timeval *x,
	struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating Y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * `tv_usec' is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

bool fulltest(const uint32_t *hash, const uint32_t *target)
{
	int i;
	bool rc = true;
	
	for (i = 7; i >= 0; i--) {
		if (hash[i] > target[i]) {
			rc = false;
			break;
		}
		if (hash[i] < target[i]) {
			rc = true;
			break;
		}
	}

	return rc;
}

void diff_to_target(uint32_t *target, double diff)
{
	uint64_t m;
	int k;
	
	for (k = 6; k > 0 && diff > 1.0; k--)
		diff /= 4294967296.0;
	m = 4294901760.0 / diff;
	if (m == 0 && k == 6)
		memset(target, 0xff, 32);
	else {
		memset(target, 0, 32);
		target[k] = (uint32_t)m;
		target[k + 1] = (uint32_t)(m >> 32);
	}
}

#ifdef WIN32
#define socket_blocks() (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#define socket_blocks() (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

#define RBUFSIZE 2048
#define RECVSIZE (RBUFSIZE - 4)

struct thread_q *tq_new(void)
{
	struct thread_q *tq;

	tq = calloc(1, sizeof(*tq));
	if (!tq)
		return NULL;

	INIT_LIST_HEAD(&tq->q);
	pthread_mutex_init(&tq->mutex, NULL);
	pthread_cond_init(&tq->cond, NULL);

	return tq;
}
