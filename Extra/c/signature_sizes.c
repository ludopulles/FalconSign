/*
 * Signature size determination for Falcon implementation.
 *
 * @author   Ludo Pulles <ludo.pulles@cwi.nl>
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2017-2019  Falcon Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@nccgroup.com>
 */

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * This code uses only the external API.
 */

#include "falcon.h"

static void *
xmalloc(size_t len)
{
	void *buf;

	if (len == 0) {
		return NULL;
	}
	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "memory allocation error\n");
		exit(EXIT_FAILURE);
	}
	return buf;
}

static void
xfree(void *buf)
{
	if (buf != NULL) {
		free(buf);
	}
}

typedef struct {
	unsigned logn;
	shake256_context rng;
	uint8_t *tmp;
	size_t tmp_len;
	uint8_t *pk;
	uint8_t *sk;
	uint8_t *sig;
	size_t sig_len;
} bench_context;

static void
test_sig_size_falcon(unsigned logn, int num_keys, int num_sigs_per_key)
{
	bench_context bc;
	char message[5] = "data";

	bc.logn = logn;
	if (shake256_init_prng_from_system(&bc.rng) != 0) {
		fprintf(stderr, "random seeding failed\n");
		exit(EXIT_FAILURE);
	}

	bc.sig_len = FALCON_SIG_COMPRESSED_MAXSIZE(logn);
	bc.tmp_len = FALCON_TMPSIZE_KEYGEN(logn);
	if (FALCON_TMPSIZE_SIGNDYN(logn) > bc.tmp_len)
		bc.tmp_len = FALCON_TMPSIZE_SIGNDYN(logn);

	bc.pk = xmalloc(FALCON_PUBKEY_SIZE(logn));
	bc.sk = xmalloc(FALCON_PRIVKEY_SIZE(logn));
	bc.tmp = xmalloc(bc.tmp_len);
	bc.sig = xmalloc(bc.sig_len);

	long long sum_sz = 0, sumsq_sz = 0;

	printf("%4u: ", 1u << logn);
	fflush(stdout);

	for (int i = 0; i < num_keys; i++) {
		falcon_keygen_make(&bc.rng, logn, bc.sk, FALCON_PRIVKEY_SIZE(logn), bc.pk, FALCON_PUBKEY_SIZE(logn), bc.tmp, bc.tmp_len);
		for (int j = 0; j < num_sigs_per_key; j++) {
			bc.sig_len = FALCON_SIG_COMPRESSED_MAXSIZE(logn);

			message[0] = j & 0xFF;
			message[1] = (j >> 8) & 0xFF;

			assert(falcon_sign_dyn(&bc.rng, bc.sig, &bc.sig_len, FALCON_SIG_COMPRESSED, bc.sk, FALCON_PRIVKEY_SIZE(bc.logn), message, 4, bc.tmp, bc.tmp_len) == 0);
			sum_sz += bc.sig_len;
			sumsq_sz += (long long)bc.sig_len * bc.sig_len;
		}
	}

	double avg = (double)sum_sz / (double)(num_keys * num_sigs_per_key);
	double var = (double)sumsq_sz / (double)(num_keys * num_sigs_per_key) - avg*avg;
	printf("%7.2f +/- %5.2f\n", avg, sqrt(var));

	xfree(bc.tmp);
	xfree(bc.pk);
	xfree(bc.sk);
	xfree(bc.sig);
}

int main()
{
	int num_keys = 100, num_sigs_per_key = 100;
	printf("degree   avg (+/- std)\n");
	for (unsigned logn = 1; logn <= 10; logn++) {
		test_sig_size_falcon(logn, num_keys, num_sigs_per_key);
	}
	return 0;
}
