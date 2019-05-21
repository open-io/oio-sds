/*
OpenIO SDS core library
Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <sys/uio.h>
#include <sys/eventfd.h>

#include <glib.h>
#include <liberasurecode/erasurecode.h>
#include <python2.7/Python.h>

#include "ecp.h"

#define MAXBLOCKS 24

const int algo_JERASURE_RS_VAND = EC_BACKEND_JERASURE_RS_VAND;
const int algo_JERASURE_RS_CAUCHY = EC_BACKEND_JERASURE_RS_CAUCHY;
const int algo_ISA_L_RS_VAND = EC_BACKEND_ISA_L_RS_VAND;
const int algo_ISA_L_RS_CAUCHY = EC_BACKEND_ISA_L_RS_CAUCHY;
const int algo_SHSS = EC_BACKEND_SHSS;
const int algo_LIBERASURECODE_RS_VAND = EC_BACKEND_LIBERASURECODE_RS_VAND;
const int algo_LIBPHAZR = EC_BACKEND_LIBPHAZR;

struct ec_handle_s {
	ec_backend_id_t backend;
	int k;
	int m;
	int instance;
};

struct ecp_ctx_s {
	/* Cache of open liberasurecode handles */
	GArray *array_ec_handles;
	GMutex lock_ec_handles;
};

enum ecp_action_e {
	THP_NOTSET = 0,
	THP_ENCODE = 1,
	THP_DECODE = 2
};

struct ecp_job_s {
	struct iovec original;
	struct iovec encoded[24];

	int algo;
	int k;
	int m;
	int status;

	int fd_wakeup;

	guint64 fragment_size;
	enum ecp_action_e action;
};

static struct ecp_ctx_s ecp_ctx = {};

static GThreadPool *thp = NULL;

static void __attribute__((constructor)) ecp_init(void);

static void __attribute__((destructor)) ecp_fini(void);

static void _action_common(struct ecp_job_s *job, struct ecp_ctx_s *ctx);


static void ecp_init(void) {
	thp = g_thread_pool_new((GFunc)_action_common, &ecp_ctx, 1, TRUE, NULL);
	g_assert_nonnull(thp);

	g_mutex_init(&ecp_ctx.lock_ec_handles);
	ecp_ctx.array_ec_handles =
		g_array_sized_new(FALSE, FALSE, sizeof(struct ec_handle_s), 16);
}

static void ecp_fini(void) {
	g_thread_pool_free(thp, FALSE, FALSE);
	thp = NULL;

	g_mutex_lock(&ecp_ctx.lock_ec_handles);
	g_mutex_unlock(&ecp_ctx.lock_ec_handles);
	g_mutex_clear(&ecp_ctx.lock_ec_handles);

	while (ecp_ctx.array_ec_handles->len > 0) {
		const guint last_idx = ecp_ctx.array_ec_handles->len - 1;
		struct ec_handle_s *last = &g_array_index(
				ecp_ctx.array_ec_handles, struct ec_handle_s, last_idx);
		int rc = liberasurecode_instance_destroy(last->instance);
		g_assert_cmpint(rc, ==, 0);
		g_array_remove_index_fast(ecp_ctx.array_ec_handles, last_idx);
	}
}

static void _job_ping(struct ecp_job_s *job) {
	int64_t evt = 1;
	(void) write(job->fd_wakeup, &evt, 8);
}

static int _get_instance(struct ecp_job_s *job, struct ecp_ctx_s *ctx) {
	g_mutex_lock(&ctx->lock_ec_handles);
	for (guint i=0; i<ctx->array_ec_handles->len ;i++) {
		struct ec_handle_s *h = &g_array_index(
				ctx->array_ec_handles, struct ec_handle_s, i);
		int b = (int) h->backend;
		if (b == job->algo && h->k == job->k && h->m == job->m) {
			g_mutex_unlock(&ctx->lock_ec_handles);
			return h->instance;
		}
	}

	struct ec_args ea = {
		.k = job->k, .m = job->m,
		.w = 8, .hd = job->m,
		.ct = CHKSUM_CRC32
	};
	int instance = liberasurecode_instance_create(job->algo, &ea);

	if (instance >= 0) {
		struct ec_handle_s h = {};
		h.backend = job->algo;
		h.k = ea.k;
		h.m = ea.m;
		h.instance = instance;
		g_array_append_vals(ctx->array_ec_handles, &h, 1);
	}

	g_mutex_unlock(&ctx->lock_ec_handles);
	return instance;
}

static void _action_encode(struct ecp_job_s *job, struct ecp_ctx_s *ctx) {
	char **data = NULL, **parity = NULL;
	int instance = _get_instance(job, ctx);

	int rc = liberasurecode_encode(instance,
			job->original.iov_base, job->original.iov_len,
			&data, &parity, &job->fragment_size);
	job->status = rc;

	if (rc == 0) {
		int i = 0;
		for (int j=0; j<job->k ;j++,i++) {
			job->encoded[i].iov_base = data[j];
			job->encoded[i].iov_len = job->fragment_size;
			data[j] = NULL;
		}
		for (int j=0; j<job->m ;j++,i++) {
			job->encoded[i].iov_base = parity[j];
			job->encoded[i].iov_len = job->fragment_size;
			parity[j] = NULL;
		}
		rc = liberasurecode_encode_cleanup(instance, data, parity);
		g_assert_cmpint(rc, ==, 0);
	}

	return _job_ping(job);
}

static void _action_decode(struct ecp_job_s *job, struct ecp_ctx_s *ctx) {
	int instance = _get_instance(job, ctx);
	(void) instance;
	job->status = -1;
	return _job_ping(job);
}

static void _action_common(struct ecp_job_s *job, struct ecp_ctx_s *ctx) {
	g_assert_nonnull(job);
	g_assert_nonnull(ctx);
	switch (job->action) {
		case THP_ENCODE:
			return _action_encode(job, ctx);
		case THP_DECODE:
			return _action_decode(job, ctx);
		default:
			job->status = G_MININT;
			return _job_ping(job);
	}
}

static gboolean _job_check(struct ecp_job_s *job) {
	switch (job->algo) {
		case EC_BACKEND_JERASURE_RS_VAND:
		case EC_BACKEND_JERASURE_RS_CAUCHY:
		case EC_BACKEND_FLAT_XOR_HD:
		case EC_BACKEND_ISA_L_RS_VAND:
		case EC_BACKEND_SHSS:
		case EC_BACKEND_LIBERASURECODE_RS_VAND:
		case EC_BACKEND_ISA_L_RS_CAUCHY:
		case EC_BACKEND_LIBPHAZR:
			break;
		default:
			return FALSE;
	}

	if (job->k <= 0 || job->m <= 0)
		return FALSE;
	if (job->k + job->m > MAXBLOCKS)
		return FALSE;
	if (job->m > 6)
		return FALSE;

	if (job->action == THP_ENCODE) {
		if (!job->original.iov_base || !job->original.iov_len)
			return FALSE;
	} else if (job->action == THP_DECODE) {
		/* No check yet on the number of blocs.
		 * Some algorithms accept to decode with less than K */
	} else {
		return FALSE;
	}

	return TRUE;
}

struct ecp_job_s * ecp_job_init(int algo, int k, int m) {
	struct ecp_job_s *h = g_malloc0(sizeof(*h));
	h->algo = algo;
	h->k = k;
	h->m = m;
	h->status = -1;
	h->fd_wakeup = eventfd(0, EFD_SEMAPHORE);
	return h;
}

int ecp_job_status(struct ecp_job_s *job) {
	g_assert_nonnull(job);
	return job->status;
}

int ecp_job_fd(struct ecp_job_s *job) {
	g_assert_nonnull(job);
	return job->fd_wakeup;
}

void ecp_job_close(struct ecp_job_s *job) {
	if (!job)
		return;

	if (job->fd_wakeup >= 0) {
		close(job->fd_wakeup);
		job->fd_wakeup = -1;
	}

	/* TODO(jfs): memory cleanup */

	g_free(job);
}

static void _submit(struct ecp_job_s *job, enum ecp_action_e action) {
	g_assert_nonnull(job);
	job->action = action;
	if (_job_check(job)) {
		g_thread_pool_push(thp, job, NULL);
	} else {
		job->status = EINVAL;
		return _job_ping(job);
	}
}

void ecp_job_encode(struct ecp_job_s *job) {
	return _submit(job, THP_ENCODE);
}

void ecp_job_decode(struct ecp_job_s *job) {
	return _submit(job, THP_DECODE);
}


void ecp_job_set_original(struct ecp_job_s *job, void *base, int len) {
	g_assert_nonnull(job);
	job->original.iov_base = base;
	job->original.iov_len = len;
}

PyObject* ecp_job_get_fragments(struct ecp_job_s *job) {
	g_assert_nonnull(job);
	g_assert_cmpint(job->action, ==, THP_ENCODE);
	const int max = job->k + job->m;
	PyObject *out = PyTuple_New(max);
	for (int i=0; i<max ;i++) {
		PyObject *buf = PyBuffer_FromMemory(
				job->encoded[i].iov_base, job->encoded[i].iov_len);
		PyTuple_SetItem(out, i, buf);
	}
	return out;
}
