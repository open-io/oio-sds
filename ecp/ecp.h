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

/**
 * Deferred EC computations.
 *
 * This API is for people who know what they are doing.
 */

#ifndef OIO_SDS__core__oioecp_h
# define OIO_SDS__core__oioecp_h 1

extern const int algo_JERASURE_RS_VAND;
extern const int algo_JERASURE_RS_CAUCHY;
extern const int algo_ISA_L_RS_VAND;
extern const int algo_ISA_L_RS_CAUCHY;
extern const int algo_SHSS;
extern const int algo_LIBERASURECODE_RS_VAND;
extern const int algo_LIBPHAZR;

struct ecp_job_s;

/* Allocate and prepare a job structure */
struct ecp_job_s * ecp_job_init(int algo, int k, int m);

void ecp_job_set_original(struct ecp_job_s *job, void *base, int len);

PyObject* ecp_job_get_fragments(struct ecp_job_s *job);

/* Return a file descriptor you just have to read on to wait for the
 * job's completion. */
int ecp_job_fd(struct ecp_job_s *job);

/* Return the status of the defered liberasurecode call */
int ecp_job_status(struct ecp_job_s *job);

/* Free the job structure and its internal resources.
 * The just must be terminated. */
void ecp_job_close(struct ecp_job_s *job);

/* Submit an encoding job */
void ecp_job_encode(struct ecp_job_s *job);

/* Submit a decoding job */
void ecp_job_decode(struct ecp_job_s *job);

#endif  /* OIO_SDS__core__oioecp_h */
