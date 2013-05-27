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

#ifndef __ROUND_BUFFER_H__
# define __ROUND_BUFFER_H__

# include <stdint.h>
# include <sys/types.h>

typedef struct round_buffer_s round_buffer_t;

typedef ssize_t (*rb_input_f) (void *uData, char *b, size_t s);

/* create a new round_buffer with full_size preallocated and
 * a mark set, with the read and write pointer set on the mark */
round_buffer_t* rb_create_with_callback (size_t full_size,
	rb_input_f feeder, void *user_data);

/*  */
void rb_destroy (round_buffer_t *rb);

/* get the whole amount of data between the mark and the write
 * pointer */
size_t rb_get_whole_size (round_buffer_t *rb);

/*  */
size_t rb_get_remaining_size (round_buffer_t *rb);

/*  */
size_t rb_get_available_size (round_buffer_t *rb);

/* set the mark on the read pointer */
void rb_set_mark (round_buffer_t *rb);

/* set the read pointer on the mark */
void rb_return_to_mark (round_buffer_t *rb);

/*dump all the round_buffers, DO NOT USE!*/
void rb_dump (round_buffer_t *rb);

/* ------------------------------------------------------------------------- */

ssize_t rb_input_from (round_buffer_t *rb, char *pB, size_t s);
void rb_handle_read_error(gpointer _rb);

#endif /*__ROUND_BUFFER_H__*/
