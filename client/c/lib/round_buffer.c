#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.client.buffer"
#endif

#include "./gs_internals.h"

#ifndef SLAB_SIZE
# define SLAB_SIZE (1<<19)
#endif

#define RB_DEBUG(rb) \
	TRACE("mark=(%i,%"G_GSIZE_FORMAT",%"G_GSIZE_FORMAT",%"G_GSIZE_FORMAT") read=(%i,%"G_GSIZE_FORMAT",%"G_GSIZE_FORMAT",%"G_GSIZE_FORMAT") write=(%i,%"G_GSIZE_FORMAT",%"G_GSIZE_FORMAT",%"G_GSIZE_FORMAT")",\
		rb->pos_mark.slab->number,  rb->pos_mark.offset,  rb->pos_mark.size, rb->pos_mark.slab->length,\
		pos_read->slab->number,  pos_read->offset,  pos_read->size, pos_read->slab->length,\
		rb->pos_write.slab->number, rb->pos_write.offset, rb->pos_write.size,rb->pos_write.slab->length)

/* the whole slab_s structure is aligned on SLAB_SIZE bytes */

struct slab_s
{
	int number;
	size_t length;
	struct slab_s *next;
	struct slab_s *prev;
	unsigned char buffer [SLAB_SIZE-sizeof(size_t)-(2*sizeof(struct slab_s*))];
};

struct mark_s
{
	struct slab_s *slab;
	size_t offset; /* where is the mark in the slab's buffer */
	size_t size;   /* where is the mark in the rb's buffer */
};

struct round_buffer_s
{
	GMutex *lock;
	GMutex *dbr_lock;
	GCond *cond;
	GCond *cond2;
	GHashTable *data_being_read;
	guint nb_copies;
	size_t size;
	struct mark_s  pos_mark;
	struct mark_s  pos_write;
	GHashTable *pos_read; // <GThread*, struct mark_s*>
	struct slab_s *slabs;
	rb_input_f     input;
	void          *user_data;
};


round_buffer_t* rb_create_with_callback (const size_t full_size,
	rb_input_f feeder, void *user_data)
{
	int numbers=0;
	size_t allocated_size = 0;
	
	g_assert(full_size < G_MAXUINT);

	round_buffer_t *rb = NULL;
	rb = calloc (1, sizeof(round_buffer_t));
	if (!rb)
		return NULL;

	rb->lock = g_mutex_new();
	rb->dbr_lock = g_mutex_new();
	rb->cond = g_cond_new();
	rb->cond2 = g_cond_new();
	rb->data_being_read = g_hash_table_new_full(g_direct_hash, g_int_equal, NULL, g_free);
	rb->nb_copies = 0;
	
	while (allocated_size < full_size + 1)
	{
		struct slab_s *newSlab = NULL;
		newSlab = malloc(sizeof(struct slab_s));
		newSlab->number = numbers++;
		newSlab->length = 0;
		if (rb->slabs)
		{
			newSlab->next = rb->slabs->next;
			newSlab->prev = rb->slabs;
		}
		else
		{
			newSlab->next = newSlab;
			newSlab->prev = newSlab;
		}
		newSlab->next->prev = newSlab;
		newSlab->prev->next = newSlab;
		rb->slabs = newSlab;
		allocated_size += sizeof(newSlab->buffer);
	}

	rb->pos_mark.slab = rb->slabs;
	rb->pos_write.slab = rb->slabs;

	rb->pos_read = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

	rb->size = allocated_size;
	rb->input = feeder;
	rb->user_data = user_data;

	MYASSERT(rb->slabs);

	return rb;
}


void rb_destroy (round_buffer_t *rb)
{
	struct slab_s *s;
	g_mutex_lock(rb->lock);
	if (!rb) {
		g_mutex_unlock(rb->lock);
		return;
	}
	if (rb->pos_read)
		g_hash_table_destroy(rb->pos_read);
	MYASSERT(rb->slabs);
	s = rb->slabs->next;
	rb->slabs->next = NULL;
	while (s)
	{
		struct slab_s *next = s->next;
		free(s);
		s = next;
	}
	g_mutex_free(rb->dbr_lock);
	g_cond_free(rb->cond);
	g_cond_free(rb->cond2);
	g_hash_table_destroy(rb->data_being_read);
	g_mutex_unlock(rb->lock);
	g_mutex_free(rb->lock);
	memset(rb,0x00,sizeof(*rb));
	free(rb);
}


size_t rb_get_whole_size (round_buffer_t *rb)
{
	size_t ret;
	g_mutex_lock(rb->lock);
	MYASSERT(rb);
	ret = rb ? rb->size : 0;
	g_mutex_unlock(rb->lock);
	return ret;
}


size_t rb_get_remaining_size (round_buffer_t *rb)
{
	size_t ret;
	g_mutex_lock(rb->lock);
	MYASSERT(rb);
	MYASSERT(rb->size > rb->pos_write.size);
	ret = rb ? rb->size - rb->pos_write.size : 0;
	g_mutex_unlock(rb->lock);
	return ret;
}


size_t rb_get_available_size (round_buffer_t *rb)
{
	size_t ret;
	g_mutex_lock(rb->lock);
	MYASSERT(rb);
	struct mark_s *pos_read = g_hash_table_lookup(rb->pos_read, g_thread_self());
	// pos_read may be NULL if rb_input_from was never called
	if (pos_read) {
		MYASSERT(rb->pos_write.size > pos_read->size);
		ret = rb ? rb->pos_write.size - pos_read->size : 0 ;
	} else {
		TRACE("No pos_read found for thread %p.", g_thread_self());
		ret = 0;
	}
	g_mutex_unlock(rb->lock);
	return ret;
}


void rb_set_mark (round_buffer_t *rb)
{
	struct slab_s *s;
	
	g_mutex_lock(rb->lock);
	MYASSERT(rb);

	struct mark_s *pos_read = g_hash_table_lookup(rb->pos_read, g_thread_self());
	// pos_read may be NULL if rb_input_from was never called
	if (pos_read) {
		MYASSERT (rb->pos_write.size >= pos_read->size);

		/*clean the slabs between the mark(old) and the read(new) positions*/
		for (s=rb->pos_mark.slab ; s!=pos_read->slab ; s=s->next) {
			s->length=0;
		}

		rb->pos_write.size -= pos_read->size;
		pos_read->size = 0;

		memcpy(&(rb->pos_mark), pos_read, sizeof(struct mark_s));
		RB_DEBUG(rb);
	} else {
		TRACE("No pos_read found for thread %p.", g_thread_self());
	}
	g_mutex_unlock(rb->lock);
}


void rb_return_to_mark (round_buffer_t *rb)
{
	if (!rb)
		return;
	g_mutex_lock(rb->lock);
	struct mark_s *pos_read = g_hash_table_lookup(rb->pos_read, g_thread_self());
	// pos_read may be NULL if rb_input_from was never called
	if (pos_read) {
		memcpy (pos_read, &(rb->pos_mark), sizeof (struct mark_s));
		RB_DEBUG(rb);
	} else {
		TRACE("No pos_read found for thread %p.", g_thread_self());
	}
	g_mutex_unlock(rb->lock);
}

void rb_handle_read_error(gpointer _rb)
{
	round_buffer_t *rb = _rb;
	g_cond_broadcast(rb->cond);
	g_cond_broadcast(rb->cond2);
	g_mutex_unlock(rb->lock);
}

ssize_t rb_input_from (round_buffer_t *rb, char *pB, size_t s)
{
	// Locks accesses to data_being_read
	GMutex *lock = NULL;
	// GCond used when waiting for data to be read
	GCond *cond = NULL;
	// GCond used when waiting for all reads to get done
	GCond *cond2 = NULL;
	// <write address, read count>
	// Counts the number of copies done for a given write address
	GHashTable *data_being_read = NULL;

	guint *p_value;
	size_t l, rsize, wsize;
	struct mark_s *r, *w, *m;
	
	if (s == 0)
		return 0;

	MYASSERT (pB);

	g_mutex_lock(rb->lock);
	lock = rb->dbr_lock;
	cond = rb->cond;
	cond2 = rb->cond2;
	data_being_read = rb->data_being_read;

	MYASSERT (rb);
	
	struct mark_s *pos_read = g_hash_table_lookup(rb->pos_read, g_thread_self());
	if (NULL == pos_read) {
		pos_read = calloc(1, sizeof(struct mark_s));
		pos_read->slab = rb->slabs;
		g_hash_table_insert(rb->pos_read, g_thread_self(), pos_read);
		rb->nb_copies++;
	}
	MYASSERT(pos_read);

	r = pos_read;
	w = &(rb->pos_write);
	m = &(rb->pos_mark);

	rsize = r->size;
	wsize = w->size;

	p_value = g_hash_table_lookup(data_being_read, w);

	g_mutex_unlock(rb->lock);
	
	g_mutex_lock(lock);

	/*did we read all the data?*/
	if (rsize >= wsize)
	{
		if (p_value && *p_value == 0) {
			TRACE("rb_input_from: thread %p waiting for data to be read.", g_thread_self());
			while (*p_value == 0)
				g_cond_wait(cond, lock);
			TRACE("rb_input_from: thread %p woken up.", g_thread_self());
		} else {
			if (NULL == p_value) {
				p_value = (gpointer) calloc(1, sizeof(guint));
				g_hash_table_insert(data_being_read, w, p_value);
			} else {
				// Tests whether we need to wait for all threads to read current buffer
				if (*p_value > 1 && *p_value < rb->nb_copies) {
					TRACE("rb_input_from: thread %p waiting for all threads to read current buffer.", g_thread_self());
					while (*p_value < rb->nb_copies)
						g_cond_wait(cond2, lock);
				}
			}
			TRACE("rb_input_from: thread %p reading data.", g_thread_self());
			g_mutex_unlock(lock);
			ssize_t nbRead, maxRead;

			g_mutex_lock(rb->lock);
			/*skip to the next slab if necessary*/
			if (sizeof(w->slab->buffer) <= w->offset)
			{
				TRACE("write mark at end of slab, skipping to next : %i -> %i",
						w->slab->number, w->slab->next->number);

				w->slab = w->slab->next;
				w->offset = 0;

			}

			/*write at most until the mark offset*/
			if (w->slab == m->slab) {
				if (w->offset >= m->offset)
					maxRead = sizeof(w->slab->buffer) - w->offset;
				else
					maxRead = m->offset - w->offset;
			} else
				maxRead = sizeof(w->slab->buffer) - w->offset;

			/*fill the available space*/
			nbRead = rb->input (rb->user_data, (char*)w->slab->buffer + w->offset, maxRead);
			if (nbRead == 0)
			{
				TRACE("%"G_GSIZE_FORMAT" bytes wanted : %s", maxRead, "end of input");
				g_mutex_unlock(rb->lock);
				return 0;
			}
			if (nbRead < 0)
			{
				TRACE("%"G_GSIZE_FORMAT" bytes wanted : %s", maxRead, "input error");
				g_mutex_unlock(rb->lock);
				return -1;
			}

			w->size += nbRead;
			w->offset += nbRead;
			w->slab->length += nbRead;
			if (w->slab->length > sizeof(w->slab->buffer))
				w->slab->length = sizeof(w->slab->buffer);

			TRACE("%"G_GSIZE_FORMAT" wanted, %"G_GSIZE_FORMAT" filled", maxRead, nbRead);
			g_mutex_unlock(rb->lock);

			g_mutex_lock(lock);

			TRACE("rb_input_from: thread %p end reading data, broadcasting.", g_thread_self());
			g_cond_broadcast(cond);
		}
	}
	g_mutex_unlock(lock);

	g_mutex_lock(rb->lock);
	/*let's skip the slab if its end has been reached*/
	while (r->offset && r->offset >= r->slab->length)
	{
		TRACE("read mark at end of slab, skipping to next : %i -> %i",
			r->slab->number, r->slab->next->number);
		
		r->slab = r->slab->next;
		r->offset = 0;
	}

	/*compute the size that can be read*/
	if (r->slab==w->slab) {
		if (w->offset > r->offset) {
			l = w->offset - r->offset;
		} else {
			l = r->slab->length - r->offset;
		}
	} else {
		l = r->slab->length - r->offset;
	}
	/* l <- available size in the last slab */
	l = (l>s ? s : l);
	/* l <- available size in the buffer */

	memcpy (pB, r->slab->buffer + r->offset, l);

	r->size += l;
	r->offset += l;
	(*p_value)++;

	TRACE("read %"G_GSIZE_FORMAT" bytes from %p (offset %"G_GSIZE_FORMAT")", l, r->slab->buffer, r->offset);

	RB_DEBUG(rb);
	g_mutex_unlock(rb->lock);

	g_mutex_lock(lock);
	// If all threads have read this buffer, signal waiting thread so it can start writing again
	if (*p_value == rb->nb_copies) {
		TRACE("rb_input_from: thread %p all threads are done reading buffer, signaling.", g_thread_self());
		g_cond_signal(cond2);
	}
	g_mutex_unlock(lock);

	return l;
}


void rb_dump (round_buffer_t *rb)
{
	struct slab_s *s;
	if (!rb)
	{
		TRACE("invalid parameter");
		return;
	}
	g_mutex_lock(rb->lock);
	
	TRACE("Positions:");
	struct mark_s *pos_read = g_hash_table_lookup(rb->pos_read, g_thread_self());
	// pos_read may be NULL if rb_input_from was never called
	if (pos_read) {
		TRACE(" read:  n=%d o=%"G_GSIZE_FORMAT" s=%"G_GSIZE_FORMAT,  pos_read->slab->number, pos_read->offset, pos_read->size);
	} else {
		TRACE(" read:  unavailable");
	}
	TRACE(" write: n=%d o=%"G_GSIZE_FORMAT" s=%"G_GSIZE_FORMAT, rb->pos_write.slab->number, rb->pos_write.offset, rb->pos_write.size);
	TRACE(" mark:  n=%d o=%"G_GSIZE_FORMAT" s=%"G_GSIZE_FORMAT,  rb->pos_mark.slab->number, rb->pos_mark.offset, rb->pos_mark.size);
	TRACE("Slabs:");
	s = rb->slabs;
	do {
		TRACE(" n=%d b=%p l=%"G_GSIZE_FORMAT, s->number, s->buffer, s->length);
		s = s->next;
	} while (s!=rb->slabs);
	g_mutex_unlock(rb->lock);
}


