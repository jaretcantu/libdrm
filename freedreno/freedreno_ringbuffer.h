/* -*- mode: C; c-file-style: "k&r"; tab-width 4; indent-tabs-mode: t; -*- */

/*
 * Copyright (C) 2012 Rob Clark <robclark@freedesktop.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *    Rob Clark <robclark@freedesktop.org>
 */

#ifndef FREEDRENO_RINGBUFFER_H_
#define FREEDRENO_RINGBUFFER_H_

#include <freedreno_drmif.h>

/* the ringbuffer object is not opaque so that OUT_RING() type stuff
 * can be inlined.  Note that users should not make assumptions about
 * the size of this struct.. more stuff will be added when we eventually
 * have a kernel driver that can deal w/ reloc's..
 */

struct fd_rb_bo;

struct fd_ringbuffer {
	int size;
	uint32_t *cur, *end, *start, *last_start;
	struct fd_pipe *pipe;
	struct fd_rb_bo *bo;
	uint32_t last_timestamp;
};

/* ringbuffer flush flags:
 *   SAVE_GMEM - GMEM contents not preserved to system memory
 *       in cmds flushed so if there is a context switch after
 *       this flush and before the next one the kernel must
 *       save GMEM contents
 *   SUBMIT_IB_LIST - tbd..
 */
#define DRM_FREEDRENO_CONTEXT_SAVE_GMEM       1
#define DRM_FREEDRENO_CONTEXT_SUBMIT_IB_LIST  4


struct fd_ringbuffer * fd_ringbuffer_new(struct fd_pipe *pipe,
		uint32_t size);
void fd_ringbuffer_del(struct fd_ringbuffer *ring);
void fd_ringbuffer_reset(struct fd_ringbuffer *ring);
int fd_ringbuffer_flush(struct fd_ringbuffer *ring);
uint32_t fd_ringbuffer_timestamp(struct fd_ringbuffer *ring);
int fd_ringbuffer_begin(struct fd_ringbuffer *ring, int ndwords);

static inline void fd_ringbuffer_emit(struct fd_ringbuffer *ring,
		uint32_t data)
{
	(*ring->cur++) = data;
}

void fd_ringbuffer_emit_reloc(struct fd_ringbuffer *ring,
		struct fd_bo *bo, uint32_t offset);

#endif /* FREEDRENO_RINGBUFFER_H_ */