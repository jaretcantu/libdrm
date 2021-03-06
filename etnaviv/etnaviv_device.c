/*
 * Copyright (C) 2014 Etnaviv Project
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
 *    Christian Gmeiner <christian.gmeiner@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include <xf86drm.h>
#include <xf86atomic.h>

#include "etnaviv_priv.h"
#include "etnaviv_drmif.h"

static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;

static void add_bucket(struct etna_device *dev, int size)
{
	unsigned i = dev->num_buckets;

	assert(i < ARRAY_SIZE(dev->cache_bucket));

	list_inithead(&dev->cache_bucket[i].list);
	dev->cache_bucket[i].size = size;
	dev->num_buckets++;
}

static void init_cache_buckets(struct etna_device *dev)
{
	unsigned long size, cache_max_size = 64 * 1024 * 1024;

	/* OK, so power of two buckets was too wasteful of memory.
	 * Give 3 other sizes between each power of two, to hopefully
	 * cover things accurately enough.  (The alternative is
	 * probably to just go for exact matching of sizes, and assume
	 * that for things like composited window resize the tiled
	 * width/height alignment and rounding of sizes to pages will
	 * get us useful cache hit rates anyway)
	 */
	add_bucket(dev, 4096);
	add_bucket(dev, 4096 * 2);
	add_bucket(dev, 4096 * 3);

	/* Initialize the linked lists for BO reuse cache. */
	for (size = 4 * 4096; size <= cache_max_size; size *= 2) {
		add_bucket(dev, size);
		add_bucket(dev, size + size * 1 / 4);
		add_bucket(dev, size + size * 2 / 4);
		add_bucket(dev, size + size * 3 / 4);
	}
}

struct etna_device * etna_device_new(int fd)
{
	struct etna_device *dev = calloc(sizeof(*dev), 1);

	if (!dev)
		return NULL;

	atomic_set(&dev->refcnt, 1);
	dev->fd = fd;
	dev->handle_table = drmHashCreate();
	dev->name_table = drmHashCreate();
	init_cache_buckets(dev);

	return dev;
}

struct etna_device * etna_device_ref(struct etna_device *dev)
{
	atomic_inc(&dev->refcnt);
	return dev;
}

static void etna_device_del_impl(struct etna_device *dev)
{
	etna_cleanup_bo_cache(dev, 0);
	drmHashDestroy(dev->handle_table);
	drmHashDestroy(dev->name_table);

	free(dev);
}

drm_private void etna_device_del_locked(struct etna_device *dev)
{
	if (!atomic_dec_and_test(&dev->refcnt))
		return;

	etna_device_del_impl(dev);
}

void etna_device_del(struct etna_device *dev)
{
	if (!atomic_dec_and_test(&dev->refcnt))
		return;

	pthread_mutex_lock(&table_lock);
	etna_device_del_impl(dev);
	pthread_mutex_unlock(&table_lock);
}
