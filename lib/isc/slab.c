/* ref: https://github.com/bbu/userland-slab-allocator */

#include "slab.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <math.h>
#include <assert.h>

#define SLOTS_ALL_ZERO ((uint64_t) 0)
#define SLOTS_FIRST ((uint64_t) 1)
#define FIRST_FREE_SLOT(s) ((size_t) __builtin_ctzll(s))
#define FREE_SLOTS(s) ((size_t) __builtin_popcountll(s))
#define ONE_USED_SLOT(slots, empty_slotmask) \
    ( \
        ( \
            (~(slots) & (empty_slotmask))       & \
            ((~(slots) & (empty_slotmask)) - 1)   \
        ) == SLOTS_ALL_ZERO \
    )

#define POWEROF2(x) ((x) != 0 && ((x) & ((x) - 1)) == 0)

#define LIKELY(exp) __builtin_expect(exp, 1)
#define UNLIKELY(exp) __builtin_expect(exp, 0)

size_t slab_pagesize;

#ifndef NDEBUG
static int slab_is_valid(const struct slab_chain *const sch)
{
    assert(POWEROF2(slab_pagesize));
    assert(POWEROF2(sch->slabsize));
    assert(POWEROF2(sch->pages_per_alloc));

    assert(sch->itemcount >= 2 && sch->itemcount <= 64);
    assert(sch->itemsize >= 1 && sch->itemsize <= SIZE_MAX);
    assert(sch->pages_per_alloc >= slab_pagesize);
    assert(sch->pages_per_alloc >= sch->slabsize);

    assert(offsetof(struct slab_header, data) +
        sch->itemsize * sch->itemcount <= sch->slabsize);

    assert(sch->empty_slotmask == ~SLOTS_ALL_ZERO >> (64 - sch->itemcount));
    assert(sch->initial_slotmask == (sch->empty_slotmask ^ SLOTS_FIRST));
    assert(sch->alignment_mask == ~(sch->slabsize - 1));

    const struct slab_header *const heads[] =
        {sch->full, sch->empty, sch->partial};

    for (size_t head = 0; head < 3; ++head) {
        const struct slab_header *prev = NULL, *slab;

        for (slab = heads[head]; slab != NULL; slab = slab->next) {
            if (prev == NULL)
                assert(slab->prev == NULL);
            else
                assert(slab->prev == prev);

            switch (head) {
            case 0:
                assert(slab->slots == SLOTS_ALL_ZERO);
                break;

            case 1:
                assert(slab->slots == sch->empty_slotmask);
                break;

            case 2:
                assert((slab->slots & ~sch->empty_slotmask) == SLOTS_ALL_ZERO);
                assert(FREE_SLOTS(slab->slots) >= 1);
                assert(FREE_SLOTS(slab->slots) < sch->itemcount);
                break;
            }

            if (slab->refcount == 0) {
                assert((uintptr_t) slab % sch->slabsize == 0);

                if (sch->slabsize >= slab_pagesize)
                    assert((uintptr_t) slab->page % sch->slabsize == 0);
                else
                    assert((uintptr_t) slab->page % slab_pagesize == 0);
            } else {
                if (sch->slabsize >= slab_pagesize)
                    assert((uintptr_t) slab % sch->slabsize == 0);
                else
                    assert((uintptr_t) slab % slab_pagesize == 0);
            }

            prev = slab;
        }
    }

    return 1;
}
#endif

void slab_init(struct slab_chain *const sch, const size_t itemsize)
{
    assert(sch != NULL);
    assert(itemsize >= 1 && itemsize <= SIZE_MAX);
    assert(POWEROF2(slab_pagesize));

    sch->itemsize = itemsize;

    const size_t data_offset = offsetof(struct slab_header, data);
    const size_t least_slabsize = data_offset + 64 * sch->itemsize;
    sch->slabsize = (size_t) 1 << (size_t) ceil(log2(least_slabsize));
    sch->itemcount = 64;

    if (sch->slabsize - least_slabsize != 0) {
        const size_t shrinked_slabsize = sch->slabsize >> 1;

        if (data_offset < shrinked_slabsize &&
            shrinked_slabsize - data_offset >= 2 * sch->itemsize) {

            sch->slabsize = shrinked_slabsize;
            sch->itemcount = (shrinked_slabsize - data_offset) / sch->itemsize;
        }
    }

    sch->pages_per_alloc = sch->slabsize > slab_pagesize ?
        sch->slabsize : slab_pagesize;

    sch->empty_slotmask = ~SLOTS_ALL_ZERO >> (64 - sch->itemcount);
    sch->initial_slotmask = sch->empty_slotmask ^ SLOTS_FIRST;
    sch->alignment_mask = ~(sch->slabsize - 1);
    sch->partial = sch->empty = sch->full = NULL;

    assert(slab_is_valid(sch));
}

void *slab_alloc(struct slab_chain *const sch)
{
    assert(sch != NULL);
    assert(slab_is_valid(sch));

    if (LIKELY(sch->partial != NULL)) {
        /* found a partial slab, locate the first free slot */
        register const size_t slot = FIRST_FREE_SLOT(sch->partial->slots);
        sch->partial->slots ^= SLOTS_FIRST << slot;

        if (UNLIKELY(sch->partial->slots == SLOTS_ALL_ZERO)) {
            /* slab has become full, change state from partial to full */
            struct slab_header *const tmp = sch->partial;

            /* skip first slab from partial list */
            if (LIKELY((sch->partial = sch->partial->next) != NULL))
                sch->partial->prev = NULL;

            if (LIKELY((tmp->next = sch->full) != NULL))
                sch->full->prev = tmp;

            sch->full = tmp;
            return sch->full->data + slot * sch->itemsize;
        } else {
            return sch->partial->data + slot * sch->itemsize;
        }
    } else if (LIKELY((sch->partial = sch->empty) != NULL)) {
        /* found an empty slab, change state from empty to partial */
        if (LIKELY((sch->empty = sch->empty->next) != NULL))
            sch->empty->prev = NULL;

        sch->partial->next = NULL;

        /* slab is located either at the beginning of page, or beyond */
        UNLIKELY(sch->partial->refcount != 0) ?
            sch->partial->refcount++ : sch->partial->page->refcount++;

        sch->partial->slots = sch->initial_slotmask;
        return sch->partial->data;
    } else {
        /* no empty or partial slabs available, create a new one */
        if (sch->slabsize <= slab_pagesize) {
            sch->partial = mmap(NULL, sch->pages_per_alloc,
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if (UNLIKELY(sch->partial == MAP_FAILED))
                return perror("mmap"), sch->partial = NULL;
        } else {
            const int err = posix_memalign((void **) &sch->partial,
                sch->slabsize, sch->pages_per_alloc);

            if (UNLIKELY(err != 0)) {
                fprintf(stderr, "posix_memalign(align=%zu, size=%zu): %d\n",
                    sch->slabsize, sch->pages_per_alloc, err);

                return sch->partial = NULL;
            }
        }

        struct slab_header *prev = NULL;

        const char *const page_end =
            (char *) sch->partial + sch->pages_per_alloc;

        union {
            const char *c;
            struct slab_header *const s;
        } curr = {
            .c = (const char *) sch->partial + sch->slabsize
        };

        __builtin_prefetch(sch->partial, 1);

        sch->partial->prev = sch->partial->next = NULL;
        sch->partial->refcount = 1;
        sch->partial->slots = sch->initial_slotmask;

        if (LIKELY(curr.c != page_end)) {
            curr.s->prev = NULL;
            curr.s->refcount = 0;
            curr.s->page = sch->partial;
            curr.s->slots = sch->empty_slotmask;
            sch->empty = prev = curr.s;

            while (LIKELY((curr.c += sch->slabsize) != page_end)) {
                prev->next = curr.s;
                curr.s->prev = prev;
                curr.s->refcount = 0;
                curr.s->page = sch->partial;
                curr.s->slots = sch->empty_slotmask;
                prev = curr.s;
            }

            prev->next = NULL;
        }

        return sch->partial->data;
    }

    /* unreachable */
}

void slab_free(struct slab_chain *const sch, const void *const addr)
{
    assert(sch != NULL);
    assert(slab_is_valid(sch));
    assert(addr != NULL);
    
    struct slab_header *const slab = (void *)
        ((uintptr_t) addr & sch->alignment_mask);

    register const int slot = ((const char *) addr - (char *) slab -
        offsetof(struct slab_header, data)) / sch->itemsize;

    if (UNLIKELY(slab->slots == SLOTS_ALL_ZERO)) {
        /* target slab is full, change state to partial */
        slab->slots = SLOTS_FIRST << slot;

        if (LIKELY(slab != sch->full)) {
            if (LIKELY((slab->prev->next = slab->next) != NULL))
                slab->next->prev = slab->prev;

            slab->prev = NULL;
        } else if (LIKELY((sch->full = sch->full->next) != NULL)) {
            sch->full->prev = NULL;
        }

        slab->next = sch->partial;

        if (LIKELY(sch->partial != NULL))
            sch->partial->prev = slab;

        sch->partial = slab;
    } else if (UNLIKELY(ONE_USED_SLOT(slab->slots, sch->empty_slotmask))) {
        /* target slab is partial and has only one filled slot */
        if (UNLIKELY(slab->refcount == 1 || (slab->refcount == 0 &&
            slab->page->refcount == 1))) {

            /* unmap the whole page if this slab is the only partial one */
            if (LIKELY(slab != sch->partial)) {
                if (LIKELY((slab->prev->next = slab->next) != NULL))
                    slab->next->prev = slab->prev;
            } else if (LIKELY((sch->partial = sch->partial->next) != NULL)) {
                sch->partial->prev = NULL;
            }

            void *const page = UNLIKELY(slab->refcount != 0) ? slab : slab->page;
            const char *const page_end = (char *) page + sch->pages_per_alloc;
            char found_head = 0;

            union {
                const char *c;
                const struct slab_header *const s;
            } s;

            for (s.c = page; s.c != page_end; s.c += sch->slabsize) {
                if (UNLIKELY(s.s == sch->empty))
                    found_head = 1;
                else if (UNLIKELY(s.s == slab))
                    continue;
                else if (LIKELY((s.s->prev->next = s.s->next) != NULL))
                    s.s->next->prev = s.s->prev;
            }

            if (UNLIKELY(found_head && (sch->empty = sch->empty->next) != NULL))
                sch->empty->prev = NULL;

            if (sch->slabsize <= slab_pagesize) {
                if (UNLIKELY(munmap(page, sch->pages_per_alloc) == -1))
                    perror("munmap");
            } else {
                free(page);
            }
        } else {
            slab->slots = sch->empty_slotmask;

            if (LIKELY(slab != sch->partial)) {
                if (LIKELY((slab->prev->next = slab->next) != NULL))
                    slab->next->prev = slab->prev;

                slab->prev = NULL;
            } else if (LIKELY((sch->partial = sch->partial->next) != NULL)) {
                sch->partial->prev = NULL;
            }

            slab->next = sch->empty;

            if (LIKELY(sch->empty != NULL))
                sch->empty->prev = slab;

            sch->empty = slab;

            UNLIKELY(slab->refcount != 0) ?
                slab->refcount-- : slab->page->refcount--;
        }
    } else {
        /* target slab is partial, no need to change state */
        slab->slots |= SLOTS_FIRST << slot;
    }
}

void slab_traverse(const struct slab_chain *const sch, void (*fn)(const void *))
{
    assert(sch != NULL);
    assert(fn != NULL);
    assert(slab_is_valid(sch));

    const struct slab_header *slab;
    const char *item, *end;
    const size_t data_offset = offsetof(struct slab_header, data);

    for (slab = sch->partial; slab; slab = slab->next) {
        item = (const char *) slab + data_offset;
        end = item + sch->itemcount * sch->itemsize;
        uint64_t mask = SLOTS_FIRST;

        do {
            if (!(slab->slots & mask))
                fn(item);

            mask <<= 1;
        } while ((item += sch->itemsize) != end);
    }

    for (slab = sch->full; slab; slab = slab->next) {
        item = (const char *) slab + data_offset;
        end = item + sch->itemcount * sch->itemsize;

        do fn(item);
        while ((item += sch->itemsize) != end);
    }
}

void slab_destroy(const struct slab_chain *const sch)
{
    assert(sch != NULL);
    assert(slab_is_valid(sch));

    struct slab_header *const heads[] = {sch->partial, sch->empty, sch->full};
    struct slab_header *pages_head = NULL, *pages_tail;

    for (size_t i = 0; i < 3; ++i) {
        struct slab_header *slab = heads[i];

        while (slab != NULL) {
            if (slab->refcount != 0) {
                struct slab_header *const page = slab;
                slab = slab->next;

                if (UNLIKELY(pages_head == NULL))
                    pages_head = page;
                else
                    pages_tail->next = page;

                pages_tail = page;
            } else {
                slab = slab->next;
            }
        }
    }

    if (LIKELY(pages_head != NULL)) {
        pages_tail->next = NULL;
        struct slab_header *page = pages_head;

        if (sch->slabsize <= slab_pagesize) {
            do {
                void *const target = page;
                page = page->next;

                if (UNLIKELY(munmap(target, sch->pages_per_alloc) == -1))
                    perror("munmap");
            } while (page != NULL);
        } else {
            do {
                void *const target = page;
                page = page->next;
                free(target);
            } while (page != NULL);
        }
    }
}
