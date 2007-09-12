/*
 * Copyright (c) 1999-2000
 * 
 * The Regents of the University of Michigan ("The Regents") and
 * Merit Network, Inc. All rights reserved.  Redistribution and use
 * in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above 
 * copyright notice, this list of conditions and the 
 * following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above 
 * copyright notice, this list of conditions and the 
 * following disclaimer in the documentation and/or other 
 * materials provided with the distribution.
 * 
 * 3. All advertising materials mentioning features or use of 
 * this software must display the following acknowledgement:
 * 
 *   This product includes software developed by the University of
 *   Michigan, Merit Network, Inc., and their contributors.
 * 
 * 4. Neither the name of the University, Merit Network, nor the
 * names of their contributors may be used to endorse or 
 * promote products derived from this software without 
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL TH E REGENTS
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HO WEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This source was adapted from MRT's RCS Ids:
 * Id: radix.h,v 1.6 1999/08/03 03:32:53 masaki Exp
 * Id: mrt.h,v 1.57.2.6 1999/12/28 23:41:27 labovit Exp
 * Id: defs.h,v 1.5.2.2 2000/01/15 14:19:16 masaki Exp
 */

#include <isc/magic.h>
#include <isc/types.h>
#include <isc/mutex.h>
#include <isc/net.h>
#include <isc/refcount.h>

#include <string.h>

#ifndef _RADIX_H
#define _RADIX_H

#define NETADDR_TO_PREFIX_T(na,pt,bits) \
	do { \
	        memset(&(pt), 0, sizeof(pt)); \
                if((bits) && (na) != NULL) { \
		        memcpy(&(pt).add.sin, &(na)->type.in, ((bits)+7)/8); \
		        (pt).bitlen = (bits); \
		        (pt).family = (na)->family; \
                } else \
		        (pt).family = AF_INET; \
		isc_refcount_init(&(pt).refcount, 0); \
	} while(0)

typedef struct isc_prefix {
    unsigned int family;	/* AF_INET | AF_INET6 */
    unsigned int bitlen;
    isc_refcount_t refcount;
    union {
		struct in_addr sin;
		struct in6_addr sin6;
    } add;
} isc_prefix_t;

typedef void (*void_fn_t)();

#define isc_prefix_tochar(prefix) ((char *)&(prefix)->add.sin)
#define isc_prefix_touchar(prefix) ((u_char *)&(prefix)->add.sin)

#define BIT_TEST(f, b)  ((f) & (b))

/*
 * We need "first match" when we search the radix tree to preserve
 * compatibility with the existing ACL implementation. Radix trees
 * naturally lend themselves to "best match". In order to get "first
 * match" behavior, we remember the entries are added to the tree,
 * and when a search is made, we find all matching entries, and return
 * the one that was added first.
 */

typedef struct isc_radix_node {
   isc_uint32_t bit;			/* bit length of the prefix */
   isc_prefix_t *prefix;		/* who we are in radix tree */
   struct isc_radix_node *l, *r;	/* left and right children */
   struct isc_radix_node *parent;	/* may be used */
   void *data;				/* pointer to data */
   int node_num;			/* which node this was in the tree, 
   					   or -1 for glue nodes */
} isc_radix_node_t;

#define RADIX_TREE_MAGIC         ISC_MAGIC('R','d','x','T');
#define RADIX_TREE_VALID(a)      ISC_MAGIC_VALID(a, RADIX_TREE_MAGIC);

typedef struct isc_radix_tree {
   unsigned int		magic;
   isc_mem_t		*mctx;
   isc_radix_node_t 	*head;
   isc_uint32_t		maxbits;	/* for IP, 32 bit addresses */
   int num_active_node;			/* for debugging purposes */
   int num_added_node;			/* total number of nodes */
} isc_radix_tree_t;


isc_result_t
isc_radix_search(isc_radix_tree_t *radix, isc_radix_node_t **target, isc_prefix_t *prefix);

isc_result_t
isc_radix_insert(isc_radix_tree_t *radix, isc_radix_node_t **target, isc_radix_node_t *source, isc_prefix_t *prefix);

void
isc_radix_remove(isc_radix_tree_t *radix, isc_radix_node_t *node);

isc_result_t
isc_radix_create(isc_mem_t *mctx, isc_radix_tree_t **target, int maxbits);

void
isc_destroy_radix(isc_radix_tree_t *radix, void_fn_t func);

void
isc_radix_process(isc_radix_tree_t *radix, void_fn_t func);


#define RADIX_MAXBITS 128
#define RADIX_NBIT(x)        (0x80 >> ((x) & 0x7f))
#define RADIX_NBYTE(x)       ((x) >> 3)

#define RADIX_DATA_GET(node, type) (type *)((node)->data)
#define RADIX_DATA_SET(node, value) ((node)->data = (void *)(value))

#define RADIX_WALK(Xhead, Xnode) \
    do { \
        isc_radix_node_t *Xstack[RADIX_MAXBITS+1]; \
        isc_radix_node_t **Xsp = Xstack; \
        isc_radix_node_t *Xrn = (Xhead); \
        while ((Xnode = Xrn)) { \
            if (Xnode->prefix)

#define RADIX_WALK_ALL(Xhead, Xnode) \
do { \
        isc_radix_node_t *Xstack[RADIX_MAXBITS+1]; \
        isc_radix_node_t **Xsp = Xstack; \
        isc_radix_node_t *Xrn = (Xhead); \
        while ((Xnode = Xrn)) { \
	    if (1)

#define RADIX_WALK_BREAK { \
	    if (Xsp != Xstack) { \
		Xrn = *(--Xsp); \
	     } else { \
		Xrn = (radix_node_t *) 0; \
	    } \
	    continue; }

#define RADIX_WALK_END \
            if (Xrn->l) { \
                if (Xrn->r) { \
                    *Xsp++ = Xrn->r; \
                } \
                Xrn = Xrn->l; \
            } else if (Xrn->r) { \
                Xrn = Xrn->r; \
            } else if (Xsp != Xstack) { \
                Xrn = *(--Xsp); \
            } else { \
                Xrn = (isc_radix_node_t *) 0; \
            } \
        } \
    } while (0)

#endif /* _RADIX_H */
