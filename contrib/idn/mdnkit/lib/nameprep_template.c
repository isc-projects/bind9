/* $Id: nameprep_template.c,v 1.1.2.1 2002/02/08 12:14:11 marka Exp $ */

/*
 * Copyright (c) 2001 Japan Network Information Center.  All rights reserved.
 *  
 * By using this file, you agree to the terms and conditions set forth bellow.
 * 
 * 			LICENSE TERMS AND CONDITIONS 
 * 
 * The following License Terms and Conditions apply, unless a different
 * license is obtained from Japan Network Information Center ("JPNIC"),
 * a Japanese association, Kokusai-Kougyou-Kanda Bldg 6F, 2-3-4 Uchi-Kanda,
 * Chiyoda-ku, Tokyo 101-0047, Japan.
 * 
 * 1. Use, Modification and Redistribution (including distribution of any
 *    modified or derived work) in source and/or binary forms is permitted
 *    under this License Terms and Conditions.
 * 
 * 2. Redistribution of source code must retain the copyright notices as they
 *    appear in each source code file, this License Terms and Conditions.
 * 
 * 3. Redistribution in binary form must reproduce the Copyright Notice,
 *    this License Terms and Conditions, in the documentation and/or other
 *    materials provided with the distribution.  For the purposes of binary
 *    distribution the "Copyright Notice" refers to the following language:
 *    "Copyright (c) Japan Network Information Center.  All rights reserved."
 * 
 * 4. Neither the name of JPNIC may be used to endorse or promote products
 *    derived from this Software without specific prior written approval of
 *    JPNIC.
 * 
 * 5. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY JPNIC
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *    PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL JPNIC BE LIABLE
 *    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *    ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * 6. Indemnification by Licensee
 *    Any person or entities using and/or redistributing this Software under
 *    this License Terms and Conditions shall defend indemnify and hold
 *    harmless JPNIC from and against any and all judgements damages,
 *    expenses, settlement liabilities, cost and other liabilities of any
 *    kind as a result of use and redistribution of this Software or any
 *    claim, suite, action, litigation or proceeding by any third party
 *    arising out of or relates to this License Terms and Conditions.
 * 
 * 7. Governing Law, Jurisdiction and Venue
 *    This License Terms and Conditions shall be governed by and and
 *    construed in accordance with the law of Japan. Any person or entities
 *    using and/or redistributing this Software under this License Terms and
 *    Conditions hereby agrees and consent to the personal and exclusive
 *    jurisdiction and venue of Tokyo District Court of Japan.
 */

/*
 * Include this file once for each version of NAMEPREP.
 * VERSION should be defined to appropriate value before inclusion.
 */

#ifndef NAMEPREP_TEMPLATE_INIT
#define NAMEPREP_TEMPLATE_INIT

/* Symbol composition. */
#define compose_sym2(a, b)		compose_sym2X(a, b)
#define compose_sym2X(a, b)		a ## b
#define compose_sym3(a, b, c)		compose_sym3X(a, b, c)
#define compose_sym3X(a, b, c)		a ## b ## c

/* Index calculation for multi-level index tables. */
#define IDX0(type, v) IDX_0(v, BITS1(type), BITS2(type))
#define IDX1(type, v) IDX_1(v, BITS1(type), BITS2(type))
#define IDX2(type, v) IDX_2(v, BITS1(type), BITS2(type))

#define IDX_0(v, bits1, bits2)	((v) >> ((bits1) + (bits2)))
#define IDX_1(v, bits1, bits2)	(((v) >> (bits2)) & ((1 << (bits1)) - 1))
#define IDX_2(v, bits1, bits2)	((v) & ((1 << (bits2)) - 1))

#define BITS1(type)	type ## _BITS_1
#define BITS2(type)	type ## _BITS_2

#endif /* NAMEPREP_TEMPLATE_INIT */

static const char *
compose_sym2(nameprep_map_, VERSION) (unsigned long v) {
	int idx0 = IDX0(MAP, v);
	int idx1 = IDX1(MAP, v);
	int idx2 = IDX2(MAP, v);
	int offset;

#define IMAP	compose_sym3(nameprep_, VERSION, _map_imap)
#define TABLE	compose_sym3(nameprep_, VERSION, _map_table)
#define DATA	compose_sym3(nameprep_, VERSION, _map_data)
	offset = TABLE[IMAP[IMAP[idx0] + idx1]].tbl[idx2];
	if (offset == 0)
		return (NULL);	/* no mapping */
	return (const char *)(DATA + offset);
#undef IMAP
#undef TABLE
#undef DATA
}

static int
compose_sym2(nameprep_prohibited_, VERSION) (unsigned long v) {
	int idx0 = IDX0(PROH, v);
	int idx1 = IDX1(PROH, v);
	int idx2 = IDX2(PROH, v);
	const unsigned char *bm;

#define IMAP	compose_sym3(nameprep_, VERSION, _prohibited_imap)
#define BITMAP	compose_sym3(nameprep_, VERSION, _prohibited_bitmap)
	bm = BITMAP[IMAP[IMAP[idx0] + idx1]].bm;
	return (bm[idx2 / 8] & (1 << (idx2 % 8)));
#undef IMAP
#undef BITMAP
}

static int
compose_sym2(nameprep_unassigned_, VERSION) (unsigned long v) {
	int idx0 = IDX0(UNAS, v);
	int idx1 = IDX1(UNAS, v);
	int idx2 = IDX2(UNAS, v);
	const unsigned char *bm;

#define IMAP	compose_sym3(nameprep_, VERSION, _unassigned_imap)
#define BITMAP	compose_sym3(nameprep_, VERSION, _unassigned_bitmap)
	bm = BITMAP[IMAP[IMAP[idx0] + idx1]].bm;
	return (bm[idx2 / 8] & (1 << (idx2 % 8)));
#undef IMAP
#undef BITMAP
}
