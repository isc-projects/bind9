#ifndef lint
static char const yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif
#include <stdlib.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING (yyerrflag!=0)
#if defined(c_plusplus) || defined(__cplusplus)
#include <stdlib.h>
#else
extern char *getenv();
extern void *realloc();
#endif
static int yygrowstack();
#define YYPREFIX "yy"
#if !defined(lint) && !defined(SABER)
static char rcsid[] = "$Id: confparser.c,v 1.1 1999/07/19 13:25:17 brister Exp $";
#endif /* not lint */

/*
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

 
#include <config.h>

#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h> 
#include <limits.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h> 

#include <syslog.h>

#include <isc/assertions.h>
#include <isc/mutex.h>
#include <isc/lex.h>
#include <isc/symtab.h>
#include <isc/error.h>
#include <isc/once.h>


#include <dns/confparser.h>
#include <dns/confctx.h>
 
#include <dns/result.h>
#include <dns/rdatatype.h>
#include <dns/rdataclass.h>

#include <dns/types.h>

#include <dns/confcommon.h>


/* Type keys for symtab lookup */
#define KEYWORD_SYM_TYPE 0x1
#define CLASS_SYM_TYPE 0x2
#define ACL_SYM_TYPE 0x3

 
static isc_mutex_t yacc_mutex;

/* All these statics are protected by the above yacc_mutex */
static dns_c_ctx_t	       *currcfg;
static isc_mem_t	       *memctx; /* used for internal allocations */
static isc_lex_t	       *mylexer;
static isc_symtab_t	       *keywords;
static dns_c_cbks_t	       *callbacks;
static isc_lexspecials_t	specials;

#define CONF_MAX_IDENT 1024

/* This should be sufficient to permit multiple parsers and lexers if needed */
#define yyparse confyyparse
#define yylex confyylex

#define YYDEBUG 1 

static isc_result_t	tmpres;
static int		debug_lexer;
 

typedef union {
	char		       *text;
	int			number;
	isc_int32_t		l_int;
	isc_uint32_t		ul_int;
	isc_uint16_t		port_int;
	dns_c_zonetype_t	ztype;
	struct in_addr		ip4_addr;
	struct in6_addr		ip6_addr;
	dns_c_addr_t		ipaddress;

	isc_boolean_t		boolean;
	dns_rdataclass_t	rrclass;
	dns_c_severity_t	severity;
	dns_c_trans_t		transport;
	dns_transfer_format_t	tformat;
	dns_c_category_t	logcat;
	
	dns_c_ipmatch_element_t	*ime;
	dns_c_ipmatch_list_t	*iml;

	dns_c_forw_t		forward;
	dns_c_rrso_t           *rrorder;
	dns_c_rrso_list_t      *rrolist;
	dns_rdatatype_t		ordertype;
	dns_rdataclass_t	orderclass;
	dns_c_ordering_t	ordering;
	dns_c_iplist_t	       *iplist;
} YYSTYPE;
#define L_STRING 257
#define L_QSTRING 258
#define L_INTEGER 259
#define L_IP4ADDR 260
#define L_IP6ADDR 261
#define L_LBRACE 262
#define L_RBRACE 263
#define L_EOS 264
#define L_SLASH 265
#define L_BANG 266
#define L_QUOTE 267
#define L_MASTER 268
#define L_SLAVE 269
#define L_SORTLIST 270
#define L_HINT 271
#define L_STUB 272
#define L_FORWARD 273
#define L_INCLUDE 274
#define L_END_INCLUDE 275
#define L_OPTIONS 276
#define L_DIRECTORY 277
#define L_PIDFILE 278
#define L_NAMED_XFER 279
#define L_DUMP_FILE 280
#define L_STATS_FILE 281
#define L_MEMSTATS_FILE 282
#define L_FAKE_IQUERY 283
#define L_RECURSION 284
#define L_FETCH_GLUE 285
#define L_QUERY_SOURCE 286
#define L_LISTEN_ON 287
#define L_PORT 288
#define L_ACL 289
#define L_ADDRESS 290
#define L_ALGID 291
#define L_ALLOW_QUERY 292
#define L_ALLOW_TRANSFER 293
#define L_ALLOW_UPDATE 294
#define L_ALSO_NOTIFY 295
#define L_BLACKHOLE 296
#define L_BOGUS 297
#define L_CATEGORY 298
#define L_CHANNEL 299
#define L_CHECK_NAMES 300
#define L_DEBUG 301
#define L_DIALUP 302
#define L_DYNAMIC 303
#define L_FAIL 304
#define L_FIRST 305
#define L_FORWARDERS 306
#define L_IF_NO_ANSWER 307
#define L_IF_NO_DOMAIN 308
#define L_IGNORE 309
#define L_FILE_IXFR 310
#define L_IXFR_TMP 311
#define L_SEC_KEY 312
#define L_KEYS 313
#define L_LOGGING 314
#define L_MASTERS 315
#define L_NULL_OUTPUT 316
#define L_ONLY 317
#define L_PRINT_CATEGORY 318
#define L_PRINT_SEVERITY 319
#define L_PRINT_TIME 320
#define L_PUBKEY 321
#define L_RESPONSE 322
#define L_SECRET 323
#define L_SERVER 324
#define L_SEVERITY 325
#define L_SIZE 326
#define L_SUPPORT_IXFR 327
#define L_SYSLOG 328
#define L_TOPOLOGY 329
#define L_TRANSFER_SOURCE 330
#define L_TRANSFERS 331
#define L_TRUSTED_KEYS 332
#define L_VERSIONS 333
#define L_WARN 334
#define L_RRSET_ORDER 335
#define L_ORDER 336
#define L_NAME 337
#define L_CLASS 338
#define L_CONTROLS 339
#define L_INET 340
#define L_UNIX 341
#define L_PERM 342
#define L_OWNER 343
#define L_GROUP 344
#define L_ALLOW 345
#define L_DATASIZE 346
#define L_STACKSIZE 347
#define L_CORESIZE 348
#define L_DEFAULT 349
#define L_UNLIMITED 350
#define L_FILES 351
#define L_VERSION 352
#define L_HOSTSTATS 353
#define L_DEALLOC_ON_EXIT 354
#define L_TRANSFERS_IN 355
#define L_TRANSFERS_OUT 356
#define L_TRANSFERS_PER_NS 357
#define L_TRANSFER_FORMAT 358
#define L_MAX_TRANSFER_TIME_IN 359
#define L_ONE_ANSWER 360
#define L_MANY_ANSWERS 361
#define L_NOTIFY 362
#define L_AUTH_NXDOMAIN 363
#define L_MULTIPLE_CNAMES 364
#define L_USE_IXFR 365
#define L_MAINTAIN_IXFR_BASE 366
#define L_CLEAN_INTERVAL 367
#define L_INTERFACE_INTERVAL 368
#define L_STATS_INTERVAL 369
#define L_MAX_LOG_SIZE_IXFR 370
#define L_HEARTBEAT 371
#define L_USE_ID_POOL 372
#define L_MAX_NCACHE_TTL 373
#define L_HAS_OLD_CLIENTS 374
#define L_EXPERT_MODE 375
#define L_ZONE 376
#define L_TYPE 377
#define L_FILE 378
#define L_YES 379
#define L_TRUE 380
#define L_NO 381
#define L_FALSE 382
#define YYERRCODE 256
const short yylhs[] = {                                        -1,
    0,   41,   41,   42,   42,   42,   42,   42,   42,   42,
   42,   42,   42,   43,   52,   44,   53,   53,   54,   54,
   54,   54,   54,   54,   54,   54,   54,   54,   54,   54,
   54,   54,   54,   54,   54,   54,   54,   54,   54,   54,
   54,   54,   55,   54,   54,   54,   54,   54,   54,   54,
   54,   54,   54,   54,   54,   54,   54,   54,   54,   54,
   54,   60,   54,   45,   62,   62,   63,   63,   63,   61,
   61,   21,   21,   22,   22,   35,   35,   64,   37,   37,
   12,   12,   25,   25,   65,   66,   57,   57,   57,   57,
   24,   24,   26,   26,    1,    1,    1,    1,    1,   38,
   38,   38,   29,   29,   29,    2,    2,    2,    2,   58,
   58,   58,   58,   39,   39,   39,   39,   59,   59,   59,
   56,   56,   67,   67,   68,   69,   46,   70,   70,   71,
   71,   75,   73,   77,   73,   78,   73,   73,   79,   79,
   79,   79,   76,   76,   81,   72,   83,   83,   83,   83,
   84,   84,   85,   74,   74,   74,   74,   74,   19,   19,
   20,   20,   80,   80,   86,   86,   86,   86,   32,   32,
   87,   82,   82,   18,   18,   18,   88,   47,   89,   89,
   90,   90,   90,   90,   92,   90,    7,    7,    4,    4,
    4,    5,    5,    5,    5,    5,    6,   34,   93,   94,
   94,   91,   91,   95,   51,   96,   96,   30,   36,   50,
   33,   98,   48,   48,   97,   97,   27,   28,   28,   40,
   40,   40,   40,   40,  100,  100,   99,   99,   99,   99,
   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,
   99,   99,   99,   99,  101,  101,  101,  101,  101,  101,
  101,  101,  101,  101,  101,  101,  101,  101,  101,  101,
  101,  101,   14,   15,    9,   10,   11,   11,    8,   16,
   16,   13,   13,    3,    3,   17,  102,   49,  103,  103,
  104,   23,   31,   31,
};
const short yylen[] = {                                         2,
    1,    1,    2,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    3,    0,    6,    2,    3,    0,    2,
    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,
    2,    2,    2,    2,    2,    2,    2,    2,    3,    2,
    5,    2,    0,    5,    2,    4,    4,    4,    4,    4,
    1,    1,    2,    2,    2,    2,    2,    2,    2,    2,
    2,    0,    5,    5,    2,    3,    0,    8,    8,    2,
    3,    0,    2,    0,    2,    0,    2,    5,    1,    1,
    1,    1,    1,    1,    2,    2,    1,    1,    2,    2,
    0,    2,    0,    2,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    2,
    2,    2,    2,    1,    1,    1,    1,    2,    2,    2,
    0,    1,    2,    3,    1,    0,    6,    2,    3,    1,
    1,    0,   10,    0,    9,    0,    8,    4,    1,    1,
    1,    1,    0,    1,    0,    6,    1,    1,    2,    1,
    2,    2,    2,    0,    1,    1,    2,    2,    1,    1,
    0,    1,    2,    3,    2,    2,    2,    2,    1,    1,
    1,    2,    3,    1,    1,    1,    0,    7,    2,    3,
    2,    2,    2,    2,    0,    5,    2,    3,    1,    2,
    2,    1,    3,    3,    1,    3,    1,    1,    1,    0,
    1,    2,    3,    0,    7,    2,    2,    3,    3,    6,
    1,    0,   11,    5,    0,    1,    1,    0,    1,    1,
    1,    1,    1,    1,    2,    3,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    2,    2,    2,    5,    2,    2,
    4,    4,    4,    2,    4,    2,    2,    2,    2,    5,
    4,    2,    1,    1,    1,    1,    1,    1,    1,    0,
    1,    2,    3,    1,    1,    1,    0,    6,    2,    3,
    5,    1,    1,    1,
};
const short yydefred[] = {                                      0,
    0,   13,   15,    0,    0,  126,    0,  277,    0,    0,
    0,    0,    2,    4,    5,    6,    7,    8,    9,   10,
   11,   12,    0,    0,  283,  284,    0,  204,    0,  265,
  266,  267,  268,  177,    0,    0,  211,    0,    3,   14,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  219,    0,  217,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   43,    0,   62,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   51,   52,    0,    0,    0,    0,    0,  189,
  195,    0,    0,  192,  197,    0,    0,    0,    0,    0,
  130,  131,    0,    0,    0,    0,   82,   81,    0,    0,
    0,    0,   65,    0,    0,  107,  108,  109,  106,   42,
   21,   23,   22,   26,   24,   25,   99,   95,   96,   97,
   98,   28,   29,   30,    0,    0,   45,    0,    0,    0,
    0,    0,    0,    0,  100,  101,  102,    0,   61,    0,
    0,    0,  115,  116,  117,  114,  110,  111,  112,  113,
   20,   32,   33,  118,  119,  120,   79,   80,   53,   54,
   31,   37,   38,   34,   35,   55,   56,   57,   58,   60,
   40,   59,   36,   27,    0,    0,   17,    0,    0,  190,
  191,  187,    0,    0,    0,    0,    0,    0,    0,    0,
  175,  176,  145,  174,  170,  169,    0,    0,    0,  128,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  279,    0,    0,   64,   66,  236,  234,  235,  233,  243,
  232,  244,  237,  228,  229,  230,  242,  231,  238,  240,
  241,  239,    0,  227,  214,    0,   84,  282,   83,   86,
   85,   89,   90,   92,    0,    0,    0,    0,  104,  105,
  103,   39,    0,    0,    0,   16,   18,  194,  196,  210,
  188,  193,    0,    0,  206,  207,    0,    0,    0,  127,
  129,  181,  185,  182,  183,  184,    0,    0,  179,    0,
  278,  280,    0,    0,  220,  221,  222,  223,  224,    0,
   48,    0,   46,   47,   49,  125,    0,    0,    0,   50,
    0,    0,    0,    0,  208,  209,  205,    0,  136,  141,
  142,  140,  139,    0,    0,  138,    0,  178,  180,    0,
    0,    0,  212,   41,   44,    0,  123,   73,    0,    0,
   63,    0,   70,  171,    0,    0,    0,  160,  162,  134,
  159,  132,  198,  199,    0,    0,  281,    0,    0,    0,
  124,   75,    0,    0,   71,  146,    0,  172,    0,    0,
    0,  186,    0,  201,  202,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   77,    0,
  173,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  203,   68,   69,  275,  274,  254,
    0,    0,    0,    0,  250,  262,    0,  246,  247,    0,
    0,    0,  249,  256,  258,  259,  257,  245,    0,    0,
  225,   78,  167,  168,  166,    0,  150,  147,  165,  137,
    0,  163,    0,  153,  151,  152,    0,  157,  158,    0,
    0,    0,    0,  269,    0,    0,  264,  276,    0,   94,
    0,    0,  213,  226,  149,  164,  135,    0,  252,  253,
  251,  272,    0,  261,  255,    0,    0,    0,  133,  273,
  248,  260,
};
const short yydgoto[] = {                                      11,
  152,  140,  440,  109,  110,  111,  112,  483,  113,   33,
  114,  129,  485,  507,  486,  487,  489,  223,  369,  370,
  332,  360,  269,  161,  270,  451,   51,   52,  282,  218,
  115,  364,  124,  374,  384,  219,  189,  168,  177,  320,
   12,   13,   14,   15,   16,   17,   18,   19,   20,   21,
   22,   24,  101,  102,  170,  327,  157,  103,  104,  172,
  333,   49,   50,  334,  158,  159,  328,  329,   29,  119,
  120,  121,  122,  432,  391,  426,  390,  367,  346,  427,
  298,  365,  469,  433,  434,  428,  366,   45,  236,  237,
  375,  347,  376,  395,   43,  220,  416,  380,  265,  417,
  418,   35,  125,  126,
};
const short yysindex[] = {                                    -90,
 -208,    0,    0, -131, -131,    0,  -92,    0, -177, -128,
    0,  -90,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -168, -126,    0,    0, -110,    0,  -85,    0,
    0,    0,    0,    0,  -73, -161,    0, -131,    0,    0,
  272,   73,  -69, -101,  -61, -128,  -96, -115, -239,  -51,
    0,  -52,    0,  -41, -170,  -35,  -33,  -25,  -22,  -21,
  -20, -248, -248, -248, -176,  -49,  -18,  -17,  -14, -209,
 -248,    0,  -12,    0, -232, -232, -232, -232,   -4, -248,
 -248,  -13,    1,   10, -143,   11, -248, -248, -248, -248,
 -248,   13,   14,   15,   16,   19, -248,   20, -248, -248,
  166,  -23,    0,    0,   17,   73,   66,   23,   24,    0,
    0,  -54,   18,    0,    0, -214, -242, -226, -157,   25,
    0,    0, -233,   28, -228,   27,    0,    0,    4,  -58,
   29,   31,    0, -211,   73,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -113,  -96,    0,   32,   26,   44,
   42,   73,   73,   73,    0,    0,    0, -181,    0,   45,
   73,   46,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   55,   74,    0,   47,  -31,    0,
    0,    0,   76,   77,   78, -131, -131,   21,   56,   80,
    0,    0,    0,    0,    0,    0,   84,   88,   89,    0,
 -248,   92, -248,   96, -143, -234,   94,   97,   95,  101,
    0,   44,  107,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  -16,    0,    0,    5,    0,    0,    0,    0,
    0,    0,    0,    0,   73,   39,   52,  130,    0,    0,
    0,    0,  -92,  148,   22,    0,    0,    0,    0,    0,
    0,    0,  103,  104,    0,    0,  108,  109, -267,    0,
    0,    0,    0,    0,    0,    0,  113,  118,    0,  124,
    0,    0,   41,   51,    0,    0,    0,    0,    0,  120,
    0,  158,    0,    0,    0,    0,  132,  -92,  133,    0,
 -131,   35, -251,  134,    0,    0,    0, -226,    0,    0,
    0,    0,    0, -240,  141,    0, -131,    0,    0,  142,
  139,  143,    0,    0,    0,  149,    0,    0, -131,   85,
    0,  161,    0,    0, -224,  162,  163,    0,    0,    0,
    0,    0,    0,    0, -118,  167,    0,   73,   86, -119,
    0,    0, -128,   98,    0,    0,  168,    0, -162,  169,
 -261,    0,  167,    0,    0,  231,  176, -262,  192,  193,
  194,  195, -181, -248,  199,  205,  206,  177,  208,  -96,
  210, -248, -248,  212,  215,  211, -119,  213,    0,  218,
    0, -248, -248, -248, -235,  217, -162,  219, -162, -232,
 -245,  222,  150,  154,    0,    0,    0,    0,    0,    0,
   73,   73,   73,  -92,    0,    0,  -92,    0,    0,   44,
  220,  237,    0,    0,    0,    0,    0,    0,  234,  238,
    0,    0,    0,    0,    0,  244,    0,    0,    0,    0,
  240,    0,  242,    0,    0,    0, -162,    0,    0,  336,
  351,  392,  243,    0,  -92,  245,    0,    0,  246,    0,
  -92,  247,    0,    0,    0,    0,    0,  248,    0,    0,
    0,    0,  251,    0,    0,  -92,  253,  223,    0,    0,
    0,    0,
};
const short yyrindex[] = {                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  510,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  262,    0,  265,    0,    0,
  280,    0,    0,    0,    0,    0,    0,    0,  262,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  284,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  280,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  283,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  296,  297,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  285,    0, -215,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  299,    0,    0,
    0, -117, -215,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  302,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  227,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  -63,    0,    0,    0,  304,
    0,    0,    0,    0,    0,    0,    0,    0,  306,    0,
  307,    0,  -63,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  308,    0,    0,
    0,    0,    0,    0,    0,    0,  310,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  312,    0,  306,    0,
    0,    0,  313,  315,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  317,    0,    0,  317,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  318,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  306,    0,    0,    0,
    0,    0,    0,    0,  320,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  321,    0,    0,    0,    0,
    0,    0,
};
const short yygindex[] = {                                      0,
  -43,    0,    0, -106,  469,    0,  -93, -377,   -7,    0,
   -6, -149,   90,    0,    0,  138,    0,    0,    0,    0,
    0,    0, -156,    0,    0,    0,  255,    0,  184,  369,
   -2,  471,   -5,    0,    0,  372,  356,    0,  -68,    0,
    0,  580,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  499,    0,    0,    0,    0,    0,    0,
    0,    0,  554,  271,  446,  448,    0,  287,    0,    0,
  497,    0,    0,    0,    0, -410,    0,    0,    0,    0,
    0,    0,    0,  187,  189,  229,  267,    0,    0,  397,
    0,    0,  282,  266,    0,    0,    0,    0,    0,    0,
  249,    0,    0,  535,
};
#define YYTABLESIZE 704
const short yytable[] = {                                      32,
   34,   27,   28,  274,   38,  214,  271,  178,  179,  180,
  147,  361,  209,  475,   25,   26,   25,   26,  473,  153,
  154,   25,   26,  131,   25,   26,  173,  169,  307,   37,
   25,   26,   25,   26,  239,   53,  182,  183,  386,   32,
  128,  266,  438,  191,  192,  193,  194,  195,  339,   23,
  340,  341,  342,  201,  439,  203,  204,  343,  165,  166,
  344,  246,  231,  231,  430,  466,  498,  467,  276,  277,
  278,  431,  176,  176,  176,  176,  216,  284,  232,  232,
  247,  248,  249,  250,   36,  313,  331,  368,  251,  225,
  252,  225,  233,  233,  253,   40,  234,  234,  254,  255,
   47,   48,  214,  256,  476,  228,  221,  503,  217,  257,
  345,  155,  167,  156,  224,  226,  174,  175,  258,  222,
   72,   72,  279,  235,  235,   25,   26,  280,  503,   37,
  148,  149,  150,  151,  136,   41,  137,  138,   25,   26,
  117,  118,  130,  267,  392,  268,  139,  259,   32,  128,
  260,   42,  281,  398,  261,  422,  423,  424,  262,  214,
  127,   72,  425,   30,   31,  263,  264,   30,   31,  214,
  214,  214,  399,  400,  401,  402,   44,  214,   47,   48,
  403,  322,  404,    1,    2,    3,  405,  302,   46,  304,
  406,  407,  116,  200,  200,  408,  117,  118,    4,  200,
  123,  409,   25,   26,  105,   30,   31,  106,  213,  134,
  410,  107,  133,  293,  294,  214,  187,  188,   74,   74,
  135,    5,  141,    6,  142,   25,   26,  105,   30,   31,
  106,  289,  143,    7,  107,  144,  145,  146,  160,  411,
  207,    8,  412,  162,  163,  184,  413,  164,    9,  171,
  414,  315,  316,  181,  317,  318,  319,  108,  415,  185,
  453,   25,   26,  105,   30,   31,  106,  321,  186,  190,
  107,  196,  197,  198,  199,   32,  326,  200,  202,  211,
  108,  208,  215,  243,  396,   10,  238,  212,  230,  214,
  241,  242,  244,  490,  245,   25,   26,  105,   30,   31,
  106,  323,  268,  275,  107,  288,  283,  285,   25,   26,
  105,   30,   31,  106,  324,  156,  108,  107,  286,  155,
   32,  326,   25,   26,  105,   30,   31,  106,   53,   25,
   26,  105,   30,   31,  106,  226,  292,  287,  107,  290,
  291,  371,  297,  217,  373,  299,  216,  480,  481,  482,
  108,  300,  301,  303,  305,  310,  382,  309,  311,  331,
  446,  474,  226,  108,  312,  314,  335,  336,  455,  456,
  338,  337,  373,  214,  214,  214,  348,  419,  463,  464,
  465,  349,  350,  353,  108,  351,   25,   26,  105,   30,
   31,  106,  325,  352,  355,  107,  357,  363,  372,  377,
  378,  379,   32,  128,   25,   26,  105,   30,   31,  106,
  330,  359,  381,  107,   25,   26,  105,   30,   31,  106,
  354,  383,  468,  107,  385,  388,  389,  176,  205,  397,
  394,  421,  429,  420,  437,   54,   32,  484,   55,   32,
  484,  108,   56,   57,   58,   59,   60,   61,   62,   63,
   64,   65,   66,  441,  442,  443,  444,   67,   68,  108,
  447,   69,  448,  449,  450,   70,  452,   71,  454,  108,
  457,   72,  458,  459,  462,  430,  461,   32,  484,  470,
  512,  491,  472,   32,  484,  477,  431,   25,   26,  105,
   30,   31,  106,  436,   73,  492,  107,  493,   32,  484,
   74,  494,  495,  496,  497,  508,  502,  504,  505,    1,
  509,   75,   76,   77,  510,  511,   78,   79,   80,   81,
   82,   83,   84,   85,   86,   67,  218,   87,   88,   89,
   90,   91,   92,   93,   94,   95,   96,   97,   98,   99,
  100,   54,  108,   19,   55,   91,  267,  121,   56,   57,
   58,   59,   60,   61,   62,   63,   64,   65,   66,   87,
   88,  122,   76,   67,   68,  161,  215,   69,  143,   93,
  154,   70,  216,   71,  144,  210,  155,   72,  156,  270,
  506,  148,  271,  263,  488,  358,  445,  296,  227,  295,
  306,   39,   25,   26,  105,   30,   31,  106,  499,  206,
   73,  107,  132,  362,  273,  272,   74,   25,   26,  105,
   30,   31,  106,  500,  356,  229,  107,   75,   76,   77,
  479,  478,   78,   79,   80,   81,   82,   83,   84,   85,
   86,  387,  308,   87,   88,   89,   90,   91,   92,   93,
   94,   95,   96,   97,   98,   99,  100,  108,   25,   26,
  105,   30,   31,  106,  501,  471,  393,  107,  435,  240,
    0,    0,  108,    0,    0,  460,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  108,
};
const short yycheck[] = {                                       7,
    7,    4,    5,  160,   10,  112,  156,   76,   77,   78,
  259,  263,  106,  259,  257,  258,  257,  258,  429,   63,
   64,  257,  258,  263,  257,  258,  259,   71,  263,  258,
  257,  258,  257,  258,  263,   38,   80,   81,  263,   47,
   47,  135,  305,   87,   88,   89,   90,   91,  316,  258,
  318,  319,  320,   97,  317,   99,  100,  325,  268,  269,
  328,  273,  297,  297,  326,  301,  477,  303,  162,  163,
  164,  333,   75,   76,   77,   78,  291,  171,  313,  313,
  292,  293,  294,  295,  262,  242,  338,  328,  300,  316,
  302,  316,  327,  327,  306,  264,  331,  331,  310,  311,
  340,  341,  209,  315,  350,  263,  349,  485,  323,  321,
  378,  288,  322,  290,  117,  118,  349,  350,  330,  362,
  336,  337,  304,  358,  358,  257,  258,  309,  506,  258,
  379,  380,  381,  382,  305,  262,  307,  308,  257,  258,
  298,  299,  258,  257,  263,  259,  317,  359,  156,  156,
  362,  262,  334,  273,  366,  318,  319,  320,  370,  266,
  257,  377,  325,  260,  261,  377,  378,  260,  261,  276,
  277,  278,  292,  293,  294,  295,  262,  284,  340,  341,
  300,  275,  302,  274,  275,  276,  306,  231,  262,  233,
  310,  311,  262,  257,  258,  315,  298,  299,  289,  263,
  262,  321,  257,  258,  259,  260,  261,  262,  263,  262,
  330,  266,  264,  216,  217,  322,  360,  361,  336,  337,
  262,  312,  258,  314,  258,  257,  258,  259,  260,  261,
  262,  263,  258,  324,  266,  258,  258,  258,  288,  359,
  264,  332,  362,  262,  262,  259,  366,  262,  339,  262,
  370,  268,  269,  258,  271,  272,  273,  312,  378,  259,
  410,  257,  258,  259,  260,  261,  262,  263,  259,  259,
  266,  259,  259,  259,  259,  283,  283,  259,  259,  257,
  312,  265,  265,  342,  378,  376,  259,  264,  264,  396,
  264,  288,  264,  450,  264,  257,  258,  259,  260,  261,
  262,  263,  259,  262,  266,  259,  262,  262,  257,  258,
  259,  260,  261,  262,  263,  290,  312,  266,  264,  288,
  328,  328,  257,  258,  259,  260,  261,  262,  331,  257,
  258,  259,  260,  261,  262,  338,  259,  264,  266,  264,
  264,  344,  263,  323,  347,  262,  291,  441,  442,  443,
  312,  264,  264,  262,  259,  259,  359,  264,  264,  338,
  404,  430,  365,  312,  264,  259,  264,  264,  412,  413,
  262,  264,  375,  480,  481,  482,  264,  383,  422,  423,
  424,  264,  259,  264,  312,  345,  257,  258,  259,  260,
  261,  262,  263,  343,  263,  266,  264,  264,  258,  258,
  262,  259,  410,  410,  257,  258,  259,  260,  261,  262,
  263,  377,  264,  266,  257,  258,  259,  260,  261,  262,
  263,  337,  425,  266,  264,  264,  264,  430,  263,  344,
  264,  264,  264,  336,  259,  270,  444,  444,  273,  447,
  447,  312,  277,  278,  279,  280,  281,  282,  283,  284,
  285,  286,  287,  262,  262,  262,  262,  292,  293,  312,
  262,  296,  258,  258,  288,  300,  259,  302,  259,  312,
  259,  306,  258,  263,  257,  326,  264,  485,  485,  263,
  258,  262,  264,  491,  491,  264,  333,  257,  258,  259,
  260,  261,  262,  263,  329,  259,  266,  264,  506,  506,
  335,  264,  259,  264,  263,  259,  264,  263,  263,    0,
  263,  346,  347,  348,  264,  263,  351,  352,  353,  354,
  355,  356,  357,  358,  359,  264,  262,  362,  363,  364,
  365,  366,  367,  368,  369,  370,  371,  372,  373,  374,
  375,  270,  312,  264,  273,  262,  264,  263,  277,  278,
  279,  280,  281,  282,  283,  284,  285,  286,  287,  264,
  264,  263,  336,  292,  293,  264,  263,  296,  263,  262,
  264,  300,  263,  302,  263,  107,  264,  306,  264,  263,
  491,  264,  263,  263,  447,  331,  403,  219,  118,  218,
  235,   12,  257,  258,  259,  260,  261,  262,  263,  101,
  329,  266,   49,  333,  159,  158,  335,  257,  258,  259,
  260,  261,  262,  263,  328,  119,  266,  346,  347,  348,
  434,  433,  351,  352,  353,  354,  355,  356,  357,  358,
  359,  365,  236,  362,  363,  364,  365,  366,  367,  368,
  369,  370,  371,  372,  373,  374,  375,  312,  257,  258,
  259,  260,  261,  262,  263,  427,  375,  266,  393,  125,
   -1,   -1,  312,   -1,   -1,  417,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  312,
};
#define YYFINAL 11
#ifndef YYDEBUG
#define YYDEBUG 0
#elif YYDEBUG
#include <stdio.h>
#endif
#define YYMAXTOKEN 382
#if YYDEBUG
const char * const yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"L_STRING","L_QSTRING",
"L_INTEGER","L_IP4ADDR","L_IP6ADDR","L_LBRACE","L_RBRACE","L_EOS","L_SLASH",
"L_BANG","L_QUOTE","L_MASTER","L_SLAVE","L_SORTLIST","L_HINT","L_STUB",
"L_FORWARD","L_INCLUDE","L_END_INCLUDE","L_OPTIONS","L_DIRECTORY","L_PIDFILE",
"L_NAMED_XFER","L_DUMP_FILE","L_STATS_FILE","L_MEMSTATS_FILE","L_FAKE_IQUERY",
"L_RECURSION","L_FETCH_GLUE","L_QUERY_SOURCE","L_LISTEN_ON","L_PORT","L_ACL",
"L_ADDRESS","L_ALGID","L_ALLOW_QUERY","L_ALLOW_TRANSFER","L_ALLOW_UPDATE",
"L_ALSO_NOTIFY","L_BLACKHOLE","L_BOGUS","L_CATEGORY","L_CHANNEL",
"L_CHECK_NAMES","L_DEBUG","L_DIALUP","L_DYNAMIC","L_FAIL","L_FIRST",
"L_FORWARDERS","L_IF_NO_ANSWER","L_IF_NO_DOMAIN","L_IGNORE","L_FILE_IXFR",
"L_IXFR_TMP","L_SEC_KEY","L_KEYS","L_LOGGING","L_MASTERS","L_NULL_OUTPUT",
"L_ONLY","L_PRINT_CATEGORY","L_PRINT_SEVERITY","L_PRINT_TIME","L_PUBKEY",
"L_RESPONSE","L_SECRET","L_SERVER","L_SEVERITY","L_SIZE","L_SUPPORT_IXFR",
"L_SYSLOG","L_TOPOLOGY","L_TRANSFER_SOURCE","L_TRANSFERS","L_TRUSTED_KEYS",
"L_VERSIONS","L_WARN","L_RRSET_ORDER","L_ORDER","L_NAME","L_CLASS","L_CONTROLS",
"L_INET","L_UNIX","L_PERM","L_OWNER","L_GROUP","L_ALLOW","L_DATASIZE",
"L_STACKSIZE","L_CORESIZE","L_DEFAULT","L_UNLIMITED","L_FILES","L_VERSION",
"L_HOSTSTATS","L_DEALLOC_ON_EXIT","L_TRANSFERS_IN","L_TRANSFERS_OUT",
"L_TRANSFERS_PER_NS","L_TRANSFER_FORMAT","L_MAX_TRANSFER_TIME_IN",
"L_ONE_ANSWER","L_MANY_ANSWERS","L_NOTIFY","L_AUTH_NXDOMAIN",
"L_MULTIPLE_CNAMES","L_USE_IXFR","L_MAINTAIN_IXFR_BASE","L_CLEAN_INTERVAL",
"L_INTERFACE_INTERVAL","L_STATS_INTERVAL","L_MAX_LOG_SIZE_IXFR","L_HEARTBEAT",
"L_USE_ID_POOL","L_MAX_NCACHE_TTL","L_HAS_OLD_CLIENTS","L_EXPERT_MODE","L_ZONE",
"L_TYPE","L_FILE","L_YES","L_TRUE","L_NO","L_FALSE",
};
const char * const yyrule[] = {
"$accept : config_file",
"config_file : statement_list",
"statement_list : statement",
"statement_list : statement_list statement",
"statement : include_stmt",
"statement : options_stmt",
"statement : controls_stmt",
"statement : logging_stmt",
"statement : server_stmt",
"statement : zone_stmt",
"statement : trusted_keys_stmt",
"statement : acl_stmt",
"statement : key_stmt",
"statement : L_END_INCLUDE",
"include_stmt : L_INCLUDE L_QSTRING L_EOS",
"$$1 :",
"options_stmt : L_OPTIONS $$1 L_LBRACE options L_RBRACE L_EOS",
"options : option L_EOS",
"options : options option L_EOS",
"option :",
"option : L_VERSION L_QSTRING",
"option : L_DIRECTORY L_QSTRING",
"option : L_NAMED_XFER L_QSTRING",
"option : L_PIDFILE L_QSTRING",
"option : L_STATS_FILE L_QSTRING",
"option : L_MEMSTATS_FILE L_QSTRING",
"option : L_DUMP_FILE L_QSTRING",
"option : L_EXPERT_MODE yea_or_nay",
"option : L_FAKE_IQUERY yea_or_nay",
"option : L_RECURSION yea_or_nay",
"option : L_FETCH_GLUE yea_or_nay",
"option : L_NOTIFY yea_or_nay",
"option : L_HOSTSTATS yea_or_nay",
"option : L_DEALLOC_ON_EXIT yea_or_nay",
"option : L_USE_IXFR yea_or_nay",
"option : L_MAINTAIN_IXFR_BASE yea_or_nay",
"option : L_HAS_OLD_CLIENTS yea_or_nay",
"option : L_AUTH_NXDOMAIN yea_or_nay",
"option : L_MULTIPLE_CNAMES yea_or_nay",
"option : L_CHECK_NAMES check_names_type check_names_opt",
"option : L_USE_ID_POOL yea_or_nay",
"option : L_LISTEN_ON maybe_port L_LBRACE address_match_list L_RBRACE",
"option : L_FORWARD forward_opt",
"$$2 :",
"option : L_FORWARDERS $$2 L_LBRACE opt_forwarders_list L_RBRACE",
"option : L_QUERY_SOURCE query_source",
"option : L_ALLOW_QUERY L_LBRACE address_match_list L_RBRACE",
"option : L_ALLOW_TRANSFER L_LBRACE address_match_list L_RBRACE",
"option : L_SORTLIST L_LBRACE address_match_list L_RBRACE",
"option : L_BLACKHOLE L_LBRACE address_match_list L_RBRACE",
"option : L_TOPOLOGY L_LBRACE address_match_list L_RBRACE",
"option : size_clause",
"option : transfer_clause",
"option : L_TRANSFER_FORMAT transfer_format",
"option : L_MAX_TRANSFER_TIME_IN L_INTEGER",
"option : L_CLEAN_INTERVAL L_INTEGER",
"option : L_INTERFACE_INTERVAL L_INTEGER",
"option : L_STATS_INTERVAL L_INTEGER",
"option : L_MAX_LOG_SIZE_IXFR L_INTEGER",
"option : L_MAX_NCACHE_TTL L_INTEGER",
"option : L_HEARTBEAT L_INTEGER",
"option : L_DIALUP yea_or_nay",
"$$3 :",
"option : L_RRSET_ORDER $$3 L_LBRACE rrset_ordering_list L_RBRACE",
"controls_stmt : L_CONTROLS L_LBRACE controls L_RBRACE L_EOS",
"controls : control L_EOS",
"controls : controls control L_EOS",
"control :",
"control : L_INET maybe_wild_addr L_PORT in_port L_ALLOW L_LBRACE address_match_list L_RBRACE",
"control : L_UNIX L_QSTRING L_PERM L_INTEGER L_OWNER L_INTEGER L_GROUP L_INTEGER",
"rrset_ordering_list : rrset_ordering_element L_EOS",
"rrset_ordering_list : rrset_ordering_list rrset_ordering_element L_EOS",
"ordering_class :",
"ordering_class : L_CLASS class_name",
"ordering_type :",
"ordering_type : L_TYPE any_string",
"ordering_name :",
"ordering_name : L_NAME domain_name",
"rrset_ordering_element : ordering_class ordering_type ordering_name L_ORDER L_STRING",
"transfer_format : L_ONE_ANSWER",
"transfer_format : L_MANY_ANSWERS",
"maybe_wild_addr : ip_address",
"maybe_wild_addr : L_STRING",
"maybe_wild_port : in_port",
"maybe_wild_port : L_STRING",
"query_source_address : L_ADDRESS maybe_wild_addr",
"query_source_port : L_PORT maybe_wild_port",
"query_source : query_source_address",
"query_source : query_source_port",
"query_source : query_source_address query_source_port",
"query_source : query_source_port query_source_address",
"maybe_port :",
"maybe_port : L_PORT in_port",
"maybe_zero_port :",
"maybe_zero_port : L_PORT in_port",
"yea_or_nay : L_YES",
"yea_or_nay : L_TRUE",
"yea_or_nay : L_NO",
"yea_or_nay : L_FALSE",
"yea_or_nay : L_INTEGER",
"check_names_type : L_MASTER",
"check_names_type : L_SLAVE",
"check_names_type : L_RESPONSE",
"check_names_opt : L_WARN",
"check_names_opt : L_FAIL",
"check_names_opt : L_IGNORE",
"forward_opt : L_ONLY",
"forward_opt : L_FIRST",
"forward_opt : L_IF_NO_ANSWER",
"forward_opt : L_IF_NO_DOMAIN",
"size_clause : L_DATASIZE size_spec",
"size_clause : L_STACKSIZE size_spec",
"size_clause : L_CORESIZE size_spec",
"size_clause : L_FILES size_spec",
"size_spec : any_string",
"size_spec : L_INTEGER",
"size_spec : L_DEFAULT",
"size_spec : L_UNLIMITED",
"transfer_clause : L_TRANSFERS_IN L_INTEGER",
"transfer_clause : L_TRANSFERS_OUT L_INTEGER",
"transfer_clause : L_TRANSFERS_PER_NS L_INTEGER",
"opt_forwarders_list :",
"opt_forwarders_list : forwarders_in_addr_list",
"forwarders_in_addr_list : forwarders_in_addr L_EOS",
"forwarders_in_addr_list : forwarders_in_addr_list forwarders_in_addr L_EOS",
"forwarders_in_addr : ip_address",
"$$4 :",
"logging_stmt : L_LOGGING $$4 L_LBRACE logging_opts_list L_RBRACE L_EOS",
"logging_opts_list : logging_opt L_EOS",
"logging_opts_list : logging_opts_list logging_opt L_EOS",
"logging_opt : category_stmt",
"logging_opt : channel_stmt",
"$$5 :",
"channel_stmt : L_CHANNEL channel_name L_LBRACE L_FILE L_QSTRING $$5 maybe_file_modifiers L_EOS optional_channel_opt_list L_RBRACE",
"$$6 :",
"channel_stmt : L_CHANNEL channel_name L_LBRACE L_SYSLOG maybe_syslog_facility $$6 L_EOS optional_channel_opt_list L_RBRACE",
"$$7 :",
"channel_stmt : L_CHANNEL channel_name L_LBRACE L_NULL_OUTPUT $$7 L_EOS optional_channel_opt_list L_RBRACE",
"channel_stmt : L_CHANNEL channel_name L_LBRACE logging_non_type_keywords",
"logging_non_type_keywords : L_SEVERITY",
"logging_non_type_keywords : L_PRINT_TIME",
"logging_non_type_keywords : L_PRINT_CATEGORY",
"logging_non_type_keywords : L_PRINT_SEVERITY",
"optional_channel_opt_list :",
"optional_channel_opt_list : channel_opt_list",
"$$8 :",
"category_stmt : L_CATEGORY category_name $$8 L_LBRACE channel_list L_RBRACE",
"channel_severity : any_string",
"channel_severity : L_DEBUG",
"channel_severity : L_DEBUG L_INTEGER",
"channel_severity : L_DYNAMIC",
"version_modifier : L_VERSIONS L_INTEGER",
"version_modifier : L_VERSIONS L_UNLIMITED",
"size_modifier : L_SIZE size_spec",
"maybe_file_modifiers :",
"maybe_file_modifiers : version_modifier",
"maybe_file_modifiers : size_modifier",
"maybe_file_modifiers : version_modifier size_modifier",
"maybe_file_modifiers : size_modifier version_modifier",
"facility_name : any_string",
"facility_name : L_SYSLOG",
"maybe_syslog_facility :",
"maybe_syslog_facility : facility_name",
"channel_opt_list : channel_opt L_EOS",
"channel_opt_list : channel_opt_list channel_opt L_EOS",
"channel_opt : L_SEVERITY channel_severity",
"channel_opt : L_PRINT_TIME yea_or_nay",
"channel_opt : L_PRINT_CATEGORY yea_or_nay",
"channel_opt : L_PRINT_SEVERITY yea_or_nay",
"channel_name : any_string",
"channel_name : L_NULL_OUTPUT",
"channel : channel_name",
"channel_list : channel L_EOS",
"channel_list : channel_list channel L_EOS",
"category_name : any_string",
"category_name : L_DEFAULT",
"category_name : L_NOTIFY",
"$$9 :",
"server_stmt : L_SERVER ip_address $$9 L_LBRACE server_info_list L_RBRACE L_EOS",
"server_info_list : server_info L_EOS",
"server_info_list : server_info_list server_info L_EOS",
"server_info : L_BOGUS yea_or_nay",
"server_info : L_SUPPORT_IXFR yea_or_nay",
"server_info : L_TRANSFERS L_INTEGER",
"server_info : L_TRANSFER_FORMAT transfer_format",
"$$10 :",
"server_info : L_KEYS L_LBRACE $$10 key_list L_RBRACE",
"address_match_list : address_match_element L_EOS",
"address_match_list : address_match_list address_match_element L_EOS",
"address_match_element : address_match_simple",
"address_match_element : L_BANG address_match_simple",
"address_match_element : L_SEC_KEY L_STRING",
"address_match_simple : ip_address",
"address_match_simple : ip4_address L_SLASH L_INTEGER",
"address_match_simple : L_INTEGER L_SLASH L_INTEGER",
"address_match_simple : address_name",
"address_match_simple : L_LBRACE address_match_list L_RBRACE",
"address_name : any_string",
"key_ref : any_string",
"key_list_element : key_ref",
"maybe_eos :",
"maybe_eos : L_EOS",
"key_list : key_list_element maybe_eos",
"key_list : key_list key_list_element maybe_eos",
"$$11 :",
"key_stmt : L_SEC_KEY any_string $$11 L_LBRACE key_definition L_RBRACE L_EOS",
"key_definition : algorithm_id secret",
"key_definition : secret algorithm_id",
"algorithm_id : L_ALGID any_string L_EOS",
"secret : L_SECRET any_string L_EOS",
"acl_stmt : L_ACL any_string L_LBRACE address_match_list L_RBRACE L_EOS",
"domain_name : L_QSTRING",
"$$12 :",
"zone_stmt : L_ZONE domain_name optional_class L_LBRACE L_TYPE zone_type L_EOS $$12 optional_zone_options_list L_RBRACE L_EOS",
"zone_stmt : L_ZONE domain_name optional_class L_LBRACE zone_non_type_keywords",
"optional_zone_options_list :",
"optional_zone_options_list : zone_option_list",
"class_name : any_string",
"optional_class :",
"optional_class : class_name",
"zone_type : L_MASTER",
"zone_type : L_SLAVE",
"zone_type : L_HINT",
"zone_type : L_STUB",
"zone_type : L_FORWARD",
"zone_option_list : zone_option L_EOS",
"zone_option_list : zone_option_list zone_option L_EOS",
"zone_non_type_keywords : L_FILE",
"zone_non_type_keywords : L_FILE_IXFR",
"zone_non_type_keywords : L_IXFR_TMP",
"zone_non_type_keywords : L_MASTERS",
"zone_non_type_keywords : L_TRANSFER_SOURCE",
"zone_non_type_keywords : L_CHECK_NAMES",
"zone_non_type_keywords : L_ALLOW_UPDATE",
"zone_non_type_keywords : L_ALLOW_QUERY",
"zone_non_type_keywords : L_ALLOW_TRANSFER",
"zone_non_type_keywords : L_FORWARD",
"zone_non_type_keywords : L_FORWARDERS",
"zone_non_type_keywords : L_MAX_TRANSFER_TIME_IN",
"zone_non_type_keywords : L_MAX_LOG_SIZE_IXFR",
"zone_non_type_keywords : L_NOTIFY",
"zone_non_type_keywords : L_MAINTAIN_IXFR_BASE",
"zone_non_type_keywords : L_PUBKEY",
"zone_non_type_keywords : L_ALSO_NOTIFY",
"zone_non_type_keywords : L_DIALUP",
"zone_option : L_FILE L_QSTRING",
"zone_option : L_FILE_IXFR L_QSTRING",
"zone_option : L_IXFR_TMP L_QSTRING",
"zone_option : L_MASTERS maybe_zero_port L_LBRACE master_in_addr_list L_RBRACE",
"zone_option : L_TRANSFER_SOURCE maybe_wild_addr",
"zone_option : L_CHECK_NAMES check_names_opt",
"zone_option : L_ALLOW_UPDATE L_LBRACE address_match_list L_RBRACE",
"zone_option : L_ALLOW_QUERY L_LBRACE address_match_list L_RBRACE",
"zone_option : L_ALLOW_TRANSFER L_LBRACE address_match_list L_RBRACE",
"zone_option : L_FORWARD zone_forward_opt",
"zone_option : L_FORWARDERS L_LBRACE opt_zone_forwarders_list L_RBRACE",
"zone_option : L_MAX_TRANSFER_TIME_IN L_INTEGER",
"zone_option : L_MAX_LOG_SIZE_IXFR L_INTEGER",
"zone_option : L_NOTIFY yea_or_nay",
"zone_option : L_MAINTAIN_IXFR_BASE yea_or_nay",
"zone_option : L_PUBKEY L_INTEGER L_INTEGER L_INTEGER L_QSTRING",
"zone_option : L_ALSO_NOTIFY L_LBRACE notify_in_addr_list L_RBRACE",
"zone_option : L_DIALUP yea_or_nay",
"master_in_addr_list : in_addr_list",
"notify_in_addr_list : opt_in_addr_list",
"ip4_address : L_IP4ADDR",
"ip6_address : L_IP6ADDR",
"ip_address : ip4_address",
"ip_address : ip6_address",
"in_addr_elem : ip_address",
"opt_in_addr_list :",
"opt_in_addr_list : in_addr_list",
"in_addr_list : in_addr_elem L_EOS",
"in_addr_list : in_addr_list in_addr_elem L_EOS",
"zone_forward_opt : L_ONLY",
"zone_forward_opt : L_FIRST",
"opt_zone_forwarders_list : opt_in_addr_list",
"$$13 :",
"trusted_keys_stmt : L_TRUSTED_KEYS $$13 L_LBRACE trusted_keys_list L_RBRACE L_EOS",
"trusted_keys_list : trusted_key L_EOS",
"trusted_keys_list : trusted_keys_list trusted_key L_EOS",
"trusted_key : domain_name L_INTEGER L_INTEGER L_INTEGER L_QSTRING",
"in_port : L_INTEGER",
"any_string : L_STRING",
"any_string : L_QSTRING",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;

static void		parser_error(isc_boolean_t lasttoken,
				     const char *fmt, ...);
static void		parser_warning(isc_boolean_t lasttoken,
				       const char *fmt, ...);
static void		parser_complain(isc_boolean_t is_warning,
					isc_boolean_t last_token,
					const char *format, va_list args);
static int		intuit_token(const char *string);

static isc_boolean_t	unit_to_uint32(char *in, isc_uint32_t *out);
static isc_boolean_t	is_ip4addr(const char *string, struct in_addr *addr);
static isc_boolean_t	is_ip6addr(const char *string, struct in6_addr *addr);
static isc_result_t	keyword_init(void);
static char *		token_to_text(int token, YYSTYPE lval);
static int		token_value(isc_token_t *token,
				    isc_symtab_t *symtable);
static void		init_action(void);


static void		yyerror(const char *);
static int		yylex(void);
int			yyparse(void);


YYSTYPE			lastyylval;
int			lasttoken;


/*
 * Definition of all unique keyword tokens to be recognised by the
 * lexer. All the ``L_'' tokens defined in parser.y must be defined here too.
 */
struct token
{
	char *token;
	int yaccval;
};

static struct token keyword_tokens [] = {
	{ "{", 				L_LBRACE },
	{ "}", 				L_RBRACE },
	{ ";", 				L_EOS },
	{ "/", 				L_SLASH },
	{ "!", 				L_BANG },

	{ "acl",			L_ACL },
	{ "address",			L_ADDRESS },
	{ "algorithm",			L_ALGID },
	{ "allow",			L_ALLOW },
	{ "allow-query",		L_ALLOW_QUERY },
	{ "allow-transfer",		L_ALLOW_TRANSFER },
	{ "allow-update",		L_ALLOW_UPDATE },
	{ "also-notify",		L_ALSO_NOTIFY },
	{ "auth-nxdomain",		L_AUTH_NXDOMAIN },
	{ "blackhole",			L_BLACKHOLE },
	{ "bogus",			L_BOGUS },
	{ "category",			L_CATEGORY },
	{ "class",			L_CLASS },
	{ "channel",			L_CHANNEL },
	{ "check-names",		L_CHECK_NAMES },
	{ "cleaning-interval",		L_CLEAN_INTERVAL },
	{ "controls",			L_CONTROLS },
	{ "coresize",			L_CORESIZE },
	{ "datasize",			L_DATASIZE },
	{ "deallocate-on-exit",		L_DEALLOC_ON_EXIT },
	{ "debug",			L_DEBUG },
	{ "default",			L_DEFAULT },
	{ "dialup",			L_DIALUP },
	{ "directory",			L_DIRECTORY },
	{ "dump-file",			L_DUMP_FILE },
	{ "dynamic",			L_DYNAMIC },
	{ "expert-mode",		L_EXPERT_MODE },
	{ "fail",			L_FAIL },
	{ "fake-iquery",		L_FAKE_IQUERY },
	{ "false",			L_FALSE },
	{ "fetch-glue",			L_FETCH_GLUE },
	{ "file",			L_FILE },
	{ "files",			L_FILES },
	{ "first",			L_FIRST },
	{ "forward",			L_FORWARD },
	{ "forwarders",			L_FORWARDERS },
	{ "group",			L_GROUP },
	{ "has-old-clients",		L_HAS_OLD_CLIENTS },
	{ "heartbeat-interval",		L_HEARTBEAT },
	{ "hint",			L_HINT },
	{ "host-statistics",		L_HOSTSTATS },
	{ "if-no-answer",		L_IF_NO_ANSWER },
	{ "if-no-domain",		L_IF_NO_DOMAIN },
	{ "ignore",			L_IGNORE },
	{ "include",			L_INCLUDE },
	{ "inet",			L_INET },
	{ "interface-interval",		L_INTERFACE_INTERVAL },
	{ "ixfr-base",			L_FILE_IXFR },
	{ "ixfr-tmp-file",		L_IXFR_TMP },
	{ "key",			L_SEC_KEY },
	{ "keys",			L_KEYS },
	{ "listen-on",			L_LISTEN_ON },
	{ "logging",			L_LOGGING },
	{ "maintain-ixfr-base",		L_MAINTAIN_IXFR_BASE },
	{ "many-answers",		L_MANY_ANSWERS },
	{ "master",			L_MASTER },
	{ "masters",			L_MASTERS },
	{ "max-ixfr-log-size",		L_MAX_LOG_SIZE_IXFR },
	{ "max-ncache-ttl",		L_MAX_NCACHE_TTL },
	{ "max-transfer-time-in",	L_MAX_TRANSFER_TIME_IN },
	{ "memstatistics-file",		L_MEMSTATS_FILE },
	{ "multiple-cnames",		L_MULTIPLE_CNAMES },
	{ "name",			L_NAME },
	{ "named-xfer",			L_NAMED_XFER },
	{ "no",				L_NO },
	{ "notify",			L_NOTIFY },
	{ "null",			L_NULL_OUTPUT },
	{ "one-answer",			L_ONE_ANSWER },
	{ "only",			L_ONLY },
	{ "order",			L_ORDER },
	{ "options",			L_OPTIONS },
	{ "owner",			L_OWNER },
	{ "perm",			L_PERM },
	{ "pid-file",			L_PIDFILE },
	{ "port",			L_PORT },
	{ "print-category",		L_PRINT_CATEGORY },
	{ "print-severity",		L_PRINT_SEVERITY },
	{ "print-time",			L_PRINT_TIME },
	{ "pubkey",			L_PUBKEY },
	{ "query-source",		L_QUERY_SOURCE },
	{ "rrset-order",		L_RRSET_ORDER },
	{ "recursion",			L_RECURSION },
	{ "response",			L_RESPONSE },
	{ "secret",			L_SECRET },
	{ "server",			L_SERVER },
	{ "severity",			L_SEVERITY },
	{ "size",			L_SIZE },
	{ "slave",			L_SLAVE },
	{ "sortlist",			L_SORTLIST },
	{ "stacksize",			L_STACKSIZE },
	{ "statistics-file",		L_STATS_FILE },
	{ "statistics-interval",	L_STATS_INTERVAL },
	{ "stub",			L_STUB },
	{ "support-ixfr",		L_SUPPORT_IXFR },
	{ "syslog",			L_SYSLOG },
	{ "topology",			L_TOPOLOGY },
	{ "transfer-format",		L_TRANSFER_FORMAT },
	{ "transfer-source",		L_TRANSFER_SOURCE },
	{ "transfers",			L_TRANSFERS },
	{ "transfers-in",		L_TRANSFERS_IN },
	{ "transfers-out",		L_TRANSFERS_OUT },
	{ "transfers-per-ns",		L_TRANSFERS_PER_NS },
	{ "true",			L_TRUE },
	{ "trusted-keys",		L_TRUSTED_KEYS },
	{ "type",			L_TYPE },
	{ "unix",			L_UNIX },
	{ "unlimited",			L_UNLIMITED },
	{ "use-id-pool",		L_USE_ID_POOL },
	{ "use-ixfr",			L_USE_IXFR },
	{ "version",			L_VERSION },
	{ "versions",			L_VERSIONS },
	{ "warn",			L_WARN },
	{ "yes",			L_YES },
	{ "zone",			L_ZONE },

	{ NULL, 0 }
};


static struct token class_symbol_tokens[] = {
	{ "IN", dns_rdataclass_in },
#if 0					/* XXX expand */
	{ "CHAOS", dns_rdataclass_chaos },
	{ "HS", dns_rdataclass_hs },
	{ "HESIOD", dns_rdataclass_hs },
#endif
	{ "ANY", dns_rdataclass_any },
	{ "NONE", dns_rdataclass_none },
	{ NULL, 0 }
};


static isc_once_t once = ISC_ONCE_INIT;


static void
init_action(void)
{
	isc_mutex_init(&yacc_mutex);
}


/*
 * XXX Need a parameter to specify where error messages should go (syslog, 
 * FILE, /dev/null etc.) Also some way to tell the function to obey logging 
 * statments as appropriate.
 */
  
isc_result_t
dns_c_parse_namedconf(const char *filename, isc_mem_t *mem,
		    dns_c_ctx_t **configctx, dns_c_cbks_t *cbks)
{
	isc_result_t res;
	const char *funcname = "dns_parse_namedconf";

        RUNTIME_CHECK(isc_once_do(&once, init_action) == ISC_R_SUCCESS);
	
	/* Lock down whole parser. */
	if (isc_mutex_lock(&yacc_mutex) != ISC_R_SUCCESS) {
		return (ISC_R_UNEXPECTED);
	}

	REQUIRE(currcfg == NULL);
	REQUIRE(filename != NULL);
	REQUIRE(strlen(filename) > 0);
	REQUIRE(configctx != NULL);
	INSIST(mylexer == NULL);
	INSIST(memctx == NULL);
	INSIST(keywords == NULL);
	INSIST(callbacks == NULL);

	if (getenv("DEBUG_LEXER") != NULL) { /* XXX debug */
		debug_lexer++;
	}

	specials['{'] = 1;
	specials['}'] = 1;
	specials[';'] = 1;
	specials['/'] = 1;
	specials['"'] = 1;
	specials['!'] = 1;
#if 0
	specials['*'] = 1;
#endif

	/*
	 * This memory context is only used by the lexer routines (and must 
	 * stay that way). Any memory that must live past the return of
	 * yyparse() must be allocated via the 'mem' parameter to this
	 * function.
	*/
	res = isc_mem_create(0, 0, &memctx);
	if (res != ISC_R_SUCCESS) {
		dns_c_error(res, "%s: Error creating mem context.",
			    funcname);
		goto done;
	}

	res = keyword_init();
	if (res != ISC_R_SUCCESS) {
		dns_c_error(res, "%s: Error initializing keywords.",
			    funcname);
		goto done;
	}

	res = dns_c_ctx_new(mem, &currcfg);
	if (res != ISC_R_SUCCESS) {
		dns_c_error(res, "%s: Error creating config context.",
			    funcname);
		goto done;
	}

	res = isc_lex_create(memctx, CONF_MAX_IDENT, &mylexer);
	if (res != ISC_R_SUCCESS) {
		dns_c_error(res, "%s: Error creating lexer",
			    funcname);
		goto done;
	}
	
	isc_lex_setspecials(mylexer, specials);
	isc_lex_setcomments(mylexer, (ISC_LEXCOMMENT_C |
				      ISC_LEXCOMMENT_CPLUSPLUS |
				      ISC_LEXCOMMENT_SHELL));

	res = isc_lex_openfile(mylexer, (char *)filename) ; /* remove const */
	if (res != ISC_R_SUCCESS) {
		dns_c_error(res, "%s: Error opening file %s.",
			    funcname, filename);
		goto done;
	}

	callbacks = cbks;
	
	if (yyparse() != 0) {
		res = ISC_R_FAILURE;

		/* Syntax errors in the config file make it very difficult
		 * to clean up memory properly (which causes assertion
		 * failure when the memory manager is destroyed).
		 */
		isc_mem_destroy_check(memctx, ISC_FALSE);

		dns_c_ctx_delete(&currcfg);
		currcfg = NULL;
	} else {
		res = ISC_R_SUCCESS;
	}


 done:
	if (mylexer != NULL)
		isc_lex_destroy(&mylexer);

	isc_symtab_destroy(&keywords);

	isc_mem_destroy(&memctx);

	*configctx = currcfg;

	callbacks = NULL;
	currcfg = NULL;
	memctx = NULL;
	mylexer = NULL;

	RUNTIME_CHECK(isc_mutex_unlock(&yacc_mutex) == ISC_R_SUCCESS);

	return (res);
}



/***
 *** PRIVATE
 ***/

static isc_result_t
keyword_init(void)
{
	struct token *tok;
	isc_symvalue_t symval;

	RUNTIME_CHECK(isc_symtab_create(memctx, 97 /* prime < 100 */,
					NULL, NULL, ISC_FALSE,
					&keywords) == ISC_R_SUCCESS);


	/* Stick all the keywords into the main symbol table. */
	for (tok = &keyword_tokens[0] ; tok->token != NULL ; tok++) {
		symval.as_integer = tok->yaccval;
		RUNTIME_CHECK(isc_symtab_define(keywords, tok->token,
						KEYWORD_SYM_TYPE, symval,
						isc_symexists_reject) ==
			      ISC_R_SUCCESS);
	}

	/* Now the class names */
	for (tok = &class_symbol_tokens[0] ; tok->token != NULL ; tok++) {
		symval.as_integer = tok->yaccval;
		RUNTIME_CHECK(isc_symtab_define(keywords, tok->token,
						CLASS_SYM_TYPE, symval,
						isc_symexists_reject) ==
			      ISC_R_SUCCESS);
	}

	return (ISC_R_SUCCESS);
}



static int
yylex(void)
{
	isc_token_t token;
	isc_result_t res;
	int options = (ISC_LEXOPT_EOF |
		       ISC_LEXOPT_NUMBER |
		       ISC_LEXOPT_QSTRING |
		       ISC_LEXOPT_NOMORE);

	INSIST(mylexer != NULL);

	res = isc_lex_gettoken(mylexer, options, &token);

	switch(res) {
	case ISC_R_SUCCESS:
		res = token_value(&token, keywords); /* modifies yylval */
		break;

	case ISC_R_EOF:
		res = 0;
		break;

	case ISC_R_UNBALANCED:
		parser_error(ISC_TRUE,
			     "%s: %d: unbalanced parentheses",
			      isc_lex_getsourcename(mylexer),
			     (int)isc_lex_getsourceline(mylexer));
		res = -1;
		break;

	case ISC_R_NOSPACE:
		parser_error(ISC_TRUE,
			     "%s: %d: token too big.",
			     isc_lex_getsourcename(mylexer),
			     (int)isc_lex_getsourceline(mylexer));
		res = -1;
		break;

	case ISC_R_UNEXPECTEDEND:
		parser_error(ISC_TRUE,
			     "%s: %d: unexpected EOF",
			     isc_lex_getsourcename(mylexer),
			     (int)isc_lex_getsourceline(mylexer));
		res = -1;
		break;

	default:
		parser_error(ISC_TRUE,
			     "%s: %d unknown lexer error (%d)",
			     isc_lex_getsourcename(mylexer),
			     (int)isc_lex_getsourceline(mylexer),
			     (int)res);
		res = -1;
		break;
	}


	lastyylval = yylval;
	lasttoken = res;

	return (res);
}



static char *
token_to_text(int token, YYSTYPE lval) {
	static char buffer[1024];
	int i;

	/* Yacc keeps token numbers above 128, it seems. */
	if (token < 128) {
		if (token == 0)
			strncpy(buffer, "<end of file>", sizeof buffer);
		else
			if ((unsigned int) sprintf(buffer, "'%c'", token)
			    >= sizeof buffer) {
				abort();
			}
	} else {
		switch (token) {
		case L_STRING:
			if ((unsigned int) sprintf(buffer, "'%s'",
						   lval.text) >=
			    sizeof buffer) {
				abort();
			}
			break;
		case L_QSTRING:
			if ((unsigned int) sprintf(buffer, "\"%s\"",
						   lval.text) >=
			    sizeof buffer) {
				abort();
			}
			break;
		case L_IP6ADDR:
			strcpy(buffer, "UNAVAILABLE-IPV6-ADDRESS");
			inet_ntop(AF_INET6, &lval.ip6_addr.s6_addr,
				  buffer, sizeof buffer);
			break;
		case L_IP4ADDR:
			strcpy(buffer, "UNAVAILABLE-IPV4-ADDRESS");
			inet_ntop(AF_INET, &lval.ip4_addr.s_addr,
				  buffer, sizeof buffer);
			break;
		case L_INTEGER:
			sprintf(buffer, "%ld", (long)lval.ul_int);
			break;
		case L_END_INCLUDE:
			strcpy (buffer, "<end of include>");
			break;
		default:
			for (i = 0 ; keyword_tokens[i].token != NULL ; i++) {
				if (keyword_tokens[i].yaccval == token)
					break;
			}

			if (keyword_tokens[i].token == NULL) {
				sprintf(buffer, "UNKNOWN-TOKEN-TYPE (%d)",
					(int)token);
			} else {
				strncpy(buffer, keyword_tokens[i].token,
					sizeof buffer - 1);
				buffer[sizeof buffer - 1] = '\0';
			}
		}
	}

	return (buffer);
}


static void
parser_complain(isc_boolean_t is_warning, isc_boolean_t print_last_token,
		const char *format, va_list args)
{
	static char where[PATH_MAX + 100];
	static char message[20480];

	const char *filename = isc_lex_getsourcename(mylexer);
	int lineno = isc_lex_getsourceline(mylexer);

	/*
	 * We can't get a trace of the include files we may be nested in
	 * (lex.c has the structures hidden). So we only report the current
	 * file.
	 */
	if (filename == NULL) {
		filename = "(none)";
	}

	sprintf(where, "%s:%d ", filename, lineno);
	if ((unsigned int)vsprintf(message, format, args) >= sizeof message) {
		abort();
	}

	/* XXX this needs to use the log system instead of stdio.  */
	(void) is_warning;		/* lint happiness */

	if (print_last_token) {
		fprintf(stderr, "%s%s near ``%s''\n", where, message,
			token_to_text(lasttoken, lastyylval));
	} else {
		fprintf(stderr, "%s%s\n", where, message);
	}
}




/*
 * For reporting items that are semantic, but not syntactic errors
 */
static void
parser_error(isc_boolean_t lasttoken, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	parser_complain(ISC_TRUE, lasttoken, fmt, args);
	va_end(args);

	currcfg->errors++;
}


static void
parser_warning(isc_boolean_t lasttoken, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	parser_complain(ISC_FALSE, lasttoken, fmt, args);
	va_end(args);

	currcfg->warnings++;
}


static void
yyerror(const char *string)
{
	parser_error(ISC_TRUE, string);
}



static int
token_value(isc_token_t *token, isc_symtab_t *symtable)
{
	int res = -1;
	const char *tokstring;
	char tmpident [2];
	isc_symvalue_t keywordtok;

	switch (token->type) {
	case isc_tokentype_unknown:
		if (debug_lexer) {
			fprintf(stderr, "unknown lexer token\n");
		}

		res = -1;
		break;

	case isc_tokentype_special:
	case isc_tokentype_string:
		if (token->type == isc_tokentype_special) {
			tmpident[0] = token->value.as_char;
			tmpident[1] = '\0';
			tokstring = tmpident;
		} else {
			tokstring = token->value.as_textregion.base;
		}

		if (debug_lexer) {
			fprintf(stderr, "lexer token: %s : %s\n",
				(token->type == isc_tokentype_special ?
				 "special" : "string"), tokstring);
		}

		res = isc_symtab_lookup(symtable, tokstring,
					KEYWORD_SYM_TYPE, &keywordtok);

		if (res != ISC_R_SUCCESS) {
			res = intuit_token(tokstring);
		} else {
			res = keywordtok.as_integer;
		}
		break;

	case isc_tokentype_number:
		yylval.ul_int = (isc_uint32_t)token->value.as_ulong;
		res = L_INTEGER;

		if(debug_lexer) {
			fprintf(stderr, "lexer token: number : %lu\n",
				(unsigned long)yylval.ul_int);
		}

		break;

	case isc_tokentype_qstring:
		yylval.text = isc_mem_strdup(memctx,
					     token->value.as_textregion.base);
		if (yylval.text == NULL) {
			res = -1;
		} else {
			res = L_QSTRING;
		}

		if (debug_lexer) {
			fprintf(stderr, "lexer token: qstring : \"%s\"\n",
				yylval.text);
		}

		break;

	case isc_tokentype_eof:
		res = isc_lex_close(mylexer);
		INSIST(res == ISC_R_NOMORE || res == ISC_R_SUCCESS);

		if (isc_lex_getsourcename(mylexer) == NULL) {
			/* the only way to tell that we
			 *  closed the main file and not an included file
			 */
			if (debug_lexer) {
				fprintf(stderr, "lexer token: EOF\n");
			}
			res = 0;
		} else {
			if (debug_lexer) {
				fprintf(stderr, "lexer token: EOF (main)\n");
			}
			res = L_END_INCLUDE;
		}
		break;

	case isc_tokentype_initialws:
		if (debug_lexer) {
			fprintf(stderr, "lexer token: initial ws\n");
		}
		res = -1;
		break;

	case isc_tokentype_eol:
		if (debug_lexer) {
			fprintf(stderr, "lexer token: eol\n");
		}
		res = -1;
		break;

	case isc_tokentype_nomore:
		if (debug_lexer) {
			fprintf(stderr, "lexer token: nomore\n");
		}
		res = -1;
		break;
	}

	return (res);
}




static int
intuit_token(const char *string)
{
	int resval;

	if (is_ip4addr(string, &yylval.ip4_addr)) {
		resval = L_IP4ADDR;
	} else if (is_ip6addr(string, &yylval.ip6_addr)) {
		resval = L_IP6ADDR;
	} else {
		yylval.text = isc_mem_strdup(memctx, string);
		if (yylval.text == NULL) {
			resval = -1;
		} else {
			resval = L_STRING;
		}
	}

	return (resval);
}


/*
 * Conversion Routines
 */

static isc_boolean_t
unit_to_uint32(char *in, isc_uint32_t *out) {
	int c, units_done = 0;
	isc_uint32_t result = 0L;

	INSIST(in != NULL);

	for (; (c = *in) != '\0'; in++) {
		if (units_done)
			return (0);
		if (isdigit(c)) {
			result *= 10;
			result += (c - '0');
		} else {
			switch (c) {
			case 'k':
			case 'K':
				result *= 1024;
				units_done = 1;
				break;
			case 'm':
			case 'M':
				result *= (1024*1024);
				units_done = 1;
				break;
			case 'g':
			case 'G':
				result *= (1024*1024*1024);
				units_done = 1;
				break;
			default:
				return (0);
			}
		}
	}

	*out = result;
	return (1);
}


static isc_boolean_t
is_ip6addr(const char *string, struct in6_addr *addr)
{
#if 1
	/* XXX this need to be properly fixed for IPv6 */
	if (inet_pton(AF_INET6, string, addr) != 1) {
		return ISC_FALSE;
	}
	return ISC_TRUE;
#else
	(void)string;
	(void)addr;
	return ISC_FALSE;
#endif
}



static isc_boolean_t
is_ip4addr(const char *string, struct in_addr *addr)
{
	char addrbuf[sizeof "xxx.xxx.xxx.xxx" + 1];
	const char *p = string;
	int dots = 0;
	char dot = '.';

	while (*p) {
		if (!isdigit(*p) && *p != dot) {
			return (ISC_FALSE);
		} else if (!isdigit(*p)) {
			dots++;
		}
		p++;
	}

	if (dots > 3) {
		return (ISC_FALSE);
	} else if (dots < 3) {
		if (dots == 1) {
			if (strlen(string) + 5 <= sizeof (addrbuf)) {
				strcpy(addrbuf, string);
				strcat(addrbuf, ".0.0");
			} else {
				return (ISC_FALSE);
			}
		} else if (dots == 2) {
			if (strlen(string) + 3 <= sizeof (addrbuf)) {
				strcpy(addrbuf, string);
				strcat(addrbuf, ".0");
			} else {
				return (ISC_FALSE);
			}
		}
	} else if (strlen(string) < sizeof addrbuf) {
		strcpy (addrbuf, string);
	} else {
		return (ISC_FALSE);
	}
	
	if (inet_pton(AF_INET, addrbuf, addr) != 1) {
		return ISC_FALSE;
	}
	return ISC_TRUE;
}
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack()
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
    if ((newss = (short *)realloc(yyss, newsize * sizeof *newss)) == NULL)
        return -1;
    yyss = newss;
    yyssp = newss + i;
    if ((newvs = (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs)) == NULL)
        return -1;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab

int
yyparse()
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register const char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate])) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 14:
{
		if (isc_lex_openfile(mylexer, yyvsp[-1].text) != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE ,"Can't open file %s\n",
				     yyvsp[-1].text);
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[-1].text);
	}
break;
case 15:
{
		dns_c_options_t *options;

		tmpres = dns_c_ctx_get_options(currcfg, &options);
		if (tmpres == ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Cannot redefine options");

			/*
			 * Clean out options so rest of config won't fail
			 * or issue extra error messages
			 */
			dns_c_ctx_options_delete(&currcfg->options);
		}

		tmpres = dns_c_ctx_options_new(currcfg->mem,
					       &currcfg->options);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to create options structure: %s",
				     isc_result_totext(tmpres));
			YYABORT;
		}
		
	}
break;
case 16:
{
		if (callbacks != NULL && callbacks->optscbk != NULL) {
			tmpres = callbacks->optscbk(currcfg,
						    callbacks->optscbkuap);
			if (tmpres != ISC_R_SUCCESS) {
				YYABORT;
			}
		}
	}
break;
case 20:
{
		tmpres = dns_c_ctx_set_version(currcfg, yyvsp[0].text);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining version.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "set version error %s: %s",
				     isc_result_totext(tmpres), yyvsp[0].text);
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 21:
{
		tmpres = dns_c_ctx_set_directory(currcfg, yyvsp[0].text);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining directory");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error setting directory: %s: %s",
				     isc_result_totext(tmpres), yyvsp[0].text);
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 22:
{
		tmpres = dns_c_ctx_set_named_xfer(currcfg, yyvsp[0].text);

		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining named-xfer");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "set named-xfer error: %s: %s",
				     isc_result_totext(tmpres), yyvsp[0].text);
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 23:
{
		tmpres = dns_c_ctx_set_pid_filename(currcfg, yyvsp[0].text);

		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining pid-file");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "set pidfile error %s: %s",
				     isc_result_totext(tmpres), yyvsp[0].text);
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 24:
{
		tmpres = dns_c_ctx_set_stats_filename(currcfg, yyvsp[0].text);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining statistics-file");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "set statsfile error %s: %s",
				     isc_result_totext(tmpres), yyvsp[0].text);
			YYABORT;
		}
		
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 25:
{
		tmpres = dns_c_ctx_set_memstats_filename(currcfg, yyvsp[0].text);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining memstatistics-file");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "set memstatsfile error %s: %s",
				     isc_result_totext(tmpres), yyvsp[0].text);
			YYABORT;
		}
		
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 26:
{
		tmpres = dns_c_ctx_set_dump_filename(currcfg, yyvsp[0].text);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining dump-file");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "set dumpfile error %s: %s",
				     isc_result_totext(tmpres), yyvsp[0].text);
			YYABORT;
		}
		
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 27:
{
		tmpres = dns_c_ctx_set_expert_mode(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining fake-iquery.");
		}
	}
break;
case 28:
{
		tmpres = dns_c_ctx_set_fake_iquery(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining fake-iquery.");
		}
	}
break;
case 29:
{
		tmpres = dns_c_ctx_set_recursion(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining recursion");
		}
	}
break;
case 30:
{
		tmpres = dns_c_ctx_set_fetch_glue(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining fetch-glue.");
		}
	}
break;
case 31:
{
		tmpres = dns_c_ctx_set_notify(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining notify.");
		}
	}
break;
case 32:
{
		tmpres = dns_c_ctx_set_host_statistics(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining host-statistics.");
		}
	}
break;
case 33:
{
		tmpres = dns_c_ctx_set_dealloc_on_exit(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining deallocate-on-exit.");
		}
	}
break;
case 34:
{
		tmpres = dns_c_ctx_set_use_ixfr(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining use-ixfr.");
		}
	}
break;
case 35:
{
		tmpres = dns_c_ctx_set_maintain_ixfr_base(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining maintain-ixfr-base.");
		}
	}
break;
case 36:
{
		tmpres = dns_c_ctx_set_has_old_clients(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining has-old-clients.");
		}
	}
break;
case 37:
{
		tmpres = dns_c_ctx_set_auth_nx_domain(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining auth-nxdomain.");
		}
	}
break;
case 38:
{
		tmpres = dns_c_ctx_set_multiple_cnames(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining multiple-cnames.");
		}
	}
break;
case 39:
{
		tmpres = dns_c_ctx_set_checknames(currcfg, yyvsp[-1].transport, yyvsp[0].severity);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining check-names.");
		}
	}
break;
case 40:
{
		tmpres = dns_c_ctx_set_use_id_pool(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining use-id-pool.");
		}
	}
break;
case 41:
{
		if (yyvsp[-1].iml == NULL) {
			parser_warning(ISC_FALSE,
				       "address-match-list empty. "
				       "listen statement ignored.");
		} else {
			tmpres = dns_c_ctx_add_listen_on(currcfg, yyvsp[-3].port_int, yyvsp[-1].iml,
							 ISC_FALSE);

			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "Failed to add listen statement");
				YYABORT;
			}
		}
	}
break;
case 42:
{
		tmpres = dns_c_ctx_set_forward(currcfg, yyvsp[0].forward);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining forward");
		}
	}
break;
case 43:
{
		dns_c_ipmatch_list_t *forwarders;

		tmpres = dns_c_ctx_get_forwarders(currcfg, &forwarders);
		if (tmpres != ISC_R_NOTFOUND) {
			parser_error(ISC_FALSE,
				     "Redefining options forwarders");
			dns_c_ipmatch_list_empty(forwarders);
		} else {
			tmpres = dns_c_ipmatch_list_new(currcfg->mem,
						        &forwarders);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "Failed to create "
					     "forwarders list");
				YYABORT;
			}

			tmpres = dns_c_ctx_set_forwarders(currcfg, forwarders,
							  ISC_FALSE);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "Failed to set forwarders list.");
				YYABORT;
			}
		}
	}
break;
case 46:
{
		tmpres = dns_c_ctx_set_queryacl(currcfg, ISC_FALSE, yyvsp[-1].iml);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining allow-query list");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set allow-query");
			YYABORT;
		}
	}
break;
case 47:
{
		tmpres = dns_c_ctx_set_transferacl(currcfg, ISC_FALSE, yyvsp[-1].iml);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining allow-transfer list");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set allow-transfer");
			YYABORT;
		}
	}
break;
case 48:
{
		tmpres = dns_c_ctx_set_sortlist(currcfg, ISC_FALSE, yyvsp[-1].iml);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining sortlist.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Failed to set sortlist");
			YYABORT;
		}
	}
break;
case 49:
{
		tmpres = dns_c_ctx_set_blackhole(currcfg, ISC_FALSE, yyvsp[-1].iml);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining blackhole.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Failed to set blackhole");
			YYABORT;
		}
	}
break;
case 50:
{
		tmpres = dns_c_ctx_set_topology(currcfg, ISC_FALSE, yyvsp[-1].iml);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining topology.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Failed to set topology.");
			YYABORT;
		}
	}
break;
case 53:
{
		tmpres = dns_c_ctx_set_transfer_format(currcfg, yyvsp[0].tformat);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining transfer-format.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set transfer-format.");
			YYABORT;
		}
	}
break;
case 54:
{
		tmpres = dns_c_ctx_set_max_transfer_time_in(currcfg, yyvsp[0].l_int * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining max-transfer-time-in.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set max-transfer-time-in.");
			YYABORT;
		}
	}
break;
case 55:
{
		tmpres = dns_c_ctx_set_clean_interval(currcfg, yyvsp[0].l_int * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining cleaning-interval.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set cleaning-interval.");
			YYABORT;
		}
	}
break;
case 56:
{
		tmpres = dns_c_ctx_set_interface_interval(currcfg, yyvsp[0].l_int *
							  60);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining interface-interval.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set interface-interval.");
			YYABORT;
		}
	}
break;
case 57:
{
		tmpres = dns_c_ctx_set_stats_interval(currcfg, yyvsp[0].l_int * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining statistics-interval.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set statistics-interval.");
			YYABORT;
		}
	}
break;
case 58:
{
		tmpres = dns_c_ctx_set_max_log_size_ixfr(currcfg, yyvsp[0].l_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining max-ixfr-log-size.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set max-ixfr-log-size.");
			YYABORT;
		}
	}
break;
case 59:
{
		tmpres = dns_c_ctx_set_max_ncache_ttl(currcfg, yyvsp[0].l_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining max-ncache-ttl.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set max-ncache-ttl.");
			YYABORT;
		}
	}
break;
case 60:
{
		tmpres = dns_c_ctx_set_heartbeat_interval(currcfg, yyvsp[0].l_int *
							  60);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining heartbeat-interval.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set heartbeat-interval.");
			YYABORT;
		}
	}
break;
case 61:
{
		tmpres = dns_c_ctx_set_dialup(currcfg, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining dialup.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Failed to set dialup.");
			YYABORT;
		}
	}
break;
case 62:
{
		dns_c_rrso_list_t *ordering;

		tmpres = dns_c_ctx_get_rrsetorder_list(currcfg, &ordering);
		if (tmpres != ISC_R_NOTFOUND) {
			parser_error(ISC_FALSE,
				     "Redefining rrset-order list");
			dns_c_rrso_list_clear(ordering);
		} else {
			tmpres = dns_c_rrso_list_new(currcfg->mem, &ordering);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "Failed to create rrset-order "
					     "list");
				YYABORT;
			}
			tmpres = dns_c_ctx_set_rrsetorder_list(currcfg,
							       ISC_FALSE,
							       ordering);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "Failed to set rrset-order.");
				YYABORT;
			}
		}
	}
break;
case 68:
{
		dns_c_ctrl_t *control;

		tmpres = dns_c_ctrl_inet_new(currcfg->mem, &control,
					     yyvsp[-6].ipaddress, yyvsp[-4].port_int, yyvsp[-1].iml, ISC_FALSE);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to build inet control structure");
			YYABORT;
		}

		ISC_LIST_APPEND(currcfg->controls->elements, control, next);
	}
break;
case 69:
{
		dns_c_ctrl_t *control;

		tmpres = dns_c_ctrl_unix_new(currcfg->mem, &control,
					     yyvsp[-6].text, yyvsp[-4].l_int, yyvsp[-2].l_int, yyvsp[0].l_int);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to build unix control structure");
			YYABORT;
		}

		ISC_LIST_APPEND(currcfg->controls->elements, control, next);

		isc_mem_free(memctx, yyvsp[-6].text);
	}
break;
case 72:
{
		yyval.orderclass = dns_rdataclass_any;
	}
break;
case 73:
{
		yyval.orderclass = yyvsp[0].rrclass;
	}
break;
case 74:
{
		yyval.ordertype = dns_rdatatype_any;
	}
break;
case 75:
{
		isc_textregion_t reg;
		dns_rdatatype_t ty;

		if (strcmp(yyvsp[0].text, "*") == 0) {
			ty = dns_rdatatype_any;
		} else {
			reg.base = yyvsp[0].text;
			reg.length = strlen(yyvsp[0].text);
		
			tmpres = dns_rdatatype_fromtext(&ty, &reg);
			if (tmpres != DNS_R_SUCCESS) {
				parser_warning(ISC_TRUE,
					       "Unknown type. Assuming ``*''");
				ty = dns_rdatatype_any;
			}
		}
		
		isc_mem_free(memctx, yyvsp[0].text);
		yyval.ordertype = ty;
	}
break;
case 76:
{
		yyval.text = isc_mem_strdup(memctx, "*");
	}
break;
case 77:
{
		yyval.text = yyvsp[0].text;
	}
break;
case 78:
{
		dns_c_rrso_t *orderelem;
		dns_c_ordering_t o;

		tmpres = dns_c_string2ordering(yyvsp[0].text, &o);
		if (tmpres != ISC_R_SUCCESS) {
			parser_warning(ISC_FALSE,
				       "Unknown ordering type ``%s''."
				       " Using default", yyvsp[0].text);
			o = DNS_DEFAULT_ORDERING;
		}

		tmpres = dns_c_rrso_new(currcfg->mem,
					&orderelem, yyvsp[-4].orderclass, yyvsp[-3].ordertype, yyvsp[-2].text, o);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to create rrset-order element");
			YYABORT;
		}

		ISC_LIST_APPEND(currcfg->options->ordering->elements,
				orderelem, next);

		isc_mem_free(memctx, yyvsp[0].text);
		isc_mem_free(memctx, yyvsp[-2].text);
	}
break;
case 79:
{
		yyval.tformat = dns_one_answer;
	}
break;
case 80:
{
		yyval.tformat = dns_many_answers;
	}
break;
case 81:
{
		yyval.ipaddress = yyvsp[0].ipaddress;
	}
break;
case 82:
{
		yyval.ipaddress.a_family = AF_INET;
		yyval.ipaddress.u.a.s_addr = htonl(INADDR_ANY);

		if (strcmp(yyvsp[0].text, "*") != 0) {
			parser_error(ISC_TRUE,
				     "Bad ip-address. Using ``*''");
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 83:
{
		yyval.port_int = yyvsp[0].port_int;
	}
break;
case 84:
{
		yyval.port_int = htons(0);

		if (strcmp (yyvsp[0].text, "*") != 0) {
			parser_error(ISC_TRUE,
				     "Bad port specification. Using ``*''");
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 85:
{
		tmpres = dns_c_ctx_set_query_source_addr(currcfg, yyvsp[0].ipaddress);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining query-source address.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set query-source address.");
			YYABORT;
		}
	}
break;
case 86:
{
		tmpres = dns_c_ctx_set_query_source_port(currcfg, yyvsp[0].port_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining query-source port.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set query-source port.");
			YYABORT;
		}
	}
break;
case 91:
{
		yyval.port_int = htons(DNS_C_DEFAULTPORT);
	}
break;
case 92:
{
		yyval.port_int = yyvsp[0].port_int;
	}
break;
case 93:
{
		yyval.port_int = htons(0);
	}
break;
case 94:
{
		yyval.port_int = yyvsp[0].port_int;
	}
break;
case 95:
{
		yyval.boolean = isc_boolean_true;
	}
break;
case 96:
{
		yyval.boolean = isc_boolean_true;
	}
break;
case 97:
{
		yyval.boolean = isc_boolean_false;
	}
break;
case 98:
{
		yyval.boolean = isc_boolean_false;
	}
break;
case 99:
{
		if (yyvsp[0].l_int == 1) {
			yyval.boolean = isc_boolean_true;
		} else if (yyvsp[0].l_int == 0) {
			yyval.boolean = isc_boolean_false;
		} else {
			parser_warning(ISC_TRUE,
				       "number should be 0 or 1; assuming 1");
			yyval.boolean = isc_boolean_true;
		}
	}
break;
case 100:
{
		yyval.transport = dns_trans_primary;
	}
break;
case 101:
{
		yyval.transport = dns_trans_secondary;
	}
break;
case 102:
{
		yyval.transport = dns_trans_response;
	}
break;
case 103:
{
		yyval.severity = dns_c_severity_warn;
	}
break;
case 104:
{
		yyval.severity = dns_c_severity_fail;
	}
break;
case 105:
{
		yyval.severity = dns_c_severity_ignore;
	}
break;
case 106:
{
		yyval.forward = dns_c_forw_only;
	}
break;
case 107:
{
		yyval.forward = dns_c_forw_first;
	}
break;
case 108:
{
		yyval.forward = dns_c_forw_no_answer;
	}
break;
case 109:
{
		yyval.forward = dns_c_forw_no_domain;
	}
break;
case 110:
{
		tmpres = dns_c_ctx_set_data_size(currcfg, yyvsp[0].ul_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining datasize.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Failed to set datasize.");
			YYABORT;
		}
	}
break;
case 111:
{
		tmpres = dns_c_ctx_set_stack_size(currcfg, yyvsp[0].ul_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining stacksize.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Failed to set stacksize.");
			YYABORT;
		}
	}
break;
case 112:
{
		tmpres = dns_c_ctx_set_core_size(currcfg, yyvsp[0].ul_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining coresize.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Failed to set coresize.");
			YYABORT;
		}
	}
break;
case 113:
{
		tmpres = dns_c_ctx_set_files(currcfg, yyvsp[0].ul_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining files.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Failed to set files.");
			YYABORT;
		}
	}
break;
case 114:
{
		isc_uint32_t result;

		if (unit_to_uint32(yyvsp[0].text, &result)) {
			yyval.ul_int = result;
			if (yyval.ul_int == DNS_C_SIZE_SPEC_DEFAULT) {
				isc_uint32_t newi = DNS_C_SIZE_SPEC_DEFAULT-1;
				parser_warning(ISC_FALSE,
					       "value (%lu) too big. "
					       "Reducing to %lu",
					       (unsigned long)yyval.ul_int,
					       (unsigned long)newi);
				yyval.ul_int = newi;			}
		} else {
			parser_warning(ISC_FALSE,
				       "invalid unit string '%s'. Using "
				       "default", yyvsp[0].text);
			yyval.ul_int = DNS_C_SIZE_SPEC_DEFAULT;
		}
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 115:
{
		yyval.ul_int = (isc_uint32_t)yyvsp[0].l_int;
		if (yyval.ul_int == DNS_C_SIZE_SPEC_DEFAULT) {
			isc_uint32_t newi = DNS_C_SIZE_SPEC_DEFAULT - 1;
			parser_warning(ISC_FALSE,
				       "value (%lu) too big. Reducing to %lu",
				       (unsigned long) yyval.ul_int,
				       (unsigned long) newi);
			yyval.ul_int = newi;
		}
	}
break;
case 116:
{
		yyval.ul_int = DNS_C_SIZE_SPEC_DEFAULT;
	}
break;
case 117:
{
		yyval.ul_int = DNS_C_SIZE_SPEC_UNLIM;
	}
break;
case 118:
{
		tmpres = dns_c_ctx_set_transfers_in(currcfg, yyvsp[0].l_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE, "Redefining transfers-in.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Failed to set transfers-in.");
			YYABORT;
		}
	}
break;
case 119:
{
		tmpres = dns_c_ctx_set_transfers_out(currcfg, yyvsp[0].l_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining transfers-out.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set transfers-out.");
			YYABORT;
		}
	}
break;
case 120:
{
		tmpres = dns_c_ctx_set_transfers_per_ns(currcfg, yyvsp[0].l_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_error(ISC_FALSE,
				     "Redefining transfers-per-ns.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set transfers-per-ns.");
			YYABORT;
		}
	}
break;
case 121:
{
	}
break;
case 125:
{
		dns_c_ipmatch_element_t *ime = NULL;

		INSIST(currcfg->options != NULL);
		INSIST(currcfg->options->forwarders != NULL);

		tmpres = dns_c_ipmatch_pattern_new(currcfg->mem, &ime,
						   yyvsp[0].ipaddress, 0);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to create forwarders "
				     "address element.");
			YYABORT;
		}

		ISC_LIST_APPEND(currcfg->options->forwarders->elements,
				ime, next);
	}
break;
case 126:
{
		/* initialized in logging_init() */
		INSIST(currcfg->logging != NULL);
	}
break;
case 132:
{
		dns_c_logchan_t *newc;
		
		tmpres = dns_c_ctx_add_file_channel(currcfg, yyvsp[-3].text, &newc);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "Redefing channel %s\n", yyvsp[-3].text);
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to add new file channel.");
			YYABORT;
		}

		INSIST(newc != NULL);

		tmpres = dns_c_logchan_set_path(newc, yyvsp[0].text);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to add file channel's path.");
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[-3].text);
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 134:
{
		dns_c_logchan_t *newc;
		
		tmpres = dns_c_ctx_add_syslog_channel(currcfg, yyvsp[-3].text, &newc);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "Redefining channel %s", yyvsp[-3].text);
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to add new syslog channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_facility(newc, yyvsp[0].number);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel facility.");
			YYABORT;
		}
		isc_mem_free(memctx, yyvsp[-3].text);
	}
break;
case 136:
{
		dns_c_logchan_t *newc;
		
		tmpres = dns_c_ctx_add_null_channel(currcfg, yyvsp[-2].text, &newc);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "Redefining channel %s", yyvsp[-2].text);
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to add new channel ``%s''", yyvsp[-2].text);
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[-2].text);
	}
break;
case 138:
{
		parser_error(ISC_FALSE,
			     "First statment inside a channel definition "
			     "must be ``file'' or ``syslog'' or ``null''.");
		YYABORT;
	}
break;
case 145:
{
		dns_c_logcat_t *cat;
		
		tmpres = dns_c_ctx_add_category(currcfg, yyvsp[0].logcat, &cat);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "Redefining category ``%s''", yyvsp[0].logcat);
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to add new logging category.");
			YYABORT;
		}
	}
break;
case 147:
{
		dns_c_log_severity_t severity;
		dns_c_logchan_t *chan;

		tmpres = dns_c_string2logseverity(yyvsp[0].text, &severity);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Unknown severity ``%s''", yyvsp[0].text);
			YYABORT;
		}

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_severity(chan, severity);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "Redefining severity.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel severity.");
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 148:
{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_severity(chan, dns_c_log_debug);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "Redefining severity.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel severity(debug).");
			YYABORT;
		}
	}
break;
case 149:
{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_severity(chan, dns_c_log_debug);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "Redefining severity.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel "
				     "severity (debug).");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_debug_level(chan, yyvsp[0].l_int);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel "
				     "severity debug level.");
			YYABORT;
		}
	}
break;
case 150:
{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_severity(chan, dns_c_log_dynamic);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "Redefining severity.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel "
				     "severity (dynamic).");
			YYABORT;
		}
	}
break;
case 151:
{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_versions(chan, yyvsp[0].l_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "Redefining versions.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel versions.");
			YYABORT;
		}
	}
break;
case 152:
{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_versions(chan, -1);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "Redefining versions.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel "
				     "versions (unlimited).");
			YYABORT;
		}
	}
break;
case 153:
{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_size(chan, yyvsp[0].ul_int);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "Redefining size.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel size.");
			YYABORT;
		}
	}
break;
case 159:
{
		tmpres = dns_c_string2facility(yyvsp[0].text, &yyval.number);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE, "Unknown syslog facility.");
			yyval.number = LOG_DAEMON;
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 160:
{
		yyval.number = LOG_SYSLOG;
	}
break;
case 161:
{
		yyval.number = LOG_DAEMON;
	}
break;
case 162:
{
		yyval.number = yyvsp[0].number;
	}
break;
case 165:
{ /* nothing to do */ }
break;
case 166:
{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_printtime(chan, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "Redefining print-time.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel print-time.");
			YYABORT;
		}
	}
break;
case 167:
{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_printcat(chan, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "Redefining print-category.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel print-category.");
			YYABORT;
		}
	}
break;
case 168:
{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_set_printsev(chan, yyvsp[0].boolean);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "Redefining print-severity.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get set channel print-severity.");
			YYABORT;
		}
	}
break;
case 170:
{
		yyval.text = isc_mem_strdup(memctx, "null");
	}
break;
case 171:
{
		dns_c_logcat_t *cat;

		/*
		 * XXX validate the channel name refers to a previously
		 * defined channel
		 */
		tmpres = dns_c_ctx_currcategory(currcfg, &cat);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't get current category.");
			YYABORT;
		}

		tmpres = dns_c_logcat_add_name(cat, yyvsp[0].text);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Can't add new name to category.");
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 174:
{
		dns_c_category_t cat;

		tmpres = dns_c_string2category(yyvsp[0].text, &cat);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "Unknown category ``%s''", yyvsp[0].text);
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[0].text);

		yyval.logcat = cat;
	}
break;
case 175:
{
		yyval.logcat = dns_c_cat_default;
	}
break;
case 176:
{
		yyval.logcat = dns_c_cat_notify;
	}
break;
case 177:
{
		dns_c_srv_t *server;
		dns_c_srv_t *tmpserver;
		dns_c_srv_list_t *servers = currcfg->servers;
		
		if (servers == NULL) {
			tmpres = dns_c_srv_list_new(currcfg->mem,
						    &currcfg->servers);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "Failed to create server list");
				YYABORT;
			}
			servers = currcfg->servers;
		}

		/*
		 * Check that this IP hasn't already bee used and if it has 
		 * remove the old definition.
		 */
		server = ISC_LIST_HEAD(servers->elements);
		while (server != NULL) {
			tmpserver = ISC_LIST_NEXT(server, next);
			if (memcmp(&server->address, &yyvsp[0].ipaddress,
				   sizeof(dns_c_addr_t)) == 0) {
				parser_error(ISC_TRUE, "Redefining server");
				ISC_LIST_UNLINK(servers->elements,
						server, next);
				dns_c_srv_delete(&server);
				break;
			}
			server = tmpserver;
		}
		
		tmpres = dns_c_srv_new(currcfg->mem, yyvsp[0].ipaddress, &server);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to create server structure");
			YYABORT;
		}

		ISC_LIST_APPEND(currcfg->servers->elements, server, next);
	}
break;
case 181:
{
		dns_c_srv_t *server;
		isc_boolean_t tv;
		
		INSIST(currcfg->servers != NULL);
		server = ISC_LIST_TAIL(currcfg->servers->elements);

		INSIST(server != NULL);

		tmpres = dns_c_srv_get_bogus(server, &tv);
		if (tmpres != ISC_R_NOTFOUND) {
			parser_warning(ISC_FALSE,
				       "Redefining server bogus value");
		}
		
		dns_c_srv_set_bogus(server, yyvsp[0].boolean);
	}
break;
case 182:
{
		dns_c_srv_t *server;
		isc_boolean_t tv;

		INSIST(currcfg->servers != NULL);
		server = ISC_LIST_TAIL(currcfg->servers->elements);

		INSIST(server != NULL);

		tmpres = dns_c_srv_get_support_ixfr(server, &tv);
		if(tmpres != ISC_R_NOTFOUND) {
			parser_warning(ISC_FALSE,
				       "Redefining server support-ixfr value");
		}
		
		dns_c_srv_set_support_ixfr(server, yyvsp[0].boolean);
	}
break;
case 183:
{
		dns_c_srv_t *server;
		isc_int32_t tv;

		INSIST(currcfg->servers != NULL);
		server = ISC_LIST_TAIL(currcfg->servers->elements);

		INSIST(server != NULL);

		tmpres = dns_c_srv_get_transfers(server, &tv);
		if (tmpres != ISC_R_NOTFOUND) {
			parser_warning(ISC_FALSE,
				       "Redefining server transfers value");
		}
		
		dns_c_srv_set_transfers(server, yyvsp[0].l_int);
	}
break;
case 184:
{
		dns_c_srv_t *server;
		dns_transfer_format_t tv;
		
		INSIST(currcfg->servers != NULL);
		server = ISC_LIST_TAIL(currcfg->servers->elements);

		INSIST(server != NULL);

		tmpres = dns_c_srv_get_transfer_format(server, &tv);
		if (tmpres != ISC_R_NOTFOUND) {
			parser_warning(ISC_FALSE,
				       "Redefining server transfer-format "
				       "value");
		}
		

		dns_c_srv_set_transfer_format(server, yyvsp[0].tformat);
	}
break;
case 185:
{
		dns_c_srv_t *server;

		INSIST(currcfg->servers != NULL);
		server = ISC_LIST_TAIL(currcfg->servers->elements);
		INSIST(server != NULL);

		if (server->keys == NULL) {
			tmpres = dns_c_kid_list_new(currcfg->mem,
						    &server->keys);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "Failed to create keyid_list");
				YYABORT;
			}
		}
	}
break;
case 187:
{
		dns_c_ipmatch_list_t *ml = 0;

		if (yyvsp[-1].ime != NULL) {
			tmpres = dns_c_ipmatch_list_new(currcfg->mem, &ml);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE, "Insufficient memory");
				dns_c_ipmatch_element_delete(currcfg->mem,
							     &yyvsp[-1].ime);
				YYABORT;
			}
			
			ISC_LIST_APPEND(ml->elements, yyvsp[-1].ime, next);
		}
		
		yyval.iml = ml;
	}
break;
case 188:
{
		dns_c_ipmatch_list_t *ml = yyvsp[-2].iml;
		
		if (ml == NULL && yyvsp[-1].ime != NULL) {
			tmpres = dns_c_ipmatch_list_new(currcfg->mem, &ml);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE, "Insufficient memory");
				dns_c_ipmatch_element_delete(currcfg->mem,
							     &yyvsp[-1].ime);
				YYABORT;
			}
		}

		if (yyvsp[-1].ime != NULL) {
			ISC_LIST_APPEND(ml->elements, yyvsp[-1].ime, next);
		}
		
		yyval.iml = ml;
	}
break;
case 190:
{
		if (yyvsp[0].ime != NULL) {
			dns_c_ipmatch_negate(yyvsp[0].ime);
		}
		yyval.ime = yyvsp[0].ime;
	}
break;
case 191:
{
		dns_c_ipmatch_element_t *ime = NULL;

		if (!dns_c_ctx_key_defined_p(currcfg, yyvsp[0].text)) {
			parser_error(ISC_FALSE,
				     "Address match key element (%s) "
				     "referenced before defined", yyvsp[0].text);
			YYABORT;
		} else {
			tmpres = dns_c_ipmatch_key_new(currcfg->mem, &ime, yyvsp[0].text);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_TRUE,
					     "Failed to create address match "
					     "key element for %s", yyvsp[0].text);
				YYABORT;
			}
		}
		
		isc_mem_free(memctx, yyvsp[0].text);
		yyval.ime = ime;
	}
break;
case 192:
{
		dns_c_ipmatch_element_t *ime = NULL;

		tmpres = dns_c_ipmatch_pattern_new(currcfg->mem, &ime, yyvsp[0].ipaddress, 0);
		switch (tmpres) {
		case ISC_R_FAILURE:
			parser_error(ISC_FALSE, "bad address match element.");
			YYABORT;
			break;

		case ISC_R_NOMEMORY:
			FATAL_ERROR(__FILE__, __LINE__,
				    "Insufficient memory available.\n");
			break;

		case ISC_R_SUCCESS:
			break;
		}

		yyval.ime = ime;
	}
break;
case 193:
{
		dns_c_ipmatch_element_t *ime = NULL;

		if (yyvsp[0].l_int < 0 || yyvsp[0].l_int > 32) {
			parser_warning(ISC_FALSE,
				       "mask bits (%d) out of range: "
				       "skipping", (int)yyvsp[0].l_int);
			yyval.ime = NULL;
		} else {
			tmpres = dns_c_ipmatch_pattern_new(currcfg->mem, &ime,
							   yyvsp[-2].ipaddress, yyvsp[0].l_int);
			switch (tmpres) {
			case ISC_R_FAILURE:
				parser_error(ISC_FALSE,
					     "bad address match element.");
				YYABORT;
				break;

			case ISC_R_NOMEMORY:
				FATAL_ERROR(__FILE__, __LINE__,
				    "Insufficient memory available.\n");
				break;

			case ISC_R_SUCCESS:
				break;
			}
		}

		yyval.ime = ime;
	}
break;
case 194:
{
		struct in_addr ia;
		dns_c_ipmatch_element_t *ime = NULL;
		dns_c_addr_t address;

		if (yyvsp[-2].l_int > 255) {
			parser_error(ISC_FALSE,
				     "address out of range; skipping");
			YYABORT;
		} else {
			if (yyvsp[0].l_int < 0 || yyvsp[0].l_int > 32) {
				parser_warning(ISC_FALSE,
					   "mask bits out of range; skipping");
				yyval.ime = NULL;
			} else {
				ia.s_addr = htonl((yyvsp[-2].l_int & 0xff) << 24);

				address.a_family = AF_INET;
				address.u.a = ia;
				
				tmpres = dns_c_ipmatch_pattern_new(currcfg->mem,
								   &ime,
								   address,
								   yyvsp[0].l_int);
				switch (tmpres) {
				case ISC_R_FAILURE:
					parser_error(ISC_FALSE,
						     "bad address match "
						     "element.");
					break;

				case ISC_R_NOMEMORY:
					FATAL_ERROR(__FILE__, __LINE__,
						    "Insufficient memory "
						    "available.\n");
					break;

				case ISC_R_SUCCESS:
					break;
				}
			}
		}

		yyval.ime = ime;
	}
break;
case 196:
{
		dns_c_ipmatch_element_t *ime = NULL;
		
		if (yyvsp[-1].iml != NULL) {
			tmpres = dns_c_ipmatch_indirect_new(currcfg->mem, &ime,
							  yyvsp[-1].iml, NULL);
			switch (tmpres) {
			case ISC_R_SUCCESS:
				break;

			case ISC_R_NOMEMORY:
				FATAL_ERROR(__FILE__, __LINE__,
					    "Insufficient memory "
					    "available.\n");
				break;
			}
		}

		dns_c_ipmatch_list_delete(&yyvsp[-1].iml);

		yyval.ime = ime;
	}
break;
case 197:
{
		dns_c_ipmatch_element_t *elem;
		dns_c_acl_t *acl;

		tmpres = dns_c_acl_table_get_acl(currcfg->acls, yyvsp[0].text, &acl);
		if (tmpres == ISC_R_NOTFOUND) {
			parser_warning(ISC_FALSE,
				       "Undefined acl ``%s'' referenced",
				       yyvsp[0].text);
			elem = NULL;
		} else {
			tmpres = dns_c_ipmatch_acl_new(currcfg->mem, &elem, yyvsp[0].text);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "Failed to create IPE-ACL\n");
				YYABORT;
			}
		}

		isc_mem_free(memctx, yyvsp[0].text);
		yyval.ime = elem;
	}
break;
case 199:
{
		dns_c_srv_t *currserver;
		dns_c_kid_t *keyid;

		INSIST(currcfg->servers != NULL);
		currserver = ISC_LIST_TAIL(currcfg->servers->elements);
		INSIST(currserver != NULL);

		INSIST(currserver->keys != NULL);

		if (!dns_c_ctx_key_defined_p(currcfg, yyvsp[0].text)) {
			parser_error(ISC_FALSE,
				     "Server keys key_id (%s) "
				     "referenced before defined", yyvsp[0].text);
			YYABORT;
		} else {
			tmpres = dns_c_kid_new(currserver->keys, yyvsp[0].text, &keyid);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "Failed to create keyid\n");
				YYABORT;
			}
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 204:
{
		dns_c_kdef_t *keydef;
		
		if (currcfg->keydefs == NULL) {
			tmpres = dns_c_kdef_list_new(currcfg->mem,
						     &currcfg->keydefs);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "Failed to create keylist");
				YYABORT;
			}
		}
		
		tmpres = dns_c_kdef_new(currcfg->keydefs, yyvsp[0].text, &keydef);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to create key definition");
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 206:
{
		dns_c_kdef_t *keydef;

		INSIST(currcfg->keydefs != NULL);

		keydef = ISC_LIST_TAIL(currcfg->keydefs->keydefs);
		INSIST(keydef != NULL);

		dns_c_kdef_set_algorithm(keydef, yyvsp[-1].text);
		dns_c_kdef_set_secret(keydef, yyvsp[0].text);

		isc_mem_free(memctx, yyvsp[-1].text);
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 207:
{
		dns_c_kdef_t *keydef;

		INSIST(currcfg->keydefs != NULL);

		keydef = ISC_LIST_TAIL(currcfg->keydefs->keydefs);
		INSIST(keydef != NULL);

		dns_c_kdef_set_secret(keydef, yyvsp[-1].text);
		dns_c_kdef_set_algorithm(keydef, yyvsp[0].text);

		isc_mem_free(memctx, yyvsp[-1].text);
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 208:
{
		yyval.text = yyvsp[-1].text;
	}
break;
case 209:
{
		yyval.text = yyvsp[-1].text;
	}
break;
case 210:
{
		dns_c_acl_t *acl;

		INSIST(currcfg->acls != NULL);
			
		tmpres = dns_c_acl_new(currcfg->acls, yyvsp[-4].text, ISC_FALSE, &acl);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to create acl %s", yyvsp[-4].text);
			YYABORT;
		}
		
		dns_c_acl_set_ipml(acl, yyvsp[-2].iml, ISC_FALSE);
			
		isc_mem_free(memctx, yyvsp[-4].text);
	}
break;
case 211:
{
		yyval.text = yyvsp[0].text;
	}
break;
case 212:
{
		dns_c_zone_t *zone;

		if (currcfg->zlist == NULL) {
			tmpres = dns_c_zone_list_new(currcfg->mem,
						  &currcfg->zlist);
			if (tmpres != ISC_R_SUCCESS) {
				dns_c_error(tmpres,
					    "Failed to create zone list");
				YYABORT;
			}
		}

		tmpres = dns_c_zone_new(currcfg->zlist, yyvsp[-1].ztype, yyvsp[-4].rrclass, yyvsp[-5].text, &zone);
		if (tmpres != ISC_R_SUCCESS) {
			dns_c_error(tmpres, "Error creating new zone.");
			YYABORT;
		}

		if (currcfg->options != NULL) {
			zone->afteropts = ISC_TRUE;
		}
		
		isc_mem_free(memctx, yyvsp[-5].text);
	}
break;
case 213:
{
		dns_c_zone_t *zone;

		if (callbacks != NULL && callbacks->zonecbk != NULL) {
			zone = ISC_LIST_TAIL(currcfg->zlist->zones);
			tmpres = callbacks->zonecbk(currcfg,
						    zone,
						    callbacks->zonecbkuap);
			if (tmpres != ISC_R_SUCCESS) {
				YYABORT;
			}

			dns_c_zone_list_rmzone(currcfg->zlist, zone);
		}
	}
break;
case 214:
{
		parser_error(ISC_FALSE,
			     "First statement in a zone definition must "
			     "be ``type''");
		YYABORT;
	}
break;
case 217:
{
		isc_textregion_t reg;
		dns_rdataclass_t cl;

		if (strcmp(yyvsp[0].text, "*") == 0) {
			cl = dns_rdataclass_any;
		} else {
			reg.base = yyvsp[0].text;
			reg.length = strlen(yyvsp[0].text);
			
			tmpres = dns_rdataclass_fromtext(&cl, &reg);
			if (tmpres != DNS_R_SUCCESS) {
				parser_error(ISC_TRUE,
					     "Unknown class assuming ``*''.");
				cl = dns_rdataclass_any;
			}
		}
		
		isc_mem_free(memctx, yyvsp[0].text);
		yyval.rrclass = cl;
	}
break;
case 218:
{
		yyval.rrclass = dns_rdataclass_in;
	}
break;
case 220:
{
		yyval.ztype = dns_c_zone_master;
	}
break;
case 221:
{
		yyval.ztype = dns_c_zone_slave;
	}
break;
case 222:
{
		yyval.ztype = dns_c_zone_hint;
	}
break;
case 223:
{
		yyval.ztype = dns_c_zone_stub;
	}
break;
case 224:
{
		yyval.ztype = dns_c_zone_forward;
	}
break;
case 245:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_file(zone, yyvsp[0].text);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone filename.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set zone file name");
		}
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 246:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_ixfr_base(zone, yyvsp[0].text);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "Redefining ixfr-base.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set zone ixfr_base.");
		}
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 247:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_ixfr_tmp(zone, yyvsp[0].text);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "Redefining ixfr-tmp-file.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "Failed to set zone ixfr_tmp-file.");
		}
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 248:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_master_port(zone, yyvsp[-3].port_int);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone master's port.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone master port.");
		}

		tmpres = dns_c_zone_set_master_ips(zone, yyvsp[-1].iplist, ISC_FALSE);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone masters ips.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone masters ips.");
		}
	}
break;
case 249:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_transfer_source(zone, yyvsp[0].ipaddress);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone transfer-source.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone transfer-source.");
		}
	}
break;
case 250:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_checknames(zone, yyvsp[0].severity);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone check-names.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone check-names.");
		}
	}
break;
case 251:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_allow_upd(zone, yyvsp[-1].iml, ISC_FALSE);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone allow-update.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone allow-update.");
		}
	}
break;
case 252:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_allow_query(zone, yyvsp[-1].iml, ISC_FALSE);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone allow-query.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone allow-query.");
		}
	}
break;
case 253:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_allow_transfer(zone, yyvsp[-1].iml, ISC_FALSE);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone allow-transfer.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone allow-transfer.");
		}
	}
break;
case 254:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_forward(zone, yyvsp[0].forward);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone forward.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone forward.");
		}
	}
break;
case 255:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);
		dns_c_iplist_t *iplist;
		
		INSIST(zone != NULL);

		if (yyvsp[-1].iplist == NULL) {	/* user defined empty list */
			tmpres = dns_c_iplist_new(currcfg->mem, 5, &iplist);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_TRUE,
					     "Failed to create new zone "
					     "iplist");
				YYABORT;
			}
		} else {
			iplist = yyvsp[-1].iplist;
		}
		
		tmpres = dns_c_zone_set_forwarders(zone, iplist, ISC_FALSE);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone forwarders.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone forwarders.");
		}
	}
break;
case 256:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_max_trans_time_in(zone, yyvsp[0].l_int);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone "
				       "max-transfer-time-in.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone "
				     "max-transfer-time-in.");
		}
	}
break;
case 257:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_max_ixfr_log(zone, yyvsp[0].l_int);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone max-ixfr-log-size.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone max-ixfr-log-size.");
		}
	}
break;
case 258:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_notify(zone, yyvsp[0].boolean);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone notify.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone notify.");
		}
	}
break;
case 259:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_maint_ixfr_base(zone, yyvsp[0].boolean);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone maintain-ixfr-base.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone maintain-ixfr-base.");
		}
	}
break;
case 260:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);
		dns_c_pubkey_t *pubkey;
		
		INSIST(zone != NULL);

		tmpres = dns_c_pubkey_new(currcfg->mem, yyvsp[-3].l_int,
					  yyvsp[-2].l_int, yyvsp[-1].l_int, yyvsp[0].text, &pubkey);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE,
				     "Failed to create a zone pubkey");
			YYABORT;
		}
		
		tmpres = dns_c_zone_set_pubkey(zone, pubkey, ISC_FALSE);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone pubkey.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			dns_c_pubkey_delete(&pubkey);
			parser_error(ISC_FALSE,
				     "Failed to set zone pubkey.");
		}

		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 261:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_also_notify(zone, yyvsp[-1].iplist, ISC_FALSE);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone also-notify.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone also-notify.");
		}
	}
break;
case 262:
{
		dns_c_zone_t *zone = ISC_LIST_TAIL(currcfg->zlist->zones);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_set_dialup(zone, yyvsp[0].boolean);
		switch (tmpres) {
		case ISC_R_EXISTS:
			parser_warning(ISC_FALSE,
				       "Redefining zone dialup.");
			break;

		case ISC_R_SUCCESS:
			/* nothing */
			break;

		default:
			parser_error(ISC_FALSE,
				     "Failed to set zone dialup.");
		}
	}
break;
case 265:
{
		yyval.ipaddress.a_family = AF_INET;
		yyval.ipaddress.u.a = yyvsp[0].ip4_addr;
	}
break;
case 266:
{
		yyval.ipaddress.a_family = AF_INET6;
		yyval.ipaddress.u.a6 = yyvsp[0].ip6_addr;
	}
break;
case 267:
{
		yyval.ipaddress = yyvsp[0].ipaddress;
	}
break;
case 268:
{
		yyval.ipaddress = yyvsp[0].ipaddress;
	}
break;
case 270:
{
		dns_c_iplist_t *list;

		tmpres = dns_c_iplist_new(currcfg->mem, 5, &list);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE,
				     "Failed to create new iplist");
			YYABORT;
		}

		yyval.iplist = list;
	}
break;
case 272:
{
		dns_c_iplist_t *list;

		tmpres = dns_c_iplist_new(currcfg->mem, 5, &list);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE,
				     "Failed to create new iplist");
			YYABORT;
		}

		tmpres = dns_c_iplist_append(list, yyvsp[-1].ipaddress);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE,
				     "Failed to append master address");
			YYABORT;
		}
		
		yyval.iplist = list;
	}
break;
case 273:
{
		tmpres = dns_c_iplist_append(yyvsp[-2].iplist, yyvsp[-1].ipaddress);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE,
				     "Failed to append master address");
			YYABORT;
		}

		yyval.iplist = yyvsp[-2].iplist;
	}
break;
case 274:
{
		yyval.forward = dns_c_forw_only;
	}
break;
case 275:
{
		yyval.forward = dns_c_forw_first;
	}
break;
case 277:
{
		dns_c_tkey_list_t *newlist;
		
		tmpres = dns_c_ctx_get_trusted_keys(currcfg, &newlist);
		if (tmpres == ISC_R_NOTFOUND) {
			tmpres = dns_c_tkey_list_new(currcfg->mem, &newlist);
			if (tmpres != ISC_R_SUCCESS) {
				dns_c_error(tmpres,
					 "Failed to create trusted key list.");
				YYABORT;
			}

			tmpres = dns_c_ctx_set_trusted_keys(currcfg,
							    newlist,
							    ISC_FALSE);
			if (tmpres != ISC_R_SUCCESS) {
				dns_c_error(tmpres,
					    "Failed to set trusted keys");
				YYABORT;
			}
		}
	}
break;
case 281:
{
		dns_c_tkey_t *tkey;
		dns_c_tkey_list_t *list;

		tmpres = dns_c_ctx_get_trusted_keys(currcfg, &list);
		if (tmpres != ISC_R_SUCCESS) {
			dns_c_error(tmpres, "No trusted key list defined!");
			YYABORT;
		}

		tmpres = dns_c_tkey_new(currcfg->mem, yyvsp[-4].text, yyvsp[-3].l_int, yyvsp[-2].l_int,
					yyvsp[-1].l_int, yyvsp[0].text, &tkey);
		if (tmpres != ISC_R_SUCCESS) {
			dns_c_error(tmpres, "Failed to create trusted key");
			YYABORT;
		}

		tmpres = dns_c_tkey_list_append(list, tkey, ISC_FALSE);
		if (tmpres != ISC_R_SUCCESS) {
			dns_c_error(tmpres, "Failed to append trusted key.");
			YYABORT;
		}

		isc_mem_free(memctx, yyvsp[-4].text);
		isc_mem_free(memctx, yyvsp[0].text);
	}
break;
case 282:
{
		if (yyvsp[0].l_int < 0 || yyvsp[0].l_int > 65535) {
			parser_warning(ISC_TRUE,
			  "invalid IP port number '%d'; setting port to 0",
				       (int)yyvsp[0].l_int);
			yyvsp[0].l_int = 0;
		} else
			yyval.port_int = htons(yyvsp[0].l_int);
	}
break;
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    return (1);
yyaccept:
    return (0);
}
