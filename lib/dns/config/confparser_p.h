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
extern YYSTYPE yylval;
