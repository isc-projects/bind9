#ifndef res_private_h
#define res_private_h

union __res_sockaddr_union {
	struct sockaddr_in      sin;
	struct sockaddr_in6     sin6;
	int64_t                 __align;        /* 64bit alignment */
	char                    __space[128];   /* max size */
};

struct __res_state_ext {
	union __res_sockaddr_union nsaddrs[MAXNS];
	struct sort_list {
		int     af;
		union {
			struct in_addr  ina;
			struct in6_addr in6a;
		} addr, mask;
	} sort_list[MAXRESOLVSORT];
	char nsuffix[64];
	char bsuffix[64];
};

extern int
res_ourserver_p(const res_state statp, const struct sockaddr *sa);

#endif
