#if !HAVE_CUSE
#define cuse_allocate(n,fd) 0
#define cuse_init() do {} while(0)
#else
int cuse_allocate(int num, int *out_fd);
void cuse_init(void);
#endif
