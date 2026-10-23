//
// Copyright (c) 2026 Ordo One AB.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//

// Standalone crash probe for the interposer's pointer classifier, driven by
// the AlignedPointerSafety death tests. It runs in its *own* minimal process
// on purpose: only in a sparsely-mapped address space does libc reliably place
// a large allocation against an unmapped guard page, which is the condition
// that makes `malloc_interposer_is_ours` read unmapped memory. The parent test
// process is too populated for that to reproduce in-process.
//
//   argv[1] == "free" -> exercise replacement_free (the production free path)
//   argv[1] == "tagged" -> exercise malloc_interposer_is_ours with a synthetic
//                           Objective-C tagged pointer (Darwin only)
//   argv[1] == "mmap"   -> exercise replacement_malloc_size with a page-aligned
//                           pointer owned by no malloc zone whose preceding
//                           page is PROT_NONE (Darwin only)
//   argv[1] == "thread-exit" -> free on exiting threads after the interposer's
//                           own thread-specific destructor has freed the
//                           thread's counter block
//   otherwise         -> exercise malloc_interposer_is_ours directly
//
// Exit codes:
//   0 : the classifier ran without faulting (and classified the external
//       allocation as "not ours")
//   1 : the classifier misclassified an external pointer as ours
//   3 : allocation failed (inconclusive)
// A SIGSEGV/SIGBUS termination means the classifier dereferenced an
// unmapped/invalid address — the bug under test.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#if __APPLE__
#include <sys/mman.h>
#endif

#include <interposer.h>
#include <pthread.h>

// A thread-specific key created after the interposer's, so its destructor runs
// after the interposer's has freed the exiting thread's counter block, as the
// Swift runtime's and libdispatch's do. Its free must not count into that block.
static pthread_key_t late_key;

static void late_free(void *ptr) {
    replacement_free(ptr);
}

static void *exiting_thread(void *unused) {
    (void)unused;
    // The first counted allocation creates this thread's counter block.
    replacement_free(replacement_malloc(32));
    pthread_setspecific(late_key, replacement_malloc(48));
    return NULL;
}

static int thread_exit_probe(void) {
    malloc_interposer_enable();
    // Creates the interposer's key on this thread before ours.
    replacement_free(replacement_malloc(16));
    if (pthread_key_create(&late_key, late_free) != 0) {
        return 3;
    }
    for (int i = 0; i < 20000; i++) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, exiting_thread, NULL) != 0) {
            return 3;
        }
        pthread_join(thread, NULL);
        // Reuse what the exiting threads freed, so a write into a freed block
        // corrupts a live one or a free list.
        void *again[4];
        for (int j = 0; j < 4; j++) again[j] = replacement_malloc(96);
        for (int j = 0; j < 4; j++) replacement_free(again[j]);
    }
    return 0;
}

int main(int argc, char **argv) {
    size_t pageSize = (size_t)getpagesize();
    int freePath = (argc > 1 && strcmp(argv[1], "free") == 0);
    int taggedPath = (argc > 1 && strcmp(argv[1], "tagged") == 0);
    int mmapPath = (argc > 1 && strcmp(argv[1], "mmap") == 0);

    if (argc > 1 && strcmp(argv[1], "thread-exit") == 0) {
        return thread_exit_probe();
    }

    if (taggedPath) {
#if __APPLE__
        // Set both TAG_MASK bits used by objc4: bit 0 on x86_64 and bit 63 on
        // arm64.
        const uintptr_t taggedPointerBits = ((uintptr_t)1 << 63) | (uintptr_t)1;
        const void *taggedPointer = (const void *)taggedPointerBits;
        return replacement_malloc_size(taggedPointer) ? 1 : 0;
#else
        // Objective-C tagged pointers and replacement_malloc_size are Darwin-only.
        return 0;
#endif
    }

    if (mmapPath) {
#if __APPLE__
        // Page-aligned memory that belongs to no malloc zone, with the page
        // before it unreadable. malloc_size accepts any pointer and must
        // return 0 here; the classifier must not probe the preceding page.
        // (Zone-owned page-aligned blocks from valloc / posix_memalign are the
        // separate case covered by the default mode.)
        char *base = mmap(NULL, 2 * pageSize, PROT_READ | PROT_WRITE,
                          MAP_ANON | MAP_PRIVATE, -1, 0);
        if (base == MAP_FAILED) {
            return 3;
        }
        if (mprotect(base, pageSize, PROT_NONE) != 0) {
            return 3;
        }
        const void *page = base + pageSize;
        return replacement_malloc_size(page) ? 1 : 0;
#else
        // replacement_malloc_size is Darwin-only.
        return 0;
#endif
    }

    // A few large sizes so at least one lands in its own fresh mmap with an
    // unmapped preceding page.
    const size_t sizes[] = { 64UL << 20, 128UL << 20, 256UL << 20 };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        void *ptr = NULL;
        if (posix_memalign(&ptr, pageSize, sizes[i]) != 0 || ptr == NULL) {
            return 3;
        }
        if (freePath) {
            replacement_free(ptr); // classifies via is_ours; faults on the guard page
        } else {
            if (malloc_interposer_is_ours(ptr)) {
                free(ptr);
                return 1;
            }
            free(ptr);
        }
    }
    return 0;
}
