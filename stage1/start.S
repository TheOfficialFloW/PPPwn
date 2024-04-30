/*
 * Copyright (C) 2024 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

.intel_syntax noprefix

#define SOFTCLOCK_STACK_SIZE 0x88
#define ND6_LLINFO_TIMER_STACK_SIZE 0x38

.section .text
.global _start
_start:
  call stage1

  # Restore rsp
  mov rsp, rbx
  sub rsp, (SOFTCLOCK_STACK_SIZE + ND6_LLINFO_TIMER_STACK_SIZE)

  # nd6_llinfo_timer epiloque
  add rsp, 8
  pop rbx
  pop r12
  pop r13
  pop r14
  pop r15
  pop rbp
  ret
