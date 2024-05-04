/*
 * Copyright (C) 2024 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef __OFFSETS_H__
#define __OFFSETS_H__


#if FIRMWARE == 850 // FW 8.50

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0

#define kdlsym_addr_printf 0xffffffff8235d570

#define kdlsym_addr_sysent 0xffffffff832fc5c0

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2 // Identical to 9.00

#define kdlsym_addr_copyin_patch1 0xffffffff825a4337
#define kdlsym_addr_copyin_patch2 0xffffffff825a4343

#define kdlsym_addr_copyout_patch1 0xffffffff825a4242
#define kdlsym_addr_copyout_patch2 0xffffffff825a424e

#define kdlsym_addr_copyinstr_patch1 0xffffffff825a47e3
#define kdlsym_addr_copyinstr_patch2 0xffffffff825a47ef
#define kdlsym_addr_copyinstr_patch3 0xffffffff825a4820


#elif FIRMWARE == 900 // FW 9.00

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0

#define kdlsym_addr_printf 0xffffffff822b7a30

#define kdlsym_addr_sysent 0xffffffff83300310

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff824716f7
#define kdlsym_addr_copyin_patch2 0xffffffff82471703

#define kdlsym_addr_copyout_patch1 0xffffffff82471602
#define kdlsym_addr_copyout_patch2 0xffffffff8247160e

#define kdlsym_addr_copyinstr_patch1 0xffffffff82471ba3
#define kdlsym_addr_copyinstr_patch2 0xffffffff82471baf
#define kdlsym_addr_copyinstr_patch3 0xffffffff82471be0


#elif (FIRMWARE == 903 || FIRMWARE == 904) // FW 9.03/9.04

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0 // Identical to 9.00

#define kdlsym_addr_printf 0xffffffff822b79e0

#define kdlsym_addr_sysent 0xffffffff832fc310

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2 // Identical to 9.00

#define kdlsym_addr_copyin_patch1 0xffffffff82471377
#define kdlsym_addr_copyin_patch2 0xffffffff82471383

#define kdlsym_addr_copyout_patch1 0xffffffff82471282
#define kdlsym_addr_copyout_patch2 0xffffffff8247128e

#define kdlsym_addr_copyinstr_patch1 0xffffffff82471823
#define kdlsym_addr_copyinstr_patch2 0xffffffff8247182f
#define kdlsym_addr_copyinstr_patch3 0xffffffff82471860


#elif (FIRMWARE == 950 || FIRMWARE == 960) // FW 9.50 / 9.60

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0
#define kdlsym_addr_printf 0xffffffff82405470

#define kdlsym_addr_sysent 0xffffffff832f92f0

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff82401f07
#define kdlsym_addr_copyin_patch2 0xffffffff82401f13

#define kdlsym_addr_copyout_patch1 0xffffffff82401e12
#define kdlsym_addr_copyout_patch2 0xffffffff82401e1e

#define kdlsym_addr_copyinstr_patch1 0xffffffff824023b3
#define kdlsym_addr_copyinstr_patch2 0xffffffff824023bf
#define kdlsym_addr_copyinstr_patch3 0xffffffff824023f0


#elif (FIRMWARE == 1000 || FIRMWARE == 1001) // FW 10.00/10.01

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0
#define kdlsym_addr_printf 0xffffffff822c50f0

#define kdlsym_addr_sysent 0xffffffff83302d90

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff82672f67
#define kdlsym_addr_copyin_patch2 0xffffffff82672f73

#define kdlsym_addr_copyout_patch1 0xffffffff82672e72
#define kdlsym_addr_copyout_patch2 0xffffffff82672e7e

#define kdlsym_addr_copyinstr_patch1 0xffffffff82673413
#define kdlsym_addr_copyinstr_patch2 0xffffffff8267341f
#define kdlsym_addr_copyinstr_patch3 0xffffffff82673450


#elif (FIRMWARE == 1050 || FIRMWARE == 1070 || FIRMWARE == 1071) // FW 10.50 / 10.70 / 10.71

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0
#define kdlsym_addr_printf 0xffffffff82650e80

#define kdlsym_addr_sysent 0xffffffff833029c0

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff822d75b7
#define kdlsym_addr_copyin_patch2 0xffffffff822d75c3

#define kdlsym_addr_copyout_patch1 0xffffffff822d74c2
#define kdlsym_addr_copyout_patch2 0xffffffff822d74ce

#define kdlsym_addr_copyinstr_patch1 0xffffffff822d7a63
#define kdlsym_addr_copyinstr_patch2 0xffffffff822d7a6f
#define kdlsym_addr_copyinstr_patch3 0xffffffff822d7aa0


#elif FIRMWARE == 1100 // FW 11.00

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0
#define kdlsym_addr_printf 0xffffffff824fcbd0

#define kdlsym_addr_sysent 0xffffffff83301760

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff824de037
#define kdlsym_addr_copyin_patch2 0xffffffff824de043

#define kdlsym_addr_copyout_patch1 0xffffffff824ddf42
#define kdlsym_addr_copyout_patch2 0xffffffff824ddf4e

#define kdlsym_addr_copyinstr_patch1 0xffffffff824de4e3
#define kdlsym_addr_copyinstr_patch2 0xffffffff824de4ef
#define kdlsym_addr_copyinstr_patch3 0xffffffff824de520


#else

#error "Invalid firmware"

#endif

#define kdlsym(sym) (kaslr_offset + kdlsym_addr_##sym)

#endif
