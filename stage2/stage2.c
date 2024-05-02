/*
 * Copyright (C) 2024 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

// clang-format off
#include "proc_utils.h"

extern uint8_t payloadbin[];
extern int32_t payloadbin_size;



int memcmp(const void * str1,
  const void * str2, size_t count) {
  const unsigned char * s1 = (const unsigned char * ) str1;
  const unsigned char * s2 = (const unsigned char * ) str2;

  while (count--> 0) {
    if ( * s1++ != * s2++)
      return s1[-1] < s2[-1] ? -1 : 1;
  }
  return 0;
}

static int ksys_open(struct thread * td,
  const char * path, int flags, int mode) {
  int( * sys_open)(struct thread * , struct open_args * ) =
    (void * ) sysents[SYS_open].sy_call;

  td -> td_retval[0] = 0;

  struct open_args uap;
  uap.path = (char * ) path;
  uap.flags = flags;
  uap.mode = mode;
  int error = sys_open(td, & uap);
  if (error)
    return -error;

  return td -> td_retval[0];
}

static int ksys_write(struct thread * td, int fd,
  const void * buf,
    size_t nbytes) {
  int( * sys_write)(struct thread * , struct write_args * ) =
    (void * ) sysents[SYS_write].sy_call;

  td -> td_retval[0] = 0;

  struct write_args uap;
  uap.fd = fd;
  uap.buf = buf;
  uap.nbyte = nbytes;
  int error = sys_write(td, & uap);
  if (error)
    return -error;

  return td -> td_retval[0];
}

static int ksys_close(struct thread * td, int fd) {
  int( * sys_close)(struct thread * , struct close_args * ) =
    (void * ) sysents[SYS_close].sy_call;

  td -> td_retval[0] = 0;

  struct close_args uap;
  uap.fd = fd;
  int error = sys_close(td, & uap);
  if (error)
    return -error;

  return td -> td_retval[0];
}

struct sce_proc * proc_find_by_name(uint8_t * kbase,
  const char * name) {
  struct sce_proc * p;

  if (!name) {
    return NULL;
  }
  //printf("after name\n");

  p = * (struct proclist ** )(kbase + all_proc_offset);
  do {
    // printf("p->p_comm: %s\n", p->p_comm);
    if (!memcmp(p -> p_comm, name, strlen(name))) {
      return p;
    }
  } while ((p = p -> p_forw));

  return NULL;
}
#define USB_LOADER 1
#if USB_LOADER
static int ksys_read(struct thread * td, int fd, void * buf, size_t nbytes) {
  int( * sys_read)(struct thread * , struct read_args * ) =
    (void * ) sysents[SYS_read].sy_call;

  td -> td_retval[0] = 0;

  struct read_args uap;
  uap.fd = fd;
  uap.buf = buf;
  uap.nbyte = nbytes;
  int error = sys_read(td, & uap);
  if (error)
    return -error;

  return td -> td_retval[0];
}
#endif
#if ENABLE_DEBUG_MENU
int shellui_patch(struct thread * td, uint8_t * kbase) {
  uint8_t * libkernel_sys_base = NULL,
    * executable_base = NULL,
    * app_base = NULL;

  size_t n;
  void * M_TEMP = (void * )(kbase + M_TEMP_offset);
  uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;
  void( * free)(void * ptr, int type) = (void * )(kbase + free_offset);
  int( * printf)(const char * format, ...) = (void * ) kdlsym(printf);

  struct proc_vm_map_entry * entries = NULL;
  size_t num_entries = 0;

  int ret = 0;

  uint32_t ofs_to_ret_1[] = {
    0x0001D1C0,
    0x0001D520,
  };

  uint8_t mov__eax_1__ret[6] = {
    0xB8,
    0x01,
    0x00,
    0x00,
    0x00,
    0xC3
  };

  struct sce_proc * ssui = proc_find_by_name(kbase, "SceShellUI");

  if (!ssui) {
    ret = -1;
    goto error;
  }
  printf("ssui->pid: %d\n", ssui -> pid);

  ret = proc_get_vm_map(td, kbase, ssui, & entries, & num_entries);
  if (ret)
    goto error;

  for (int i = 0; i < num_entries; i++) {
    if (!memcmp(entries[i].name, "executable", 10) && (entries[i].prot >= (PROT_READ | PROT_EXEC))) {
      executable_base = (uint8_t * ) entries[i].start;
      break;
    }
  }

  if (!executable_base) {
    ret = 1;
    goto error;
  }

  for (int i = 0; i < num_entries; i++) {
    if (!memcmp(entries[i].name, "app.exe.sprx", 12) && (entries[i].prot >= (PROT_READ | PROT_EXEC))) {
      app_base = (uint8_t * ) entries[i].start;
      break;
    }
  }

  if (!app_base) {
    ret = 1;
    goto error;
  }

  // enable remote play menu - credits to Aida
  for (int i = 0; i < num_entries; i++) {
    if (!memcmp(entries[i].name, "libkernel_sys.sprx", 18) && (entries[i].prot >= (PROT_READ | PROT_EXEC))) {
      libkernel_sys_base = (uint8_t * ) entries[i].start;
      break;
    }
  }

  if (!libkernel_sys_base) {
    ret = -1;
    goto error;
  }

  // enable debug settings menu
  for (int i = 0; i < COUNT_OF(ofs_to_ret_1); i++) {
    ret = proc_write_mem(td, kbase, ssui, (void * )(libkernel_sys_base + ofs_to_ret_1[i]), sizeof(mov__eax_1__ret), mov__eax_1__ret, & n);
    if (ret)
      goto error;
  }

  error:
    if (entries)
      free(entries, M_TEMP);

  return ret;
}

int shellcore_fpkg_patch(struct thread * td, uint8_t * kbase) {
  uint8_t * text_seg_base = NULL;
  size_t n;

  struct proc_vm_map_entry * entries = NULL;
  size_t num_entries = 0;

  int ret = 0;

  uint32_t call_ofs_for__xor__eax_eax__3nop[] = {
    // call sceKernelIsGenuineCEX
    sceKernelIsGenuineCEX,
    sceKernelIsGenuineCEX_1,
    sceKernelIsGenuineCEX_2,
    sceKernelIsGenuineCEX_3,
    // call nidf_libSceDipsw
    dipsw_libSceDipsw,
    dipsw_libSceDipsw_1,
    dipsw_libSceDipsw_2,
    dipsw_libSceDipsw_3,
  };

  void * M_TEMP = (void * )(kbase + M_TEMP_offset);
  void( * free)(void * ptr, int type) = (void * )(kbase + free_offset);
  uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;
  int( * printf)(const char * format, ...) = (void * ) kdlsym(printf);

  uint8_t xor__eax_eax__inc__eax[5] = {
    0x31,
    0xC0,
    0xFF,
    0xC0,
    0x90
  };

  struct proc * ssc = proc_find_by_name(kbase, "SceShellCore");

  if (!ssc) {
    ret = -1;
    goto error;
  }

  ret = proc_get_vm_map(td, kbase, ssc, & entries, & num_entries);
  if (ret) {
    goto error;
  }

  for (int i = 0; i < num_entries; i++) {
    if (entries[i].prot == (PROT_READ | PROT_EXEC)) {
      text_seg_base = (uint8_t * ) entries[i].start;
      break;
    }
  }

  if (!text_seg_base) {
    ret = -1;
    goto error;
  }

  // enable installing of debug packages
  for (int i = 0; i < COUNT_OF(call_ofs_for__xor__eax_eax__3nop); i++) {
    ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + call_ofs_for__xor__eax_eax__3nop[i]), 5, "\x31\xC0\x90\x90\x90", & n);
    if (ret)
      goto error;
  }

  ret = proc_write_mem(td, kbase, ssc, text_seg_base + enable_data_mount_patch, sizeof(xor__eax_eax__inc__eax), xor__eax_eax__inc__eax, & n);
  if (ret)
    goto error;

  // enable fpkg for patches
  ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + enable_fpkg_patch), 8, "\xE9\x96\x00\x00\x00\x90\x90\x90", & n);
  if (ret)
    goto error;

  // this offset corresponds to "fake\0" string in the Shellcore's memory
  ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + fake_free_patch), 5, "free\0", & n);
  if (ret)
    goto error;

  // make pkgs installer working with external hdd
  ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + pkg_installer_patch), 1, "\0", & n);
  if (ret)
    goto error;

  // enable support with 6.xx external hdd
  ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + ext_hdd_patch), 1, "\xEB", & n);
  if (ret)
    goto error;

  // enable debug trophies on retail
  ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + debug_trophies_patch), 5, "\x31\xc0\x90\x90\x90", & n);
  if (ret) {
    goto error;
  }

  error:
    if (entries)
      free(entries, M_TEMP);

  return ret;
}
#endif
#define SYS_kexec 11

struct sys_kexec_args {
  int( * fptr)(void * );
  void * arg;
};

static int sys_kexec(struct thread * td, struct sys_kexec_args * uap) {
  return uap -> fptr(uap -> arg);

}

void stage2(void) {
  uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;
  uint8_t * kbase = (uint8_t * )(rdmsr(0xC0000082) - 0x1C0);
  int( * printf)(const char * format, ...) = (void * ) kdlsym(printf);
  //  int (*printf)(const char *format, ...) =
  //  (void*)(kernel_base+0x000B7A30);//(void *)kdlsym(printf);//0x000B7A30
  sysents = (struct sysent * ) kdlsym(sysent);
  //
  printf("**********************************   stage2\n");

  // Disable write protection
  uint64_t cr0 = rcr0();
  load_cr0(cr0 & ~CR0_WP);

  // Allow syscalls everywhere
  *(uint32_t * ) kdlsym(amd_syscall_patch1) = 0;
  *(uint16_t * ) kdlsym(amd_syscall_patch2) = 0x9090;
  *(uint16_t * ) kdlsym(amd_syscall_patch3) = 0x9090;
  *(uint8_t * ) kdlsym(amd_syscall_patch4) = 0xeb;

  // Allow user and kernel addresses
  uint8_t nops[] = {
    0x90,
    0x90,
    0x90
  };

  *(uint16_t * ) kdlsym(copyin_patch1) = 0x9090;
  memcpy((void * ) kdlsym(copyin_patch2), nops, sizeof(nops));

  *(uint16_t * ) kdlsym(copyout_patch1) = 0x9090;
  memcpy((void * ) kdlsym(copyout_patch2), nops, sizeof(nops));

  *(uint16_t * ) kdlsym(copyinstr_patch1) = 0x9090;
  memcpy((void * ) kdlsym(copyinstr_patch2), nops, sizeof(nops));
  *(uint16_t * ) kdlsym(copyinstr_patch3) = 0x9090;

  printf("Patching vm_map_protect, ptrace, ASLR and kmem_alloc\n");

  // patch vm_map_protect check

  memcpy((void * )(kbase + vm_map_protect_p), "\x90\x90\x90\x90\x90\x90", 6);

  // patch ptrace
  *(uint8_t * )(kbase + ptrace_p) = 0xEB;
  memcpy((void * )(kbase + ptrace_p2), "\xE9\x7C\x02\x00\x00", 5);

  // patch sceSblACMgrIsAllowedSystemLevelDebugging

  memcpy((void * )(kbase + sceSblACMgrIsAllowedSystemLevelDebugging_p), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8); //900

  // patch ASLR, thanks 2much4u
  *(uint16_t * )(kbase + disable_aslr_p) = 0x9090;

  // patch kmem_alloc
  *(uint8_t * )(kbase + kemem_1) = VM_PROT_ALL;
  *(uint8_t * )(kbase + kemem_2) = VM_PROT_ALL;

  // Install kexec syscall 11
  struct sysent * sys = & sysents[SYS_kexec];
  sys -> sy_narg = 2;
  sys -> sy_call = (void * ) sys_kexec;
  sys -> sy_thrcnt = 1;

  printf("kexec added\n");

  // Restore write protection
  load_cr0(cr0);

  // Send notification
  OrbisNotificationRequest notify = {};
  notify.targetId = -1;
  notify.useIconImageUri = 1;
  memcpy( & notify.message, "PPPwned: Payload Injected successfully", 40);

  struct thread * td = curthread;
  void( * vm_map_lock)(struct vm_map * map) = (void * )(kbase + vm_map_lock_offset);
  struct vmspace * vm;
  struct vm_map * map;
  int r;
  int( * vm_map_insert)(struct vm_map * map, struct vm_object * object,
      vm_ooffset_t offset, vm_offset_t start, vm_offset_t end,
      vm_prot_t prot, vm_prot_t max, int cow) =
    (void * )(kbase + vm_map_insert_offset);
  int( * vm_map_unlock)(struct vm_map * map) = (void * )(kbase + vm_map_unlock_offset);

  #if ENABLE_DEBUG_MENU
  printf("Enabling Debug Menu\n");
  shellui_patch(td, kbase);
  shellcore_fpkg_patch(td, kbase);
  printf("Done.\n");
  #endif
  int fd;

  #if USB_LOADER
 void* buffer = NULL;
 void (*free)(void * ptr, int type) = (void *)(kbase + free_offset);
 void* M_TEMP = (void *)(kbase + M_TEMP_offset);
  void * ( * malloc)(unsigned long size, void * type, int flags) = (void * )(kbase + malloc_offset);
  fd = ksys_open(td, "/mnt/usb0/payload.bin", O_RDONLY, 0);
  if (fd < 0)
    fd = ksys_open(td, "/mnt/usb1/payload.bin", O_RDONLY, 0);
  if (fd < 0)
    fd = ksys_open(td, "/mnt/usb2/payload.bin", O_RDONLY, 0);
  if (fd < 0)
    fd = ksys_open(td, "/data/payload.bin", O_RDONLY, 0);

  if (fd < 0) {
    printf( "Failed to open payload.bin from local storage\n");
    return;
  }

  static
  const int PAYLOAD_SZ = 0x400000;

  if ((buffer = malloc(PAYLOAD_SZ, M_TEMP, 0)) == NULL) {
   printf(  "Failed to allocate memory for payload\n");
    return;
  }

  int payload_size = ksys_read(td, fd, buffer, PAYLOAD_SZ);
  if (payload_size <= 0) {
    printf(  "Failed to read payload\n");
    free(buffer, M_TEMP);
    return;
  }
  ksys_close(td, fd);
  printf("payload_size: %d\n", payload_size);

  #endif

  printf("Finding SceShellCore process...\n");

  struct sce_proc * p = proc_find_by_name(kbase, "SceShellCore");
  if (!p) {
    printf("could not find SceShellCore process!\n");
    return;
  }
  printf("Found SceShellCore process @ PID %d\n", p -> pid);

  vm = p -> p_vmspace;
  map = & vm -> vm_map;

  // allocate some memory.
  vm_map_lock(map);
  r = vm_map_insert(map, NULL, NULL, PAYLOAD_BASE, PAYLOAD_BASE + 0x400000, VM_PROT_ALL, VM_PROT_ALL, 0);
  vm_map_unlock(map);
  if (r) {
    printf("failed to allocate payload memory!\n");
    return r;
  }
  printf("Allocated payload memory @ 0x%016lx\n", PAYLOAD_BASE);
  printf("Writing payload...\n");
  // write the payload
  #if USB_LOADER
 // r = proc_write_mem(td, kbase, p, (void * ) PAYLOAD_BASE, buffer, payload_size, NULL);
  struct iovec iov;
    struct uio uio;
    
    int (*proc_rwmem)(struct proc *p, struct uio *uio) = (void *)(kbase + proc_rmem_offset);

    if(payload_size >= 0x400000){
        printf("Size %d too big\n", payload_size);
        return 1;
    }

    memset(&iov, NULL, sizeof(iov));
    iov.iov_base = (uint64_t)buffer;
    iov.iov_len = payload_size;

    memset(&uio, NULL, sizeof(uio));
    uio.uio_iov = (uint64_t)&iov;
    uio.uio_iovcnt = 1;
    uio.uio_offset = (uint64_t)PAYLOAD_BASE;
    uio.uio_resid = payload_size;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_rw =  UIO_WRITE;
    uio.uio_td = td;

    printf("proc_rw_mem: uio.uio_resid: %d\n", uio.uio_resid);
    r = proc_rwmem(p, &uio);
    
  #else
  r = proc_write_mem(td, kbase, p, (void * ) PAYLOAD_BASE, payloadbin_size, payloadbin, NULL);
  #endif
  if (r) {
    printf("failed to write payload!\n");
    return r;
  }
  printf("Wrote payload!\n");
  printf("Creating ShellCore payload thread...\n");
  // create a thread
  r = proc_create_thread(td, kbase, p, PAYLOAD_BASE);
  if (r) {
    printf("failed to create payload thread!\n");
    return r;
  }
  printf("Created payload thread!\n");


  fd = ksys_open(td, "/dev/notification0", O_WRONLY, 0);
  if (!fd)
    fd = ksys_open(td, "/dev/notification0", O_WRONLY | O_NONBLOCK, 0);
  if (!fd)
    fd = ksys_open(td, "/dev/notification1", O_WRONLY, 0);
  if (!fd)
    fd = ksys_open(td, "/dev/notification1", O_WRONLY | O_NONBLOCK, 0);

  if (fd) {
    ksys_write(td, fd, & notify, sizeof(notify));
    ksys_close(td, fd);
  }
}