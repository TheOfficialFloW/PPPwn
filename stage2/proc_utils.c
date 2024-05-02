#include "proc_utils.h"
#include "elf.h"
#include "offsets.h"

int proc_get_vm_map(struct thread *td, uint8_t *kbase, struct proc *p, struct proc_vm_map_entry **entries, uint64_t *num_entries) {
    struct proc_vm_map_entry *info = NULL;
    struct vm_map_entry *entry = NULL;
    int r = 0;

    struct vmspace *vm = p->p_vmspace;
    struct vm_map *map = &vm->vm_map;


    void (*vm_map_lock_read)(struct vm_map *map) = (void *)(kbase + vm_map_lock_read_offset);
    int (*vm_map_unlock_read)(struct vm_map *map) = (void *)(kbase + vm_map_unlock_read_offset);
    int (*vm_map_lookup_entry)(struct vm_map *map, uint64_t address, struct vm_map_entry **entry) = (void *)(kbase + vm_map_lookup_entry_offset);
    void* (*malloc)(unsigned long size, void* type, int flags) = (void*)(kbase + malloc_offset);
    uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;
    int (*printf)(const char *format, ...) = (void *)kdlsym(printf);
    

    void* M_TEMP = (void*)(kbase + 0x015621E0);
    vm_map_lock_read(map);

    int num = map->nentries;
    if (!num) {
        printf("num is 0\n");
        goto error;
    }

    r = vm_map_lookup_entry(map, NULL, &entry);
    if(r) {
        printf("vm_map_lookup_entry failed\n");
        goto error;
    }

    info = (struct proc_vm_map_entry *)malloc(num * sizeof(struct proc_vm_map_entry), M_TEMP, 2);
    if (!info) {
        printf("malloc failed\n");
        r = 1;
        goto error;
    }

    for (int i = 0; i < num; i++) {
        info[i].start = entry->start;
        info[i].end = entry->end;
        info[i].offset = entry->offset;
        info[i].prot = entry->prot & (entry->prot >> 8);
        memcpy(info[i].name, entry->name, sizeof(info[i].name));

        if (!(entry = entry->next)) {
            break;
        }
    }

error:
    vm_map_unlock_read(map);

    if (entries) {
        *entries = info;
    }

    if (num_entries) {
        *num_entries = num;
    }

    return 0;
}

int proc_rw_mem(struct thread *td, uint8_t *kbase, struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n, int write) {
    struct iovec iov;
    struct uio uio;
    
    int r = 0;
    int (*proc_rwmem)(struct proc *p, struct uio *uio) = (void *)(kbase + proc_rmem_offset);
    uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;
    int (*printf)(const char *format, ...) = (void *)kdlsym(printf);

    if(size >= 0x400000){
        printf("Size %d too big\n", size);
        return 1;
    }

    if (!p) {
        return 1;
    }

    if (size == 0) {
        if (n) {
            *n = 0;
        }

        return 0;
    }

    memset(&iov, NULL, sizeof(iov));
    iov.iov_base = (uint64_t)data;
    iov.iov_len = size;

    memset(&uio, NULL, sizeof(uio));
    uio.uio_iov = (uint64_t)&iov;
    uio.uio_iovcnt = 1;
    uio.uio_offset = (uint64_t)ptr;
    uio.uio_resid = (uint64_t)size;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_rw = write ? UIO_WRITE : UIO_READ;
    uio.uio_td = td;

    printf("proc_rw_mem: uio.uio_resid: %d\n", uio.uio_resid);
    r = proc_rwmem(p, &uio);

    if (n) {
        *n = (uint64_t)((uint64_t)size - uio.uio_resid);
    }
    

    return r;
}

int proc_read_mem(struct thread *td, uint8_t *kbase, struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n) {
    return proc_rw_mem(td, kbase, p, ptr, size, data, n, 0);
}

int proc_write_mem(struct thread *td, uint8_t *kbase,struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n) {
    return proc_rw_mem(td, kbase, p, ptr, size, data, n, 1);
}

int proc_allocate(struct thread *td, uint8_t *kbase, struct proc *p, void **address, uint64_t size) {
    uint64_t addr = NULL;
    int r = 0;
    void (*vm_map_lock)(struct vm_map *map) = (void *)(kbase + vm_map_lock_offset);
    int (*vm_map_unlock)(struct vm_map *map) = (void *)(kbase + vm_map_unlock_offset);
      int (*vm_map_insert)(struct vm_map *map, struct vm_object *object,
                       vm_ooffset_t offset, vm_offset_t start, vm_offset_t end,
                       vm_prot_t prot, vm_prot_t max, int cow) =
      (void *)(kbase + vm_map_insert_offset);
     
    int (*vm_map_findspace)(struct vm_map *map, uint64_t start, uint64_t length, uint64_t *addr) = (void *)(kbase + vm_map_findspace_offset);

    
    if (!address) {
        r = 1;
        goto error;
    }

    struct vmspace *vm = p->p_vmspace;
    struct vm_map *map = &vm->vm_map;

    vm_map_lock(map);

    r = vm_map_findspace(map, NULL, size, &addr);
    if (r) {
        vm_map_unlock(map);
        goto error;
    }

    r = vm_map_insert(map, NULL, NULL, addr, addr + size, VM_PROT_ALL, VM_PROT_ALL, 0);

    vm_map_unlock(map);

    if (r) {
        goto error;
    }

    if (address) {
        *address = (void *)addr;
    }

error:
    return r;
}

int proc_deallocate(struct thread* td, uint8_t* kbase,struct proc *p, void *address, uint64_t size) {
    int r = 0;
    void (*vm_map_lock)(struct vm_map *map) = (void *)(kbase + vm_map_lock_offset);
    int (*vm_map_unlock)(struct vm_map *map) = (void *)(kbase + vm_map_unlock_offset);
   
    int(*vm_map_delete)(struct vm_map *map, uint64_t start, uint64_t end) = (void *)(kbase + vm_map_delete_offset);

    struct vmspace *vm = p->p_vmspace;
    struct vm_map *map = &vm->vm_map;

    vm_map_lock(map);

    r = vm_map_delete(map, (uint64_t)address, (uint64_t)address + size);

    vm_map_unlock(map);

    return r;
}


int proc_create_thread(struct thread *td, uint8_t *kbase, struct proc *p, uint64_t address) {
    void *rpcldraddr = NULL;
    void *stackaddr = NULL;
    struct proc_vm_map_entry *entries = NULL;
    uint64_t num_entries = 0;
    uint64_t n = 0;
    int r = 0;
    void* M_TEMP = (void*)(kbase + M_TEMP_offset);
    void (*free)(void *ptr, int type) = (void *)(kbase + free_offset);
    
    int (*create_thread)(struct thread * td, uint64_t ctx, void (*start_func)(void *), void *arg, char *stack_base, uint64_t stack_size, char *tls_base, long *child_tid, long *parent_tid, uint64_t flags, uint64_t rtp) = (void *)(kbase + create_thread_offset);
    uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;
    int (*printf)(const char *format, ...) = (void *)kdlsym(printf);
    uint64_t ldrsize = sizeof(rpcldr);
    ldrsize += (PAGE_SIZE - (ldrsize % PAGE_SIZE));
    
    uint64_t stacksize = 0x80000;

    // allocate rpc ldr
    r = proc_allocate(td, kbase, p, &rpcldraddr, ldrsize);
    if (r) {
        printf("proc_allocate failed\n");
        goto error;
    }

    // allocate stack
    r = proc_allocate(td, kbase, p, &stackaddr, stacksize);
    if (r) {
        printf("proc_allocate failed\n");
        goto error;
    }

    // write loader
    r = proc_write_mem(td, kbase, p, rpcldraddr, sizeof(rpcldr), (void *)rpcldr, &n);
    if (r) {
        printf("proc_write_mem failed\n");
        goto error;//
    }

    // donor thread
    struct thread *thr = TAILQ_FIRST(&p->p_threads);

    // find libkernel base
    r = proc_get_vm_map(td, kbase, p, &entries, &num_entries);
    if (r) {
        printf("proc_get_vm_map failed\n");
        goto error;
    }
    printf("entries->start: %p, entries->offset %p, num_entries %d\n", entries->start, entries->offset, num_entries);

    // offsets are for 9.00 libraries

    uint64_t _scePthreadAttrInit = 0, _scePthreadAttrSetstacksize = 0, _scePthreadCreate = 0, _thr_initial = 0;
    for (int i = 0; i < num_entries; i++) {
        if (entries[i].prot != (PROT_READ | PROT_EXEC)) {
            continue;
        }

        if (!memcmp(entries[i].name, "libkernel_sys.sprx", 18)) {
            _scePthreadAttrInit = entries[i].start + _scePthreadAttrInit_offset;
            _scePthreadAttrSetstacksize = entries[i].start + _scePthreadAttrSetstacksize_offset;
            _scePthreadCreate = entries[i].start + _scePthreadCreate_offset;
            _thr_initial = entries[i].start + _thr_initial_offset;
            printf("libkernel_sys.sprx found\n");
            break;
        }
    }

    if (!_scePthreadAttrInit) {
        printf("libkernel not found\n");
        goto error;
    }

    // write variables
    r = proc_write_mem(td, kbase, p, rpcldraddr + offsetof(struct rpcldr_header, stubentry), sizeof(address), (void *)&address, &n);
    if (r) {
        printf("proc_write_mem failed\n");
        goto error;
    }

    r = proc_write_mem(td, kbase, p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadAttrInit), sizeof(_scePthreadAttrInit), (void *)&_scePthreadAttrInit, &n);
    if (r) {
        printf("proc_write_mem failed\n");
        goto error;
    }

    r = proc_write_mem(td, kbase, p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadAttrSetstacksize), sizeof(_scePthreadAttrSetstacksize), (void *)&_scePthreadAttrSetstacksize, &n);
    if (r) {
        printf("proc_write_mem failed\n");
        goto error;
    }

    r = proc_write_mem(td, kbase, p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadCreate), sizeof(_scePthreadCreate), (void *)&_scePthreadCreate, &n);
    if (r) {
        printf("proc_write_mem failed\n");
        goto error;
    }

    r = proc_write_mem(td, kbase, p, rpcldraddr + offsetof(struct rpcldr_header, thr_initial), sizeof(_thr_initial), (void *)&_thr_initial, &n);
    if (r) {
        printf("proc_write_mem failed\n");
        goto error;
    }

    // execute loader
    // note: do not enter in the pid information as it expects it to be stored in userland
    uint64_t ldrentryaddr = (uint64_t)rpcldraddr + *(uint64_t *)(rpcldr + 4);
    r = create_thread(thr, NULL, (void *)ldrentryaddr, NULL, stackaddr, stacksize, NULL, NULL, NULL, 0, NULL);
    if (r) {
        printf("create_thread failed\n");
        goto error;
    }


    // wait until loader is done
    uint8_t ldrdone = 0;
    while (!ldrdone) {
        r = proc_read_mem(td, kbase, p, (void *)(rpcldraddr + offsetof(struct rpcldr_header, ldrdone)), sizeof(ldrdone), &ldrdone, &n);
        if (r) {
            printf("proc_read_mem failed\n");
            goto error;
        }
    }

error:
    if (entries) {
        free(entries, M_TEMP);
    }

    if (rpcldraddr) {
        proc_deallocate(td, kbase, p, rpcldraddr, ldrsize);
    }

    if (stackaddr) {
        proc_deallocate(td, kbase, p, stackaddr, stacksize);
    }
    printf("proc_create_thread done .........\n");
    return r;
}
