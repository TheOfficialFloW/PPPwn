/*
 * Copyright (c) 2024 LM
 * PPPwn test payload
 */

#include "ps4.h"
void* kernel_base = NULL;
int kpayload(struct thread *td){

 kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x1C0];
 return 0;
}

int _main(struct thread *td) {
    static int (*sceKernelDebugOutText)(int, const char*) = NULL;

    // Initialize PS4 Kernel, libc, and networking
    initKernel();
    initLibc();
    initNetwork();
    initSysUtil();

    // Load and resolve libkernel_sys library
    int libk = sceKernelLoadStartModule("libkernel_sys.sprx", 0, NULL, 0, 0, 0);
    RESOLVE(libk, sceKernelDebugOutText);

    // Output initialization messages
    if (sceKernelDebugOutText) {
        sceKernelDebugOutText(0, "==========================\n");
        sceKernelDebugOutText(0, "Hello From inside Shellcore!!!\n");
        sceKernelDebugOutText(0, "==========================\n");
    }

    printf_notification("Payload ran");
    syscall(11, kpayload);
    char buf[255];
    sprintf(buf, "kernel_base: %p\n", kernel_base);
    sceKernelDebugOutText(0, buf);
    

    return 0;
}