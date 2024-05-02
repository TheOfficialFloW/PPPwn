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

# FW 9.50 / 9.60
class OffsetsFirmware_950_960:
    PPPOE_SOFTC_LIST = 0xffffffff8434c0a8

    KERNEL_MAP = 0xffffffff84347830

    SETIDT = 0xffffffff8254d320

    KMEM_ALLOC = 0xffffffff823889d0
    KMEM_ALLOC_PATCH1 = 0xffffffff82388a9c
    KMEM_ALLOC_PATCH2 = 0xffffffff82388aa4

    MEMCPY = 0xffffffff82401cc0

    MOV_CR0_RSI_UD2_MOV_EAX_1_RET = 0xffffffff822bea79

    SECOND_GADGET_OFF = 0x3b

    # 0xffffffff822c53cd : jmp qword ptr [rsi + 0x3b]
    FIRST_GADGET = 0xffffffff822c53cd

    # 0xffffffff82c6ec06 : push rbp ; jmp qword ptr [rsi]
    PUSH_RBP_JMP_QWORD_PTR_RSI = 0xffffffff82c6ec06

    # 0xffffffff822bf041 : pop rbx ; pop r14 ; pop rbp ; jmp qword ptr [rsi + 0x10]
    POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10 = 0xffffffff822bf041

    # 0xffffffff82935fc6 : lea rsp, [rsi + 0x20] ; repz ret
    LEA_RSP_RSI_20_REPZ_RET = 0xffffffff82935fc6

    # 0xffffffff826adfda : add rsp, 0x28 ; pop rbp ; ret
    ADD_RSP_28_POP_RBP_RET = 0xffffffff826adfda

    # 0xffffffff82584c1f : add rsp, 0xb0 ; pop rbp ; ret
    ADD_RSP_B0_POP_RBP_RET = 0xffffffff82584c1f

    # 0xffffffff822008e0 : ret
    RET = 0xffffffff822008e0

    # 0xffffffff82315161 : pop rdi ; ret
    POP_RDI_RET = 0xffffffff82315161

    # 0xffffffff822dd859 : pop rsi ; ret
    POP_RSI_RET = 0xffffffff822dd859

    # 0xffffffff822cad55 : pop rdx ; ret
    POP_RDX_RET = 0xffffffff822cad55

    # 0xffffffff8222d707 : pop rcx ; ret
    POP_RCX_RET = 0xffffffff8222d707

    # 0xffffffff8220fec7 : pop r8 ; pop rbp ; ret
    POP_R8_POP_RBP_RET = 0xffffffff8220fec7

    # 0xffffffff8279f14f : pop r12 ; ret
    POP_R12_RET = 0xffffffff8279f14f

    # 0xffffffff8223a7fe : pop rax ; ret
    POP_RAX_RET = 0xffffffff8223a7fe

    # 0xffffffff822008df : pop rbp ; ret
    POP_RBP_RET = 0xffffffff822008df

    # 0xffffffff82bad912 : push rsp ; pop rsi ; ret
    PUSH_RSP_POP_RSI_RET = 0xffffffff82bad912

    # 0xffffffff8235fea0 : mov rdi, qword ptr [rdi] ; pop rbp ; jmp rax
    MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX = 0xffffffff8235fea0

    # 0xffffffff824f2458 : mov byte ptr [rcx], al ; ret
    MOV_BYTE_PTR_RCX_AL_RET = 0xffffffff824f2458

    # 0xffffffff822524dc : mov rdi, rbx ; call r12
    MOV_RDI_RBX_CALL_R12 = 0xffffffff822524dc

    # 0xffffffff82252317 : mov rdi, r14 ; call r12
    MOV_RDI_R14_CALL_R12 = 0xffffffff82252317

    # 0xffffffff824a07ae : mov rsi, rbx ; call rax
    MOV_RSI_RBX_CALL_RAX = 0xffffffff824a07ae

    # 0xffffffff82567228 : mov r14, rax ; call r8
    MOV_R14_RAX_CALL_R8 = 0xffffffff82567228

    # 0xffffffff82caedfa : add rdi, rcx ; ret
    ADD_RDI_RCX_RET = 0xffffffff82caedfa

    # 0xffffffff82333437 : sub rsi, rdx ; mov rax, rsi ; pop rbp ; ret
    SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET = 0xffffffff82333437

    # 0xffffffff82b7c6e7 : jmp r14
    JMP_R14 = 0xffffffff82b7c6e7

# FW 10.50 / 10.70 / 10.71
class OffsetsFirmware_1050_1071:
    PPPOE_SOFTC_LIST = 0xffffffff844514b8

    KERNEL_MAP = 0xffffffff844a9250

    SETIDT = 0xffffffff82341470

    KMEM_ALLOC = 0xffffffff82628960
    KMEM_ALLOC_PATCH1 = 0xffffffff82628a2c
    KMEM_ALLOC_PATCH2 = 0xffffffff82628a34

    MEMCPY = 0xffffffff822d7370

    MOV_CR0_RSI_UD2_MOV_EAX_1_RET = 0xffffffff82285f39

    SECOND_GADGET_OFF = 0x3b

    # 0xffffffff8221cb8d : jmp qword ptr [rsi + 0x3b]
    FIRST_GADGET = 0xffffffff8221cb8d

    # 0xffffffff82c74cd6 : push rbp ; jmp qword ptr [rsi]
    PUSH_RBP_JMP_QWORD_PTR_RSI = 0xffffffff82c74cd6

    # 0xffffffff824a4981 : pop rbx ; pop r14 ; pop rbp ; jmp qword ptr [rsi + 0x10]
    POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10 = 0xffffffff824a4981

    # 0xffffffff82921206 : lea rsp, [rsi + 0x20] ; repz ret
    LEA_RSP_RSI_20_REPZ_RET = 0xffffffff82921206

    # 0xffffffff826c493a : add rsp, 0x28 ; pop rbp ; ret
    ADD_RSP_28_POP_RBP_RET = 0xffffffff826c493a

    # 0xffffffff822ce1af : add rsp, 0xb0 ; pop rbp ; ret
    ADD_RSP_B0_POP_RBP_RET = 0xffffffff822ce1af

    # 0xffffffff822008e0 : ret
    RET = 0xffffffff822008e0

    # 0xffffffff8236f38f : pop rdi ; ret
    POP_RDI_RET = 0xffffffff8236f38f

    # 0xffffffff82222d59 : pop rsi ; ret
    POP_RSI_RET = 0xffffffff82222d59

    # 0xffffffff82329bb2 : pop rdx ; ret
    POP_RDX_RET = 0xffffffff82329bb2

    # 0xffffffff8225a567 : pop rcx ; ret
    POP_RCX_RET = 0xffffffff8225a567

    # 0xffffffff822234fd : pop r8 ; pop rbp ; ret
    POP_R8_POP_RBP_RET = 0xffffffff822234fd

    # 0xffffffff827aa3ef : pop r12 ; ret
    POP_R12_RET = 0xffffffff827aa3ef

    # 0xffffffff82495c08 : pop rax ; ret
    POP_RAX_RET = 0xffffffff82495c08

    # 0xffffffff822008df : pop rbp ; ret
    POP_RBP_RET = 0xffffffff822008df

    # 0xffffffff82bb5092 : push rsp ; pop rsi ; ret
    PUSH_RSP_POP_RSI_RET = 0xffffffff82bb5092

    # 0xffffffff8256d4d0 : mov rdi, qword ptr [rdi] ; pop rbp ; jmp rax
    MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX = 0xffffffff8256d4d0

    # 0xffffffff822a9078 : mov byte ptr [rcx], al ; ret
    MOV_BYTE_PTR_RCX_AL_RET = 0xffffffff822a9078

    # 0xffffffff8229113c : mov rdi, rbx ; call r12
    MOV_RDI_RBX_CALL_R12 = 0xffffffff8229113c

    # 0xffffffff82290f77 : mov rdi, r14 ; call r12
    MOV_RDI_R14_CALL_R12 = 0xffffffff82290f77

    # 0xffffffff8227e3ce : mov rsi, rbx ; call rax
    MOV_RSI_RBX_CALL_RAX = 0xffffffff8227e3ce

    # 0xffffffff824f95e8 : mov r14, rax ; call r8
    MOV_R14_RAX_CALL_R8 = 0xffffffff824f95e8

    # 0xffffffff82cb4eca : add rdi, rcx ; ret
    ADD_RDI_RCX_RET = 0xffffffff82cb4eca

    # 0xffffffff8220c1e7 : sub rsi, rdx ; mov rax, rsi ; pop rbp ; ret
    SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET = 0xffffffff8220c1e7

    # 0xffffffff82b83a5b : jmp r14
    JMP_R14 = 0xffffffff82b83a5b

# FW 9.03/9.04
class OffsetsFirmware_903_904:
    PPPOE_SOFTC_LIST = 0xffffffff843e99f8

    KERNEL_MAP = 0xffffffff84464d48
    SETIDT = 0xffffffff825128e0

    KMEM_ALLOC = 0xffffffff8257a070
    KMEM_ALLOC_PATCH1 = 0xffffffff8257a13c
    KMEM_ALLOC_PATCH2 = 0xffffffff8257a144

    MEMCPY = 0xffffffff82471130

    # 0xffffffff823fb679 : mov cr0, rsi ; ud2 ; mov eax, 1 ; ret
    MOV_CR0_RSI_UD2_MOV_EAX_1_RET = 0xffffffff823fb679

    SECOND_GADGET_OFF = 0x3d

    # 0xffffffff829e686f : jmp qword ptr [rsi + 0x3d]
    FIRST_GADGET = 0xffffffff829e686f

    # 0xffffffff82c74566 : push rbp ; jmp qword ptr [rsi]
    PUSH_RBP_JMP_QWORD_PTR_RSI = 0xffffffff82c74566

    # 0xffffffff822b4151 : pop rbx ; pop r14 ; pop rbp ; jmp qword ptr [rsi + 0x10]
    POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10 = 0xffffffff822b4151

    # 0xffffffff8293fe06 : lea rsp, [rsi + 0x20] ; repz ret
    LEA_RSP_RSI_20_REPZ_RET = 0xffffffff8293fe06

    # 0xffffffff826c31aa : add rsp, 0x28 ; pop rbp ; ret
    ADD_RSP_28_POP_RBP_RET = 0xffffffff826c31aa

    # 0xffffffff8251ad2f : add rsp, 0xb0 ; pop rbp ; ret
    ADD_RSP_B0_POP_RBP_RET = 0xffffffff8251ad2f

    # 0xffffffff822008e0 : ret
    RET = 0xffffffff822008e0

    # 0xffffffff8238e75d : pop rdi ; ret
    POP_RDI_RET = 0xffffffff8238e75d

    # 0xffffffff822aad39 : pop rsi ; ret
    POP_RSI_RET = 0xffffffff822aad39

    # 0xffffffff8244cc56 : pop rdx ; ret
    POP_RDX_RET = 0xffffffff8244cc56

    # 0xffffffff822445e7 : pop rcx ; ret
    POP_RCX_RET = 0xffffffff822445e7

    # 0xffffffff822ab4dd : pop r8 ; pop rbp ; ret
    POP_R8_POP_RBP_RET = 0xffffffff822ab4dd

    # 0xffffffff8279d9cf : pop r12 ; ret
    POP_R12_RET = 0xffffffff8279d9cf

    # 0xffffffff82234ec8 : pop rax ; ret
    POP_RAX_RET = 0xffffffff82234ec8

    # 0xffffffff822008df : pop rbp ; ret
    POP_RBP_RET = 0xffffffff822008df

    # 0xffffffff82bb479a : push rsp ; pop rsi ; ret
    PUSH_RSP_POP_RSI_RET = 0xffffffff82bb479a

    # 0xffffffff82244ed0 : mov rdi, qword ptr [rdi] ; pop rbp ; jmp rax
    MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX = 0xffffffff82244ed0

    # 0xffffffff825386d8 : mov byte ptr [rcx], al ; ret
    MOV_BYTE_PTR_RCX_AL_RET = 0xffffffff825386d8

    # 0xffffffff82630b0c : mov rdi, rbx ; call r12
    MOV_RDI_RBX_CALL_R12 = 0xffffffff82630b0c

    # 0xffffffff8235b337 : mov rdi, r14 ; call r12
    MOV_RDI_R14_CALL_R12 = 0xffffffff8235b337

    # 0xffffffff822e3d2e : mov rsi, rbx ; call rax
    MOV_RSI_RBX_CALL_RAX = 0xffffffff822e3d2e

    # 0xffffffff823638c8 : mov r14, rax ; call r8
    MOV_R14_RAX_CALL_R8 = 0xffffffff823638c8

    # 0xffffffff82cb475a : add rdi, rcx ; ret
    ADD_RDI_RCX_RET = 0xffffffff82cb475a

    # 0xffffffff82409287 : sub rsi, rdx ; mov rax, rsi ; pop rbp ; ret
    SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET = 0xffffffff82409287

    # 0xffffffff82b835b3 : jmp r14
    JMP_R14 = 0xffffffff82b835b3


# FW 10.00/10.01
class OffsetsFirmware_1000_1001:
    PPPOE_SOFTC_LIST = 0xffffffff8446d920

    KERNEL_MAP = 0xffffffff8447bef8

    SETIDT = 0xffffffff8227b460

    KMEM_ALLOC = 0xffffffff8253b040
    KMEM_ALLOC_PATCH1 = 0xffffffff8253b10c
    KMEM_ALLOC_PATCH2 = 0xffffffff8253b114

    MEMCPY = 0xffffffff82672d20

    # 0xffffffff82376089 : mov cr0 rsi ; ud2 ; mov eax 1; ret
    MOV_CR0_RSI_UD2_MOV_EAX_1_RET = 0xffffffff82376089

    SECOND_GADGET_OFF = 0x3b

    # 0xffffffff82249c5d : jmp qword ptr [rsi + 0x3b]
    FIRST_GADGET = 0xffffffff82249c5d

    # 0xffffffff82c73946 : push rbp ; jmp qword ptr [rsi]
    PUSH_RBP_JMP_QWORD_PTR_RSI = 0xffffffff82c73946

    # 0xffffffff82545741 : pop rbx ; pop r14 ; pop rbp ; jmp qword ptr [rsi + 0x10]
    POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10 = 0xffffffff82545741

    # 0xffffffff8292b346 : lea rsp, [rsi + 0x20] ; repz ret
    LEA_RSP_RSI_20_REPZ_RET = 0xffffffff8292b346

    # 0xffffffff826d0d0a : add rsp, 0x28 ; pop rbp ; ret
    ADD_RSP_28_POP_RBP_RET = 0xffffffff826d0d0a

    # 0xffffffff82531c3f : add rsp, 0xb0 ; pop rbp ; ret
    ADD_RSP_B0_POP_RBP_RET = 0xffffffff82531c3f

    # 0xffffffff822008e0 : ret
    RET = 0xffffffff822008e0

    # 0xffffffff82510c4e : pop rdi ; ret
    POP_RDI_RET = 0xffffffff82510c4e

    # 0xffffffff822983e0 : pop rsi ; ret
    POP_RSI_RET = 0xffffffff822983e0

    # 0xffffffff824029b2 : pop rdx ; ret
    POP_RDX_RET = 0xffffffff824029b2

    # 0xffffffff822983ba : pop rcx ; ret
    POP_RCX_RET = 0xffffffff822983ba

    # 0xffffffff8237dd7d : pop r8 ; pop rbp ; ret
    POP_R8_POP_RBP_RET = 0xffffffff8237dd7d

    # 0xffffffff827b32ef : pop r12 ; ret
    POP_R12_RET = 0xffffffff827b32ef

    # 0xffffffff8229974f : pop rax ; ret
    POP_RAX_RET = 0xffffffff8229974f

    # 0xffffffff822008df : pop rbp ; ret
    POP_RBP_RET = 0xffffffff822008df

    # 0xffffffff82bb3ee6 : push rsp ; pop rsi ; ret
    PUSH_RSP_POP_RSI_RET = 0xffffffff82bb3ee6

    # 0xffffffff8256bfb0 : mov rdi, qword ptr [rdi] ; pop rbp ; jmp rax
    MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX = 0xffffffff8256bfb0

    # 0xffffffff824f0448 : mov byte ptr [rcx], al ; ret
    MOV_BYTE_PTR_RCX_AL_RET = 0xffffffff824f0448

    # 0xffffffff8236bbec : mov rdi, rbx ; call r12
    MOV_RDI_RBX_CALL_R12 = 0xffffffff8236bbec

    # 0xffffffff8236ba27 : mov rdi, r14 ; call r12
    MOV_RDI_R14_CALL_R12 = 0xffffffff8236ba27

    # 0xffffffff823f501e : mov rsi, rbx ; call rax
    MOV_RSI_RBX_CALL_RAX = 0xffffffff823f501e

    # 0xffffffff8259e638 : mov r14, rax ; call r8
    MOV_R14_RAX_CALL_R8 = 0xffffffff8259e638

    # 0xffffffff82cb3b3a : add rdi, rcx ; ret
    ADD_RDI_RCX_RET = 0xffffffff82cb3b3a

    # 0xffffffff822bfa87 : sub rsi, rdx ; mov rax, rsi ; pop rbp ; ret
    SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET = 0xffffffff822bfa87

    # 0xffffffff8280346f : jmp r14
    JMP_R14 = 0xffffffff8280346f


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