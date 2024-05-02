/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#ifndef KSDK_BSD_H
#define KSDK_BSD_H

/* constants */
#define DT_DIR      0x0004
#define DT_REG      0x0008

#define M_NOWAIT    0x0001
#define M_WAITOK    0x0002
#define M_ZERO      0x0100

#define	VM_PROT_NONE		0x00
#define VM_PROT_READ		0x01
#define VM_PROT_WRITE		0x02
#define VM_PROT_EXECUTE		0x04
#define VM_PROT_DEFAULT		(VM_PROT_READ | VM_PROT_WRITE)
#define VM_PROT_ALL			(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
#define VM_PROT_NO_CHANGE	0x08
#define VM_PROT_COPY		0x10
#define VM_PROT_WANTS_COPY	0x10


#define JOIN_HELPER(x, y) x##y
#define JOIN(x, y) JOIN_HELPER(x, y)

#define TYPE_PAD(size) char JOIN(_pad_, __COUNTER__)[size]
#define TYPE_VARIADIC_BEGIN(name) name { union {
#define TYPE_BEGIN(name, size) name { union { TYPE_PAD(size)
#define TYPE_END(...) }; } __VA_ARGS__
#define TYPE_FIELD(field, offset) struct { TYPE_PAD(offset); field; }

#define TYPE_CHECK_SIZE(name, size) \
  _Static_assert(sizeof(name) == (size), "Size of " #name " != " #size)

#define TYPE_CHECK_FIELD_OFFSET(name, member, offset) \
  _Static_assert(offsetof(name, member) == (offset), "Offset of " #name "." #member " != " #offset)

#define TYPE_CHECK_FIELD_SIZE(name, member, size) \
  _Static_assert(sizeof(((name*)0)->member) == (size), "Size of " #name "." #member " != " #size)

#define PROT_READ			VM_PROT_READ
#define PROT_WRITE			VM_PROT_WRITE
#define PROT_EXEC			VM_PROT_EXECUTE
#define PROT_NONE			VM_PROT_NONE

//#define	TRACEBUF	struct qm_trace trace;

#define	TAILQ_FIRST(head) ((head)->tqh_first)
#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	TAILQ_HEAD(name, type)									\
struct name {													\
	struct type *tqh_first;										\
	struct type **tqh_last;										\
	TRACEBUF													\
}

#define	TAILQ_ENTRY(type)											\
struct {															\
	struct type *tqe_next;											\
	struct type **tqe_prev;											\
	TRACEBUF														\
}

#define	LIST_ENTRY(type)											\
struct {															\
	struct type *le_next;											\
	struct type **le_prev;											\
}

#define	TAILQ_FOREACH(var, head, field)				\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);										\
(var) = TAILQ_NEXT((var), field))

struct qm_trace {
	char * lastfile;
	int lastline;
	char * prevfile;
	int prevline;
};

struct trapframe {
	uint64_t tf_rdi;	// 0x00
	uint64_t tf_rsi;	// 0x08
	uint64_t tf_rdx;	// 0x10
	uint64_t tf_rcx;	// 0x18
	uint64_t tf_r8;		// 0x20
	uint64_t tf_r9;		// 0x28
	uint64_t tf_rax;	// 0x30
	uint64_t tf_rbx;	// 0x38
	uint64_t tf_rbp;	// 0x40
	uint64_t tf_r10;	// 0x48
	uint64_t tf_r11;	// 0x50
	uint64_t tf_r12;	// 0x58
	uint64_t tf_r13;	// 0x60
	uint64_t tf_r14;	// 0x68
	uint64_t tf_r15;	// 0x70
	uint32_t tf_trapno;	// 0x78
	uint16_t tf_fs;		// 0x7C
	uint16_t tf_gs;		// 0x7E
	uint64_t tf_addr;	// 0x80
	uint32_t tf_flags;	// 0x88
	uint16_t tf_es;		// 0x8C
	uint16_t tf_ds;		// 0x8E
	uint64_t tf_err;	// 0x90
	uint64_t tf_rip;	// 0x98
	uint64_t tf_cs;		// 0xA0
	uint64_t tf_rflags;	// 0xA8
	uint64_t tf_rsp;	// 0xB0
	uint64_t tf_ss;		// 0xB8
};

struct reg {
	uint64_t r_r15;
	uint64_t r_r14;
	uint64_t r_r13;
	uint64_t r_r12;
	uint64_t r_r11;
	uint64_t r_r10;
	uint64_t r_r9;
	uint64_t r_r8;
	uint64_t r_rdi;
	uint64_t r_rsi;
	uint64_t r_rbp;
	uint64_t r_rbx;
	uint64_t r_rdx;
	uint64_t r_rcx;
	uint64_t r_rax;
	uint32_t r_trapno;
	uint16_t r_fs; // 0x7C
	uint16_t r_gs; // 0x7E
	uint32_t r_err;
	uint16_t r_es;
	uint16_t r_ds;
	uint64_t r_rip;
	uint64_t r_cs;
	uint64_t r_rflags;
	uint64_t r_rsp;
	uint64_t r_ss;
};

enum uio_rw {
	UIO_READ,
	UIO_WRITE
};

enum uio_seg {
	UIO_USERSPACE,		/* from user data space */
	UIO_SYSSPACE,		/* from system space */
	UIO_USERISPACE		/* from user I space */
};

struct iovec {
	uint64_t iov_base;
	uint64_t iov_len;
};

struct sx {
	struct lock_object lock_object;
	volatile uintptr_t sx_lock;
};

TYPE_BEGIN(struct uio, 0x30);
TYPE_FIELD(uint64_t uio_iov, 0);
TYPE_FIELD(uint32_t uio_iovcnt, 8);
TYPE_FIELD(uint64_t uio_offset, 0x10);
TYPE_FIELD(uint64_t uio_resid, 0x18);
TYPE_FIELD(uint32_t uio_segflg, 0x20);
TYPE_FIELD(uint32_t uio_rw, 0x24);
TYPE_FIELD(struct thread *uio_td, 0x28);
TYPE_END();

TYPE_BEGIN(struct vm_map_entry, 0xC0);
TYPE_FIELD(struct vm_map_entry *prev, 0);
TYPE_FIELD(struct vm_map_entry *next, 8);
TYPE_FIELD(struct vm_map_entry *left, 0x10);
TYPE_FIELD(struct vm_map_entry *right, 0x18);
TYPE_FIELD(uint64_t start, 0x20);
TYPE_FIELD(uint64_t end, 0x28);
TYPE_FIELD(uint64_t offset, 0x50);
TYPE_FIELD(uint16_t prot, 0x5C);
TYPE_FIELD(char name[32], 0x8D);
TYPE_END();

TYPE_BEGIN(struct vm_map, 0x178);
TYPE_FIELD(struct vm_map_entry header, 0);
TYPE_FIELD(struct sx lock, 0xB8);
TYPE_FIELD(struct mtx system_mtx, 0xD8);
TYPE_FIELD(int nentries, 0x100);
TYPE_END();

TYPE_BEGIN(struct vmspace, 0x250);
TYPE_FIELD(struct vm_map vm_map, 0);
// maybe I will add more later just for documentation purposes
TYPE_END();


TYPE_BEGIN(struct sce_proc, 0x800); // XXX: random, don't use directly without fixing it
TYPE_FIELD(struct proc *p_forw, 0);
TYPE_FIELD(TAILQ_HEAD(, thread) p_threads, 0x10);
TYPE_FIELD(struct ucred *p_ucred, 0x40);
TYPE_FIELD(struct filedesc *p_fd, 0x48);
TYPE_FIELD(int pid, 0xB0);
TYPE_FIELD(struct vmspace *p_vmspace, 0x168);
TYPE_FIELD(char p_comm[32], 0x454);
TYPE_FIELD(char titleid[16], 0x390);
TYPE_FIELD(char contentid[64], 0x3D4);
TYPE_FIELD(char path[64], 0x474);
TYPE_END();


#define SELF_DIGEST_SIZE 0x20
#define SELF_CONTENT_ID_SIZE 0x13
#define SELF_RANDOM_PAD_SIZE 0x0D
#define SELF_MAX_HEADER_SIZE 0x4000

enum self_format {
	SELF_FORMAT_NONE,
	SELF_FORMAT_ELF,
	SELF_FORMAT_SELF,
};

#define SIZEOF_SELF_CONTEXT 0x60 // sceSblAuthMgrAuthHeader:bzero(sbl_authmgr_context, 0x60)

TYPE_BEGIN(struct self_context, SIZEOF_SELF_CONTEXT);
	TYPE_FIELD(enum self_format format, 0x00);
	TYPE_FIELD(int elf_auth_type, 0x04); /* auth id is based on that */
	TYPE_FIELD(unsigned int total_header_size, 0x08);
	TYPE_FIELD(int ctx_id, 0x1C);
	TYPE_FIELD(uint64_t svc_id, 0x20);
	TYPE_FIELD(int buf_id, 0x30);
	TYPE_FIELD(uint8_t* header, 0x38);
	TYPE_FIELD(struct mtx lock, 0x40);
TYPE_END();

#define SIZEOF_SELF_HEADER 0x20

TYPE_BEGIN(struct self_header, SIZEOF_SELF_HEADER);
	TYPE_FIELD(uint32_t magic, 0x00);
#define SELF_MAGIC 0x1D3D154F
#define ELF_MAGIC  0x464C457F
	TYPE_FIELD(uint8_t version, 0x04);
	TYPE_FIELD(uint8_t mode, 0x05);
	TYPE_FIELD(uint8_t endian, 0x06);
	TYPE_FIELD(uint8_t attr, 0x07);
	TYPE_FIELD(uint32_t key_type, 0x08);
	TYPE_FIELD(uint16_t header_size, 0x0C);
	TYPE_FIELD(uint16_t meta_size, 0x0E);
	TYPE_FIELD(uint64_t file_size, 0x10);
	TYPE_FIELD(uint16_t num_entries, 0x18);
	TYPE_FIELD(uint16_t flags, 0x1A);
TYPE_END();

#define SIZEOF_SELF_ENTRY 0x20

TYPE_BEGIN(struct self_entry, SIZEOF_SELF_ENTRY);
	TYPE_FIELD(uint64_t props, 0x00);
	TYPE_FIELD(uint64_t offset, 0x08);
	TYPE_FIELD(uint64_t file_size, 0x10);
	TYPE_FIELD(uint64_t memory_size, 0x18);
TYPE_END();

#define SIZEOF_SELF_EX_INFO 0x40

TYPE_BEGIN(struct self_ex_info, SIZEOF_SELF_EX_INFO);
	TYPE_FIELD(uint64_t paid, 0x00);
	TYPE_FIELD(uint64_t ptype, 0x08);
#define SELF_PTYPE_FAKE 0x1
	TYPE_FIELD(uint64_t app_version, 0x10);
	TYPE_FIELD(uint64_t fw_version, 0x18);
	TYPE_FIELD(uint8_t digest[SELF_DIGEST_SIZE], 0x20);
TYPE_END();

#define SIZEOF_SELF_AUTH_INFO 0x88 // sceSblAuthMgrIsLoadable2:bzero(auth_info, 0x88)

TYPE_BEGIN(struct self_auth_info, SIZEOF_SELF_AUTH_INFO);
	TYPE_FIELD(uint64_t paid, 0x00);
	TYPE_FIELD(uint64_t caps[4], 0x08);
	TYPE_FIELD(uint64_t attrs[4], 0x28);
	TYPE_FIELD(uint8_t unk[0x40], 0x48);
TYPE_END();

#define SIZEOF_SELF_FAKE_AUTH_INFO (sizeof(uint64_t) + SIZEOF_SELF_AUTH_INFO)

TYPE_BEGIN(struct self_fake_auth_info, SIZEOF_SELF_FAKE_AUTH_INFO);
	TYPE_FIELD(uint64_t size, 0x00);
	TYPE_FIELD(struct self_auth_info info, 0x08);
TYPE_END();


#define SCE_SBL_ERROR_NPDRM_ENOTSUP 0x800F0A25
#define SIZEOF_SBL_KEY_RBTREE_ENTRY 0xA8 // sceSblKeymgrSetKey
#define SIZEOF_SBL_MAP_LIST_ENTRY 0x50 // sceSblDriverMapPages
#define SIZEOF_SBL_KEY_DESC 0x7C // sceSblKeymgrSetKey
#define SIZEOF_SBL_KEY_SLOT_DESC 0x20
#define SBL_MSG_SERVICE_MAILBOX_MAX_SIZE 0x80
#define SBL_MSG_CCP 0x8

struct sbl_mapped_page_group;

union sbl_key_desc {
	struct {
		uint16_t obf_key_id;
		uint16_t key_size;
		uint8_t escrowed_key[0x20];
	} pfs;
	struct {
		uint16_t cmd;
		uint16_t pad;
		uint16_t key_id;
	} portability;
	uint8_t raw[SIZEOF_SBL_KEY_DESC];
};
TYPE_CHECK_SIZE(union sbl_key_desc, SIZEOF_SBL_KEY_DESC);

TYPE_BEGIN(struct sbl_key_slot_desc, SIZEOF_SBL_KEY_SLOT_DESC);
	TYPE_FIELD(uint32_t key_id, 0x00);
	TYPE_FIELD(uint32_t unk_0x04, 0x04);
	TYPE_FIELD(uint32_t key_handle, 0x08); /* or -1 if it's freed */
	TYPE_FIELD(uint32_t unk_0x0C, 0x0C);
	TYPE_FIELD(TAILQ_ENTRY(sbl_key_slot_desc) list, 0x10);
TYPE_END();

TAILQ_HEAD(sbl_key_slot_queue, sbl_key_slot_desc);

TYPE_BEGIN(struct sbl_key_rbtree_entry, SIZEOF_SBL_KEY_RBTREE_ENTRY);
	TYPE_FIELD(uint32_t handle, 0x00);
	TYPE_FIELD(uint32_t occupied, 0x04);
	TYPE_FIELD(union sbl_key_desc desc, 0x08);
	TYPE_FIELD(uint32_t locked, 0x80);
	TYPE_FIELD(struct sbl_key_rbtree_entry* left, 0x88);
	TYPE_FIELD(struct sbl_key_rbtree_entry* right, 0x90);
	TYPE_FIELD(struct sbl_key_rbtree_entry* parent, 0x98);
	TYPE_FIELD(uint32_t set, 0xA0);
TYPE_END();

TYPE_BEGIN(struct sbl_map_list_entry, SIZEOF_SBL_MAP_LIST_ENTRY);
	TYPE_FIELD(struct sbl_map_list_entry* next, 0x00);
	TYPE_FIELD(struct sbl_map_list_entry* prev, 0x08);
	TYPE_FIELD(unsigned long cpu_va, 0x10);
	TYPE_FIELD(unsigned int num_page_groups, 0x18);
	TYPE_FIELD(unsigned long gpu_va, 0x20);
	TYPE_FIELD(struct sbl_mapped_page_group* page_groups, 0x28);
	TYPE_FIELD(unsigned int num_pages, 0x30);
	TYPE_FIELD(unsigned long flags, 0x38);
	TYPE_FIELD(struct proc* proc, 0x40);
	TYPE_FIELD(void* vm_page, 0x48);
TYPE_END();

#define ELF_IDENT_SIZE 0x10
#define ELF_EHDR_EXT_SIZE 0x1000

#define ELF_IDENT_MAG0  0
#define ELF_IDENT_MAG1  1
#define ELF_IDENT_MAG2  2
#define ELF_IDENT_MAG3  3
#define ELF_IDENT_CLASS 4
#define ELF_IDENT_DATA  5

#define ELF_CLASS_64 2
#define ELF_DATA_LSB 1

#define ELF_TYPE_NONE 0
#define ELF_TYPE_EXEC 2

#define ELF_MACHINE_X86_64 0x3E

#define ELF_PHDR_TYPE_NULL           0x0
#define ELF_PHDR_TYPE_LOAD           0x1
#define ELF_PHDR_TYPE_SCE_DYNLIBDATA 0x61000000
#define ELF_PHDR_TYPE_SCE_RELRO      0x61000010
#define ELF_PHDR_TYPE_SCE_COMMENT    0x6FFFFF00
#define ELF_PHDR_TYPE_SCE_VERSION    0x6FFFFF01

#define ELF_PHDR_FLAG_X 0x1
#define ELF_PHDR_FLAG_W 0x2
#define ELF_PHDR_FLAG_R 0x4

#define ELF_ET_EXEC          0x2
#define ELF_ET_SCE_EXEC      0xFE00
#define ELF_ET_SCE_EXEC_ASLR 0xFE10
#define ELF_ET_SCE_DYNAMIC   0xFE18

typedef uint16_t elf64_half_t;
typedef uint32_t elf64_word_t;
typedef uint64_t elf64_xword_t;
typedef uint64_t elf64_off_t;
typedef uint64_t elf64_addr_t;

struct elf64_ehdr {
	uint8_t ident[ELF_IDENT_SIZE];
	elf64_half_t type;
	elf64_half_t machine;
	elf64_word_t version;
	elf64_addr_t entry;
	elf64_off_t phoff;
	elf64_off_t shoff;
	elf64_word_t flags;
	elf64_half_t ehsize;
	elf64_half_t phentsize;
	elf64_half_t phnum;
	elf64_half_t shentsize;
	elf64_half_t shnum;
	elf64_half_t shstrndx;
};

struct elf64_phdr {
	elf64_word_t type;
	elf64_word_t flags;
	elf64_off_t offset;
	elf64_addr_t vaddr;
	elf64_addr_t paddr;
	elf64_xword_t filesz;
	elf64_xword_t memsz;
	elf64_xword_t align;
};

struct elf64_shdr {
	elf64_word_t name;
	elf64_word_t type;
	elf64_xword_t flags;
	elf64_addr_t addr;
	elf64_off_t offset;
	elf64_xword_t size;
	elf64_word_t link;
	elf64_word_t info;
	elf64_xword_t addralign;
	elf64_xword_t entsize;
};

#define EKPFS_SIZE 0x20
#define EEKPFS_SIZE 0x100
#define PFS_SEED_SIZE 0x10
#define PFS_FINAL_KEY_SIZE 0x20
#define SIZEOF_PFS_KEY_BLOB 0x140
#define CONTENT_KEY_SEED_SIZE 0x10
#define SELF_KEY_SEED_SIZE 0x10
#define EEKC_SIZE 0x20
#define MAX_FAKE_KEYS 32
#define SIZEOF_RSA_KEY 0x48
#define PFS_FAKE_OBF_KEY_ID 0x1337
#define SIZEOF_PFS_HEADER 0x5A0

struct fake_key_desc {
	uint8_t key[0x20];
	int occupied;
};

struct fake_key_d {
	uint32_t index;
	uint8_t seed[PFS_SEED_SIZE];
};

struct ekc {
	uint8_t content_key_seed[CONTENT_KEY_SEED_SIZE];
	uint8_t self_key_seed[SELF_KEY_SEED_SIZE];
};

union pfs_key_blob {
	struct {
		uint8_t eekpfs[EEKPFS_SIZE];
		struct ekc eekc;
		uint32_t pubkey_ver; /* 0x1/0x80000001/0xC0000001 */
		uint32_t key_ver;    /* 1 (if (rif_ver_major & 0x1) != 0, then pfs_key_ver=1, otherwise pfs_key_ver=0) */
		uint64_t header_gva;
		uint32_t header_size;
		uint32_t type;
		uint32_t finalized;
		uint32_t is_disc;
	} in;
	struct {
		uint8_t escrowed_keys[0x40];
	} out;
};

typedef union pfs_key_blob pfs_key_blob_t;
TYPE_CHECK_SIZE(pfs_key_blob_t, SIZEOF_PFS_KEY_BLOB);

struct rsa_buffer {
	uint8_t* ptr;
	size_t size;
};

TYPE_BEGIN(struct pfs_header, SIZEOF_PFS_HEADER);
	TYPE_FIELD(uint8_t crypt_seed[0x10], 0x370);
TYPE_END();

#define RIF_DIGEST_SIZE 0x10
#define RIF_DATA_SIZE 0x90
#define RIF_KEY_TABLE_SIZE 0x230
#define RIF_MAX_KEY_SIZE 0x20
#define RIF_PAYLOAD_SIZE (RIF_DIGEST_SIZE + RIF_DATA_SIZE)
#define SIZEOF_ACTDAT 0x200
#define SIZEOF_RSA_KEY 0x48
#define SIZEOF_RIF 0x400

struct rif_key_blob {
	struct ekc eekc;
	uint8_t entitlement_key[0x10];
};

union keymgr_response {
	struct {
		uint32_t type;
		uint8_t key[RIF_MAX_KEY_SIZE];
		uint8_t data[RIF_DIGEST_SIZE + RIF_DATA_SIZE];
	} decrypt_rif;
	struct {
		uint8_t raw[SIZEOF_RIF];
	} decrypt_entire_rif;
};

union keymgr_payload {
	struct {
		uint32_t cmd;
		uint32_t status;
		uint64_t data;
	};
	uint8_t buf[0x80];
};

TYPE_BEGIN(struct rsa_key, SIZEOF_RSA_KEY);
	TYPE_FIELD(uint8_t* p, 0x20);
	TYPE_FIELD(uint8_t* q, 0x28);
	TYPE_FIELD(uint8_t* dmp1, 0x30);
	TYPE_FIELD(uint8_t* dmq1, 0x38);
	TYPE_FIELD(uint8_t* iqmp, 0x40);
TYPE_END();

TYPE_BEGIN(struct actdat, SIZEOF_ACTDAT);
	TYPE_FIELD(uint32_t magic, 0x00);
	TYPE_FIELD(uint16_t version_major, 0x04);
	TYPE_FIELD(uint16_t version_minor, 0x06);
	TYPE_FIELD(uint64_t account_id, 0x08);
	TYPE_FIELD(uint64_t start_time, 0x10);
	TYPE_FIELD(uint64_t end_time, 0x18);
	TYPE_FIELD(uint64_t flags, 0x20);
	TYPE_FIELD(uint32_t unk3, 0x28);
	TYPE_FIELD(uint32_t unk4, 0x2C);
	TYPE_FIELD(uint8_t open_psid_hash[0x20], 0x60);
	TYPE_FIELD(uint8_t static_per_console_data_1[0x20], 0x80);
	TYPE_FIELD(uint8_t digest[0x10], 0xA0);
	TYPE_FIELD(uint8_t key_table[0x20], 0xB0);
	TYPE_FIELD(uint8_t static_per_console_data_2[0x10], 0xD0);
	TYPE_FIELD(uint8_t static_per_console_data_3[0x20], 0xE0);
	TYPE_FIELD(uint8_t signature[0x100], 0x100);
TYPE_END();

TYPE_BEGIN(struct rif, SIZEOF_RIF);
	TYPE_FIELD(uint32_t magic, 0x00);
	TYPE_FIELD(uint16_t version_major, 0x04);
	TYPE_FIELD(uint16_t version_minor, 0x06);
	TYPE_FIELD(uint64_t account_id, 0x08);
	TYPE_FIELD(uint64_t start_time, 0x10);
	TYPE_FIELD(uint64_t end_time, 0x18);
	TYPE_FIELD(char content_id[0x30], 0x20);
	TYPE_FIELD(uint16_t format, 0x50);
	TYPE_FIELD(uint16_t drm_type, 0x52);
	TYPE_FIELD(uint16_t content_type, 0x54);
	TYPE_FIELD(uint16_t sku_flag, 0x56);
	TYPE_FIELD(uint64_t content_flags, 0x58);
	TYPE_FIELD(uint32_t iro_tag, 0x60);
	TYPE_FIELD(uint32_t ekc_version, 0x64);
	TYPE_FIELD(uint16_t unk3, 0x6A);
	TYPE_FIELD(uint16_t unk4, 0x6C);
	TYPE_FIELD(uint8_t digest[0x10], 0x260);
	TYPE_FIELD(uint8_t data[RIF_DATA_SIZE], 0x270);
	TYPE_FIELD(uint8_t signature[0x100], 0x300);
TYPE_END();

union keymgr_request {
	struct {
		uint32_t type;
		uint8_t key[RIF_MAX_KEY_SIZE];
		uint8_t data[RIF_DIGEST_SIZE + RIF_DATA_SIZE];
	} decrypt_rif;
	struct {
		struct rif rif;
		uint8_t key_table[RIF_KEY_TABLE_SIZE];
		uint64_t timestamp;
		int status;
	} decrypt_entire_rif;
};



#endif /* KSDK_BSD_H */
