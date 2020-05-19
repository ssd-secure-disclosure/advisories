/**
 * NOTE: this file is just a fake cryptodev.h used for
 * linting on the host computer. most of these are just
 * definitions that have been straight ripped out of the 
 * FreeBSD sources.
 */

#include <sys/types.h>
#include <stdint.h>

#define CIOCGSESSION 3224396645
#define CIOCCRYPT 3224396647
#define CIOCFSESSION 2147771238
#define CRIOGET 3221513060

#define	CRYPTO_AES_CBC	11 
#define CRYPTO_NULL_CBC 0 
#define CRYPTO_NULL_HMAC 0

typedef const char* c_caddr_t;

struct session_op {
	u_int32_t	cipher;		/* ie. CRYPTO_DES_CBC */
	u_int32_t	mac;		/* ie. CRYPTO_MD5_HMAC */

	u_int32_t	keylen;		/* cipher key */
	c_caddr_t	key;
	int		mackeylen;	/* mac key */
	c_caddr_t	mackey;

  	u_int32_t	ses;		/* returns: session # */
};

/*
 * session and crypt _op structs are used by userspace programs to interact
 * with /dev/crypto.  Confusingly, the internal kernel interface is named
 * "cryptop" (no underscore).
 */
struct session2_op {
	u_int32_t	cipher;		/* ie. CRYPTO_DES_CBC */
	u_int32_t	mac;		/* ie. CRYPTO_MD5_HMAC */

	u_int32_t	keylen;		/* cipher key */
	c_caddr_t	key;
	int		mackeylen;	/* mac key */
	c_caddr_t	mackey;

  	u_int32_t	ses;		/* returns: session # */
	int		crid;		/* driver id + flags (rw) */
	int		pad[4];		/* for future expansion */
};

struct crypt_op {
	u_int32_t	ses;
	u_int16_t	op;		/* i.e. COP_ENCRYPT */
#define COP_ENCRYPT	1
#define COP_DECRYPT	2
	u_int16_t	flags;
#define	COP_F_CIPHER_FIRST	0x0001	/* Cipher before MAC. */
#define	COP_F_BATCH		0x0008	/* Batch op if possible */
	u_int		len;
	c_caddr_t	src;		/* become iov[] inside kernel */
	caddr_t		dst;
	caddr_t		mac;		/* must be big enough for chosen MAC */
	c_caddr_t	iv;
};

/* op and flags the same as crypt_op */
struct crypt_aead {
	u_int32_t	ses;
	u_int16_t	op;		/* i.e. COP_ENCRYPT */
	u_int16_t	flags;
	u_int		len;
	u_int		aadlen;
	u_int		ivlen;
	c_caddr_t	src;		/* become iov[] inside kernel */
	caddr_t		dst;
	c_caddr_t	aad;		/* additional authenticated data */
	caddr_t		tag;		/* must fit for chosen TAG length */
	c_caddr_t	iv;
};

/*
 * Parameters for looking up a crypto driver/device by
 * device name or by id.  The latter are returned for
 * created sessions (crid) and completed key operations.
 */
struct crypt_find_op {
	int		crid;		/* driver id + flags */
	char		name[32];	/* device/driver name */
};

/* bignum parameter, in packed bytes, ... */
struct crparam {
	caddr_t		crp_p;
	u_int		crp_nbits;
};

#define CRK_MAXPARAM	8

struct crypt_kop {
	u_int		crk_op;		/* ie. CRK_MOD_EXP or other */
	u_int		crk_status;	/* return status */
	u_short		crk_iparams;	/* # of input parameters */
	u_short		crk_oparams;	/* # of output parameters */
	u_int		crk_crid;	/* NB: only used by CIOCKEY2 (rw) */
	struct crparam	crk_param[CRK_MAXPARAM];
};