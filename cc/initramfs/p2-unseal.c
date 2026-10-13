/*
 * p2-unseal: release the CC's sealed keys from the TPM in the initramfs
 * (docs/03-measured-boot-sealing.md sections 3.2 to 3.6; SR-010).
 *
 *     p2-unseal <ccdir> <outdir> <name>...
 *
 * <ccdir> holds what the CC keeps on storage. None of it is secret, and none
 * of it is useful away from this TPM:
 *
 *     parent.name            Name of the persistent parent, recorded at provisioning
 *     kpol.pub               K-CC-POL public key (TPM2B_PUBLIC)
 *     policy/approved        approved policy for this release (SHA-256 digest)
 *     policy/approved.sig    MSS signature over approved || policyRef (TPMT_SIGNATURE)
 *     policy/epoch           the release's anti-rollback epoch, 0 to 63
 *     sealed/<name>.pub      sealed object (TPM2B_PUBLIC)
 *     sealed/<name>.priv     sealed object (TPM2B_PRIVATE)
 *
 * For each <name>, in a policy session salted to the parent and set to
 * encrypt the response (SR-010.4), it runs PolicyPCR over SHA-256 PCRs 0, 1,
 * 8 and 9 (SR-010.1), PolicyNV against the epoch (SR-010.3) and
 * PolicyAuthorize with the TPM's ticket for the MSS signature (SR-010.2),
 * then unseals and writes the secret to <outdir>/<name> with mode 0600.
 *
 * It prints one line per name, "P2-UNSEAL <name> ok" or "P2-UNSEAL <name>
 * refused at <step>: <reason>", and never prints secret bytes. Exit status 0
 * only if every name unsealed.
 */
#define _DEFAULT_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tcti_device.h>

/* Shared with tools/approve_policy.py; tests/test_approve_policy.py keeps them equal. */
#define PARENT_HANDLE 0x81000001
#define EPOCH_NV_INDEX 0x01000001
#define POLICY_REF "p2/cc-keys"
#define TPM_DEVICE "/dev/tpmrm0"

/*
 * TC-09's control build (cc/build.sh, -DP2_CONTROL_CLEAR_RESPONSE) leaves the
 * unseal response in the clear, to show that TC-09 would see a key on the
 * wire. It boots only in that control run. Never used to boot a CC.
 */
#ifdef P2_CONTROL_CLEAR_RESPONSE
#define SESSION_ATTRIBUTES TPMA_SESSION_CONTINUESESSION
#else
#define SESSION_ATTRIBUTES (TPMA_SESSION_ENCRYPT | TPMA_SESSION_CONTINUESESSION)
#endif

static const char *ccdir;

static int read_file(const char *rel, uint8_t *buf, size_t cap, size_t *len)
{
	char path[512];
	FILE *f;
	int bad;

	snprintf(path, sizeof(path), "%s/%s", ccdir, rel);
	f = fopen(path, "rb");
	if (!f)
		return -1;
	*len = fread(buf, 1, cap, f);
	bad = ferror(f) || fgetc(f) != EOF;   /* an error, or more than cap bytes */
	fclose(f);
	return bad ? -1 : 0;
}

#define READ_TPM_TYPE(type, rel, dest)                                              \
	({                                                                          \
		uint8_t buf_[sizeof(type)];                                         \
		size_t len_, off_ = 0;                                              \
		read_file((rel), buf_, sizeof(buf_), &len_) ||                     \
			Tss2_MU_##type##_Unmarshal(buf_, len_, &off_, (dest)) ||   \
			off_ != len_;                                               \
	})

static void refused(const char *name, const char *step, const char *reason)
{
	printf("P2-UNSEAL %s refused at %s: %s\n", name, step, reason);
}

struct release {
	ESYS_TR parent;
	ESYS_TR nv;
	TPM2B_OPERAND operand;
	TPM2B_DIGEST approved;
	TPM2B_NAME kpol_name;
	TPMT_TK_VERIFIED ticket;
};

static int unseal_one(ESYS_CONTEXT *esys, const struct release *rel, const char *name, const char *outdir)
{
	const TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_AES, .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB };
	const TPML_PCR_SELECTION pcrs = {
		.count = 1,
		.pcrSelections[0] = { .hash = TPM2_ALG_SHA256, .sizeofSelect = 3, .pcrSelect = { 0x03, 0x03, 0x00 } },
	};
	const TPM2B_DIGEST current = { .size = 0 };   /* PolicyPCR uses the PCRs as they are now */
	TPM2B_NONCE ref = { .size = sizeof(POLICY_REF) - 1 };
	ESYS_TR session = ESYS_TR_NONE, item = ESYS_TR_NONE;
	TPM2B_SENSITIVE_DATA *secret = NULL;
	TPM2B_PUBLIC pub = { 0 };
	TPM2B_PRIVATE priv = { 0 };
	char path[512];
	const char *step;
	TSS2_RC rc = TSS2_RC_SUCCESS;
	int ok = 0, fd;

	memcpy(ref.buffer, POLICY_REF, ref.size);
	step = "sealed object";
	snprintf(path, sizeof(path), "sealed/%s.pub", name);
	if (READ_TPM_TYPE(TPM2B_PUBLIC, path, &pub))
		goto out;
	snprintf(path, sizeof(path), "sealed/%s.priv", name);
	if (READ_TPM_TYPE(TPM2B_PRIVATE, path, &priv))
		goto out;

	step = "StartAuthSession";   /* salted to the parent, so the session key never crosses the bus */
	rc = Esys_StartAuthSession(esys, rel->parent, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				   NULL, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256, &session);
	if (rc)
		goto out;
	rc = Esys_TRSess_SetAttributes(esys, session, SESSION_ATTRIBUTES, 0xff);
	if (rc)
		goto out;
	step = "PolicyPCR";
	rc = Esys_PolicyPCR(esys, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &current, &pcrs);
	if (rc)
		goto out;
	step = "PolicyNV";
	rc = Esys_PolicyNV(esys, rel->nv, rel->nv, session, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			   &rel->operand, 0, TPM2_EO_BITCLEAR);
	if (rc)
		goto out;
	step = "PolicyAuthorize";
	rc = Esys_PolicyAuthorize(esys, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &rel->approved, &ref,
				  &rel->kpol_name, &rel->ticket);
	if (rc)
		goto out;
	step = "Load";
	rc = Esys_Load(esys, rel->parent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &priv, &pub, &item);
	if (rc)
		goto out;
	step = "Unseal";   /* the response is encrypted under the session key */
	rc = Esys_Unseal(esys, item, session, ESYS_TR_NONE, ESYS_TR_NONE, &secret);
	if (rc)
		goto out;

	step = "write";
	snprintf(path, sizeof(path), "%s/%s", outdir, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
	if (fd < 0)
		goto out;
	ok = write(fd, secret->buffer, secret->size) == (ssize_t)secret->size;
	ok = close(fd) == 0 && ok;

out:
	if (ok)
		printf("P2-UNSEAL %s ok\n", name);
	else
		refused(name, step, rc ? Tss2_RC_Decode(rc) : "cannot read or write a file");
	if (secret) {
		explicit_bzero(secret->buffer, sizeof(secret->buffer));
		Esys_Free(secret);
	}
	if (item != ESYS_TR_NONE)
		Esys_FlushContext(esys, item);
	if (session != ESYS_TR_NONE)
		Esys_FlushContext(esys, session);
	return ok;
}

/* Everything the policy needs that is the same for every sealed object. */
static const char *prepare(ESYS_CONTEXT *esys, struct release *rel, TSS2_RC *rc)
{
	uint8_t want[sizeof(TPMU_NAME)], epoch_text[8] = { 0 };
	TPM2B_NAME *name = NULL;
	TPM2B_PUBLIC kpol = { 0 };
	TPMT_SIGNATURE sig = { 0 };
	TPM2B_MAX_BUFFER msg = { 0 };
	TPM2B_DIGEST *ahash = NULL;
	TPMT_TK_HASHCHECK *hashcheck = NULL;
	TPMT_TK_VERIFIED *ticket = NULL;
	ESYS_TR kpol_handle = ESYS_TR_NONE;
	size_t len;
	char *end;
	unsigned long epoch;
	uint64_t mask;
	int same, i;

	*rc = Esys_TR_FromTPMPublic(esys, PARENT_HANDLE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &rel->parent);
	if (*rc)
		return "parent";
	*rc = Esys_TR_GetName(esys, rel->parent, &name);
	if (*rc)
		return "parent";
	same = !read_file("parent.name", want, sizeof(want), &len) && len == name->size &&
	       !memcmp(want, name->name, len);
	Esys_Free(name);
	if (!same)
		return "parent name";   /* not the key the CC was provisioned with */

	if (read_file("policy/approved", rel->approved.buffer, sizeof(rel->approved.buffer), &len) || len != 32)
		return "approved policy";
	rel->approved.size = 32;
	if (READ_TPM_TYPE(TPMT_SIGNATURE, "policy/approved.sig", &sig))
		return "policy signature";
	if (read_file("policy/epoch", epoch_text, sizeof(epoch_text) - 1, &len))
		return "epoch";
	epoch = strtoul((char *)epoch_text, &end, 10);
	if (end == (char *)epoch_text || (*end && *end != '\n') || epoch > 63)
		return "epoch";
	mask = epoch == 63 ? 0 : ~((1ULL << (epoch + 1)) - 1);   /* every bit above the epoch */
	rel->operand.size = 8;
	for (i = 0; i < 8; i++)
		rel->operand.buffer[i] = (uint8_t)(mask >> (56 - 8 * i));
	*rc = Esys_TR_FromTPMPublic(esys, EPOCH_NV_INDEX, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &rel->nv);
	if (*rc)
		return "epoch index";

	/* A ticket that the MSS signed this approved policy for this policyRef. */
	if (READ_TPM_TYPE(TPM2B_PUBLIC, "kpol.pub", &kpol))
		return "K-CC-POL public key";
	*rc = Esys_LoadExternal(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, &kpol, ESYS_TR_RH_OWNER,
				&kpol_handle);   /* a NULL-hierarchy ticket would not satisfy PolicyAuthorize */
	if (*rc)
		return "LoadExternal";
	*rc = Esys_TR_GetName(esys, kpol_handle, &name);
	if (!*rc) {
		rel->kpol_name = *name;
		Esys_Free(name);
		msg.size = 32 + sizeof(POLICY_REF) - 1;
		memcpy(msg.buffer, rel->approved.buffer, 32);
		memcpy(msg.buffer + 32, POLICY_REF, sizeof(POLICY_REF) - 1);
		*rc = Esys_Hash(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &msg, TPM2_ALG_SHA256, ESYS_TR_RH_NULL,
				&ahash, &hashcheck);
	}
	if (!*rc)
		*rc = Esys_VerifySignature(esys, kpol_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ahash, &sig,
					   &ticket);
	if (!*rc)
		rel->ticket = *ticket;
	Esys_Free(ahash);
	Esys_Free(hashcheck);
	Esys_Free(ticket);
	Esys_FlushContext(esys, kpol_handle);
	return *rc ? "VerifySignature" : NULL;
}

int main(int argc, char **argv)
{
	TSS2_TCTI_CONTEXT *tcti = NULL;
	ESYS_CONTEXT *esys = NULL;
	struct release rel;
	const char *step;
	size_t size = 0;
	TSS2_RC rc;
	int i, all = 1;

	if (argc < 4) {
		fprintf(stderr, "usage: %s <ccdir> <outdir> <name>...\n", argv[0]);
		return 2;
	}
	ccdir = argv[1];
	setvbuf(stdout, NULL, _IOLBF, 0);
#ifdef P2_CONTROL_CLEAR_RESPONSE
	printf("P2-UNSEAL control build: response encryption off\n");
#endif
	memset(&rel, 0, sizeof(rel));

	step = "TPM";
	rc = Tss2_Tcti_Device_Init(NULL, &size, TPM_DEVICE);
	if (!rc) {
		tcti = calloc(1, size);
		rc = tcti ? Tss2_Tcti_Device_Init(tcti, &size, TPM_DEVICE) : TSS2_BASE_RC_MEMORY;
	}
	if (!rc)
		rc = Esys_Initialize(&esys, tcti, NULL);
	if (!rc)
		step = prepare(esys, &rel, &rc);

	for (i = 3; i < argc; i++) {
		if (step)
			refused(argv[i], step, rc ? Tss2_RC_Decode(rc) : "missing or wrong CC data");
		else
			all &= unseal_one(esys, &rel, argv[i], argv[2]);
	}
	if (esys)
		Esys_Finalize(&esys);
	if (tcti) {
		Tss2_Tcti_Finalize(tcti);
		free(tcti);
	}
	return step || !all;
}
