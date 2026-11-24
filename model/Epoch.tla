------------------------------- MODULE Epoch -------------------------------
(* docs/03-measured-boot-sealing.md 3.2-3.5 as generic TPM 2.0 commands; see README.md *)
EXTENDS Naturals

CONSTANTS EpochIdx,   \* the epoch index handle, 0x01000001
          ProvAttrs,  \* its attributes at provisioning (TPM_NT_BITS is implied)
          OwnerAuth,  \* "empty" (P2) or "set"
          MaxEpoch    \* bits 1..MaxEpoch of the bit field are modeled

Indices == {EpochIdx}
Releases == {1, 2}           \* two signed releases, at epochs 1 and 2
Bits == 1..MaxEpoch
\* What a caller may choose in NV_DefineSpace. A TPM_NT_BITS index holds 8 bytes.
Flags == {"ownerwrite", "authwrite", "ownerread", "authread", "no_da", "policy_delete"}
AuthPolicies == {"empty", "other"}

VARIABLES nv,         \* NV store: index -> public area, bits and the written flag
          ownerAuth,  \* owner authValue
          committed,  \* epoch committed by the legitimate update flow
          session,    \* one policy session
          released    \* <<release epoch, committed epoch>> for every unseal
vars == <<nv, ownerAuth, committed, session, released>>

Undefined == [defined |-> FALSE, attrs |-> {}, authPolicy |-> "empty",
              nameAlg |-> "sha256", size |-> 8, bits |-> {}, written |-> FALSE]
\* Provisioning (tests/ve07/provision.py): defined, then written with no bits set.
Provisioned == [Undefined EXCEPT !.defined = TRUE, !.attrs = ProvAttrs, !.written = TRUE]

\* NV name: nameAlg || H(TPMS_NV_PUBLIC). H is taken as injective, so the tuple of
\* hashed fields stands for the name. TPMA_NV_WRITTEN is an attribute, as in the TPM.
NameOf(i, r) == <<i, r.nameAlg, r.attrs \union (IF r.written THEN {"written"} ELSE {}), r.authPolicy, r.size>>

\* Policy digests, abstracted to the inputs the TPM hashes into them.
Zero == <<"zero">>
Other == <<"other">>         \* any digest that no signed policy approves
PolicyNVDigest(name, operandB) == <<"PolicyNV", name, operandB, "TPM_EO_BITCLEAR">>
\* Each release's approved policy binds the name at provisioning; K-CC-POL signs it.
Approved(e) == PolicyNVDigest(NameOf(EpochIdx, Provisioned), {b \in Bits : b > e})
Signed == {Approved(e) : e \in Releases}
\* The sealed objects' authPolicy: PolicyAuthorize(K-CC-POL, "p2/cc-keys").
Authorized == <<"PolicyAuthorize", "K-CC-POL", "p2/cc-keys">>
NoSession == [open |-> FALSE, digest |-> Zero, via |-> 0]

\* Owner auth is usable only when empty. Every index's own authValue is empty.
OwnerKnown == ownerAuth = "empty"
CanRead(r) == "authread" \in r.attrs \/ ("ownerread" \in r.attrs /\ OwnerKnown)
CanWrite(r) == "authwrite" \in r.attrs \/ ("ownerwrite" \in r.attrs /\ OwnerKnown)

Init == /\ nv = [i \in Indices |-> Provisioned] /\ ownerAuth = OwnerAuth /\ committed = 0
        /\ session = NoSession /\ released = {}

\* TPM2_NV_DefineSpace under owner authorization. POLICY_DELETE needs the platform
\* hierarchy, and the index needs a way to read and a way to write.
NV_DefineSpace(i, a, p) ==
  /\ ~nv[i].defined /\ OwnerKnown /\ "policy_delete" \notin a
  /\ a \intersect {"ownerwrite", "authwrite"} # {} /\ a \intersect {"ownerread", "authread"} # {}
  /\ nv' = [nv EXCEPT ![i] = [Undefined EXCEPT !.defined = TRUE, !.attrs = a, !.authPolicy = p]]
  /\ UNCHANGED <<ownerAuth, committed, session, released>>

\* TPM2_NV_UndefineSpace under owner authorization.
NV_UndefineSpace(i) ==
  /\ nv[i].defined /\ OwnerKnown /\ "policy_delete" \notin nv[i].attrs
  /\ nv' = [nv EXCEPT ![i] = Undefined]
  /\ UNCHANGED <<ownerAuth, committed, session, released>>

\* TPM2_NV_SetBits: ORs operand b into the index and sets TPMA_NV_WRITTEN.
NV_SetBits(i, b) ==
  /\ nv[i].defined /\ CanWrite(nv[i])
  /\ nv' = [nv EXCEPT ![i].bits = @ \union b, ![i].written = TRUE]
  /\ UNCHANGED <<ownerAuth, committed, session, released>>

\* TPM2_StartAuthSession of a policy session; any earlier one is abandoned.
StartAuthSession ==
  /\ session' = [NoSession EXCEPT !.open = TRUE]
  /\ UNCHANGED <<nv, ownerAuth, committed, released>>

\* TPM2_PolicyNV(TPM_EO_BITCLEAR): passes if every bit of operandB is clear in the
\* written index, and extends the digest with the index's current name.
PolicyNV(i, b) ==
  /\ session.open /\ nv[i].defined /\ nv[i].written /\ CanRead(nv[i]) /\ nv[i].bits \intersect b = {}
  /\ LET d == IF session.digest = Zero THEN PolicyNVDigest(NameOf(i, nv[i]), b) ELSE Other
     IN session' = [session EXCEPT !.digest = IF d \in Signed THEN d ELSE Other]
  /\ UNCHANGED <<nv, ownerAuth, committed, released>>

\* TPM2_PolicyAuthorize with a K-CC-POL ticket. `via` (not kept by the TPM) notes whose policy.
PolicyAuthorize ==
  /\ session.open /\ session.digest \in Signed
  /\ session' = [session EXCEPT !.digest = Authorized, !.via = CHOOSE e \in Releases : Approved(e) = session.digest]
  /\ UNCHANGED <<nv, ownerAuth, committed, released>>

\* TPM2_Unseal of a sealed object in the policy session, which then ends.
Unseal ==
  /\ session.open /\ session.digest = Authorized
  /\ released' = released \union {<<session.via, committed>>} /\ session' = NoSession
  /\ UNCHANGED <<nv, ownerAuth, committed>>

\* The legitimate update (3.5, step 4): NV_SetBits of bit e with owner auth, held even
\* when set. It runs in a later boot, of release e, so no earlier session survives it.
Commit(e) ==
  /\ e > committed /\ nv[EpochIdx].defined /\ "ownerwrite" \in nv[EpochIdx].attrs
  /\ nv' = [nv EXCEPT ![EpochIdx].bits = @ \union {e}, ![EpochIdx].written = TRUE]
  /\ committed' = e /\ session' = NoSession
  /\ UNCHANGED <<ownerAuth, released>>

Next ==
  \/ \E i \in Indices, a \in SUBSET Flags, p \in AuthPolicies : NV_DefineSpace(i, a, p)
  \/ \E i \in Indices : NV_UndefineSpace(i)
  \/ \E i \in Indices, b \in SUBSET Bits : NV_SetBits(i, b) \/ PolicyNV(i, b)
  \/ StartAuthSession \/ PolicyAuthorize \/ Unseal
  \/ \E e \in Releases : Commit(e)
Spec == Init /\ [][Next]_vars

\* No release older than the committed epoch obtains the keys.
NoOldReleaseUnseals == \A r \in released : r[1] >= r[2]
\* The epoch never decreases (3.4): written, as PolicyNV needs, the index is at the committed epoch or more, and never drops.
EpochOf(r) == IF r.bits = {} THEN 0 ELSE CHOOSE b \in r.bits : \A c \in r.bits : c <= b
EpochMonotonic == [][LET was == nv[EpochIdx]  now == nv'[EpochIdx] IN now.defined /\ now.written =>
                       EpochOf(now) >= committed' /\ (was.defined /\ was.written => EpochOf(now) >= EpochOf(was))]_vars
=============================================================================
