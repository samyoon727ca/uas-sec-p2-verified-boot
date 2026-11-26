-------------------------------- MODULE Boot --------------------------------
(* docs/03-measured-boot-sealing.md 3.1-3.3: boot stages, PCRs 0/1/8/9, reboot and TPM reset over Epoch.tla; see README.md *)
EXTENDS Naturals, Sequences

CONSTANTS EpochIdx, ProvAttrs, OwnerAuth, MaxEpoch,   \* as in Epoch.tla
          Tier,            \* the attacker's tier: "root" (root on the CC) or "physical" (a captured CC)
          CapAfterUnseal   \* 3.3 step 4 (DD2-18); FALSE only in the control without the cap
VARIABLES nv, ownerAuth, committed, session, released,   \* as in Epoch.tla
          pcrs,        \* PCR -> the measurements extended into it since the last TPM reset (SHA-256 bank)
          stage, pc,   \* the running boot stage, and the index of its program's next command
          pcrPolicy,   \* what PolicyPCR added to the session's digest: "none", "approved" or "other"
          unsealedIn   \* the stages in which an Unseal released the keys
E == INSTANCE Epoch
vars == <<nv, ownerAuth, committed, session, released, pcrs, stage, pc, pcrPolicy, unsealedIn>>

PCRs == {0, 1, 8, 9}
Values == {"release", "cap"}   \* what U-Boot measures of the approved release into a PCR; p2-unseal's cap event
ApprovedPCRs == [p \in PCRs |-> <<"release">>]   \* the predicted values each signed policy covers (3.1)
Unapproved == <<"unapproved">>   \* any sequence that is no prefix of the approved one: it never becomes one again
Extended(p, s, v) == IF s # Unapproved /\ Len(s) < Len(ApprovedPCRs[p]) /\ ApprovedPCRs[p][Len(s) + 1] = v
                     THEN Append(s, v) ELSE Unapproved
Reset == [p \in PCRs |-> <<>>]

Booted == 2   \* the release that boots, the newer one
AttackerStage == "userspace"
NextStage == [rom |-> "uboot", uboot |-> "kernel", kernel |-> "initramfs", initramfs |-> "userspace"]
\* Each stage's TPM commands, in order. The ROM and the kernel extend none of PCRs 0, 1, 8 and 9.
Measure(v) == <<<<"Extend", 0, v>>, <<"Extend", 1, v>>, <<"Extend", 8, v>>, <<"Extend", 9, v>>>>
Program(s) == CASE s = "uboot" -> Measure("release")
                [] s = "initramfs" -> <<<<"StartAuthSession">>, <<"PolicyPCR">>,
                                       <<"PolicyNV", {b \in E!Bits : b > Booted}>>, <<"PolicyAuthorize">>,
                                       <<"Unseal">>>> \o (IF CapAfterUnseal THEN Measure("cap") ELSE <<>>)
                [] OTHER -> <<>>
\* Command c runs if the attacker issues it at its stage, or if it is the running stage's next command.
Issue(c) == IF stage = AttackerStage THEN UNCHANGED <<stage, pc>>
            ELSE /\ pc <= Len(Program(stage)) /\ Program(stage)[pc][1] = c[1] /\ Program(stage)[pc] = c
                 /\ pc' = pc + 1 /\ UNCHANGED stage

Init == E!Init /\ pcrs = Reset /\ stage = "rom" /\ pc = 1 /\ pcrPolicy = "none" /\ unsealedIn = {}

\* TPM2_PCR_Extend, or TPM2_PCR_Event for the cap event.
Extend(p, v) == Issue(<<"Extend", p, v>>) /\ pcrs' = [pcrs EXCEPT ![p] = Extended(p, @, v)]
                /\ UNCHANGED <<nv, ownerAuth, committed, session, released, pcrPolicy, unsealedIn>>
StartAuthSession == Issue(<<"StartAuthSession">>) /\ E!StartAuthSession /\ pcrPolicy' = "none"
                    /\ UNCHANGED <<pcrs, unsealedIn>>
\* TPM2_PolicyPCR over PCRs 0, 1, 8 and 9 as they are now. Each signed policy starts with it (3.3).
PolicyPCR == /\ Issue(<<"PolicyPCR">>) /\ session.open
             /\ pcrPolicy' = IF pcrPolicy = "none" /\ session.digest = E!Zero /\ pcrs = ApprovedPCRs
                             THEN "approved" ELSE "other"
             /\ UNCHANGED <<nv, ownerAuth, committed, session, released, pcrs, unsealedIn>>
PolicyNV(b) == Issue(<<"PolicyNV", b>>) /\ E!PolicyNV(EpochIdx, b) /\ UNCHANGED <<pcrs, pcrPolicy, unsealedIn>>
\* A signed policy is PolicyPCR then PolicyNV; PolicyAuthorize resets the digest to the authorized one.
PolicyAuthorize == Issue(<<"PolicyAuthorize">>) /\ pcrPolicy = "approved" /\ E!PolicyAuthorize
                   /\ pcrPolicy' = "none" /\ UNCHANGED <<pcrs, unsealedIn>>
Unseal == Issue(<<"Unseal">>) /\ pcrPolicy = "none" /\ E!Unseal /\ unsealedIn' = unsealedIn \union {stage}
          /\ UNCHANGED <<pcrs, pcrPolicy>>
\* The legitimate update (3.5, step 4) runs in userspace.
Commit(e) == stage = AttackerStage /\ E!Commit(e) /\ pcrPolicy' = "none" /\ UNCHANGED <<pcrs, stage, pc, unsealedIn>>
\* A stage that has run its program starts the next one.
Handover == /\ stage # AttackerStage /\ pc > Len(Program(stage)) /\ stage' = NextStage[stage] /\ pc' = 1
            /\ UNCHANGED <<nv, ownerAuth, committed, session, released, pcrs, pcrPolicy, unsealedIn>>
\* A power cycle, at any time: the TPM resets (PCRs, sessions), NV persists, the CC boots from the ROM.
Reboot == /\ pcrs' = Reset /\ session' = E!NoSession /\ pcrPolicy' = "none" /\ stage' = "rom" /\ pc' = 1
          /\ UNCHANGED <<nv, ownerAuth, committed, released, unsealedIn>>
\* The TPM alone resets (_TPM_Init, TPM2_Startup(CLEAR)) while the CC keeps running: needs its reset pin.
TPMReset == /\ Tier = "physical" /\ stage = AttackerStage /\ pcrs' = Reset /\ session' = E!NoSession
            /\ pcrPolicy' = "none" /\ UNCHANGED <<nv, ownerAuth, committed, released, stage, pc, unsealedIn>>

Next ==
  \/ \E p \in PCRs, v \in Values : Extend(p, v)
  \/ StartAuthSession \/ PolicyPCR \/ PolicyAuthorize \/ Unseal
  \/ \E b \in SUBSET E!Bits : PolicyNV(b)
  \/ \E e \in E!Releases : Commit(e)
  \/ Handover \/ Reboot \/ TPMReset
Spec == Init /\ [][Next]_vars

\* Keys are obtained only while the approved initramfs runs (stages run only signed code, SR-005).
OnlyInitramfsObtainsKeys == unsealedIn \subseteq {"initramfs"}
NoOldReleaseUnseals == E!NoOldReleaseUnseals
EpochMonotonic == E!EpochMonotonic
\* Witness, expected violated: the approved initramfs's unseal is reachable.
InitramfsNeverObtainsKeys == "initramfs" \notin unsealedIn
=============================================================================
