#!/usr/bin/env python3
"""Usage: python3 model/trace_to_tpm2.py TRACE    (a TLC JSON counterexample of model/Epoch.tla)

Prints each step of the trace as JSON: the state it reaches, the Epoch.tla action that explains it, found by comparing
the state with the one before (the pinned TLC build records no action names), and the tpm2-tools argv lists that
replay it, with {placeholders} for the harness's handles and files (model/README.md, "Replay"). Exits non-zero, naming
the state or the action, if a step matches no action, an action has no mapping or the trace has no step."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

VARS = {"nv", "ownerAuth", "committed", "session", "released"}   # Epoch.tla's variables
FLAGS = ("ownerwrite", "authwrite", "ownerread", "authread", "no_da")   # what NV_DefineSpace may set; tpm2-tools names
SESSION = ["-S", "session.ctx"]


class TraceError(ValueError):
    pass


def bits(value: object) -> list[int]:
    if not isinstance(value, list) or not all(type(b) is int and 0 <= b <= 63 for b in value):
        raise TraceError(f"not a set of bits 0 to 63: {value!r}")
    return sorted(set(value))


def mask(value: object) -> str:
    return f"{sum(1 << b for b in bits(value)):#x}"


def flush_session(prev: dict) -> list[list[str]]:
    """A session open before the step ends with it (StartAuthSession abandons it; Commit runs in a later boot)."""
    return [["tpm2_flushcontext", "-s"]] if prev["session"]["open"] else []


def nv_define(prev: dict, cur: dict, index: str, attrs: list, policy: str) -> list[list[str]]:
    if not isinstance(attrs, list) or not set(attrs) <= set(FLAGS) or policy not in ("empty", "other"):
        raise TraceError(f"NV_DefineSpace({attrs!r}, {policy!r}) has no tpm2_nvdefine mapping")
    size = cur["nv"][index]["size"]
    if type(size) is not int or size < 1:
        raise TraceError(f"not an NV size: {size!r}")
    return [["tpm2_nvdefine", "-Q", "{epoch_index}", "-C", "o", "-s", str(size),
             "-a", "|".join(["nt=bits", *(f for f in FLAGS if f in attrs)]),
             *(["-L", "{other_policy}"] if policy == "other" else [])]]


def nv_setbits(prev: dict, cur: dict, index: str, b: list) -> list[list[str]]:
    """With owner auth if the index allows it and it is known (empty), else with the index's own, empty, auth."""
    attrs = prev["nv"][index]["attrs"]
    auth = "o" if "ownerwrite" in attrs and prev["ownerAuth"] == "empty" else "{epoch_index}"
    if auth != "o" and "authwrite" not in attrs:
        raise TraceError(f"NV_SetBits on an index neither owner nor index auth may write: {attrs!r}")
    return [["tpm2_nvsetbits", "-Q", "{epoch_index}", "-C", auth, "-i", mask(b)]]


def release_of(b: list) -> int:
    """The release E whose approved policy has operand b = {E+1 .. MaxEpoch}: in the TPM, every bit above E is set."""
    b = bits(b)
    if not b or b[0] < 2 or b != list(range(b[0], b[-1] + 1)):
        raise TraceError(f"PolicyNV operand {b} is not a release's approved operand")
    return b[0] - 1


def policy_authorize(prev: dict, cur: dict, e: int) -> list[list[str]]:
    if type(e) is not int or not 1 <= e <= 62:
        raise TraceError(f"not a release: {e!r}")
    return [["tpm2_loadexternal", "-Q", "-C", "o", "-G", "ecc", "-u", "{kpol_pub}", "-c", "kpol.ctx",
             "-n", "kpol.name"],
            ["tpm2_verifysignature", "-Q", "-c", "kpol.ctx", "-g", "sha256", "-m", f"{{signed_{e}}}",
             "-s", f"{{policy_dir_{e}}}/approved.sig", "-t", "ticket.bin"],
            ["tpm2_flushcontext", "-t"],   # swtpm has no resource manager
            ["tpm2_policyauthorize", "-Q", *SESSION, "-i", f"{{policy_dir_{e}}}/approved", "-q", "{policy_ref}",
             "-n", "kpol.name", "-t", "ticket.bin"]]


def commit(prev: dict, cur: dict, e: int) -> list[list[str]]:
    """Owner auth, which the legitimate update holds even when set."""
    auth = [] if prev["ownerAuth"] == "empty" else ["-P", "{owner_auth}"]
    return [*flush_session(prev), ["tpm2_nvsetbits", "-Q", "{epoch_index}", "-C", "o", *auth, "-i", mask([e])]]


# Every action of Epoch.tla's Next. PCR stages are abstracted away in the model, so PolicyNV starts with PolicyPCR.
COMMANDS = {
    "NV_DefineSpace": nv_define,
    "NV_UndefineSpace": lambda prev, cur, i: [["tpm2_nvundefine", "-Q", "{epoch_index}", "-C", "o"]],
    "NV_SetBits": nv_setbits,
    "StartAuthSession": lambda prev, cur: [*flush_session(prev),
                                           ["tpm2_startauthsession", "--policy-session", *SESSION]],
    "PolicyNV": lambda prev, cur, i, b: [["tpm2_policypcr", "-Q", *SESSION, "-l", "{pcr_selection}"],
                                         ["tpm2_policynv", "-Q", *SESSION, "-i", f"{{operand_{release_of(b)}}}",
                                          "{epoch_index}", "bc"]],
    "PolicyAuthorize": policy_authorize,
    "Unseal": lambda prev, cur: [["tpm2_load", "-Q", "-C", "{parent}", "-u", "{sealed_pub}", "-r", "{sealed_priv}",
                                  "-c", "sealed.ctx"],
                                 ["tpm2_unseal", "-c", "sealed.ctx", "-p", "session:session.ctx"],
                                 ["tpm2_flushcontext", "-t"], ["tpm2_flushcontext", "-s"]],
    "Commit": commit,
}


def action(prev: dict, cur: dict) -> tuple[str, list]:
    """The action, with its arguments, that takes prev to cur; TraceError if no action of Epoch.tla does."""
    changed = {v for v in VARS if prev[v] != cur[v]}
    was, now = prev["session"], cur["session"]
    if "committed" in changed and changed <= {"nv", "committed", "session"}:
        return "Commit", [cur["committed"]]
    if changed in ({"session"}, {"session", "released"}) and not now["open"] and was["digest"][0] == "PolicyAuthorize":
        return "Unseal", []
    if changed == {"nv"}:
        (i, a), = prev["nv"].items()
        b = cur["nv"][i]
        if a["defined"] != b["defined"]:
            return ("NV_DefineSpace", [i, b["attrs"], b["authPolicy"]]) if b["defined"] else ("NV_UndefineSpace", [i])
        if b["defined"]:
            return "NV_SetBits", [i, sorted(set(bits(b["bits"])) - set(bits(a["bits"])))]
    if changed == {"session"} and now["open"]:
        d = now["digest"]
        if d == ["zero"]:
            return "StartAuthSession", []
        if d[0] == "PolicyNV" and d[1][0] in cur["nv"] and was["digest"] == ["zero"]:
            return "PolicyNV", [d[1][0], d[2]]
        if d[0] == "PolicyAuthorize" and was["digest"][0] == "PolicyNV":
            return "PolicyAuthorize", [now["via"]]
        if d == ["other"]:
            raise TraceError("PolicyNV to a digest no release signs: its operand is not in the trace")
    raise TraceError(f"no action of model/Epoch.tla changes {', '.join(sorted(changed)) or 'nothing'} this way")


def commands(name: str, prev: dict, cur: dict, args: list) -> list[list[str]]:
    if name not in COMMANDS:
        raise TraceError(f"no tpm2-tools mapping for action {name}")
    return COMMANDS[name](prev, cur, *args)


def translate(trace: object) -> list[dict]:
    """[{"state": n, "action": name, "args": [...], "argv": [[...], ...]}] for states 2 to N of a TLC JSON trace."""
    if not isinstance(trace, list) or len(trace) < 2:
        raise TraceError("not a TLC JSON trace with at least one step (a list of two or more states)")
    steps = []
    for n, (prev, cur) in enumerate(zip(trace, trace[1:]), start=2):
        try:
            for s in (prev, cur):
                if not isinstance(s, dict) or set(s) != VARS or len(s["nv"]) != 1 or s["ownerAuth"] not in (
                        "empty", "set") or s["nv"].keys() != cur["nv"].keys():
                    raise TraceError(f"not a state of model/Epoch.tla with one NV index: {s!r}")
            name, args = action(prev, cur)
            steps.append({"state": n, "action": name, "args": args, "argv": commands(name, prev, cur, args)})
        except TraceError as err:
            raise TraceError(f"state {n}: {err}") from None
        except (KeyError, TypeError, IndexError, AttributeError, ValueError) as err:
            raise TraceError(f"state {n}: malformed state ({type(err).__name__}: {err})") from None
    return steps


def fill(argv: list[str], values: dict[str, str]) -> list[str]:
    """argv with each {placeholder} replaced by its value; KeyError names a placeholder without one."""
    return [re.sub(r"\{(\w+)\}", lambda m: values[m.group(1)], arg) for arg in argv]


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        sys.exit(__doc__)
    try:
        print(json.dumps(translate(json.loads(Path(argv[0]).read_text())), indent=1))
    except (TraceError, OSError, ValueError) as err:
        sys.exit(f"{argv[0]}: {err}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
