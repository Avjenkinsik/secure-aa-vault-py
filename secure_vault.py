#!/usr/bin/env python3
# Simple AA-like policy gate: defines roles, approves intents, and "signs"
# (produces deterministic digest) if all policies pass.
import argparse, json, hashlib, hmac, os, time
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

@dataclass
class Intent:
    to: str
    value: int
    data: str
    chain_id: int
    nonce: int

class PolicyError(Exception):
    pass

class Vault:
    def __init__(self, secret: bytes, limits: Dict[str, int], guardians: List[str]):
        self.secret = secret
        self.limits = limits
        self.guardians = set(guardians)

    def _assert_policies(self, intent: Intent, actor: str):
        if not actor or actor not in self.guardians:
            raise PolicyError("actor not authorized")
        if intent.value < 0:
            raise PolicyError("negative value")
        daily = self.limits.get("daily", 0)
        if daily and intent.value > daily:
            raise PolicyError(f"value exceeds daily limit {daily}")
        if not intent.to.startswith("0x") or len(intent.to) != 42:
            raise PolicyError("bad recipient")
        # cooldown: refuse bursts (toy model: 5s min gap)
        last = state.get("last_ts", 0)
        if int(time.time()) - last < 5:
            raise PolicyError("cooldown not satisfied")

    def sign(self, intent: Intent, actor: str) -> Dict[str, Any]:
        self._assert_policies(intent, actor)
        payload = json.dumps(asdict(intent), sort_keys=True).encode()
        sig = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
        state["last_ts"] = int(time.time())
        return {"intent": asdict(intent), "actor": actor, "sig": "0x"+sig}

state: Dict[str, Any] = {}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--actor", required=True)
    ap.add_argument("--to", required=True)
    ap.add_argument("--value", type=int, required=True)
    ap.add_argument("--data", default="0x")
    ap.add_argument("--chain", type=int, default=1)
    ap.add_argument("--nonce", type=int, default=0)
    args = ap.parse_args()

    vault = Vault(
        secret=os.environ.get("VAULT_SECRET","demo-unsafe-key").encode(),
        limits={"daily": 10**18},  # 1 ETH in wei (toy)
        guardians=[args.actor],
    )
    intent = Intent(to=args.to, value=args.value, data=args.data, chain_id=args.chain, nonce=args.nonce)
    try:
        out = vault.sign(intent, actor=args.actor)
        print(json.dumps(out, indent=2))
    except PolicyError as e:
        print(json.dumps({"error": str(e)}, indent=2))

if __name__ == "__main__":
    main()
