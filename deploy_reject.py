#!/usr/bin/env python3
"""Insert the reject rule (/tmp/reject_rule.json) into
/etc/sing-box/conf/03_route.json right after the sniff rule.
Idempotent: removes any previous copy of the same rule first.
Run with sudo where the conf dir is root-owned."""
import json, shutil, os

CONF = "/etc/sing-box/conf/03_route.json"
RULE_FILE = "/tmp/reject_rule.json"
BAK = CONF + ".bak-20261124"


def main():
    if not os.path.exists(BAK):
        shutil.copy2(CONF, BAK)
    with open(CONF, encoding="utf-8") as f:
        data = json.load(f)
    with open(RULE_FILE, encoding="utf-8") as f:
        rule = json.load(f)
    rules = data["route"]["rules"]
    rules = [r for r in rules
             if not (r.get("action") == "reject"
                     and "weixin.qq.com" in r.get("domain_suffix", []))]
    idx = 0
    for i, r in enumerate(rules):
        if r.get("action") == "sniff":
            idx = i + 1
            break
    rules.insert(idx, rule)
    data["route"]["rules"] = rules
    with open(CONF, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("OK: reject rule at index", idx, "| total rules:", len(rules))


if __name__ == "__main__":
    main()
