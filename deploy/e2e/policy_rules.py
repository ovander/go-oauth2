"""Policy rule-language matrix via POST /api/admin/policy/simulate (draft rules)
and /api/admin/policy/validate. Each case states the expected decision."""
from flows import *

T = admin_token()

def P(**kw):
    base = {"kind": "user", "id": 7, "role": "user", "app_role": "user", "scopes": ["openid"], "amr": ["pwd"]}
    base.update(kw); return base

def sim(rules, principal, action="invoice.approve", resource=None, context=None):
    inp = {"principal": principal, "action": action, "resource": resource or {"type": "invoice", "id": "1"}, "context": context or {}}
    s, b = req("POST", f"{ADM}/api/admin/policy/simulate", {"input": inp, "rules": rules}, token=T)
    d = (b or {}).get("decision", b) if isinstance(b, dict) else b
    return s, d

def R(id, effect, when=None, actions=("invoice.approve",), **extra):
    r = {"id": id, "effect": effect, "actions": list(actions)}
    if when is not None: r["when"] = when
    r.update(extra); return r

def case(name, rules, principal, expect_allow, expect_reason=None, **kw):
    s, d = sim(rules, principal, **kw)
    ok = s == 200 and isinstance(d, dict) and d.get("allow") == expect_allow and (expect_reason is None or d.get("reason") == expect_reason)
    check(name, ok, f"{s} allow={d.get('allow') if isinstance(d, dict) else d} reason={d.get('reason') if isinstance(d, dict) else ''} rule={d.get('rule') if isinstance(d, dict) else ''} obl={d.get('obligations') if isinstance(d, dict) else ''}")
    return d

A = lambda attr, op, value=None, **k: {"attr": attr, "op": op, **({"value": value} if value is not None else {}), **k}
admin_only = R("admins", "allow", A("principal.app_role", "eq", "admin"))

# Defaults and basic matching
case("no rules → default deny", [], P(), False, "no_applicable_rule")
case("eq matches → allow", [admin_only], P(app_role="admin"), True, "allowed_by_rule")
case("eq does not match → default deny", [admin_only], P(), False, "no_applicable_rule")
case("action not listed → rule does not apply", [admin_only], P(app_role="admin"), False, action="invoice.delete")
case("action wildcard", [R("w", "allow", None, actions=("invoice.*",))], P(), True, action="invoice.delete")
case("rule without condition applies to everyone", [R("all", "allow")], P(), True)
case("disabled rule is ignored", [R("all", "allow", disabled=True)], P(), False)

# Deny overrides
case("deny overrides allow", [R("all", "allow"), R("block", "deny", A("principal.role", "eq", "user"))], P(), False)
case("deny that does not match leaves allow", [R("all", "allow"), R("block", "deny", A("principal.role", "eq", "guest"))], P(), True)

# Operators
case("ne", [R("r", "allow", A("principal.role", "ne", "guest"))], P(), True)
case("in", [R("r", "allow", A("principal.app_role", "in", ["admin", "manager"]))], P(app_role="manager"), True)
case("not_in", [R("r", "allow", A("principal.app_role", "not_in", ["admin"]))], P(), True)
case("gt on resource attribute (1200 > 1000)", [R("r", "allow", A("resource.attributes.amount", "gt", 1000))], P(), True, resource={"type": "invoice", "id": "1", "attributes": {"amount": 1200}})
case("lte on resource attribute (1200 <= 1000 false)", [R("r", "allow", A("resource.attributes.amount", "lte", 1000))], P(), False, resource={"type": "invoice", "id": "1", "attributes": {"amount": 1200}})
case("gte/lt boundary (1000 >= 1000)", [R("r", "allow", A("resource.attributes.amount", "gte", 1000))], P(), True, resource={"type": "invoice", "id": "1", "attributes": {"amount": 1000}})
case("contains on a list (scopes has openid)", [R("r", "allow", A("principal.scopes", "contains", "openid"))], P(), True)
case("starts_with", [R("r", "allow", A("resource.id", "starts_with", "inv-"))], P(), True, resource={"type": "invoice", "id": "inv-9"})
case("cidr match", [R("r", "allow", A("context.ip", "cidr", "10.0.0.0/8"))], P(), True, context={"ip": "10.1.2.3"})
case("cidr no match", [R("r", "allow", A("context.ip", "cidr", "10.0.0.0/8"))], P(), False, context={"ip": "192.0.2.1"})
case("exists", [R("r", "allow", A("resource.attributes.amount", "exists"))], P(), True, resource={"type": "invoice", "id": "1", "attributes": {"amount": 5}})
case("ref: owner equals principal id", [R("r", "allow", {"attr": "resource.attributes.owner_id", "op": "eq", "ref": "principal.id"})], P(id=7), True, resource={"type": "invoice", "id": "1", "attributes": {"owner_id": 7}})
case("ref: owner differs", [R("r", "allow", {"attr": "resource.attributes.owner_id", "op": "eq", "ref": "principal.id"})], P(id=8), False, resource={"type": "invoice", "id": "1", "attributes": {"owner_id": 7}})

# Boolean composition
case("all: both hold", [R("r", "allow", {"all": [A("principal.role", "eq", "user"), A("principal.app_role", "eq", "admin")]})], P(app_role="admin"), True)
case("all: one fails", [R("r", "allow", {"all": [A("principal.role", "eq", "user"), A("principal.app_role", "eq", "admin")]})], P(), False)
case("any: one holds", [R("r", "allow", {"any": [A("principal.role", "eq", "admin"), A("principal.app_role", "eq", "user")]})], P(), True)
case("not", [R("r", "allow", {"not": A("principal.role", "eq", "guest")})], P(), True)

# Three-valued logic: missing attributes
case("unknown attr on an allow → does not allow", [R("r", "allow", A("resource.attributes.amount", "lt", 5000))], P(), False, resource={"type": "invoice", "id": "1"})
case("unknown attr on a deny → denies", [R("all", "allow"), R("r", "deny", A("resource.attributes.amount", "gt", 5000))], P(), False, resource={"type": "invoice", "id": "1"})
case("not(unknown) is still unknown (no allow)", [R("r", "allow", {"not": A("resource.attributes.flag", "eq", True)})], P(), False, resource={"type": "invoice", "id": "1"})

# Obligations
d = case("require_mfa obligation surfaces", [R("r", "allow", obligations=["require_mfa"])], P(), True)
check("  obligations returned", isinstance(d, dict) and "require_mfa" in (d.get("obligations") or []), str(d.get("obligations") if isinstance(d, dict) else d))

# Validation of malformed rules
def validate(name, rules, expect_valid):
    s, b = req("POST", f"{ADM}/api/admin/policy/validate", {"rules": rules}, token=T)
    ok = (s == 200 and b.get("valid") is True) if expect_valid else (s in (200, 400, 422) and not (isinstance(b, dict) and b.get("valid") is True))
    check(name, ok, f"{s} {json.dumps(b)[:150]}")
validate("validate: good rule set", [admin_only], True)
validate("validate: unknown operator refused", [R("r", "allow", A("principal.role", "regex", ".*"))], False)
validate("validate: unknown attribute refused", [R("r", "allow", A("principal.shoe_size", "eq", 42))], False)
validate("validate: bad effect refused", [R("r", "maybe")], False)
validate("validate: duplicate rule ids refused", [R("r", "allow"), R("r", "deny")], False)
validate("validate: empty actions refused", [R("r", "allow", actions=())], False)

# The saved policy cannot lock admins out: PUT a deny-everything rule must be refused or not gate policy routes.
s, cur = req("GET", f"{ADM}/api/admin/policy", token=T)
s, b = req("PUT", f"{ADM}/api/admin/policy", {"rules": cur["rules"] + [R("lockout", "deny", None, actions=("* /api/admin/*",))], "note": "e2e lockout attempt", "base_version": cur["version"]}, token=T)
s2, b2 = req("GET", f"{ADM}/api/admin/policy", token=T)
s3, b3 = req("GET", f"{ADM}/api/admin/users", token=T)
check("deny-all on the admin API: policy page stays reachable (fix path)", s2 == 200, f"PUT={s} then GET /policy={s2}, GET /users={s3}")
if s in (200, 201):
    rs, rb = req("POST", f"{ADM}/api/admin/policy/versions/{cur['version']}/restore", {}, token=T)
    s4, _ = req("GET", f"{ADM}/api/admin/users", token=T)
    check("restore the previous version repairs access", rs == 200 and s4 == 200, f"restore={rs} then /users={s4}")
s, b = req("PUT", f"{ADM}/api/admin/policy", {"rules": cur["rules"], "note": "stale write", "base_version": cur["version"] - 1}, token=T)
check("stale base_version refused (optimistic concurrency)", s == 409, f"{s} {str(b)[:100]}")

print(f"\n{sum(bool(ok) for _, ok in results)}/{len(results)} passed")
