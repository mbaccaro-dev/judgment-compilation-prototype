//! Domain-neutral, finite typed-warrant evaluator. No I/O or external effects.
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const SCHEMA: &str = "jc-local-semantic-contracts/2";
const COORDINATE_MODEL: &str = "CHILD_Gs_EQUALS_PARENT_Gs_APPEND_PARENT_L;L_EQUALS_SIBLING_ORDINAL";
const CEILING: &str = "LOCAL_TYPED_WARRANT_EXECUTION_ONLY;NO_COMPLIANCE_OR_RESPONSIBILITY_VERDICT";
type Result<T> = std::result::Result<T, String>;
type Index<'a> = BTreeMap<&'a str, &'a Value>;
fn need(ok: bool, reason: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn obj(v: &Value) -> Result<&Map<String, Value>> {
    v.as_object().ok_or_else(|| "expected object".into())
}
fn arr(v: &Value) -> Result<&Vec<Value>> {
    v.as_array().ok_or_else(|| "expected list".into())
}
fn string(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| "expected string".into())
}
fn text(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        !s.is_empty()
            && s.chars().count() <= 4096
            && s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
                == s
            && !s.chars().any(|c| c < ' ')
    })
}
fn fields(v: &Value, required: &[&str], optional: &[&str]) -> Result<()> {
    let o = obj(v)?;
    need(
        required.iter().all(|k| o.contains_key(*k))
            && o.keys()
                .all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str())),
        "unexpected or missing fields",
    )
}
fn names(v: &Value) -> Result<BTreeSet<&str>> {
    let a = arr(v)?;
    need(a.iter().all(text), "invalid or duplicate names")?;
    let out: BTreeSet<_> = a.iter().map(|v| v.as_str().unwrap()).collect();
    need(out.len() == a.len(), "invalid or duplicate names")?;
    Ok(out)
}
fn index<'a>(v: &'a Value, label: &str) -> Result<Index<'a>> {
    let a = arr(v)?;
    let mut out = BTreeMap::new();
    for row in a {
        need(
            row.is_object() && text(&row["id"]),
            &format!("invalid {label} identity"),
        )?;
        need(
            out.insert(row["id"].as_str().unwrap(), row).is_none(),
            &format!("duplicate {label} identity"),
        )?;
    }
    Ok(out)
}
fn path(v: &Value) -> Result<Vec<u64>> {
    let a = arr(v)?;
    need(
        a.len() <= 64
            && a.iter()
                .all(|v| v.as_u64().is_some_and(|i| (1..=2147483647).contains(&i))),
        "invalid canonical domain path",
    )?;
    Ok(a.iter().map(|i| i.as_u64().unwrap()).collect())
}

type SemanticKey = (Vec<u64>, u64);

fn stack_prefix(stack: &str) -> Result<u64> {
    match stack {
        "judgment" => Ok(1),
        "work" => Ok(2),
        "architecture" => Ok(3),
        _ => Err("unknown semantic stack".into()),
    }
}

fn semantic_key(v: &Value, stack: &str) -> Result<SemanticKey> {
    fields(v, &["Gs", "L"], &[])?;
    let gs = arr(&v["Gs"])?;
    let prefix = stack_prefix(stack)?;
    need(
        !gs.is_empty()
            && gs.len() <= 64
            && gs[0].as_u64() == Some(prefix)
            && gs[1..]
                .iter()
                .all(|part| part.as_u64().is_some_and(|n| n <= 2147483647))
            && v["L"].as_u64().is_some_and(|level| level <= 2147483647),
        "invalid semantic coordinate",
    )?;
    Ok((
        gs.iter().map(|part| part.as_u64().unwrap()).collect(),
        v["L"].as_u64().unwrap(),
    ))
}

fn semantic_index(v: &Value, stack: &str) -> Result<BTreeSet<SemanticKey>> {
    let rows = arr(v)?;
    need(!rows.is_empty(), "semantic definition tree required")?;
    let mut out = BTreeSet::new();
    for row in rows {
        fields(row, &["coordinate", "label", "aliases"], &[])?;
        need(
            out.insert(semantic_key(&row["coordinate"], stack)?) && text(&row["label"]),
            "duplicate or invalid semantic definition",
        )?;
        names(&row["aliases"])?;
    }
    for (gs, _) in &out {
        if gs.len() > 1 {
            need(
                out.contains(&(gs[..gs.len() - 1].to_vec(), gs[gs.len() - 1])),
                "dangling semantic definition branch",
            )?;
        }
    }
    Ok(out)
}
fn bounded_integer(v: &Value, positive: bool) -> bool {
    v.as_i64()
        .is_some_and(|n| (-2147483647..=2147483647).contains(&n) && (!positive || n > 0))
}
fn source_links(v: &Value, sources: &Index<'_>) -> Result<()> {
    let ids = names(v)?;
    need(
        !ids.is_empty() && ids.iter().all(|id| sources.contains_key(id)),
        "unsupported semantic source link",
    )
}
fn value_type(predicate: &Value) -> &str {
    predicate
        .get("value_type")
        .and_then(Value::as_str)
        .unwrap_or("BOOLEAN")
}
fn quantity(
    pack: &Value,
    value: &Value,
) -> Result<((Vec<u64>, String, Option<String>), i128, i128)> {
    let unit_path = path(&value["unit_path"])?;
    let node = arr(&pack["domain"])?
        .iter()
        .find(|n| path(&n["path"]).ok().as_ref() == Some(&unit_path))
        .ok_or("unknown quantity unit")?;
    let unit = obj(&node["unit"])?;
    let amount = value["amount"].as_i64().ok_or("invalid quantity amount")? as i128;
    let numerator = unit["numerator"]
        .as_i64()
        .ok_or("invalid exact unit scale")? as i128;
    let denominator = unit["denominator"]
        .as_i64()
        .ok_or("invalid exact unit scale")? as i128;
    let mut n = amount * numerator;
    let mut d = denominator;
    let gcd = |mut a: i128, mut b: i128| {
        a = a.abs();
        b = b.abs();
        while b != 0 {
            let r = a % b;
            a = b;
            b = r;
        }
        if a == 0 { 1 } else { a }
    };
    let g = gcd(n, d);
    n /= g;
    d /= g;
    Ok((
        (
            path(&unit["dimension_path"])?,
            string(&unit["basis"])?.to_owned(),
            unit.get("calendar_id")
                .map(string)
                .transpose()?
                .map(str::to_owned),
        ),
        n,
        d,
    ))
}
fn validate_value(pack: &Value, predicate: &Value, value: &Value, nullable: bool) -> Result<()> {
    if value.is_null() && nullable {
        return Ok(());
    }
    match value_type(predicate) {
        "BOOLEAN" => need(value.is_boolean(), "invalid Boolean value"),
        "INTEGER" => need(
            bounded_integer(value, false),
            "invalid bounded integer value",
        ),
        "DOMAIN" => {
            need(
                arr(&pack["domain"])?.iter().any(|n| n["path"] == *value),
                "unknown domain value",
            )?;
            need(
                compare(pack, predicate, value, &predicate["domain_root"], "IS_A")?,
                "domain value outside declared classification root",
            )
        }
        "QUANTITY" => {
            fields(value, &["amount", "unit_path"], &[])?;
            need(
                bounded_integer(&value["amount"], false),
                "invalid quantity amount",
            )?;
            let unit_path = path(&value["unit_path"])?;
            need(
                arr(&pack["domain"])?.iter().any(|n| {
                    path(&n["path"]).ok().as_ref() == Some(&unit_path) && n.get("unit").is_some()
                }),
                "unknown quantity unit",
            )
        }
        _ => Err("unsupported value type".into()),
    }
}
fn value_key(pack: &Value, predicate: &Value, value: &Value) -> Result<String> {
    if value_type(predicate) == "QUANTITY" {
        let (dimension, n, d) = quantity(pack, value)?;
        canonical(&json!([[dimension.0, dimension.1, dimension.2], n, d]))
    } else {
        canonical(value)
    }
}
fn compare(
    pack: &Value,
    predicate: &Value,
    left: &Value,
    right: &Value,
    operator: &str,
) -> Result<bool> {
    let kind = value_type(predicate);
    if operator == "IS_A" {
        need(kind == "DOMAIN", "specialization requires domain values")?;
        let target = path(right)?;
        let mut todo = vec![path(left)?];
        let mut visited = BTreeSet::new();
        while let Some(current) = todo.pop() {
            if current == target {
                return Ok(true);
            }
            if visited.insert(current.clone()) {
                let node = arr(&pack["domain"])?
                    .iter()
                    .find(|n| path(&n["path"]).ok().as_ref() == Some(&current))
                    .ok_or("unknown domain value")?;
                if let Some(edges) = node.get("specializes").and_then(Value::as_array) {
                    for edge in edges {
                        todo.push(path(&edge["path"])?);
                    }
                }
            }
        }
        return Ok(false);
    }
    need(
        ["EQ", "LT", "LE", "GT", "GE"].contains(&operator),
        "unsupported comparison",
    )?;
    if kind == "QUANTITY" {
        let (ld, ln, ldv) = quantity(pack, left)?;
        let (rd, rn, rdv) = quantity(pack, right)?;
        need(ld == rd, "incompatible quantity dimensions or unit bases")?;
        let (a, b) = (ln * rdv, rn * ldv);
        return Ok(match operator {
            "EQ" => a == b,
            "LT" => a < b,
            "LE" => a <= b,
            "GT" => a > b,
            "GE" => a >= b,
            _ => false,
        });
    }
    if kind == "BOOLEAN" || kind == "DOMAIN" {
        need(operator == "EQ", "unordered semantic value")?;
    }
    let ordering = if kind == "INTEGER" {
        left.as_i64()
            .ok_or("invalid bounded integer value")?
            .cmp(&right.as_i64().ok_or("invalid bounded integer value")?)
    } else {
        canonical(left)?.cmp(&canonical(right)?)
    };
    Ok(match operator {
        "EQ" => ordering.is_eq(),
        "LT" => ordering.is_lt(),
        "LE" => ordering.is_le(),
        "GT" => ordering.is_gt(),
        "GE" => ordering.is_ge(),
        _ => false,
    })
}
fn unit_sources(pack: &Value, value: &Value) -> Result<BTreeSet<String>> {
    if let Some(path_value) = value.get("unit_path") {
        let target = path(path_value)?;
        let node = arr(&pack["domain"])?
            .iter()
            .find(|n| path(&n["path"]).ok().as_ref() == Some(&target))
            .ok_or("unknown quantity unit")?;
        Ok(names(&node["unit"]["source_ids"])?
            .into_iter()
            .map(str::to_owned)
            .collect())
    } else {
        Ok(BTreeSet::new())
    }
}
fn order(steps: &Value) -> Result<Vec<String>> {
    let by_id = index(steps, "steps")?;
    let mut deps = BTreeMap::new();
    for (id, step) in &by_id {
        let d = names(&step["depends_on"])?;
        need(
            d.iter().all(|i| by_id.contains_key(i)) && !d.contains(id),
            "dangling or self dependency",
        )?;
        deps.insert(*id, d);
    }
    let mut remaining: BTreeSet<_> = by_id.keys().copied().collect();
    let mut done = BTreeSet::new();
    let mut out = Vec::new();
    while !remaining.is_empty() {
        let ready: Vec<_> = remaining
            .iter()
            .copied()
            .filter(|i| deps[i].is_subset(&done))
            .collect();
        need(!ready.is_empty(), "cyclic architecture dependencies")?;
        for id in ready {
            remaining.remove(id);
            done.insert(id);
            out.push(id.to_owned());
        }
    }
    Ok(out)
}

fn validate_completion(completion: &Value, step_ids: &BTreeSet<&str>) -> Result<()> {
    fields(
        completion,
        &["required_steps", "exclusive_terminal_groups"],
        &[],
    )?;
    let required = names(&completion["required_steps"])?;
    need(!required.is_empty(), "completion required steps required")?;
    let groups = arr(&completion["exclusive_terminal_groups"])?;
    need(!groups.is_empty(), "completion terminal groups required")?;
    let mut accounted = required;
    for group in groups {
        let alternatives = names(group)?;
        need(
            alternatives.len() >= 2,
            "exclusive terminal group requires alternatives",
        )?;
        need(
            alternatives.is_disjoint(&accounted),
            "completion step appears more than once",
        )?;
        accounted.extend(alternatives);
    }
    need(
        &accounted == step_ids,
        "completion must account for every architecture step",
    )
}

fn architecture_complete(architecture: &Value, results: &[Value]) -> Result<bool> {
    let Some(completion) = architecture.get("completion") else {
        return Ok(results.iter().all(|result| result["status"] == "APPLIED"));
    };
    let mut by_id = BTreeMap::new();
    for result in results {
        by_id.insert(string(&result["step_id"])?, result);
    }
    for step in names(&completion["required_steps"])? {
        if by_id[step]["status"] != "APPLIED" {
            return Ok(false);
        }
    }
    for group in arr(&completion["exclusive_terminal_groups"])? {
        let alternatives = names(group)?;
        let applied: Vec<_> = alternatives
            .iter()
            .filter(|step| by_id[**step]["status"] == "APPLIED")
            .collect();
        if applied.len() != 1 {
            return Ok(false);
        }
        for step in alternatives {
            let result = by_id[step];
            if result["status"] != "APPLIED"
                && (result["status"] != "NOT_APPLICABLE" || !arr(&result["residuals"])?.is_empty())
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// serde_json's default map decoder accepts duplicate fields; this recursive
/// visitor rejects them before any semantic object or result can be produced.
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("finite JSON without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
                Number::from_f64(v)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(Strict(v)) = a.next_element()? {
                    out.push(v);
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    let Strict(v) = a.next_value()?;
                    out.insert(k, v);
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn parse_json(raw: &str) -> Result<Value> {
    let mut d = serde_json::Deserializer::from_str(raw);
    let Strict(v) = Strict::deserialize(&mut d).map_err(|e| format!("invalid JSON: {e}"))?;
    d.end().map_err(|e| format!("invalid JSON: {e}"))?;
    Ok(v)
}
/// All validated contract numbers are integer domain components. Objects use
/// Unicode scalar ordering (BTreeMap) and strings retain their UTF-8 bytes,
/// matching Python sort_keys=True, ensure_ascii=False, separators=(',', ':').
pub fn canonical(v: &Value) -> Result<String> {
    serde_json::to_string(v).map_err(|_| "not canonical JSON".into())
}
fn digest(v: &Value) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(canonical(v)?.as_bytes())))
}

pub fn validate_semantic_pack(p: &Value) -> Result<()> {
    fields(
        p,
        &[
            "schema",
            "id",
            "root_id",
            "domain",
            "semantic_capital",
            "entity_kinds",
            "predicates",
            "sources",
            "judgments",
            "work",
            "architectures",
        ],
        &[],
    )?;
    need(
        p["schema"] == SCHEMA && text(&p["id"]) && text(&p["root_id"]),
        "unsupported schema or identity",
    )?;
    fields(
        &p["semantic_capital"],
        &["coordinate_model", "judgment", "work", "architecture"],
        &[],
    )?;
    need(
        p["semantic_capital"]["coordinate_model"] == COORDINATE_MODEL,
        "unsupported semantic coordinate model",
    )?;
    let judgment_semantics = semantic_index(&p["semantic_capital"]["judgment"], "judgment")?;
    let work_semantics = semantic_index(&p["semantic_capital"]["work"], "work")?;
    let architecture_semantics =
        semantic_index(&p["semantic_capital"]["architecture"], "architecture")?;
    let kinds = names(&p["entity_kinds"])?;
    need(!kinds.is_empty(), "entity kinds required")?;
    let domain = arr(&p["domain"])?;
    need(!domain.is_empty(), "domain root required")?;
    let mut paths = BTreeSet::new();
    for node in domain {
        fields(
            node,
            &["path", "label", "aliases"],
            &["entity_kind", "specializes", "unit"],
        )?;
        need(
            paths.insert(path(&node["path"])?) && text(&node["label"]),
            "duplicate domain position or invalid label",
        )?;
        names(&node["aliases"])?;
    }
    need(
        paths.contains(&Vec::new())
            && paths
                .iter()
                .all(|p| p.is_empty() || paths.contains(&p[..p.len() - 1])),
        "dangling domain branch",
    )?;
    let predicates = index(&p["predicates"], "predicates")?;
    for pred in predicates.values() {
        fields(
            pred,
            &["id", "roles", "origin"],
            &["input_kind", "value_type", "classification", "domain_root"],
        )?;
        need(
            ["BOOLEAN", "INTEGER", "DOMAIN", "QUANTITY"].contains(&value_type(pred)),
            "unsupported predicate value type",
        )?;
        if value_type(pred) == "DOMAIN" {
            need(
                pred.get("classification") == Some(&json!("EXACT"))
                    && pred.get("domain_root").is_some()
                    && paths.contains(&path(&pred["domain_root"])?),
                "domain classification requires a valid semantic root",
            )?;
        } else {
            need(
                pred.get("classification").is_none() && pred.get("domain_root").is_none(),
                "domain root only applies to domain classification",
            )?;
        }
        let input = pred
            .get("input_kind")
            .map(string)
            .transpose()?
            .unwrap_or("SCENARIO_FACT");
        need(
            ["SCENARIO_FACT", "PARAMETER_BINDING", "EVIDENCE"].contains(&input),
            "unsupported input kind",
        )?;
        need(
            ["INPUT", "DERIVED"].contains(&string(&pred["origin"])?),
            "invalid predicate origin",
        )?;
        let roles = obj(&pred["roles"])?;
        need(
            !roles.is_empty()
                && roles
                    .iter()
                    .all(|(k, v)| text(&json!(k)) && v.as_str().is_some_and(|s| kinds.contains(s))),
            "invalid predicate roles",
        )?;
    }
    let sources = index(&p["sources"], "sources")?;
    for s in sources.values() {
        fields(s, &["id", "sha256"], &[])?;
        need(
            s["sha256"].as_str().is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            }),
            "invalid source hash",
        )?;
    }
    let mut entity_kinds = BTreeSet::new();
    for node in domain {
        if let Some(kind) = node.get("entity_kind") {
            let kind = string(kind)?;
            need(
                kinds.contains(kind) && entity_kinds.insert(kind),
                "invalid or duplicate domain entity kind",
            )?;
        }
        let mut seen = BTreeSet::new();
        if let Some(edges) = node.get("specializes") {
            need(edges.is_array(), "invalid specialization list")?;
            for edge in arr(edges)? {
                fields(edge, &["path", "source_ids"], &[])?;
                let target = path(&edge["path"])?;
                need(
                    paths.contains(&target)
                        && target != path(&node["path"])?
                        && seen.insert(target),
                    "invalid specialization edge",
                )?;
                source_links(&edge["source_ids"], &sources)?;
            }
        }
        if let Some(unit) = node.get("unit") {
            fields(
                unit,
                &[
                    "dimension_path",
                    "numerator",
                    "denominator",
                    "source_ids",
                    "basis",
                ],
                &["calendar_id"],
            )?;
            let dimension = path(&unit["dimension_path"])?;
            need(
                paths.contains(&dimension)
                    && !domain.iter().any(|n| {
                        path(&n["path"]).ok().as_ref() == Some(&dimension)
                            && n.get("unit").is_some()
                    }),
                "invalid unit dimension",
            )?;
            need(
                bounded_integer(&unit["numerator"], true)
                    && bounded_integer(&unit["denominator"], true),
                "invalid exact unit scale",
            )?;
            let basis = string(&unit["basis"])?;
            need(
                ["FIXED_RATIO", "CALENDAR_DAY", "BUSINESS_DAY"].contains(&basis),
                "unsupported unit basis",
            )?;
            if basis == "FIXED_RATIO" {
                need(
                    unit.get("calendar_id").is_none(),
                    "fixed-ratio unit cannot assert a calendar",
                )?;
            } else {
                need(
                    unit.get("calendar_id").is_some_and(text)
                        && unit["numerator"] == 1
                        && unit["denominator"] == 1,
                    "calendar units require an explicit calendar identity and no fixed-second conversion",
                )?;
            }
            source_links(&unit["source_ids"], &sources)?;
        }
    }
    fn reaches(
        domain: &[Value],
        from: &[u64],
        target: &[u64],
        seen: &mut BTreeSet<Vec<u64>>,
    ) -> Result<bool> {
        if from == target {
            return Ok(true);
        }
        if !seen.insert(from.to_vec()) {
            return Ok(false);
        }
        let node = domain
            .iter()
            .find(|n| path(&n["path"]).ok().as_deref() == Some(from))
            .ok_or("unknown domain value")?;
        if let Some(edges) = node.get("specializes").and_then(Value::as_array) {
            for edge in edges {
                if reaches(domain, &path(&edge["path"])?, target, seen)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    for node in domain {
        let here = path(&node["path"])?;
        if let Some(edges) = node.get("specializes").and_then(Value::as_array) {
            for edge in edges {
                let target = path(&edge["path"])?;
                need(
                    !reaches(domain, &target, &here, &mut BTreeSet::new())?,
                    "cyclic domain specialization",
                )?;
            }
        }
    }
    let judgments = index(&p["judgments"], "judgments")?;
    for j in judgments.values() {
        fields(
            j,
            &[
                "id",
                "semantic_coordinate",
                "bindings",
                "premises",
                "output",
                "source_ids",
                "residual",
            ],
            &["overrides"],
        )?;
        need(
            judgment_semantics.contains(&semantic_key(&j["semantic_coordinate"], "judgment")?),
            "unknown judgment semantic definition",
        )?;
        let bindings = obj(&j["bindings"])?;
        need(
            !bindings.is_empty()
                && bindings
                    .iter()
                    .all(|(k, v)| text(&json!(k)) && v.as_str().is_some_and(|s| kinds.contains(s))),
            "invalid required bindings",
        )?;
        let premises = arr(&j["premises"])?;
        need(!premises.is_empty(), "warrant premises required")?;
        need(text(&j["residual"]), "residual explanation required")?;
        let source_ids = names(&j["source_ids"])?;
        need(
            !source_ids.is_empty() && source_ids.iter().all(|s| sources.contains_key(s)),
            "unsupported judgment source link",
        )?;
        for (clause, output) in premises
            .iter()
            .map(|v| (v, false))
            .chain(std::iter::once((&j["output"], true)))
        {
            fields(
                clause,
                &["predicate", "arguments", "value"],
                if output {
                    &["semantic_kind"]
                } else {
                    &["operator"]
                },
            )?;
            let pred = predicates
                .get(string(&clause["predicate"])?)
                .ok_or("unsupported predicate or truth value")?;
            validate_value(p, pred, &clause["value"], false)?;
            if !output {
                let operator = clause
                    .get("operator")
                    .and_then(Value::as_str)
                    .unwrap_or("EQ");
                need(
                    operator == "EQ"
                        || (operator == "IS_A" && value_type(pred) == "DOMAIN")
                        || (["LT", "LE", "GT", "GE"].contains(&operator)
                            && ["INTEGER", "QUANTITY"].contains(&value_type(pred))),
                    "unsupported premise operator",
                )?;
            }
            let args = obj(&clause["arguments"])?;
            let roles = obj(&pred["roles"])?;
            need(args.keys().eq(roles.keys()), "predicate arguments mismatch")?;
            need(
                args.iter().all(|(k, v)| {
                    v.as_str()
                        .and_then(|s| bindings.get(s))
                        .is_some_and(|b| b == &roles[k])
                }),
                "unbound or mistyped warrant role",
            )?;
        }
        need(
            predicates[string(&j["output"]["predicate"])?]["origin"] == "DERIVED",
            "output must use derived predicate",
        )?;
        need(
            ["SOURCE_BOUND_REQUIREMENT", "SCENARIO_DERIVATION"]
                .contains(&string(&j["output"]["semantic_kind"])?),
            "unsupported output authority/type",
        )?;
        need(
            premises
                .iter()
                .all(|c| c["predicate"] != j["output"]["predicate"]),
            "circular warrant",
        )?;
    }
    for j in judgments.values() {
        if let Some(overrides) = j.get("overrides") {
            let mut targets = BTreeSet::new();
            for edge in arr(overrides)? {
                fields(edge, &["judgment_id", "source_ids"], &[])?;
                need(
                    text(&edge["judgment_id"]) && targets.insert(string(&edge["judgment_id"])?),
                    "invalid judgment override",
                )?;
                source_links(&edge["source_ids"], &sources)?;
            }
            let own_id = string(&j["id"])?;
            need(
                !targets.is_empty()
                    && targets
                        .iter()
                        .all(|target| judgments.contains_key(target) && *target != own_id),
                "invalid judgment override",
            )?;
            for target in targets {
                let target_judgment = judgments[target];
                need(
                    j["bindings"] == target_judgment["bindings"]
                        && j["output"]["predicate"] == target_judgment["output"]["predicate"]
                        && j["output"]["arguments"] == target_judgment["output"]["arguments"],
                    "incompatible judgment override",
                )?;
            }
        }
    }
    let mut remaining: BTreeSet<&str> = judgments.keys().copied().collect();
    let mut done = BTreeSet::new();
    while !remaining.is_empty() {
        let ready: Vec<&str> = remaining
            .iter()
            .copied()
            .filter(|id| {
                judgments[*id]
                    .get("overrides")
                    .and_then(Value::as_array)
                    .is_none_or(|edges| {
                        edges.iter().all(|edge| {
                            edge["judgment_id"]
                                .as_str()
                                .is_some_and(|target| done.contains(target))
                        })
                    })
            })
            .collect();
        need(!ready.is_empty(), "cyclic judgment overrides")?;
        for id in ready {
            remaining.remove(id);
            done.insert(id);
        }
    }
    let work = index(&p["work"], "work")?;
    for w in work.values() {
        if w["operation"] == "RESOLVE_JUDGMENTS" {
            fields(
                w,
                &[
                    "id",
                    "semantic_coordinate",
                    "operation",
                    "judgments",
                    "domain_path",
                ],
                &[],
            )?;
            need(
                work_semantics.contains(&semantic_key(&w["semantic_coordinate"], "work")?),
                "unknown work semantic definition",
            )?;
            let selected = names(&w["judgments"])?;
            need(
                !selected.is_empty()
                    && selected.iter().all(|j| judgments.contains_key(j))
                    && paths.contains(&path(&w["domain_path"])?),
                "unsupported work judgment/domain link",
            )?;
            let first = judgments[*selected.first().unwrap()];
            need(
                selected.iter().all(|j| {
                    judgments[*j]["bindings"] == first["bindings"]
                        && judgments[*j]["output"]["predicate"] == first["output"]["predicate"]
                        && judgments[*j]["output"]["arguments"] == first["output"]["arguments"]
                }),
                "incompatible resolution candidates",
            )?;
            for selected_judgment in &selected {
                if let Some(overrides) = judgments[*selected_judgment].get("overrides") {
                    for edge in arr(overrides)? {
                        need(
                            selected.contains(string(&edge["judgment_id"])?),
                            "incomplete override candidate closure",
                        )?;
                    }
                }
                for candidate in judgments.values() {
                    if candidate
                        .get("overrides")
                        .and_then(Value::as_array)
                        .is_some_and(|a| a.iter().any(|x| x["judgment_id"] == *selected_judgment))
                    {
                        need(
                            selected.contains(string(&candidate["id"])?),
                            "incomplete override candidate closure",
                        )?;
                    }
                }
            }
            continue;
        }
        if w["operation"] == "COMPARE_VALUES" {
            fields(
                w,
                &[
                    "id",
                    "semantic_coordinate",
                    "operation",
                    "bindings",
                    "left",
                    "right",
                    "operator",
                    "output",
                    "domain_path",
                ],
                &[],
            )?;
            need(
                work_semantics.contains(&semantic_key(&w["semantic_coordinate"], "work")?),
                "unknown work semantic definition",
            )?;
            let bindings = obj(&w["bindings"])?;
            need(
                !bindings.is_empty()
                    && bindings.iter().all(|(role, kind)| {
                        text(&json!(role)) && kind.as_str().is_some_and(|k| kinds.contains(k))
                    }),
                "invalid comparison bindings",
            )?;
            let selectors = [&w["left"], &w["right"], &w["output"]];
            let mut selected_predicates = Vec::new();
            for selector in selectors {
                fields(selector, &["predicate", "arguments"], &[])?;
                let predicate = predicates
                    .get(string(&selector["predicate"])?)
                    .ok_or("unsupported comparison predicate")?;
                let arguments = obj(&selector["arguments"])?;
                let roles = obj(&predicate["roles"])?;
                need(
                    arguments.keys().eq(roles.keys())
                        && arguments.iter().all(|(role, binding)| {
                            binding
                                .as_str()
                                .and_then(|b| bindings.get(b))
                                .is_some_and(|kind| kind == &roles[role])
                        }),
                    "comparison predicate arguments mismatch",
                )?;
                selected_predicates.push(*predicate);
            }
            let left = selected_predicates[0];
            let right = selected_predicates[1];
            let output = selected_predicates[2];
            need(
                value_type(left) == value_type(right)
                    && output["origin"] == "DERIVED"
                    && string(&w["output"]["predicate"])? != string(&w["left"]["predicate"])?
                    && paths.contains(&path(&w["domain_path"])?),
                "invalid comparison work",
            )?;
            let operator = string(&w["operator"])?;
            need(
                ["EQ", "LT", "LE", "GT", "GE"].contains(&operator)
                    && (operator == "EQ" || ["INTEGER", "QUANTITY"].contains(&value_type(left))),
                "unsupported comparison operator",
            )?;
            continue;
        }
        fields(
            w,
            &[
                "id",
                "semantic_coordinate",
                "operation",
                "judgment",
                "domain_path",
            ],
            &[],
        )?;
        need(
            work_semantics.contains(&semantic_key(&w["semantic_coordinate"], "work")?),
            "unknown work semantic definition",
        )?;
        need(
            w["operation"] == "APPLY_JUDGMENT",
            "unsupported work operation",
        )?;
        need(
            judgments.contains_key(string(&w["judgment"])?)
                && paths.contains(&path(&w["domain_path"])?),
            "unsupported work judgment/domain link",
        )?;
    }
    let architectures = index(&p["architectures"], "architectures")?;
    for a in architectures.values() {
        fields(a, &["id", "semantic_coordinate", "steps"], &["completion"])?;
        need(
            architecture_semantics
                .contains(&semantic_key(&a["semantic_coordinate"], "architecture")?),
            "unknown architecture semantic definition",
        )?;
        let steps = arr(&a["steps"])?;
        need(!steps.is_empty(), "architecture steps required")?;
        for step in steps {
            fields(step, &["id", "work", "depends_on"], &[])?;
            need(
                work.contains_key(string(&step["work"])?),
                "unsupported architecture work link",
            )?;
        }
        order(&a["steps"])?;
        if let Some(completion) = a.get("completion") {
            let step_ids: BTreeSet<_> = index(&a["steps"], "steps")?.keys().copied().collect();
            validate_completion(completion, &step_ids)?;
        }
    }
    Ok(())
}

fn validate_request(p: &Value, r: &Value) -> Result<()> {
    fields(r, &["entities", "facts", "bindings"], &["unknowns"])?;
    let entities = obj(&r["entities"])?;
    let kinds = names(&p["entity_kinds"])?;
    need(
        entities
            .iter()
            .all(|(k, v)| text(&json!(k)) && v.as_str().is_some_and(|s| kinds.contains(s))),
        "invalid entity identities/kinds",
    )?;
    obj(&r["bindings"])?;
    let predicates = index(&p["predicates"], "predicates")?;
    let facts = index(&r["facts"], "facts")?;
    for fact in facts.values() {
        fields(fact, &["id", "predicate", "arguments", "value"], &[])?;
        let pred = predicates
            .get(string(&fact["predicate"])?)
            .ok_or("unsupported or forged derived input fact")?;
        need(
            !string(&fact["id"])?.starts_with("derived:") && pred["origin"] == "INPUT",
            "unsupported or forged derived input fact",
        )?;
        validate_value(p, pred, &fact["value"], true)?;
        let roles = obj(&pred["roles"])?;
        let args = obj(&fact["arguments"])?;
        need(args.keys().eq(roles.keys()), "fact arguments mismatch")?;
        need(
            args.iter().all(|(k, v)| {
                v.as_str()
                    .and_then(|s| entities.get(s))
                    .is_some_and(|kind| kind == &roles[k])
            }),
            "dangling or mistyped fact entity",
        )?;
    }
    if let Some(unknowns) = r.get("unknowns") {
        arr(unknowns)?;
        let mut seen = BTreeSet::new();
        for unknown in arr(unknowns)? {
            if unknown.is_string() {
                let unknown = string(unknown)?;
                need(text(&json!(unknown)), "invalid unscoped unknown")?;
                need(
                    seen.insert(format!("text\u{0}{unknown}")),
                    "duplicate declared unknown",
                )?;
            } else {
                fields(unknown, &["id", "text", "predicate", "arguments"], &[])?;
                need(
                    text(&unknown["id"]) && text(&unknown["text"]),
                    "invalid scoped unknown identity/text",
                )?;
                let predicate = predicates
                    .get(string(&unknown["predicate"])?)
                    .ok_or("unknown scope must name a declared input predicate")?;
                need(
                    predicate["origin"] == "INPUT",
                    "unknown scope must name a declared input predicate",
                )?;
                let roles = obj(&predicate["roles"])?;
                let arguments = obj(&unknown["arguments"])?;
                need(
                    arguments.keys().eq(roles.keys())
                        && arguments.iter().all(|(role, entity)| {
                            entity
                                .as_str()
                                .and_then(|id| entities.get(id))
                                .is_some_and(|kind| kind == &roles[role])
                        }),
                    "fact arguments mismatch",
                )?;
                need(
                    seen.insert(format!("id\u{0}{}", string(&unknown["id"])?)),
                    "duplicate declared unknown",
                )?;
            }
        }
    }
    Ok(())
}

fn unknown_residuals(
    r: &Value,
    selectors: &[&Value],
    bound: &Map<String, Value>,
    include_unscoped: bool,
) -> Result<Vec<Value>> {
    let mut slots = Vec::new();
    for selector in selectors {
        let arguments = obj(&selector["arguments"])?;
        if arguments.values().all(|binding| {
            binding
                .as_str()
                .is_some_and(|role| bound.contains_key(role))
        }) {
            let resolved = Value::Object(
                arguments
                    .iter()
                    .map(|(role, binding)| {
                        Ok((
                            role.clone(),
                            bound[binding.as_str().ok_or("unbound selector role")?].clone(),
                        ))
                    })
                    .collect::<Result<Map<String, Value>>>()?,
            );
            slots.push((string(&selector["predicate"])?.to_owned(), resolved));
        }
    }
    let mut residuals = Vec::new();
    for unknown in arr(r.get("unknowns").unwrap_or(&json!([])))? {
        if let Some(text) = unknown.as_str() {
            if include_unscoped {
                residuals.push(json!({"reason":"USER_DECLARED_UNKNOWN","text":text}));
            }
        } else if slots.iter().any(|(predicate, arguments)| {
            unknown["predicate"].as_str() == Some(predicate.as_str())
                && unknown["arguments"] == *arguments
        }) {
            residuals.push(json!({
                "reason":"USER_DECLARED_UNKNOWN",
                "unknown_id":unknown["id"],
                "text":unknown["text"],
                "predicate":unknown["predicate"],
                "arguments":unknown["arguments"],
            }));
        }
    }
    Ok(residuals)
}

fn specialization_sources(
    pack: &Value,
    actual: &[u64],
    expected: &[u64],
) -> Result<BTreeSet<String>> {
    fn visit(
        pack: &Value,
        current: &[u64],
        expected: &[u64],
        seen: &mut BTreeSet<Vec<u64>>,
    ) -> Result<Option<BTreeSet<String>>> {
        if current == expected {
            return Ok(Some(BTreeSet::new()));
        }
        if !seen.insert(current.to_vec()) {
            return Ok(None);
        }
        let node = arr(&pack["domain"])?
            .iter()
            .find(|n| path(&n["path"]).ok().as_deref() == Some(current))
            .ok_or("unknown domain value")?;
        if let Some(edges) = node.get("specializes").and_then(Value::as_array) {
            for edge in edges {
                let next = path(&edge["path"])?;
                if let Some(mut sources) = visit(pack, &next, expected, seen)? {
                    sources.extend(names(&edge["source_ids"])?.into_iter().map(str::to_owned));
                    return Ok(Some(sources));
                }
            }
        }
        Ok(None)
    }
    Ok(visit(pack, actual, expected, &mut BTreeSet::new())?.unwrap_or_default())
}

fn evaluate(
    p: &Value,
    judgment_id: &str,
    r: &Value,
    binding: &Value,
    facts: &[Value],
) -> Result<Value> {
    let judgments = index(&p["judgments"], "judgments")?;
    let j = judgments.get(judgment_id).ok_or("unknown judgment")?;
    let input_bindings = obj(binding)?;
    let required = obj(&j["bindings"])?;
    need(
        input_bindings.keys().all(|k| required.contains_key(k)),
        "foreign required binding",
    )?;
    let entities = obj(&r["entities"])?;
    let mut residuals = Vec::new();
    let mut bound = Map::new();
    for (role, kind) in required {
        let empty = json!([]);
        let candidates = names(input_bindings.get(role).unwrap_or(&empty))?;
        need(
            candidates.iter().all(|s| entities.get(*s) == Some(kind)),
            "invalid binding candidate",
        )?;
        if candidates.len() != 1 {
            residuals.push(json!({"reason":if candidates.is_empty() {"MISSING_BINDING"} else {"AMBIGUOUS_BINDING"}, "binding":role,"candidates":candidates}));
        } else {
            bound.insert(role.clone(), json!(candidates.first().unwrap()));
        }
    }
    let selectors: Vec<&Value> = arr(&j["premises"])?.iter().collect();
    residuals.extend(unknown_residuals(r, &selectors, &bound, true)?);
    let mut support: BTreeSet<String> = BTreeSet::new();
    let mut semantic_sources: BTreeSet<String> = BTreeSet::new();
    let mut opposed = false;
    if bound.len() == required.len() {
        let predicates = index(&p["predicates"], "predicates")?;
        for (i, clause) in arr(&j["premises"])?.iter().enumerate() {
            let args: Map<String, Value> = obj(&clause["arguments"])?
                .iter()
                .map(|(k, v)| (k.clone(), bound[v.as_str().unwrap()].clone()))
                .collect();
            let args = Value::Object(args);
            let matched: Vec<_> = facts
                .iter()
                .filter(|f| f["predicate"] == clause["predicate"] && f["arguments"] == args)
                .collect();
            let pred = predicates[clause["predicate"].as_str().unwrap()];
            let values: BTreeSet<_> = matched
                .iter()
                .filter(|f| !f["value"].is_null())
                .map(|f| value_key(p, pred, &f["value"]))
                .collect::<Result<BTreeSet<_>>>()?;
            if values.len() > 1 {
                let ids: BTreeSet<_> = matched.iter().map(|f| f["id"].as_str().unwrap()).collect();
                residuals.push(json!({"reason":"CONFLICTING_FACTS","premise":i,"predicate":clause["predicate"],"arguments":args,"fact_ids":ids}));
            } else if matched.iter().any(|f| f["value"].is_null()) {
                let ids: BTreeSet<_> = matched.iter().map(|f| f["id"].as_str().unwrap()).collect();
                residuals.push(json!({"reason":"UNKNOWN_EVIDENCE","premise":i,"predicate":clause["predicate"],"arguments":args,"fact_ids":ids}));
            } else if values.is_empty() {
                let pred = predicates[clause["predicate"].as_str().unwrap()];
                let reason = match pred
                    .get("input_kind")
                    .and_then(Value::as_str)
                    .unwrap_or("SCENARIO_FACT")
                {
                    "PARAMETER_BINDING" => "MISSING_PARAMETER",
                    "EVIDENCE" => "MISSING_EVIDENCE",
                    _ => "MISSING_FACT",
                };
                residuals.push(json!({"reason":reason,"premise":i,"predicate":clause["predicate"],"arguments":args}));
            } else if !compare(
                p,
                pred,
                &matched.iter().find(|f| !f["value"].is_null()).unwrap()["value"],
                &clause["value"],
                clause
                    .get("operator")
                    .and_then(Value::as_str)
                    .unwrap_or("EQ"),
            )? {
                opposed = true;
            } else {
                for f in &matched {
                    support.insert(f["id"].as_str().unwrap().to_owned());
                    if let Some(ids) = f.get("source_ids") {
                        semantic_sources.extend(names(ids)?.into_iter().map(str::to_owned));
                    }
                    semantic_sources.extend(unit_sources(p, &f["value"])?);
                }
                if clause.get("operator").and_then(Value::as_str) == Some("IS_A") {
                    semantic_sources.extend(specialization_sources(
                        p,
                        &path(&matched.iter().find(|f| !f["value"].is_null()).unwrap()["value"])?,
                        &path(&clause["value"])?,
                    )?);
                }
                semantic_sources.extend(unit_sources(p, &clause["value"])?);
            }
        }
    }
    let status = if !residuals.is_empty() {
        "UNRESOLVED"
    } else if opposed {
        "NOT_APPLICABLE"
    } else {
        "APPLIED"
    };
    let output = if status == "APPLIED" {
        let clause = &j["output"];
        let args: Map<String, Value> = obj(&clause["arguments"])?
            .iter()
            .map(|(k, v)| (k.clone(), bound[v.as_str().unwrap()].clone()))
            .collect();
        let mut output_sources: BTreeSet<String> = names(&j["source_ids"])?
            .into_iter()
            .map(str::to_owned)
            .collect();
        output_sources.extend(semantic_sources);
        json!({"id":format!("derived:{}",digest(&json!({"judgment":judgment_id,"bindings":bound,"support":support}))?),
            "predicate":clause["predicate"], "arguments":args, "value":clause["value"],
            "type":"DETERMINISTIC_DERIVATION", "semantic_kind":clause["semantic_kind"],
            "support":support, "source_ids":output_sources})
    } else {
        Value::Null
    };
    let explanation = if residuals.is_empty() {
        Value::Null
    } else {
        j["residual"].clone()
    };
    for residual in &mut residuals {
        residual["type"] = json!("UNRESOLVED");
    }
    let sources: Vec<_> = arr(&p["sources"])?
        .iter()
        .filter(|s| arr(&j["source_ids"]).unwrap().contains(&s["id"]))
        .map(|s| {
            let mut source = s.clone();
            source["type"] = json!("SOURCE_BOUND");
            source
        })
        .collect();
    Ok(
        json!({"judgment_id":judgment_id, "judgment_coordinate":j["semantic_coordinate"], "status":status, "bindings":bound,"output":output,
        "residuals":residuals,"residual_explanation":explanation,"source_requirements":sources,
        "claim_ceiling":CEILING,"compliance_verdict":null,"responsibility_determination":null,"external_effects":[]}),
    )
}

fn work_binding<'a>(work: &'a Value, judgments: &Index<'a>) -> Result<&'a Value> {
    if work["operation"] == "COMPARE_VALUES" {
        return Ok(&work["bindings"]);
    }
    if work["operation"] == "RESOLVE_JUDGMENTS" {
        return Ok(&judgments[*names(&work["judgments"])?.first().unwrap()]["bindings"]);
    }
    Ok(&judgments[string(&work["judgment"])?]["bindings"])
}

fn execute_work(
    p: &Value,
    work: &Value,
    r: &Value,
    binding: &Value,
    facts: &[Value],
) -> Result<Value> {
    let judgments = index(&p["judgments"], "judgments")?;
    if work["operation"] == "APPLY_JUDGMENT" {
        return evaluate(p, string(&work["judgment"])?, r, binding, facts);
    }
    if work["operation"] == "RESOLVE_JUDGMENTS" {
        let selected = names(&work["judgments"])?;
        let bindings = obj(binding)?;
        let entities = obj(&r["entities"])?;
        let required = obj(work_binding(work, &judgments)?)?;
        need(
            bindings.keys().all(|key| required.contains_key(key)),
            "foreign required binding",
        )?;
        let mut bound = Map::new();
        let mut residuals = Vec::new();
        for (role, kind) in required {
            let empty = json!([]);
            let candidates = names(bindings.get(role).unwrap_or(&empty))?;
            need(
                candidates.iter().all(|id| entities.get(*id) == Some(kind)),
                "invalid binding candidate",
            )?;
            if candidates.len() == 1 {
                bound.insert(role.clone(), json!(candidates.first().unwrap()));
            } else {
                residuals.push(json!({"type":"UNRESOLVED","reason":if candidates.is_empty(){"MISSING_BINDING"}else{"AMBIGUOUS_BINDING"},"binding":role,"candidates":candidates}));
            }
        }
        for unknown in arr(r.get("unknowns").unwrap_or(&json!([])))? {
            if let Some(text) = unknown.as_str() {
                residuals.push(
                    json!({"type":"UNRESOLVED","reason":"USER_DECLARED_UNKNOWN","text":text}),
                );
            }
        }
        let mut candidates = BTreeMap::new();
        let mut applicable = BTreeSet::new();
        for judgment_id in &selected {
            let result = evaluate(p, judgment_id, r, binding, facts)?;
            if result["status"] == "APPLIED" {
                applicable.insert((*judgment_id).to_owned());
            }
            if result["status"] == "UNRESOLVED" {
                residuals.push(json!({"type":"UNRESOLVED","reason":"CANDIDATE_APPLICABILITY_UNRESOLVED","judgment_id":judgment_id,"details":result["residuals"]}));
            }
            candidates.insert((*judgment_id).to_owned(), result);
        }
        let mut edges = Vec::new();
        let mut suppressed = BTreeSet::new();
        for source in &applicable {
            if let Some(overrides) = judgments[source.as_str()].get("overrides") {
                for override_edge in arr(overrides)? {
                    let target = string(&override_edge["judgment_id"])?;
                    if applicable.contains(target) {
                        suppressed.insert(target.to_owned());
                        edges.push(json!({"from_judgment":source,"to_judgment":target,"relation":"OVERRIDES","source_ids":override_edge["source_ids"]}));
                    }
                }
            }
        }
        edges.sort_by_key(|edge| canonical(edge).unwrap());
        let winners: BTreeSet<_> = applicable.difference(&suppressed).cloned().collect();
        if residuals.is_empty() && winners.len() != 1 {
            residuals.push(json!({"type":"UNRESOLVED","reason":if winners.is_empty() {"NO_APPLICABLE_JUDGMENT"} else {"CONFLICTING_JUDGMENTS"},"candidates":winners}));
        }
        let candidate_results: Vec<Value> = candidates.values().cloned().collect();
        let selected_judgment = if residuals.is_empty() {
            Value::String(winners.first().unwrap().clone())
        } else {
            Value::Null
        };
        let output = if residuals.is_empty() {
            let winner = winners.first().unwrap();
            let mut output = candidates[winner]["output"].clone();
            let mut sources: BTreeSet<String> = names(&output["source_ids"])?
                .into_iter()
                .map(str::to_owned)
                .collect();
            for edge in &edges {
                sources.extend(names(&edge["source_ids"])?.into_iter().map(str::to_owned));
            }
            output["source_ids"] = json!(sources);
            output["id"] = json!(format!(
                "derived:{}",
                digest(
                    &json!({"work":work,"bindings":bound,"candidate_results":candidate_results,"override_edges":edges})
                )?
            ));
            output
        } else {
            Value::Null
        };
        return Ok(
            json!({"work_id":work["id"],"status":if residuals.is_empty(){"APPLIED"}else{"UNRESOLVED"},"bindings":bound,"output":output,"residuals":residuals,"claim_ceiling":CEILING,"compliance_verdict":null,"responsibility_determination":null,"external_effects":[],"selection_trace":{"candidates":candidate_results,"override_edges":edges,"selected_judgment":selected_judgment}}),
        );
    }
    let bindings = obj(binding)?;
    let entities = obj(&r["entities"])?;
    let required = obj(&work["bindings"])?;
    need(
        bindings.keys().all(|k| required.contains_key(k)),
        "foreign required binding",
    )?;
    let mut bound = Map::new();
    let mut residuals = Vec::new();
    for (role, kind) in required {
        let empty = json!([]);
        let candidates = names(bindings.get(role).unwrap_or(&empty))?;
        need(
            candidates.iter().all(|id| entities.get(*id) == Some(kind)),
            "invalid binding candidate",
        )?;
        if candidates.len() == 1 {
            bound.insert(role.clone(), json!(candidates.first().unwrap()));
        } else {
            residuals.push(json!({"type":"UNRESOLVED","reason":if candidates.is_empty(){"MISSING_BINDING"}else{"AMBIGUOUS_BINDING"},"binding":role,"candidates":candidates}));
        }
    }
    for unknown in arr(r.get("unknowns").unwrap_or(&json!([])))? {
        if let Some(text) = unknown.as_str() {
            residuals
                .push(json!({"type":"UNRESOLVED","reason":"USER_DECLARED_UNKNOWN","text":text}));
        }
    }
    let predicates = index(&p["predicates"], "predicates")?;
    let mut values = Map::new();
    let mut support = BTreeSet::new();
    let mut source_ids = BTreeSet::new();
    if residuals.is_empty() {
        for mut residual in unknown_residuals(r, &[&work["left"], &work["right"]], &bound, false)? {
            residual["type"] = json!("UNRESOLVED");
            residuals.push(residual);
        }
        for operand in ["left", "right"] {
            let selector = &work[operand];
            let predicate = predicates[string(&selector["predicate"])?];
            let args: Map<String, Value> = obj(&selector["arguments"])?
                .iter()
                .map(|(role, binding)| (role.clone(), bound[binding.as_str().unwrap()].clone()))
                .collect();
            let args = Value::Object(args);
            let matched: Vec<_> = facts
                .iter()
                .filter(|fact| {
                    fact["predicate"] == selector["predicate"] && fact["arguments"] == args
                })
                .collect();
            let keys = matched
                .iter()
                .filter(|fact| !fact["value"].is_null())
                .map(|fact| value_key(p, predicate, &fact["value"]))
                .collect::<Result<BTreeSet<_>>>()?;
            let fact_ids: BTreeSet<_> = matched
                .iter()
                .filter_map(|fact| fact["id"].as_str())
                .collect();
            if keys.len() > 1 {
                residuals.push(json!({"type":"UNRESOLVED","reason":"CONFLICTING_FACTS","operand":operand,"predicate":selector["predicate"],"arguments":args,"fact_ids":fact_ids}));
                continue;
            }
            if matched.iter().any(|fact| fact["value"].is_null()) {
                residuals.push(json!({"type":"UNRESOLVED","reason":"UNKNOWN_EVIDENCE","operand":operand,"predicate":selector["predicate"],"arguments":args,"fact_ids":fact_ids}));
                continue;
            }
            if matched.is_empty() {
                let reason = match predicate
                    .get("input_kind")
                    .and_then(Value::as_str)
                    .unwrap_or("SCENARIO_FACT")
                {
                    "PARAMETER_BINDING" => "MISSING_PARAMETER",
                    "EVIDENCE" => "MISSING_EVIDENCE",
                    _ => "MISSING_FACT",
                };
                residuals.push(json!({"type":"UNRESOLVED","reason":reason,"operand":operand,"predicate":selector["predicate"],"arguments":args,"fact_ids":fact_ids}));
                continue;
            }
            if predicate["origin"] == "DERIVED" && matched.len() != 1 {
                residuals.push(json!({"type":"UNRESOLVED","reason":"AMBIGUOUS_DERIVED_RESULT","operand":operand,"predicate":selector["predicate"],"arguments":args,"fact_ids":fact_ids}));
                continue;
            }
            let fact = matched[0];
            values.insert(operand.to_owned(), fact["value"].clone());
            for fact in matched {
                support.insert(fact["id"].as_str().unwrap().to_owned());
                if let Some(ids) = fact.get("source_ids") {
                    source_ids.extend(names(ids)?.into_iter().map(str::to_owned));
                }
                source_ids.extend(unit_sources(p, &fact["value"])?);
            }
        }
    }
    if !residuals.is_empty() {
        return Ok(
            json!({"work_id":work["id"],"status":"UNRESOLVED","bindings":bound,"output":null,"residuals":residuals,"claim_ceiling":CEILING,"compliance_verdict":null,"responsibility_determination":null,"external_effects":[]}),
        );
    }
    let left_predicate = predicates[string(&work["left"]["predicate"])?];
    let output_selector = &work["output"];
    let args: Map<String, Value> = obj(&output_selector["arguments"])?
        .iter()
        .map(|(role, binding)| (role.clone(), bound[binding.as_str().unwrap()].clone()))
        .collect();
    let value = compare(
        p,
        left_predicate,
        &values["left"],
        &values["right"],
        string(&work["operator"])?,
    )?;
    let output = json!({"id":format!("derived:{}",digest(&json!({"work":work,"bindings":bound,"values":values,"support":support}))?),"predicate":output_selector["predicate"],"arguments":args,"value":value,"type":"DETERMINISTIC_DERIVATION","semantic_kind":"SCENARIO_DERIVATION","support":support,"source_ids":source_ids});
    Ok(
        json!({"work_id":work["id"],"status":"APPLIED","bindings":bound,"output":output,"residuals":[],"claim_ceiling":CEILING,"compliance_verdict":null,"responsibility_determination":null,"external_effects":[],"comparison":{"operator":work["operator"],"left":values["left"],"right":values["right"],"value":value}}),
    )
}

/// Execute in sorted topological waves. A step reads original facts and outputs from its ancestors.
pub fn execute_architecture(p: &Value, architecture_id: &str, r: &Value) -> Result<Value> {
    validate_semantic_pack(p)?;
    validate_request(p, r)?;
    let architectures = index(&p["architectures"], "architectures")?;
    let architecture = architectures
        .get(architecture_id)
        .ok_or("unknown architecture")?;
    let steps = index(&architecture["steps"], "steps")?;
    let bindings = obj(&r["bindings"])?;
    need(
        bindings.keys().all(|s| steps.contains_key(s.as_str())),
        "foreign architecture step binding",
    )?;
    let work = index(&p["work"], "work")?;
    // Validate supplied bindings before dependency blocking. A malformed child
    // cannot be smuggled through an unresolved parent and into request identity.
    let judgments = index(&p["judgments"], "judgments")?;
    let entities = obj(&r["entities"])?;
    for (sid, binding) in bindings {
        let step = steps[sid.as_str()];
        let required_work = work[string(&step["work"])?];
        let required_bindings = work_binding(required_work, &judgments)?;
        need(binding.is_object(), "invalid step bindings")?;
        let supplied = obj(binding)?;
        let required = obj(required_bindings)?;
        need(
            supplied.keys().all(|k| required.contains_key(k)),
            "foreign required binding",
        )?;
        for (role, values) in supplied {
            let candidates = names(values)?;
            need(
                candidates
                    .iter()
                    .all(|i| entities.get(*i) == Some(&required[role])),
                "invalid binding candidate",
            )?;
        }
    }
    let mut results: BTreeMap<String, Value> = BTreeMap::new();
    let mut ancestors: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let ordered = order(&architecture["steps"])?;
    for sid in &ordered {
        let step = steps[sid.as_str()];
        let dependencies = names(&step["depends_on"])?;
        let mut parents: BTreeSet<String> = dependencies.iter().map(|s| (*s).to_owned()).collect();
        for d in &dependencies {
            parents.extend(ancestors[*d].iter().cloned());
        }
        let blocked: Vec<_> = dependencies
            .iter()
            .filter(|i| results[**i]["status"] != "APPLIED")
            .copied()
            .collect();
        let mut result = if !blocked.is_empty() {
            json!({"status":"BLOCKED","output":null,"residuals":[{"type":"UNRESOLVED","reason":"DEPENDENCY_UNRESOLVED_OR_NOT_APPLICABLE","steps":blocked}]})
        } else {
            let mut facts = arr(&r["facts"])?.clone();
            for ancestor in &parents {
                let o = &results[ancestor]["output"];
                if !o.is_null() {
                    facts.push(o.clone());
                }
            }
            let empty = json!({});
            let binding = bindings.get(sid).unwrap_or(&empty);
            need(binding.is_object(), "invalid step bindings")?;
            execute_work(p, work[string(&step["work"])?], r, binding, &facts)?
        };
        if !result["output"].is_null() {
            let id = digest(
                &json!({"architecture":architecture_id,"step":sid,"output":result["output"]}),
            )?;
            result["output"]["id"] = json!(format!("derived:{id}"));
        }
        result["step_id"] = json!(sid);
        result["work_id"] = step["work"].clone();
        result["work_coordinate"] = work[string(&step["work"])?]["semantic_coordinate"].clone();
        results.insert(sid.clone(), result);
        ancestors.insert(sid.clone(), parents);
    }
    let results: Vec<_> = ordered
        .iter()
        .map(|id| results.remove(id).unwrap())
        .collect();
    let outputs: Vec<_> = results
        .iter()
        .filter(|r| !r["output"].is_null())
        .map(|r| r["output"].clone())
        .collect();
    let mut graph = Vec::new();
    for o in &outputs {
        for support in arr(&o["support"])? {
            graph.push(json!({"from":support,"to":o["id"],"relation":"SUPPORTS"}));
        }
    }
    Ok(
        json!({"architecture_id":architecture_id,"architecture_coordinate":architecture["semantic_coordinate"],"status":if architecture_complete(architecture, &results)? {"COMPLETE"} else {"UNRESOLVED"},
        "steps":results,"outputs":outputs,"unknowns":r.get("unknowns").cloned().unwrap_or_else(||json!([])),"support_graph":graph,"pack_sha256":digest(p)?,"request_sha256":digest(r)?,
        "claim_ceiling":CEILING,"compliance_verdict":null,"responsibility_determination":null,"external_effects":[]}),
    )
}

const COMPOSITION_SCHEMA: &str = "jc-semantic-node-composition/1";

fn canonical_sorted(values: &[Value]) -> Result<Vec<Value>> {
    let mut keyed = Vec::new();
    for value in values {
        keyed.push((canonical(value)?, value.clone()));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed.into_iter().map(|(_, value)| value).collect())
}

fn coordinate_parent(coordinate: &Value, stack: &str) -> Result<Option<Value>> {
    let (gs, _) = semantic_key(coordinate, stack)?;
    if gs.len() == 1 {
        return Ok(None);
    }
    Ok(Some(
        json!({"Gs": gs[..gs.len() - 1], "L": gs[gs.len() - 1]}),
    ))
}

/// Expose semantic definition-tree adjacency only.  These edges do not imply
/// specialization, precedence, execution, or support.
pub fn stack_definition_relations(p: &Value, stack: &str) -> Result<Value> {
    validate_semantic_pack(p)?;
    stack_prefix(stack)?;
    let rows = arr(&p["semantic_capital"][stack])?;
    let mut by_key = BTreeMap::new();
    for row in rows {
        by_key.insert(semantic_key(&row["coordinate"], stack)?, row);
    }
    let mut relations = Vec::new();
    for row in by_key.values() {
        let coordinate = row["coordinate"].clone();
        let parent = coordinate_parent(&coordinate, stack)?;
        let mut children = Vec::new();
        for other in by_key.values() {
            if coordinate_parent(&other["coordinate"], stack)? == Some(coordinate.clone()) {
                children.push(other["coordinate"].clone());
            }
        }
        children.sort_by_key(|value| semantic_key(value, stack).unwrap());
        if let Some(parent_coordinate) = &parent {
            need(
                by_key.contains_key(&semantic_key(parent_coordinate, stack)?),
                "definition parent is not admitted",
            )?;
        }
        relations.push(json!({
            "stack": stack,
            "coordinate": coordinate,
            "label": row["label"],
            "aliases": names(&row["aliases"] )?,
            "parent_coordinate": parent,
            "child_coordinates": children,
            "relation": "STACK_DEFINITION_PARENT",
            "implies_specialization": false,
            "implies_precedence": false,
            "implies_execution": false,
        }));
    }
    Ok(Value::Array(relations))
}

fn definition_relation(p: &Value, stack: &str, coordinate: &Value) -> Result<Value> {
    stack_definition_relations(p, stack)?
        .as_array()
        .and_then(|relations| {
            relations
                .iter()
                .find(|relation| relation["coordinate"] == *coordinate)
                .cloned()
        })
        .ok_or_else(|| "node has no admitted stack definition".into())
}

/// Decompose every source-bound part of one admitted Judgment warrant.
pub fn decompose_judgment(p: &Value, judgment_id: &str) -> Result<Value> {
    validate_semantic_pack(p)?;
    let judgments = index(&p["judgments"], "judgments")?;
    let judgment = judgments
        .get(judgment_id)
        .ok_or("unknown admitted Judgment")?;
    let overrides = judgment
        .get("overrides")
        .map(arr)
        .transpose()?
        .map_or(Ok(Vec::new()), |values| canonical_sorted(values))?;
    Ok(json!({
        "id": judgment["id"],
        "stack_definition": definition_relation(p, "judgment", &judgment["semantic_coordinate"] )?,
        "typed_bindings": judgment["bindings"],
        "premises": canonical_sorted(arr(&judgment["premises"])?)?,
        "output": judgment["output"],
        "overrides": overrides,
        "source_ids": names(&judgment["source_ids"] )?,
        "residual": judgment.get("residual").cloned().unwrap_or(Value::Null),
    }))
}

/// Rebind only an unchanged decomposition of an admitted Judgment warrant.
pub fn rebind_judgment(p: &Value, parts: &Value) -> Result<Value> {
    let judgment_id = parts
        .get("id")
        .and_then(Value::as_str)
        .ok_or("invalid Judgment parts")?;
    let expected = decompose_judgment(p, judgment_id)?;
    need(
        canonical(parts)? == canonical(&expected)?,
        "Judgment parts drift from the admitted warrant",
    )?;
    Ok(expected)
}

fn composition_port(selector: &Value, predicates: &Index<'_>) -> Result<Value> {
    let predicate = predicates
        .get(string(&selector["predicate"])?)
        .ok_or("unsupported composition predicate")?;
    Ok(json!({
        "predicate": predicate["id"],
        "arguments": selector["arguments"],
        "roles": predicate["roles"],
        "value_type": value_type(predicate),
        "origin": predicate["origin"],
    }))
}

fn work_interface(p: &Value, work: &Value) -> Result<Value> {
    let judgments = index(&p["judgments"], "judgments")?;
    let predicates = index(&p["predicates"], "predicates")?;
    let operation = string(&work["operation"])?;
    let selected: Vec<&Value> = match operation {
        "APPLY_JUDGMENT" => vec![
            *judgments
                .get(string(&work["judgment"])?)
                .ok_or("unknown admitted Judgment")?,
        ],
        "RESOLVE_JUDGMENTS" => names(&work["judgments"])?
            .into_iter()
            .map(|id| {
                judgments
                    .get(id)
                    .copied()
                    .ok_or_else(|| "unknown admitted Judgment".into())
            })
            .collect::<Result<Vec<_>>>()?,
        "COMPARE_VALUES" => Vec::new(),
        _ => return Err("operation has no executable interface".into()),
    };
    let (bindings, inputs, output, conclusion_scope) = if selected.is_empty() {
        (
            work["bindings"].clone(),
            vec![
                composition_port(&work["left"], &predicates)?,
                composition_port(&work["right"], &predicates)?,
            ],
            composition_port(&work["output"], &predicates)?,
            "COMPARISON_CONDITION_ONLY",
        )
    } else {
        let mut inputs = Vec::new();
        for judgment in &selected {
            for premise in arr(&judgment["premises"])? {
                inputs.push(composition_port(premise, &predicates)?);
            }
        }
        (
            selected[0]["bindings"].clone(),
            inputs,
            composition_port(&selected[0]["output"], &predicates)?,
            "DECLARED_JUDGMENT_CONCLUSION_ONLY",
        )
    };
    let mut unique_inputs = BTreeMap::new();
    for input in inputs {
        unique_inputs.insert(canonical(&input)?, input);
    }
    let producer = match operation {
        "APPLY_JUDGMENT" => "semantic_contracts._evaluate",
        "RESOLVE_JUDGMENTS" => "semantic_contracts._execute_work:RESOLVE_JUDGMENTS",
        "COMPARE_VALUES" => "semantic_contracts._execute_work:COMPARE_VALUES",
        _ => unreachable!(),
    };
    Ok(json!({
        "operation": operation,
        "producer": producer,
        "bindings": bindings,
        "inputs": unique_inputs.into_values().collect::<Vec<_>>(),
        "output": output,
        "judgment_ids": selected.iter().map(|judgment| judgment["id"].clone()).collect::<Vec<_>>(),
        "conclusion_scope": conclusion_scope,
        "missing_or_conflicting_input": "UNRESOLVED",
        "external_effects": [],
    }))
}

/// Decompose an admitted Work node and its existing execution interface.
pub fn decompose_work(p: &Value, work_id: &str) -> Result<Value> {
    validate_semantic_pack(p)?;
    let work_rows = index(&p["work"], "work")?;
    let work = work_rows.get(work_id).ok_or("unknown admitted Work")?;
    let interface = work_interface(p, work)?;
    Ok(json!({
        "id": work["id"],
        "stack_definition": definition_relation(p, "work", &work["semantic_coordinate"] )?,
        "domain_path": work["domain_path"],
        "declared_operation": interface["operation"],
        "producer_interface": interface["producer"],
        "typed_bindings": interface["bindings"],
        "inputs": interface["inputs"],
        "output": interface["output"],
        "judgment_dependencies": interface["judgment_ids"],
        "conclusion_scope": interface["conclusion_scope"],
        "missing_or_conflicting_input": interface["missing_or_conflicting_input"],
        "external_effects": [],
    }))
}

/// Rebind only an unchanged decomposition of an admitted Work interface.
pub fn rebind_work(p: &Value, parts: &Value) -> Result<Value> {
    let work_id = parts
        .get("id")
        .and_then(Value::as_str)
        .ok_or("invalid Work parts")?;
    let expected = decompose_work(p, work_id)?;
    need(
        canonical(parts)? == canonical(&expected)?,
        "Work parts drift from the admitted interface",
    )?;
    Ok(expected)
}

/// Decompose an acyclic Architecture into its canonical, existing Work wiring.
pub fn decompose_architecture(p: &Value, architecture_id: &str) -> Result<Value> {
    validate_semantic_pack(p)?;
    let architectures = index(&p["architectures"], "architectures")?;
    let architecture = architectures
        .get(architecture_id)
        .ok_or("unknown admitted Architecture")?;
    let ordered_ids = order(&architecture["steps"])?;
    let steps = index(&architecture["steps"], "steps")?;
    let mut ordered_steps = Vec::new();
    let mut edges = Vec::new();
    for step_id in &ordered_ids {
        let step = steps[step_id.as_str()];
        let dependencies = names(&step["depends_on"])?;
        for dependency in &dependencies {
            edges.push(json!({"from_step": dependency, "to_step": step["id"]}));
        }
        ordered_steps.push(json!({
            "step_id": step["id"],
            "work_id": step["work"],
            "depends_on": dependencies,
            "work": decompose_work(p, string(&step["work"])?)?,
        }));
    }
    let mut completion = architecture.get("completion").cloned();
    if let Some(value) = &mut completion {
        let required = names(&value["required_steps"])?;
        value["required_steps"] = json!(required);
        let mut groups = Vec::new();
        for group in arr(&value["exclusive_terminal_groups"])? {
            groups.push(json!(names(group)?));
        }
        value["exclusive_terminal_groups"] = json!(canonical_sorted(&groups)?);
    }
    let complete_only_after = completion.as_ref().map_or_else(
        || json!(ordered_ids),
        |value| value["required_steps"].clone(),
    );
    Ok(json!({
        "id": architecture["id"],
        "stack_definition": definition_relation(p, "architecture", &architecture["semantic_coordinate"] )?,
        "ordered_steps": ordered_steps,
        "dependency_edges": canonical_sorted(&edges)?,
        "completion": completion,
        "terminal_contract": {
            "complete_only_after": complete_only_after,
            "unresolved_on_missing_or_conflicting_input": true,
            "external_effects": [],
        },
    }))
}

/// Rebind only unchanged acyclic Architecture wiring.
pub fn rebind_architecture(p: &Value, parts: &Value) -> Result<Value> {
    let architecture_id = parts
        .get("id")
        .and_then(Value::as_str)
        .ok_or("invalid Architecture parts")?;
    let expected = decompose_architecture(p, architecture_id)?;
    need(
        canonical(parts)? == canonical(&expected)?,
        "Architecture parts drift from the admitted wiring",
    )?;
    Ok(expected)
}

fn source_rows(p: &Value, source_ids: &BTreeSet<String>) -> Result<Vec<Value>> {
    let mut rows = Vec::new();
    for source in arr(&p["sources"])? {
        if source["id"]
            .as_str()
            .is_some_and(|source_id| source_ids.contains(source_id))
        {
            rows.push(source.clone());
        }
    }
    rows.sort_by_key(|value| value["id"].as_str().unwrap_or_default().to_owned());
    Ok(rows)
}

fn semantic_basis(p: &Value, architecture: &Value) -> Result<Value> {
    let ordered_steps = arr(&architecture["ordered_steps"])?;
    let mut work_ids = BTreeSet::new();
    for step in ordered_steps {
        work_ids.insert(string(&step["work_id"])?.to_owned());
    }
    let mut work = Vec::new();
    for work_id in &work_ids {
        work.push(decompose_work(p, work_id)?);
    }
    let mut judgment_ids = BTreeSet::new();
    for work_parts in &work {
        for judgment_id in names(&work_parts["judgment_dependencies"])? {
            judgment_ids.insert(judgment_id.to_owned());
        }
    }
    let mut judgments = Vec::new();
    let mut source_ids = BTreeSet::new();
    for judgment_id in &judgment_ids {
        let judgment = decompose_judgment(p, judgment_id)?;
        for source_id in names(&judgment["source_ids"])? {
            source_ids.insert(source_id.to_owned());
        }
        judgments.push(judgment);
    }
    Ok(json!({
        "schema": COMPOSITION_SCHEMA,
        "pack_identity": {"schema": p["schema"], "id": p["id"], "root_id": p["root_id"]},
        "domain": canonical_sorted(arr(&p["domain"])?)?,
        "entity_kinds": names(&p["entity_kinds"] )?,
        "predicates": canonical_sorted(arr(&p["predicates"])?)?,
        "sources": canonical_sorted(arr(&p["sources"])?)?,
        "architecture": architecture,
        "work": work,
        "judgments": judgments,
        "judgment_sources": source_rows(p, &source_ids)?,
    }))
}

/// Compose one existing Architecture into an immutable, exact-pack-bound program.
pub fn compose_architecture_program(p: &Value, architecture_id: &str) -> Result<Value> {
    validate_semantic_pack(p)?;
    let architecture = rebind_architecture(p, &decompose_architecture(p, architecture_id)?)?;
    let body = json!({
        "schema": COMPOSITION_SCHEMA,
        "pack_id": p["id"],
        "architecture_id": architecture["id"],
        "architecture": architecture,
        "semantic_sha256": digest(&semantic_basis(p, &architecture)?)?,
        "claim_ceiling": CEILING,
        "external_effects": [],
    });
    let program_sha256 = digest(&body)?;
    let mut program = body;
    let object = program
        .as_object_mut()
        .ok_or("composition body is not an object")?;
    object.insert(
        "composition_id".into(),
        json!(format!("composition:{program_sha256}")),
    );
    object.insert("program_sha256".into(), json!(program_sha256));
    Ok(program)
}

/// Verify the exact composition against the current pack, then use the one
/// accepted runtime instead of introducing another evaluator.
pub fn execute_composed_program(p: &Value, program: &Value, request: &Value) -> Result<Value> {
    let architecture_id = program
        .get("architecture_id")
        .and_then(Value::as_str)
        .ok_or("invalid composed program")?;
    validate_semantic_pack(p)?;
    let expected = compose_architecture_program(p, architecture_id)?;
    need(
        canonical(program)? == canonical(&expected)?,
        "program is not the exact admitted composition for this pack",
    )?;
    let execution = execute_architecture(p, architecture_id, request)?;
    Ok(json!({
        "schema": COMPOSITION_SCHEMA,
        "composition_id": expected["composition_id"],
        "program_sha256": expected["program_sha256"],
        "semantic_sha256": expected["semantic_sha256"],
        "status": execution["status"],
        "execution": execution,
        "claim_ceiling": CEILING,
        "external_effects": [],
    }))
}

pub fn run_json(raw: &str) -> Result<String> {
    // One complete JSON request is consumed before any output is released.
    let input = parse_json(raw)?;
    fields(
        &input,
        &["operation", "pack", "architecture_id", "request"],
        &[],
    )?;
    need(
        input["operation"] == "execute_architecture",
        "unsupported operation",
    )?;
    let result = execute_architecture(
        &input["pack"],
        string(&input["architecture_id"])?,
        &input["request"],
    )?;
    canonical(&json!({"ok":true,"result":result}))
}
