//! Tool parameters: one declaration drives both the JSON Schema shown to the agent and the
//! validation applied to what the agent sends, so the two cannot drift apart.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// The type of a parameter and its bounds.
#[derive(Clone, Debug)]
pub enum Kind {
    Str { max_len: usize },
    Int { min: i64, max: i64 },
    Bool,
    Choice(Vec<String>),
    StrList { max_items: usize, max_len: usize },
}

/// One declared tool parameter.
#[derive(Clone, Debug)]
pub struct Param {
    pub name: String,
    pub description: String,
    pub kind: Kind,
    pub required: bool,
}

impl Param {
    fn new(name: &str, description: &str, kind: Kind) -> Param {
        Param {
            name: name.to_string(),
            description: description.to_string(),
            kind,
            required: false,
        }
    }

    /// A string of at most 1024 characters (see `max_len`).
    pub fn str(name: &str, description: &str) -> Param {
        Param::new(name, description, Kind::Str { max_len: 1024 })
    }

    /// An integer within `min..=max`.
    pub fn int(name: &str, description: &str, min: i64, max: i64) -> Param {
        Param::new(name, description, Kind::Int { min, max })
    }

    pub fn bool(name: &str, description: &str) -> Param {
        Param::new(name, description, Kind::Bool)
    }

    /// One of a fixed set of strings.
    pub fn choice(name: &str, description: &str, values: &[&str]) -> Param {
        let values = values.iter().map(|v| v.to_string()).collect();
        Param::new(name, description, Kind::Choice(values))
    }

    /// A list of at most 64 strings of at most 256 characters each.
    pub fn list(name: &str, description: &str) -> Param {
        Param::new(
            name,
            description,
            Kind::StrList {
                max_items: 64,
                max_len: 256,
            },
        )
    }

    pub fn required(mut self) -> Param {
        self.required = true;
        self
    }

    /// Changes the maximum length of a string parameter.
    pub fn max_len(mut self, max_len: usize) -> Param {
        if let Kind::Str { .. } = self.kind {
            self.kind = Kind::Str { max_len };
        }
        self
    }
}

/// The JSON Schema (`inputSchema`) for a set of parameters.
pub fn input_schema(params: &[Param]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for param in params {
        let mut property = match &param.kind {
            Kind::Str { max_len } => json!({"type": "string", "maxLength": max_len}),
            Kind::Int { min, max } => json!({"type": "integer", "minimum": min, "maximum": max}),
            Kind::Bool => json!({"type": "boolean"}),
            Kind::Choice(values) => json!({"type": "string", "enum": values}),
            Kind::StrList { max_items, max_len } => json!({
                "type": "array",
                "items": {"type": "string", "maxLength": max_len},
                "maxItems": max_items
            }),
        };
        if let Some(object) = property.as_object_mut() {
            object.insert("description".to_string(), json!(param.description));
        }
        properties.insert(param.name.clone(), property);
        if param.required {
            required.push(json!(param.name));
        }
    }
    let mut schema = serde_json::Map::new();
    schema.insert("type".to_string(), json!("object"));
    schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert("required".to_string(), Value::Array(required));
    }
    schema.insert("additionalProperties".to_string(), json!(false));
    Value::Object(schema)
}

/// Validated arguments of one tool call.
#[derive(Debug, Default)]
pub struct Args {
    values: BTreeMap<String, Value>,
}

impl Args {
    /// Validates what the agent sent against the declared parameters. Anything not
    /// declared, missing, of the wrong type or out of bounds is an error whose message
    /// tells the agent how to fix the call.
    pub fn parse(params: &[Param], input: Option<&Value>) -> Result<Args, String> {
        let empty = serde_json::Map::new();
        let object = match input {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(object)) => object,
            Some(_) => return Err("the arguments must be a JSON object".to_string()),
        };
        for key in object.keys() {
            if !params.iter().any(|p| p.name == *key) {
                let accepted: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
                return Err(if accepted.is_empty() {
                    format!("unknown argument {key:?}: this tool takes no arguments")
                } else {
                    format!(
                        "unknown argument {key:?}: this tool accepts {}",
                        accepted.join(", ")
                    )
                });
            }
        }
        let mut values = BTreeMap::new();
        for param in params {
            match object.get(&param.name) {
                None | Some(Value::Null) => {
                    if param.required {
                        return Err(format!("missing required argument {:?}", param.name));
                    }
                }
                Some(value) => {
                    values.insert(param.name.clone(), checked_value(param, value)?);
                }
            }
        }
        Ok(Args { values })
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(Value::as_str)
    }

    pub fn int(&self, name: &str) -> Option<i64> {
        self.values.get(name).and_then(Value::as_i64)
    }

    pub fn bool(&self, name: &str) -> Option<bool> {
        self.values.get(name).and_then(Value::as_bool)
    }

    pub fn list(&self, name: &str) -> Option<Vec<&str>> {
        let items = self.values.get(name)?.as_array()?;
        Some(items.iter().filter_map(Value::as_str).collect())
    }
}

/// Checks one argument against its declaration and returns it in canonical form.
fn checked_value(param: &Param, value: &Value) -> Result<Value, String> {
    let name = &param.name;
    match &param.kind {
        Kind::Str { max_len } => {
            let text = value
                .as_str()
                .ok_or_else(|| format!("argument {name:?} must be a string"))?;
            check_text(name, text, *max_len)?;
        }
        Kind::Int { min, max } => {
            // JSON has one number type: 5.0 is as much an integer as 5.
            let whole = |f: f64| (f.fract() == 0.0 && f.abs() < 9.0e15).then_some(f as i64);
            let number = value
                .as_i64()
                .or_else(|| value.as_f64().and_then(whole))
                .ok_or_else(|| format!("argument {name:?} must be an integer"))?;
            if number < *min || number > *max {
                return Err(format!("argument {name:?} must be between {min} and {max}"));
            }
            return Ok(Value::from(number));
        }
        Kind::Bool => {
            value
                .as_bool()
                .ok_or_else(|| format!("argument {name:?} must be true or false"))?;
        }
        Kind::Choice(choices) => {
            let text = value
                .as_str()
                .ok_or_else(|| format!("argument {name:?} must be a string"))?;
            if !choices.iter().any(|c| c == text) {
                return Err(format!(
                    "argument {name:?} must be one of: {}",
                    choices.join(", ")
                ));
            }
        }
        Kind::StrList { max_items, max_len } => {
            let items = value
                .as_array()
                .ok_or_else(|| format!("argument {name:?} must be a list of strings"))?;
            if items.len() > *max_items {
                return Err(format!(
                    "argument {name:?} may have at most {max_items} items"
                ));
            }
            for item in items {
                let text = item
                    .as_str()
                    .ok_or_else(|| format!("argument {name:?} must be a list of strings"))?;
                check_text(name, text, *max_len)?;
            }
        }
    }
    Ok(value.clone())
}

/// AIDEV-NOTE: no argument of any tool may contain a control character (NUL, newline,
/// escape...). Nothing legitimate needs one, and it closes off a whole class of
/// injection into command lines, log queries and the audit log.
fn check_text(name: &str, text: &str, max_len: usize) -> Result<(), String> {
    // Counted in characters, which is what `maxLength` in the schema means.
    if text.chars().count() > max_len {
        return Err(format!(
            "argument {name:?} is longer than {max_len} characters"
        ));
    }
    if text.chars().any(char::is_control) {
        return Err(format!("argument {name:?} contains a control character"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Param> {
        vec![
            Param::str("unit", "Unit name").required(),
            Param::int("lines", "Lines", 1, 500),
            Param::bool("all", "All"),
            Param::choice("action", "Action", &["start", "stop"]).required(),
            Param::list("rule", "Rule"),
        ]
    }

    #[test]
    fn schema_describes_every_parameter_and_forbids_extras() {
        let want = json!({
            "type": "object",
            "properties": {
                "unit": {"type": "string", "description": "Unit name", "maxLength": 1024},
                "lines": {"type": "integer", "description": "Lines", "minimum": 1, "maximum": 500},
                "all": {"type": "boolean", "description": "All"},
                "action": {"type": "string", "description": "Action", "enum": ["start", "stop"]},
                "rule": {
                    "type": "array",
                    "description": "Rule",
                    "items": {"type": "string", "maxLength": 256},
                    "maxItems": 64
                }
            },
            "required": ["unit", "action"],
            "additionalProperties": false
        });
        assert_eq!(input_schema(&sample()), want);
    }

    #[test]
    fn schema_for_no_parameters_is_an_empty_object_schema() {
        let want = json!({"type": "object", "properties": {}, "additionalProperties": false});
        assert_eq!(input_schema(&[]), want);
    }

    #[test]
    fn valid_arguments_come_back_typed() {
        let input = json!({
            "unit": "nginx.service", "lines": 50, "all": true,
            "action": "stop", "rule": ["-p", "tcp"]
        });
        let args = Args::parse(&sample(), Some(&input)).unwrap();
        assert_eq!(args.str("unit"), Some("nginx.service"));
        assert_eq!(args.int("lines"), Some(50));
        assert_eq!(args.bool("all"), Some(true));
        assert_eq!(args.str("action"), Some("stop"));
        assert_eq!(args.list("rule"), Some(vec!["-p", "tcp"]));
    }

    #[test]
    fn optional_parameters_may_be_absent_or_null() {
        let input = json!({"unit": "a", "action": "start", "lines": null});
        let args = Args::parse(&sample(), Some(&input)).unwrap();
        assert_eq!(args.int("lines"), None);
        assert_eq!(args.bool("all"), None);
        assert_eq!(args.list("rule"), None);
    }

    #[test]
    fn no_arguments_are_fine_when_nothing_is_required() {
        let params = vec![Param::bool("all", "All")];
        assert!(Args::parse(&params, None).is_ok());
        assert!(Args::parse(&params, Some(&Value::Null)).is_ok());
        assert!(Args::parse(&params, Some(&json!({}))).is_ok());
    }

    fn error_for(input: Value) -> String {
        Args::parse(&sample(), Some(&input)).unwrap_err()
    }

    #[test]
    fn invalid_arguments_are_rejected_with_the_offending_name() {
        let cases: &[(Value, &str)] = &[
            // missing required
            (json!({"action": "start"}), "unit"),
            (json!({"unit": "a", "action": null}), "action"),
            // not declared
            (
                json!({"unit": "a", "action": "start", "force": true}),
                "force",
            ),
            // wrong types
            (json!({"unit": 5, "action": "start"}), "unit"),
            (
                json!({"unit": "a", "action": "start", "lines": "50"}),
                "lines",
            ),
            (
                json!({"unit": "a", "action": "start", "lines": 1.5}),
                "lines",
            ),
            (json!({"unit": "a", "action": "start", "all": "yes"}), "all"),
            (
                json!({"unit": "a", "action": "start", "rule": "-p tcp"}),
                "rule",
            ),
            (
                json!({"unit": "a", "action": "start", "rule": ["-p", 6]}),
                "rule",
            ),
            // out of bounds
            (json!({"unit": "a", "action": "start", "lines": 0}), "lines"),
            (
                json!({"unit": "a", "action": "start", "lines": 501}),
                "lines",
            ),
            (json!({"unit": "a", "action": "restart"}), "action"),
            (json!({"unit": "x".repeat(1025), "action": "start"}), "unit"),
            // control characters never belong in an argument
            (json!({"unit": "a\u{0}b", "action": "start"}), "unit"),
            (json!({"unit": "a\nb", "action": "start"}), "unit"),
            (
                json!({"unit": "a", "action": "start", "rule": ["ok", "bad\u{1b}"]}),
                "rule",
            ),
        ];
        for (input, name) in cases {
            let message = error_for(input.clone());
            assert!(
                message.contains(name),
                "input {input} gave {message:?}, expected it to name {name:?}"
            );
        }
    }

    #[test]
    fn a_whole_number_written_as_a_float_counts_as_an_integer() {
        // JSON does not distinguish 5 from 5.0, and the schema type "integer" admits both
        let args = Args::parse(
            &sample(),
            Some(&json!({"unit": "a", "action": "start", "lines": 5.0})),
        )
        .unwrap();
        assert_eq!(args.int("lines"), Some(5));
        assert!(
            Args::parse(
                &sample(),
                Some(&json!({"unit": "a", "action": "start", "lines": 500.0}))
            )
            .is_ok()
        );
        assert!(
            Args::parse(
                &sample(),
                Some(&json!({"unit": "a", "action": "start", "lines": 501.0}))
            )
            .is_err()
        );
        assert!(
            Args::parse(
                &sample(),
                Some(&json!({"unit": "a", "action": "start", "lines": 1e300}))
            )
            .is_err()
        );
    }

    #[test]
    fn string_length_is_counted_in_characters_as_the_schema_says() {
        let params = vec![Param::str("value", "Value").max_len(4)];
        // four characters, eight bytes
        assert!(Args::parse(&params, Some(&json!({"value": "\u{e9}\u{e9}\u{e9}\u{e9}"}))).is_ok());
        assert!(
            Args::parse(
                &params,
                Some(&json!({"value": "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}"}))
            )
            .is_err()
        );
    }

    #[test]
    fn arguments_must_be_an_object() {
        assert!(Args::parse(&sample(), Some(&json!(["unit"]))).is_err());
        assert!(Args::parse(&sample(), Some(&json!("unit"))).is_err());
    }

    #[test]
    fn a_list_longer_than_its_limit_is_rejected() {
        let many: Vec<String> = (0..65).map(|i| i.to_string()).collect();
        let message = error_for(json!({"unit": "a", "action": "start", "rule": many}));
        assert!(message.contains("rule"), "{message:?}");
    }

    #[test]
    fn max_len_changes_the_limit_that_is_enforced() {
        let params = vec![Param::str("value", "Value").max_len(4)];
        assert!(Args::parse(&params, Some(&json!({"value": "abcd"}))).is_ok());
        assert!(Args::parse(&params, Some(&json!({"value": "abcde"}))).is_err());
    }
}
