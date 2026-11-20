//! Argument templates for operator-defined commands.
//!
//! Each element of a custom tool's `command` list is a template:
//!
//! - `{name}` is replaced by the value of parameter `name`; if that parameter was not
//!   given, the whole element is left out of the command;
//! - `{name?text}` (which must be the whole element) becomes `text` when the boolean
//!   parameter `name` is true, and is left out otherwise;
//! - everything else is literal.
//!
//! AIDEV-NOTE: a template only ever produces one argv element, and nothing here or later
//! is parsed by a shell, so a parameter value cannot add arguments or commands.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    Text(String),
    Param(String),
    Flag { param: String, text: String },
}

/// A parameter value supplied when rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Flag(bool),
}

/// Parses one command element.
pub fn parse(element: &str) -> Result<Vec<Piece>, String> {
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut rest = element;
    while let Some(open) = rest.find(['{', '}']) {
        if rest[open..].starts_with('}') {
            return Err(format!("{element:?}: '}}' without a matching '{{'"));
        }
        literal.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after
            .find(['{', '}'])
            .filter(|i| after[*i..].starts_with('}'))
            .ok_or_else(|| format!("{element:?}: '{{' without a matching '}}'"))?;
        if !literal.is_empty() {
            pieces.push(Piece::Text(std::mem::take(&mut literal)));
        }
        match after[..close].split_once('?') {
            Some((name, text)) => {
                check_name(element, name)?;
                if text.is_empty() {
                    return Err(format!("{element:?}: nothing after '?' in {{{name}?}}"));
                }
                pieces.push(Piece::Flag {
                    param: name.to_string(),
                    text: text.to_string(),
                });
            }
            None => {
                let name = &after[..close];
                check_name(element, name)?;
                pieces.push(Piece::Param(name.to_string()));
            }
        }
        rest = &after[close + 1..];
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        pieces.push(Piece::Text(literal));
    }
    if pieces.len() > 1 && pieces.iter().any(|p| matches!(p, Piece::Flag { .. })) {
        return Err(format!(
            "{element:?}: {{name?text}} must be the whole element"
        ));
    }
    Ok(pieces)
}

fn check_name(element: &str, name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{element:?}: {name:?} is not a parameter name (a-z, 0-9 and '_', starting with a letter)"
        ))
    }
}

/// Renders one command element, or `None` when the element is to be left out.
pub fn render(pieces: &[Piece], values: &BTreeMap<String, Value>) -> Option<String> {
    let mut out = String::new();
    for piece in pieces {
        match piece {
            Piece::Text(text) => out.push_str(text),
            Piece::Param(name) => match values.get(name)? {
                Value::Text(text) => out.push_str(text),
                Value::Flag(true) => out.push_str("true"),
                Value::Flag(false) => out.push_str("false"),
            },
            Piece::Flag { param, text } => {
                if values.get(param) != Some(&Value::Flag(true)) {
                    return None;
                }
                out.push_str(text);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Piece {
        Piece::Text(s.to_string())
    }
    fn param(s: &str) -> Piece {
        Piece::Param(s.to_string())
    }

    #[test]
    fn parse_splits_literals_and_placeholders() {
        let cases: Vec<(&str, Vec<Piece>)> = vec![
            ("plain", vec![text("plain")]),
            ("", vec![]),
            ("{state}", vec![param("state")]),
            ("--state={state}", vec![text("--state="), param("state")]),
            ("{a}:{b_2}", vec![param("a"), text(":"), param("b_2")]),
            (
                "{force?--force}",
                vec![Piece::Flag {
                    param: "force".to_string(),
                    text: "--force".to_string(),
                }],
            ),
        ];
        for (element, want) in cases {
            assert_eq!(parse(element), Ok(want), "element {element:?}");
        }
    }

    #[test]
    fn parse_rejects_malformed_placeholders() {
        for bad in [
            "{state",
            "state}",
            "{}",
            "{bad name}",
            "{Upper}",
            "{a?x}tail",
            "pre{a?x}",
            "{a?}",
            "{{a}}",
            "{a{b}}",
            "{a?x}{b}",
            "{1a}",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    fn values(list: &[(&str, Value)]) -> BTreeMap<String, Value> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn rendered(element: &str, list: &[(&str, Value)]) -> Option<String> {
        render(&parse(element).unwrap(), &values(list))
    }

    #[test]
    fn render_substitutes_given_parameters() {
        let up = Value::Text("up".to_string());
        assert_eq!(rendered("plain", &[]), Some("plain".to_string()));
        assert_eq!(
            rendered("--state={state}", &[("state", up.clone())]),
            Some("--state=up".to_string())
        );
        assert_eq!(
            rendered(
                "{a}:{b}",
                &[("a", up.clone()), ("b", Value::Text("y".to_string()))]
            ),
            Some("up:y".to_string())
        );
        assert_eq!(
            rendered("{on}", &[("on", Value::Flag(true))]),
            Some("true".to_string())
        );
        assert_eq!(
            rendered("{on}", &[("on", Value::Flag(false))]),
            Some("false".to_string())
        );
    }

    #[test]
    fn render_leaves_out_elements_whose_parameter_is_missing() {
        let up = Value::Text("up".to_string());
        assert_eq!(rendered("--state={state}", &[]), None);
        assert_eq!(rendered("{a}:{b}", &[("a", up)]), None);
    }

    #[test]
    fn render_emits_a_flag_only_when_true() {
        assert_eq!(
            rendered("{force?--force}", &[("force", Value::Flag(true))]),
            Some("--force".to_string())
        );
        assert_eq!(
            rendered("{force?--force}", &[("force", Value::Flag(false))]),
            None
        );
        assert_eq!(rendered("{force?--force}", &[]), None);
        // a text value is not a true flag
        assert_eq!(
            rendered(
                "{force?--force}",
                &[("force", Value::Text("true".to_string()))]
            ),
            None
        );
    }

    #[test]
    fn a_value_is_never_re_parsed_as_a_template() {
        let sneaky = Value::Text("{other}".to_string());
        assert_eq!(
            rendered("{a}", &[("a", sneaky)]),
            Some("{other}".to_string())
        );
    }
}
