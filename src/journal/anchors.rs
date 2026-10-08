//! Anchors: parameter values that are found when a step runs, not fixed
//! when it was recorded, so a recipe made on one file works on the next.
//!
//! An absolute offset such as 0x1F40 is right for one file and wrong for
//! another. A recipe step's parameter may therefore be an [`Anchor`] in
//! place of a literal:
//!
//! | Anchor | JSON | Means |
//! | --- | --- | --- |
//! | [`Anchor::Step`] | `{"step": 12, "path": "result.matches[0].offset"}` | a value an earlier step was given or returned |
//! | [`Anchor::Find`] | `{"find": {"hex": "7EA5"}, "nth": 0}` | where a search matches |
//! | [`Anchor::Structure`] | `{"structure": "png", "field": "IHDR.width", "part": "value"}` | a parsed field's offset, length or value |
//! | [`Anchor::Finding`] | `{"finding": {"category": "compressed", "nth": 0}}` | a finding's span |
//! | [`Anchor::Selection`] | `{"selection": "current"}` | whatever is selected when the recipe runs |
//! | [`Anchor::Param`] | `{"param": "key"}` | a value the person supplies when running the recipe |
//! | [`Anchor::Sheet`] | `{"sheet": {"step": 3}}`, `{"sheet": "payload"}`, `{"sheet": "input"}` | the sheet step 3 made, the sheet labelled payload, or the run's input |
//! | [`Anchor::Pick`] | `{"pick": {"step": 5, "list": "job.strings", "where": {"text": {"regex": "^NC500-"}}, "field": "text"}}` | an item chosen by what it holds from a list in a step's result ([`pick`]) |
//! | [`Anchor::Then`] | `{"of": ANCHOR, "then": [{"add": 16}, {"encode": "text_to_hex"}]}` | a value another anchor finds, transformed ([`then`]) |
//! | [`Anchor::Var`] | `{"var": "serial"}` | the value last bound to a variable with `vars.set` |
//!
//! **How an anchor is marked in a recipe step's parameters.** Any value at
//! any depth of a step's `params` may be `{"$anchor": ANCHOR}`, an object
//! with that one key; everything else is a literal. The marker keeps a
//! literal object that happens to look like an anchor (a `selection`
//! parameter, say) from being taken for one:
//!
//! ```json
//! {"method": "packets.sets.create",
//!  "params": {"from": "length_field", "start": {"$anchor": {"find": {"hex": "7EA5"}}}, "len": 4096}}
//! ```
//!
//! In a journal entry's `derived_from`, which maps parameter paths to
//! anchors, anchors are written bare: the map says they are anchors.
//!
//! **At call time** every caller may mark anchors in a call's params, as a
//! recipe step's are, with two shorthands: `{"$var": "serial"}` for
//! `{"$anchor": {"var": "serial"}}`, and `{"$sheet": 7}` or `{"$sheet":
//! "payload"}` for a sheet anchor (see [`as_anchor`]). They are resolved
//! against the live session before the call runs ([`crate::api::call_as`]):
//! step and pick anchors read the journal's entries, and the sheets are
//! those the session's steps made.
//!
//! **Paths** name a value inside JSON: dotted keys and `[n]` indices, such
//! as `matches[0].offset` or `length_field.offset`. A step anchor's path
//! starts at the entry, so it begins with `result.` or `params.`.
//!
//! This module declares the types, the JSON plumbing and how each anchor
//! resolves when a step runs ([`Anchor::resolve`]); capturing one while
//! recording is [`super::provenance`]'s.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::findings::{self, QueryParams};
use crate::api::selection::DocParams;
use crate::api::structure::{self, ParseParams};
use crate::api::values::MAX_PAGE;
use crate::api::{ApiError, MAX_CALL_BYTES, Workspace, workspace};
use crate::plugin::{Category, Field, Finding};
use crate::search::SearchMode;

pub mod live;
pub mod pick;
pub mod then;

pub use pick::{Pick, Sort, SortOrder, StepRef};
pub use then::Operation;

/// The key that marks an anchor among a step's literal parameters.
pub const ANCHOR_KEY: &str = "$anchor";
/// The key of the shorthand for a variable anchor: `{"$var": "serial"}`.
pub const VAR_KEY: &str = "$var";
/// The key of the shorthand for a sheet anchor: `{"$sheet": 7}`.
pub const SHEET_KEY: &str = "$sheet";

/// A value found when a step runs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Anchor {
    /// A value an earlier step was given or returned.
    Step {
        /// The earlier step's number.
        step: u64,
        /// Where in that step's entry: `result.matches[0].offset`,
        /// `params.start`.
        path: String,
    },
    /// Where a search matches, as `search.find` would find it.
    Find {
        find: Needle,
        /// Which match, counting from 0.
        #[serde(default)]
        nth: usize,
        /// The match's offset (the default) or length.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        part: Option<Part>,
    },
    /// A field of a structure a parser recognises.
    Structure {
        /// The parser's id, such as `png`.
        structure: String,
        /// The field's dotted name, such as `IHDR.width`.
        field: String,
        /// The field's offset (the default), length or value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        part: Option<Part>,
    },
    /// A finding's span.
    Finding {
        finding: FindingMatch,
        /// The span's offset (the default) or length.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        part: Option<Part>,
    },
    /// What is selected when the step runs.
    Selection {
        selection: SelectionWhich,
        /// The selection itself (the default, as `{"range": …}` or
        /// `{"ranges": …}`), or its first range's offset or length.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        part: Option<Part>,
    },
    /// A value the person supplies when running the recipe, declared in
    /// its `parameters`.
    Param {
        /// The parameter's name.
        param: String,
    },
    /// A document of the run: a sheet an earlier step made, one labelled,
    /// or the run's input.
    Sheet {
        sheet: SheetRef,
    },
    /// An item chosen from a list in an earlier step's result, by what it
    /// holds.
    Pick {
        pick: Pick,
    },
    /// A value another anchor finds, transformed: arithmetic, conversions.
    Then {
        /// The anchor whose value is transformed.
        of: Box<Anchor>,
        /// The operations, in order.
        then: Vec<Operation>,
    },
    /// The value last bound to a variable with `vars.set`.
    Var {
        /// The variable's name, such as `serial`.
        var: String,
    },
}

/// Which document of a run a sheet anchor names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SheetRef {
    /// The sheet labelled `label` among those an earlier step made: one of
    /// the sheets a `recipes.run` step's recipe made, say.
    Labelled { step: u64, label: String },
    /// The sheet an earlier step made: its `nth` (from 0) when it made
    /// several.
    Step {
        step: u64,
        #[serde(default, skip_serializing_if = "is_zero")]
        nth: usize,
    },
    /// The run's input, as `"input"`, or the sheet a step labelled so with
    /// its `makes`.
    Named(String),
}

/// The name a sheet anchor gives the run's input.
pub const INPUT: &str = "input";

fn is_zero(value: &usize) -> bool {
    *value == 0
}

impl SheetRef {
    /// "the sheet step 3 made", "the 2nd sheet step 3 made", "the run's
    /// input", "the sheet labelled payload".
    pub fn describe(&self) -> String {
        match self {
            SheetRef::Step { step, nth: 0 } => format!("the sheet step {step} made"),
            SheetRef::Step { step, nth } => format!("the {} sheet step {step} made", ordinal(*nth)),
            SheetRef::Named(name) if name == INPUT => "the run's input".to_string(),
            SheetRef::Named(label) => format!("the sheet labelled {label}"),
            SheetRef::Labelled { step, label } => format!("the sheet labelled {label} that step {step} made"),
        }
    }
}

/// Whether `text` is a document's id as the API gives them, such as
/// "doc-4": how a recipe tells a document named literally among a step's
/// parameters.
pub fn is_document_id(text: &str) -> bool {
    text.strip_prefix("doc-").is_some_and(|number| !number.is_empty() && number.chars().all(|digit| digit.is_ascii_digit()))
}

/// The documents a run has: its input, and the sheets its steps made, by
/// step and by label.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RunSheets {
    /// The document the run is on.
    pub input: Option<String>,
    /// The sheets each step made, in the order made.
    pub made: BTreeMap<u64, Vec<String>>,
    /// The sheets steps labelled with their `makes`.
    pub labels: BTreeMap<String, String>,
}

impl RunSheets {
    /// The documents of a run on `input`, before any step has run.
    pub fn on(input: &str) -> Self {
        RunSheets { input: Some(input.to_string()), ..RunSheets::default() }
    }

    /// Whether `doc` is the run's input or a sheet one of its steps made.
    pub fn holds(&self, doc: &str) -> bool {
        self.input.as_deref() == Some(doc) || self.made.values().flatten().any(|made| made == doc)
    }

    /// Whether `sheet` names a sheet the run does not have yet, but one of
    /// its later steps may make.
    pub fn is_waiting_for(&self, sheet: &SheetRef) -> bool {
        match sheet {
            SheetRef::Step { step, .. } | SheetRef::Labelled { step, .. } => !self.made.contains_key(step),
            SheetRef::Named(name) => name != INPUT && !self.labels.contains_key(name),
        }
    }
}

/// What a find anchor looks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Needle {
    /// Bytes written as hex, such as "7EA5".
    Hex(String),
    /// UTF-8 text.
    Text(String),
}

/// Which part of a found thing an anchor gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    /// Its offset in the document.
    Offset,
    /// Its length in bytes.
    Len,
    /// Its value (a field's decoded value, the selection itself).
    Value,
}

/// Which finding a finding anchor names: the `nth` of those that match a
/// category or whose id starts with a prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FindingMatch {
    /// The finding's category, such as `compressed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The start of the finding's id, or of the part after its kind, such as `image/png` for `signature:image/png`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Which of those matching, counting from 0 in offset order.
    #[serde(default)]
    pub nth: usize,
}

/// Which selection a selection anchor means: only `"current"` for now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SelectionWhich {
    /// What is selected when the step runs.
    Current,
}

/// `anchor` marked for a step's parameters: `{"$anchor": …}`.
pub fn marked(anchor: &Anchor) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(ANCHOR_KEY.to_string(), serde_json::to_value(anchor).unwrap_or(Value::Null));
    Value::Object(object)
}

/// The anchor `value` marks, when it is `{"$anchor": …}` and nothing else,
/// or one of the shorthands `{"$var": name}` and `{"$sheet": step, label or
/// {"step", "label"}}`.
pub fn as_anchor(value: &Value) -> Option<Anchor> {
    let object = value.as_object().filter(|object| object.len() == 1)?;
    let (key, marked) = object.iter().next()?;
    match key.as_str() {
        ANCHOR_KEY => serde_json::from_value(marked.clone()).ok(),
        VAR_KEY => Some(Anchor::Var { var: marked.as_str()?.to_string() }),
        SHEET_KEY => match marked {
            Value::Number(step) => Some(Anchor::Sheet { sheet: SheetRef::Step { step: step.as_u64()?, nth: 0 } }),
            Value::String(label) => Some(Anchor::Sheet { sheet: SheetRef::Named(label.clone()) }),
            Value::Object(_) => Some(Anchor::Sheet { sheet: serde_json::from_value(marked.clone()).ok()? }),
            _ => None,
        },
        _ => None,
    }
}

/// Whether `value` is marked as an anchor, well formed or not: an object of
/// one key, `$anchor`, `$var` or `$sheet`. A marker that does not read as
/// an anchor is a mistake to report, not a literal to pass on.
pub fn is_marked(value: &Value) -> bool {
    value.as_object().filter(|object| object.len() == 1).and_then(|object| object.keys().next()).is_some_and(|key| [ANCHOR_KEY, VAR_KEY, SHEET_KEY].contains(&key.as_str()))
}

/// Every anchor marked in `params`, with its path (`start`,
/// `length_field.offset`), in the order they appear.
pub fn anchors_in(params: &Value) -> Vec<(String, Anchor)> {
    let mut found = Vec::new();
    visit_paths(params, "", &mut |path, value| match as_anchor(value) {
        Some(anchor) => {
            found.push((path.to_string(), anchor));
            false
        }
        None => true,
    });
    found
}

/// Visit `value` and every value inside it, depth first and in key order,
/// each with its path written as [`value_at`] reads it: below `root` (`root`
/// itself for `value`, then `root.key` and `root[0]`; a key alone when
/// `root` is empty). `visit` says whether to look inside the value it is
/// given.
pub(crate) fn visit_paths<'a>(value: &'a Value, root: &str, visit: &mut impl FnMut(&str, &'a Value) -> bool) {
    if !visit(root, value) {
        return;
    }
    match value {
        Value::Object(fields) => {
            for (key, item) in fields {
                let path = if root.is_empty() { key.clone() } else { format!("{root}.{key}") };
                visit_paths(item, &path, visit);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                visit_paths(item, &format!("{root}[{index}]"), visit);
            }
        }
        _ => {}
    }
}

/// One step of a path: a key or an index.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathStep {
    Key(String),
    Index(usize),
}

/// `path` split into keys and indices: `matches[0].offset` is
/// `matches`, `0`, `offset`.
fn parse_path(path: &str) -> Result<Vec<PathStep>, ApiError> {
    let invalid = || ApiError::invalid_params(format!("'{path}' is not a path; write keys with dots and indices in brackets, such as result.matches[0].offset"));
    let mut steps = Vec::new();
    for part in path.split('.') {
        let (key, mut rest) = part.split_once('[').map_or((part, ""), |(key, rest)| (key, rest));
        if !key.is_empty() {
            steps.push(PathStep::Key(key.to_string()));
        } else if rest.is_empty() {
            return Err(invalid());
        }
        while !rest.is_empty() {
            let (index, after) = rest.split_once(']').ok_or_else(invalid)?;
            steps.push(PathStep::Index(index.parse().map_err(|_| invalid())?));
            rest = match after {
                "" => "",
                after => after.strip_prefix('[').ok_or_else(invalid)?,
            };
        }
    }
    Ok(steps)
}

/// The value at `path` in `value`, if there is one.
pub fn value_at<'a>(value: &'a Value, path: &str) -> Result<Option<&'a Value>, ApiError> {
    let mut current = value;
    for step in parse_path(path)? {
        let next = match step {
            PathStep::Key(key) => current.get(key.as_str()),
            PathStep::Index(index) => current.get(index),
        };
        let Some(next) = next else { return Ok(None) };
        current = next;
    }
    Ok(Some(current))
}

/// Put `replacement` at `path` in `value`, which must already hold a value
/// there (as a literal to turn into an anchor does). Returns the value it
/// replaced.
pub fn replace_at(value: &mut Value, path: &str, replacement: Value) -> Result<Value, ApiError> {
    let mut current = value;
    for step in parse_path(path)? {
        let next = match step {
            PathStep::Key(key) => current.get_mut(key.as_str()),
            PathStep::Index(index) => current.get_mut(index),
        };
        current = next.ok_or_else(|| ApiError::not_found(format!("there is no value at '{path}'")))?;
    }
    Ok(std::mem::replace(current, replacement))
}

/// What resolving an anchor may use: the workspace and document the step
/// runs on, what earlier steps of the run were given and returned, and the
/// values the person supplied.
pub struct ResolveContext<'a> {
    pub workspace: &'a mut dyn Workspace,
    /// The document the step runs on (an id); the current one when `None`.
    pub doc: Option<String>,
    /// Each earlier step of this run by its number, as
    /// `{"params": …, "result": …}`, which step anchors' paths start in.
    pub steps: &'a BTreeMap<u64, Value>,
    /// The recipe's parameters as the person gave them.
    pub parameters: &'a BTreeMap<String, Value>,
    /// The run's input and the sheets its steps have made, which sheet
    /// anchors name.
    pub sheets: &'a RunSheets,
}

impl Anchor {
    /// The value this anchor stands for now, in the run `context` describes.
    ///
    /// * **Step**: the value at `path` in what an earlier step of *this run*
    ///   was given and returned, `{"params", "result", "job"?}` (`job` is
    ///   the finished job's result, for a step that started a job the run
    ///   waited for: `job.candidates[0].period`).
    /// * **Find**: the `nth` match (from 0) of the bytes or text in the
    ///   step's document, searching from its start; `part` gives its
    ///   offset (the default), its length, or `{"range": [offset, len]}`.
    /// * **Structure**: `structure` is the structure's finding id (for the
    ///   built-in parsers, the parser's id: png, jpeg, mbr). The structure is
    ///   the parser's at offset 0 of the document, or else the first found
    ///   among the findings (in the first 16 MiB). `field` is the names from
    ///   the structure's root joined with dots, a second or later sibling of
    ///   the same name written `name[n]` (from 0): `chunks.IDAT[1].data`. As
    ///   a shorthand the first name may also be one at any depth (the first
    ///   so named, depth first), so `IHDR.width` works too. `part` gives the
    ///   field's offset (the default), length, or value (a number when it
    ///   reads as one, else the text the parser shows).
    /// * **Finding**: the `nth` (from 0, in offset order) of the findings the
    ///   Findings list would show in the first 16 MiB that are of the
    ///   category and whose id starts with `id` (or whose id's part after
    ///   its kind does: `image/png` finds `signature:image/png`); `part` gives its start
    ///   (the default), length, or `{"range": [start, len]}`.
    /// * **Selection**: what is selected in the step's document when the
    ///   step runs, as `selection.set` takes it (the default, and `value`),
    ///   or its first range's start or length.
    /// * **Param**: the value given for the recipe's parameter, or, given
    ///   none, what the anchor its default names finds.
    /// * **Sheet**: the run's input, or a sheet a step of the run made.
    /// * **Pick**: an item chosen from a list in an earlier step's value
    ///   (see [`pick`]).
    /// * **Then**: what another anchor finds, transformed (see [`then`]).
    /// * **Var**: the value last bound to the variable with `vars.set`.
    ///
    /// The error says which anchor failed and why, and carries the anchor
    /// as `data.anchor`.
    pub fn resolve(&self, context: &mut ResolveContext<'_>) -> Result<Value, ApiError> {
        let resolved = match self {
            Anchor::Step { step, path } => resolve_step(*step, path, context),
            Anchor::Find { find, nth, part } => resolve_find(find, *nth, *part, context),
            Anchor::Structure { structure, field, part } => resolve_structure(structure, field, *part, context),
            Anchor::Finding { finding, part } => resolve_finding(finding, *part, context),
            Anchor::Selection { part, .. } => resolve_selection(*part, context),
            Anchor::Param { param } => resolve_param(param, context),
            Anchor::Sheet { sheet } => resolve_sheet(sheet, context.sheets, &*context.workspace),
            Anchor::Pick { pick } => pick.resolve(context),
            Anchor::Then { of, then } => of.resolve(context).and_then(|value| then.iter().try_fold(value, |value, operation| operation.apply(value))),
            Anchor::Var { var } => resolve_var(var, &*context.workspace),
        };
        resolved.map_err(|error| {
            let data = serde_json::json!({ "anchor": self, "reason": error.to_json() });
            ApiError::new(error.code, format!("{} did not resolve: {}", self.describe(), error.message)).with_data(data)
        })
    }

    /// The anchor in a few words, for reports and errors: "the 2nd match of
    /// hex 7EA5", "the value at result.matches[0] of step 3".
    pub fn describe(&self) -> String {
        match self {
            Anchor::Step { step, path } => format!("the value at {path} of step {step}"),
            Anchor::Find { find, nth, part } => format!("the {}{} match of {}", part_phrase(*part), ordinal(*nth), find.describe()),
            Anchor::Structure { structure, field, part } => format!("the {}field {field} of the {structure} structure", part_phrase(*part)),
            Anchor::Finding { finding, part } => format!("the {}{}", part_phrase(*part), finding.describe()),
            Anchor::Selection { part, .. } => format!("the {}current selection", part_phrase(*part)),
            Anchor::Param { param } => format!("the parameter '{param}'"),
            Anchor::Sheet { sheet } => sheet.describe(),
            Anchor::Pick { pick } => pick.describe(),
            Anchor::Then { of, then } => {
                let operations: Vec<String> = then.iter().map(Operation::describe).collect();
                format!("{}, {}", of.describe(), operations.join(", "))
            }
            Anchor::Var { var } => format!("the variable ${var}"),
        }
    }

    /// The earlier steps whose values this anchor reads (a step anchor's,
    /// a pick's, and those of the anchor a then transforms), the steps of
    /// a pick named by label found in `sheets`.
    pub fn cited_steps(&self, sheets: &RunSheets) -> Vec<u64> {
        match self {
            Anchor::Step { step, .. } => vec![*step],
            Anchor::Pick { pick } => pick.step.number(sheets).ok().into_iter().collect(),
            Anchor::Then { of, .. } => of.cited_steps(sheets),
            _ => Vec::new(),
        }
    }

    /// The variables this anchor reads, at any depth.
    pub fn variables(&self) -> Vec<String> {
        match self {
            Anchor::Var { var } => vec![var.clone()],
            Anchor::Then { of, .. } => of.variables(),
            _ => Vec::new(),
        }
    }

    /// This anchor with each step it names by number changed as `renumber`
    /// says (`None` when the step is not there to name), at any depth.
    pub fn renumbered(&self, renumber: &impl Fn(u64) -> Option<u64>) -> Option<Anchor> {
        Some(match self {
            Anchor::Step { step, path } => Anchor::Step { step: renumber(*step)?, path: path.clone() },
            Anchor::Sheet { sheet: SheetRef::Step { step, nth } } => Anchor::Sheet { sheet: SheetRef::Step { step: renumber(*step)?, nth: *nth } },
            Anchor::Sheet { sheet: SheetRef::Labelled { step, label } } => Anchor::Sheet { sheet: SheetRef::Labelled { step: renumber(*step)?, label: label.clone() } },
            Anchor::Pick { pick } => {
                let mut pick = pick.clone();
                if let StepRef::Number(step) = pick.step {
                    pick.step = StepRef::Number(renumber(step)?);
                }
                Anchor::Pick { pick }
            }
            Anchor::Then { of, then } => Anchor::Then { of: Box::new(of.renumbered(renumber)?), then: then.clone() },
            other => other.clone(),
        })
    }

    /// Whether this anchor, or one inside it, is of a kind format 1
    /// recipes do not have: a sheet, pick, then or variable anchor.
    pub fn needs_second_format(&self) -> bool {
        matches!(self, Anchor::Sheet { .. } | Anchor::Pick { .. } | Anchor::Then { .. } | Anchor::Var { .. })
    }
}

impl Needle {
    /// "hex 7EA5" or "the text 'PK'".
    pub fn describe(&self) -> String {
        match self {
            Needle::Hex(hex) => format!("hex {hex}"),
            Needle::Text(text) => format!("the text '{text}'"),
        }
    }

    /// The bytes to look for, read as `search.find` reads its query.
    pub fn bytes(&self) -> Result<Vec<u8>, ApiError> {
        let (mode, query) = match self {
            Needle::Hex(hex) => (SearchMode::Hex, hex),
            Needle::Text(text) => (SearchMode::Text, text),
        };
        crate::api::search::needle(mode, query, true)
    }
}

impl FindingMatch {
    /// "1st image finding whose id starts with image/png".
    pub fn describe(&self) -> String {
        let category = self.category.as_deref().map_or(String::new(), |category| format!("{category} "));
        let id = self.id.as_deref().map_or(String::new(), |id| format!(" whose id starts with {id}"));
        format!("{} {category}finding{id}", ordinal(self.nth))
    }

    /// Those of `findings` (as [`findings_in`] lists them) that this names
    /// with any `nth`, in their order: the one it names is the `nth` of
    /// them. Recording a finding anchor counts with this too.
    pub fn matching<'a>(&self, findings: &'a [Finding]) -> Result<Vec<&'a Finding>, ApiError> {
        let mut matching = Vec::new();
        for finding in findings {
            if self.matches(finding)? {
                matching.push(finding);
            }
        }
        Ok(matching)
    }

    /// Whether `finding` is one of those this names.
    fn matches(&self, finding: &Finding) -> Result<bool, ApiError> {
        if let Some(category) = &self.category {
            let wanted: Category = serde_json::from_value(Value::String(category.clone()))
                .map_err(|_| ApiError::invalid_params(format!("'{category}' is not a finding category, such as compressed, image or timestamp")))?;
            if finding.category != wanted {
                return Ok(false);
            }
        }
        Ok(match &self.id {
            Some(prefix) => finding.id.starts_with(prefix.as_str()) || finding.id.split_once(':').is_some_and(|(_, rest)| rest.starts_with(prefix.as_str())),
            None => true,
        })
    }
}

/// "1st", "2nd", "3rd", "4th" for 0, 1, 2, 3: which one, counting from 0.
pub(crate) fn ordinal(index: usize) -> String {
    let number = index + 1;
    let suffix = match (number % 10, number % 100) {
        (_, 11..=13) => "th",
        (1, _) => "st",
        (2, _) => "nd",
        (3, _) => "rd",
        _ => "th",
    };
    format!("{number}{suffix}")
}

fn part_phrase(part: Option<Part>) -> &'static str {
    match part {
        None => "",
        Some(Part::Offset) => "offset of the ",
        Some(Part::Len) => "length of the ",
        Some(Part::Value) => "value of the ",
    }
}

/// The part of a span an anchor asks for: its offset (the default), its
/// length, or the span itself as `{"range": [start, len]}`, as
/// `selection.set` and the edits take it.
fn span_part(start: usize, len: usize, part: Option<Part>) -> Value {
    match part.unwrap_or(Part::Offset) {
        Part::Offset => Value::from(start),
        Part::Len => Value::from(len),
        Part::Value => serde_json::json!({ "range": [start, len] }),
    }
}

fn resolve_step(step: u64, path: &str, context: &ResolveContext<'_>) -> Result<Value, ApiError> {
    let Some(entry) = context.steps.get(&step) else {
        let ran: Vec<String> = context.steps.keys().map(u64::to_string).collect();
        let ran = if ran.is_empty() { "none has yet".to_string() } else { format!("those that have are {}", ran.join(", ")) };
        return Err(ApiError::not_found(format!("step {step} has not run earlier in this run ({ran})")));
    };
    let root = path.split(['.', '[']).next().unwrap_or_default();
    if !matches!(root, "params" | "result" | "job") {
        return Err(ApiError::invalid_params(format!("a step anchor's path starts with params., result. or job., not '{path}'")));
    }
    match value_at(entry, path)? {
        Some(value) => Ok(value.clone()),
        None => Err(ApiError::not_found(format!("step {step} has nothing at {path}"))),
    }
}

/// The document the step runs on: the context's, or the current one.
fn document_of<'w>(context: &'w mut ResolveContext<'_>) -> Result<(String, &'w mut crate::document::Document), ApiError> {
    let doc = context.doc.clone();
    workspace::document(&mut *context.workspace, doc.as_deref())
}

fn resolve_find(needle: &Needle, nth: usize, part: Option<Part>, context: &mut ResolveContext<'_>) -> Result<Value, ApiError> {
    let bytes = needle.bytes()?;
    let (doc, document) = document_of(context)?;
    let mut found = 0;
    for at in crate::search::matches_from(document, &bytes, 0) {
        if found == nth {
            return Ok(span_part(at, bytes.len(), part));
        }
        found += 1;
    }
    let times = match found {
        0 => "it does not occur".to_string(),
        1 => "it occurs once".to_string(),
        found => format!("it occurs {found} times"),
    };
    Err(ApiError::not_found(format!("{doc} has no {} match of {}: {times}", ordinal(nth), needle.describe())))
}

/// The findings `findings.query` lists in the first `len` bytes of document
/// `doc` (at most a call's worth, the first 16 MiB), in offset order, at
/// least `min_confidence` confident (0.5 when `None`, `findings.query`'s
/// own floor; the Findings list shows those below it too, dimmed), without
/// recording a read. A finding anchor counts among
/// these, both when it is recorded and when it resolves.
pub(crate) fn findings_in(workspace: &mut dyn Workspace, doc: &str, len: u64, min_confidence: Option<f32>) -> Result<Vec<Finding>, ApiError> {
    let len = len.min(MAX_CALL_BYTES as u64);
    let mut found = Vec::new();
    let mut next = None;
    loop {
        let params = QueryParams { doc: Some(doc.to_string()), start: 0, len: Some(len), categories: None, min_confidence, producers: None, limit: Some(MAX_PAGE), next };
        let page = findings::query(workspace, params)?;
        found.extend(page.findings);
        match page.next {
            Some(cursor) => next = Some(cursor),
            None => return Ok(found),
        }
    }
}

/// [`findings_in`] the whole of the step's document.
fn findings_of(context: &mut ResolveContext<'_>, min_confidence: Option<f32>) -> Result<Vec<Finding>, ApiError> {
    let doc = workspace::resolve(&*context.workspace, context.doc.as_deref())?;
    let len = workspace::info(&*context.workspace, &doc)?.len;
    findings_in(&mut *context.workspace, &doc, len, min_confidence)
}

fn resolve_finding(wanted: &FindingMatch, part: Option<Part>, context: &mut ResolveContext<'_>) -> Result<Value, ApiError> {
    let found = findings_of(context, None)?;
    let matching = wanted.matching(&found)?;
    match matching.get(wanted.nth) {
        Some(finding) => Ok(span_part(finding.start, finding.len, part)),
        None => Err(ApiError::not_found(format!("the document has {} such finding{} in its first 16 MiB", matching.len(), if matching.len() == 1 { "" } else { "s" }))),
    }
}

fn resolve_structure(parser: &str, field: &str, part: Option<Part>, context: &mut ResolveContext<'_>) -> Result<Value, ApiError> {
    let is_parser = context.workspace.registry().has_parser(parser);
    let made_at_start = if is_parser { parse_at(context, parser, 0)? } else { None };
    let structure = match made_at_start {
        Some(structure) => structure,
        None => find_structure(context, parser, is_parser)?.ok_or_else(|| {
            let message = if is_parser {
                format!("the {parser} parser recognises nothing at offset 0 or at any finding in the first 16 MiB")
            } else {
                format!("there is no parser '{parser}' (structure.parsers lists them), and no finding in the first 16 MiB has that id")
            };
            ApiError::not_found(message)
        })?,
    };
    let found = field_at(&structure.fields, field)?.ok_or_else(|| {
        let names: Vec<&str> = structure.fields.iter().map(|field| field.name.as_str()).collect();
        ApiError::not_found(format!("the {parser} structure at {:#x} has no field {field} (its top-level fields are {})", structure.start, names.join(", ")))
    })?;
    Ok(match part.unwrap_or(Part::Offset) {
        Part::Offset => Value::from(found.offset),
        Part::Len => Value::from(found.len),
        Part::Value => field_value(&found.value),
    })
}

/// The structure `parser` makes of the step's document from `at`, if any,
/// as `structure.parse` makes it.
fn parse_at(context: &mut ResolveContext<'_>, parser: &str, at: usize) -> Result<Option<Finding>, ApiError> {
    let params = ParseParams { doc: context.doc.clone(), at: at as u64, parser: Some(parser.to_string()) };
    Ok(structure::parse(&mut *context.workspace, params)?.structures.into_iter().next())
}

/// The first structure of `parser` among the findings: one a detector
/// made with its fields, or else one the parser makes at a finding's start.
fn find_structure(context: &mut ResolveContext<'_>, parser: &str, is_parser: bool) -> Result<Option<Finding>, ApiError> {
    let found = findings_of(context, Some(0.0))?;
    if let Some(made) = found.iter().find(|finding| finding.id == parser && !finding.fields.is_empty()) {
        return Ok(Some(made.clone()));
    }
    if !is_parser {
        return Ok(None);
    }
    let mut starts: Vec<usize> = found.iter().map(|finding| finding.start).filter(|start| *start > 0).collect();
    starts.dedup();
    for start in starts {
        if let Some(structure) = parse_at(context, parser, start)? {
            return Ok(Some(structure));
        }
    }
    Ok(None)
}

/// The field `path` names in `fields`: its first name at any depth (depth
/// first), each later name a child of the one before; `name[n]` is the
/// n-th (from 0) so named.
fn field_at<'a>(fields: &'a [Field], path: &str) -> Result<Option<&'a Field>, ApiError> {
    let names = field_path(path)?;
    let Some(((first, first_index), rest)) = names.split_first() else { return Ok(None) };
    // From the root first, as recorded; else the first so named at any depth.
    let at_root = fields.iter().filter(|field| field.name == *first).nth(*first_index);
    let mut so_named = Vec::new();
    if at_root.is_none() {
        collect_named(fields, first, &mut so_named);
    }
    let Some(mut current) = at_root.or_else(|| so_named.get(*first_index).copied()) else { return Ok(None) };
    for (name, index) in rest {
        let Some(child) = current.children.iter().filter(|child| child.name == *name).nth(*index) else { return Ok(None) };
        current = child;
    }
    Ok(Some(current))
}

fn collect_named<'a>(fields: &'a [Field], name: &str, found: &mut Vec<&'a Field>) {
    for field in fields {
        if field.name == name {
            found.push(field);
        }
        collect_named(&field.children, name, found);
    }
}

/// A field path's names, each with which of those so named it means:
/// `IDAT[1].length` is IDAT 1, length 0. Names may hold spaces
/// (`bit depth`).
fn field_path(path: &str) -> Result<Vec<(String, usize)>, ApiError> {
    let invalid = || ApiError::invalid_params(format!("'{path}' is not a field name; write the names with dots, such as IHDR.width or IDAT[1].length"));
    path.split('.')
        .map(|part| {
            let (name, index) = match part.strip_suffix(']').and_then(|part| part.rsplit_once('[')) {
                Some((name, index)) => (name, index.parse().map_err(|_| invalid())?),
                None => (part, 0),
            };
            if name.is_empty() { Err(invalid()) } else { Ok((name.to_string(), index)) }
        })
        .collect()
}

/// A field's value as JSON: a number when the parser's text reads as an
/// integer ([`parse_integer`]), else the text.
fn field_value(text: &str) -> Value {
    parse_integer(text).map_or_else(|| Value::String(text.to_string()), Value::Number)
}

/// `text` as an integer, surrounding space aside: decimal (negative too) or
/// hex after `0x` or `0X`. How a field's shown value, a recipe parameter
/// given as text and a literal compared with a field are all read.
pub(crate) fn parse_integer(text: &str) -> Option<serde_json::Number> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok().map(serde_json::Number::from);
    }
    match text.parse::<u64>() {
        Ok(number) => Some(number.into()),
        Err(_) => text.parse::<i64>().ok().map(serde_json::Number::from),
    }
}

fn resolve_selection(part: Option<Part>, context: &mut ResolveContext<'_>) -> Result<Value, ApiError> {
    let doc = context.doc.clone();
    let selected = crate::api::selection::get_selection(&mut *context.workspace, DocParams { doc })?;
    let Some(selection) = selected.selection else {
        return Err(ApiError::not_found(format!("nothing is selected in {}", selected.doc)));
    };
    let (start, len) = selected.ranges.first().copied().unwrap_or_default();
    Ok(match part {
        None | Some(Part::Value) => serde_json::to_value(selection).unwrap_or(Value::Null),
        Some(Part::Offset) => Value::from(start),
        Some(Part::Len) => Value::from(len),
    })
}

fn resolve_sheet(sheet: &SheetRef, sheets: &RunSheets, workspace: &dyn Workspace) -> Result<Value, ApiError> {
    let found = match sheet {
        SheetRef::Labelled { step, label } => {
            let made = sheets.made.get(step).ok_or_else(|| ApiError::not_found(format!("step {step} has not made a sheet earlier in this run")))?;
            let label_of = |doc: &str| crate::api::workspace::info(workspace, doc).ok().and_then(|info| info.label);
            made.iter().find(|doc| label_of(doc).as_deref() == Some(label.as_str())).cloned().ok_or_else(|| {
                let known: Vec<String> = made.iter().filter_map(|doc| label_of(doc)).collect();
                let known = if known.is_empty() { "none of them is labelled".to_string() } else { format!("those labelled are {}", known.join(", ")) };
                ApiError::not_found(format!("step {step} made no sheet labelled {label} ({known})"))
            })?
        }
        SheetRef::Named(name) if name == INPUT => sheets.input.clone().ok_or_else(|| ApiError::not_found("the run has no input document"))?,
        SheetRef::Named(label) => sheets.labels.get(label).cloned().ok_or_else(|| {
            let known: Vec<&str> = sheets.labels.keys().map(String::as_str).collect();
            let known = if known.is_empty() { "no step has labelled one yet".to_string() } else { format!("those labelled are {}", known.join(", ")) };
            ApiError::not_found(format!("no step of this run has made a sheet labelled {label} ({known})"))
        })?,
        SheetRef::Step { step, nth } => {
            let made = sheets.made.get(step).ok_or_else(|| ApiError::not_found(format!("step {step} has not made a sheet earlier in this run")))?;
            made.get(*nth).cloned().ok_or_else(|| match made.len() {
                0 => ApiError::not_found(format!("step {step} made no sheet in this run")),
                count => ApiError::not_found(format!("step {step} made {count} sheet{} in this run, so there is no {}", if count == 1 { "" } else { "s" }, ordinal(*nth))),
            })?
        }
    };
    Ok(Value::String(found))
}

/// A parameter's value; a parameter whose default is an anchor, given no
/// value, has that anchor marked as its value, which is resolved here.
fn resolve_param(name: &str, context: &mut ResolveContext<'_>) -> Result<Value, ApiError> {
    let value = context.parameters.get(name).cloned().ok_or_else(|| {
        let given: Vec<&str> = context.parameters.keys().map(String::as_str).collect();
        let given = if given.is_empty() { "none was given".to_string() } else { format!("those given are {}", given.join(", ")) };
        ApiError::invalid_params(format!("no value was given for it ({given})"))
    })?;
    match as_anchor(&value) {
        Some(default) => default.resolve(context),
        None => Ok(value),
    }
}

fn resolve_var(name: &str, workspace: &dyn Workspace) -> Result<Value, ApiError> {
    if let Some(binding) = workspace.journal().variable(name) {
        return Ok(binding.value.clone());
    }
    let bound: Vec<String> = workspace.journal().variables().keys().map(|name| format!("${name}")).collect();
    let bound = if bound.is_empty() { "none is".to_string() } else { format!("those bound are {}", bound.join(", ")) };
    Err(ApiError::not_found(format!("no value is bound to ${name}; bind one with vars.set ({bound})")))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::api::ErrorCode;

    fn round_trip(anchor: Anchor, written: Value) {
        assert_eq!(serde_json::to_value(&anchor).unwrap(), written, "{anchor:?} is written as the design shows");
        assert_eq!(serde_json::from_value::<Anchor>(written).unwrap(), anchor);
    }

    #[test]
    fn every_kind_of_anchor_is_written_as_the_design_s_table_shows() {
        round_trip(Anchor::Step { step: 12, path: "result.matches[0].offset".into() }, json!({"step": 12, "path": "result.matches[0].offset"}));
        round_trip(Anchor::Find { find: Needle::Hex("7EA5".into()), nth: 0, part: None }, json!({"find": {"hex": "7EA5"}, "nth": 0}));
        round_trip(
            Anchor::Structure { structure: "png".into(), field: "IHDR.width".into(), part: Some(Part::Value) },
            json!({"structure": "png", "field": "IHDR.width", "part": "value"}),
        );
        round_trip(
            Anchor::Finding { finding: FindingMatch { category: Some("compressed".into()), id: None, nth: 0 }, part: None },
            json!({"finding": {"category": "compressed", "nth": 0}}),
        );
        round_trip(Anchor::Selection { selection: SelectionWhich::Current, part: None }, json!({"selection": "current"}));
        round_trip(Anchor::Param { param: "key".into() }, json!({"param": "key"}));
        round_trip(Anchor::Sheet { sheet: SheetRef::Step { step: 3, nth: 0 } }, json!({"sheet": {"step": 3}}));
        round_trip(Anchor::Sheet { sheet: SheetRef::Step { step: 3, nth: 1 } }, json!({"sheet": {"step": 3, "nth": 1}}));
        round_trip(Anchor::Sheet { sheet: SheetRef::Named("payload".into()) }, json!({"sheet": "payload"}));
        round_trip(Anchor::Sheet { sheet: SheetRef::Named(INPUT.into()) }, json!({"sheet": "input"}));
        let pick = Pick {
            step: StepRef::Number(7),
            list: "job.strings".into(),
            condition: Some(json!({"text": {"regex": "^NC500-[0-9A-F]{8}$"}}).as_object().unwrap().clone()),
            sort: None,
            nth: 0,
            field: Some("text".into()),
        };
        round_trip(Anchor::Pick { pick }, json!({"pick": {"step": 7, "list": "job.strings", "where": {"text": {"regex": "^NC500-[0-9A-F]{8}$"}}, "field": "text"}}));
        round_trip(
            Anchor::Then { of: Box::new(Anchor::Var { var: "serial".into() }), then: vec![Operation::Encode(then::Encoding::TextToHex)] },
            json!({"of": {"var": "serial"}, "then": [{"encode": "text_to_hex"}]}),
        );
        round_trip(Anchor::Then { of: Box::new(Anchor::Param { param: "lba".into() }), then: vec![Operation::Mul(512), Operation::Int, Operation::Len] }, json!({"of": {"param": "lba"}, "then": [{"mul": 512}, "int", "len"]}));
        round_trip(Anchor::Var { var: "serial".into() }, json!({"var": "serial"}));
    }

    #[test]
    fn the_shorthands_mark_variable_and_sheet_anchors() {
        assert_eq!(as_anchor(&json!({"$var": "serial"})), Some(Anchor::Var { var: "serial".into() }));
        assert_eq!(as_anchor(&json!({"$sheet": 7})), Some(Anchor::Sheet { sheet: SheetRef::Step { step: 7, nth: 0 } }));
        assert_eq!(as_anchor(&json!({"$sheet": "payload"})), Some(Anchor::Sheet { sheet: SheetRef::Named("payload".into()) }));
        assert_eq!(as_anchor(&json!({"$sheet": [1]})), None);
        assert!(is_marked(&json!({"$sheet": [1]})), "a marker that does not read is still a marker, to report");
        assert!(!is_marked(&json!({"var": "serial"})));
    }

    #[test]
    fn a_pick_chooses_an_item_by_what_it_holds_from_an_earlier_step_s_list() {
        let mut workspace = crate::api::test_support::workspace_with("a.bin", b"abc");
        let strings = json!([
            {"offset": 4, "text": "novacamd v2.1", "tag": null},
            {"offset": 40, "text": "NC500-2F357657", "tag": "serial"},
            {"offset": 90, "text": "NC500-FFFF", "tag": null},
        ]);
        let candidates = json!([{"key": "65ffb33565ffb335", "score": 0.67}, {"key": "65ffb335", "score": 0.66}]);
        let done = BTreeMap::from([(7, json!({"params": {}, "result": {"job": "job-1"}, "job": {"strings": strings}})), (9, json!({"params": {}, "result": {"candidates": candidates}}))]);
        let sheets = RunSheets::on("doc-1");
        let mut resolve = |anchor: Value| serde_json::from_value::<Anchor>(anchor).unwrap().resolve(&mut ResolveContext { workspace: &mut workspace, doc: None, steps: &done, parameters: &BTreeMap::new(), sheets: &sheets });
        let serial = resolve(json!({"pick": {"step": 7, "list": "job.strings", "where": {"text": {"regex": "^NC500-[0-9A-F]{8}$"}}, "field": "text"}}));
        assert_eq!(serial.unwrap(), json!("NC500-2F357657"));
        assert_eq!(resolve(json!({"pick": {"step": 7, "list": "job.strings", "where": {"tag": "serial"}, "field": "offset"}})).unwrap(), json!(40));
        let shortest = json!({"pick": {"step": 9, "list": "result.candidates", "where": {"key": {"regex": "^.{1,8}$"}}, "field": "key"}});
        assert_eq!(resolve(shortest).unwrap(), json!("65ffb335"));
        let by_score = json!({"pick": {"step": 9, "list": "result.candidates", "sort": {"by": "score"}, "field": "key"}});
        assert_eq!(resolve(by_score).unwrap(), json!("65ffb335"), "sorted ascending, the lowest score is first");
        let missing = resolve(json!({"pick": {"step": 7, "list": "job.strings", "where": {"text": {"regex": "^ZZ"}}}})).unwrap_err();
        assert!(missing.message.contains("none of the 3 items of job.strings of step 7 passes where text matches /^ZZ/"), "{}", missing.message);
        let second = resolve(json!({"pick": {"step": 7, "list": "job.strings", "where": {"tag": "serial"}, "nth": 1}})).unwrap_err();
        assert!(second.message.ends_with("1 of the items of job.strings of step 7 pass where tagged serial, so there is no 2nd"), "{}", second.message);
    }

    #[test]
    fn a_then_anchor_transforms_what_another_finds() {
        let mut workspace = crate::api::test_support::workspace_with("a.bin", b"....SYNCLOG\0header");
        let sheets = RunSheets::on("doc-1");
        let none = BTreeMap::new();
        let anchor: Anchor = serde_json::from_value(json!({"of": {"find": {"text": "SYNCLOG"}}, "then": [{"add": 16}]})).unwrap();
        let value = anchor.resolve(&mut ResolveContext { workspace: &mut workspace, doc: None, steps: &none, parameters: &BTreeMap::new(), sheets: &sheets }).unwrap();
        assert_eq!(value, json!(20));
        assert_eq!(anchor.describe(), "the 1st match of the text 'SYNCLOG', plus 16");
    }

    #[test]
    fn a_variable_anchor_reads_the_value_last_bound() {
        let mut workspace = crate::api::test_support::workspace_with("a.bin", b"abc");
        let sheets = RunSheets::on("doc-1");
        let none = BTreeMap::new();
        let anchor = Anchor::Var { var: "serial".into() };
        let unbound = anchor.resolve(&mut ResolveContext { workspace: &mut workspace, doc: None, steps: &none, parameters: &BTreeMap::new(), sheets: &sheets }).unwrap_err();
        assert!(unbound.message.contains("no value is bound to $serial; bind one with vars.set (none is)"), "{}", unbound.message);
        workspace.journal_mut().bind_variable("serial", json!("NC500-2F357657"), Some(4));
        let bound = anchor.resolve(&mut ResolveContext { workspace: &mut workspace, doc: None, steps: &none, parameters: &BTreeMap::new(), sheets: &sheets }).unwrap();
        assert_eq!(bound, json!("NC500-2F357657"));
    }

    #[test]
    fn renumbering_reaches_the_steps_inside_picks_and_thens() {
        let anchor: Anchor = serde_json::from_value(json!({"of": {"pick": {"step": 12, "list": "result.candidates", "field": "key"}}, "then": [{"encode": "hex_to_text"}]})).unwrap();
        let renumbered = anchor.renumbered(&|step| (step == 12).then_some(3)).unwrap();
        assert_eq!(serde_json::to_value(&renumbered).unwrap()["of"]["pick"]["step"], 3);
        assert_eq!(renumbered.cited_steps(&RunSheets::default()), [3]);
        assert_eq!(anchor.renumbered(&|_| None), None, "a step the recipe does not hold cannot be named");
        let labelled: Anchor = serde_json::from_value(json!({"pick": {"step": "@rootfs", "list": "job.strings"}})).unwrap();
        assert_eq!(labelled.renumbered(&|_| None), Some(labelled.clone()), "a step named by its sheet's label keeps it");
    }

    #[test]
    fn a_sheet_anchor_names_the_run_s_input_a_sheet_a_step_made_or_one_labelled() {
        let mut workspace = crate::api::test_support::workspace_with("a.bin", b"abc");
        let sheets = RunSheets { input: Some("doc-1".into()), made: BTreeMap::from([(2, vec!["doc-2".into(), "doc-3".into()]), (4, Vec::new())]), labels: BTreeMap::from([("payload".into(), "doc-3".into())]) };
        let none = BTreeMap::new();
        let mut resolve = |sheet: SheetRef| Anchor::Sheet { sheet }.resolve(&mut ResolveContext { workspace: &mut workspace, doc: None, steps: &none, parameters: &BTreeMap::new(), sheets: &sheets });
        assert_eq!(resolve(SheetRef::Named(INPUT.into())).unwrap(), json!("doc-1"));
        assert_eq!(resolve(SheetRef::Step { step: 2, nth: 0 }).unwrap(), json!("doc-2"));
        assert_eq!(resolve(SheetRef::Step { step: 2, nth: 1 }).unwrap(), json!("doc-3"));
        assert_eq!(resolve(SheetRef::Named("payload".into())).unwrap(), json!("doc-3"));
        let later = resolve(SheetRef::Step { step: 9, nth: 0 }).unwrap_err();
        assert!(later.message.contains("the sheet step 9 made did not resolve: step 9 has not made a sheet earlier in this run"), "{}", later.message);
        let third = resolve(SheetRef::Step { step: 2, nth: 2 }).unwrap_err();
        assert!(third.message.ends_with("step 2 made 2 sheets in this run, so there is no 3rd"), "{}", third.message);
        assert!(resolve(SheetRef::Step { step: 4, nth: 0 }).unwrap_err().message.ends_with("step 4 made no sheet in this run"));
        let unknown = resolve(SheetRef::Named("rootfs".into())).unwrap_err();
        assert!(unknown.message.ends_with("no step of this run has made a sheet labelled rootfs (those labelled are payload)"), "{}", unknown.message);
    }

    #[test]
    fn a_document_s_id_is_told_from_other_text() {
        assert!(is_document_id("doc-1") && is_document_id("doc-42"));
        assert!(!is_document_id("doc-") && !is_document_id("doc-1a") && !is_document_id("current") && !is_document_id("/tmp/doc-1"));
    }

    #[test]
    fn a_find_anchor_written_by_hand_may_leave_out_which_match() {
        let anchor: Anchor = serde_json::from_value(json!({"find": {"text": "PK"}})).unwrap();
        assert_eq!(anchor, Anchor::Find { find: Needle::Text("PK".into()), nth: 0, part: None });
    }

    #[test]
    fn the_anchor_schema_offers_each_kind() {
        let schema = schemars::schema_for!(Anchor).to_value();
        assert_eq!(schema["anyOf"].as_array().map(Vec::len), Some(10), "{schema}");
    }

    #[test]
    fn a_marked_anchor_is_told_apart_from_a_literal_that_looks_like_one() {
        let anchor = Anchor::Param { param: "key".into() };
        assert_eq!(marked(&anchor), json!({"$anchor": {"param": "key"}}));
        assert_eq!(as_anchor(&json!({"$anchor": {"param": "key"}})), Some(anchor));
        assert_eq!(as_anchor(&json!({"selection": "current"})), None, "only the marker makes an anchor");
        assert_eq!(as_anchor(&json!({"$anchor": {"param": "key"}, "other": 1})), None);
    }

    #[test]
    fn the_anchors_in_a_step_s_params_are_listed_with_their_paths() {
        let params = json!({
            "from": "length_field",
            "start": {"$anchor": {"find": {"hex": "7EA5"}, "nth": 0}},
            "length_field": {"offset": {"$anchor": {"param": "offset"}}, "encoding": "u16"},
            "ranges": [[{"$anchor": {"step": 3, "path": "result.offset"}}, 4]],
        });
        let paths: Vec<String> = anchors_in(&params).into_iter().map(|(path, _)| path).collect();
        assert_eq!(paths, ["length_field.offset", "ranges[0][0]", "start"]);
    }

    #[test]
    fn a_path_reaches_into_objects_and_arrays_and_a_literal_can_be_replaced_there() {
        let mut entry = json!({"result": {"matches": [{"offset": 7}, {"offset": 64}]}, "params": {"ranges": [[1, 2]]}});
        assert_eq!(value_at(&entry, "result.matches[1].offset").unwrap(), Some(&json!(64)));
        assert_eq!(value_at(&entry, "params.ranges[0][1]").unwrap(), Some(&json!(2)));
        assert_eq!(value_at(&entry, "result.matches[5].offset").unwrap(), None);
        assert!(value_at(&entry, "result.matches[x]").is_err());
        assert!(value_at(&entry, "result..matches").is_err());
        let replaced = replace_at(&mut entry, "params.ranges[0][0]", marked(&Anchor::Param { param: "start".into() })).unwrap();
        assert_eq!(replaced, json!(1));
        assert_eq!(anchors_in(&entry["params"]).len(), 1);
        assert_eq!(replace_at(&mut entry, "params.missing", json!(0)).unwrap_err().code, ErrorCode::NotFound);
    }
}
