//! Provenance: noting, while recording, where a step's values came from,
//! and editing it afterwards, so a recipe made from the journal is
//! portable.
//!
//! **While recording.** Where the window knows a value came from an earlier
//! result, the call carries `derived_from` (parameter path → [`Anchor`]),
//! through [`crate::api::call_derived`], `ViewerApp::perform_derived`, or
//! `ViewerApp::with_provenance` around an action that makes one call
//! ([`capture`]). A semantic anchor (a search match, a structure field, a
//! finding, the selection) is preferred to a step anchor when both apply,
//! because it finds the value again in another file; a step anchor is the
//! fallback, citing a read that is first moved into the journal with
//! [`super::promote`].
//!
//! **Clients** (MCP, Ask, Lua) carry no provenance in band: a call's params
//! are the method's own. A client that used an earlier result says so
//! afterwards with `history.make_anchor {step, path, anchor}`, which also
//! promotes a cited read; `history.suggest_anchors` offers the anchors that
//! fit a step's literals.
//!
//! **Editing.** [`make_anchor`], [`make_parameter`] and [`clear_anchor`] set
//! or clear one parameter's anchor in an entry's `derived_from`;
//! [`suggest_anchors`] proposes anchors for a step's literals. The History
//! tab calls them directly, clients through the `history.*` methods in
//! `src/api/provenance.rs`.
//!
//! **The recipe with anchors** ([`Recipe::with_anchors`]) is
//! [`Recipe::from_journal`] with these rules:
//!
//! * each literal at a `derived_from` path becomes `{"$anchor": …}`; a path
//!   the params no longer hold (summarised, say) stays literal;
//! * steps are numbered 1, 2, 3… in step order, and step anchors are
//!   renumbered to match; a step anchor citing a step the recipe does not
//!   hold (failed, left out or dropped) stays literal;
//! * each [`Anchor::Param`] declares its parameter: the type and default
//!   from the literal (or as `history.make_parameter` gave them), its
//!   description as given;
//! * a `doc` that names the recorded document is dropped, so the step runs
//!   on whichever document the recipe runs on;
//! * a `selection.set` whose selection is anchored drops a `cursor` at the
//!   end of the last range, which is where the cursor goes when it is
//!   omitted, so it follows the anchored range.
//!
//! **Anchor conventions** this module writes, which resolving follows:
//!
//! * a find anchor's needle is `{"text"}` for a text search and `{"hex"}` of
//!   the needle's bytes otherwise; `nth` counts `search.find_all`'s matches
//!   (overlapping, in document order) from 0;
//! * a finding anchor names the finding's whole `id`, and `nth` counts the
//!   findings `findings.query` lists (by default confidence) whose id
//!   starts with it, in offset order;
//! * a structure anchor's `structure` is the parser's id (a finding's id),
//!   and `field` joins the field names from the structure's root with dots;
//!   when siblings share a name the second and later are `name[n]`,
//!   counting from 0;
//! * a step anchor's path may start `job.`, meaning the result the job the
//!   step started finished with (`job.candidates[0].period` of an
//!   `analysis.period_scan`), which the runner keeps when it awaits jobs.

pub mod capture;

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::anchors::{self, Anchor, FindingMatch, Needle, Part, SelectionWhich};
use super::recipe::{ParameterType, Recipe, RecipeParameter};
use super::{DerivedFrom, Journal, JournalEntry, JournalSession};
use crate::api::search::{FindAllParams, FindParams};
use crate::api::{self, ApiError, Workspace};
use crate::document::Document;
use crate::plugin::{Field, Finding};
use crate::search::SearchMode;

/// Most matches counted to say which match a find anchor names; past it a
/// match is cited by the step that found it instead.
pub const MOST_MATCHES_COUNTED: usize = 100_000;
/// Longest parameter name.
const PARAMETER_NAME_LIMIT: usize = 64;
/// Earlier entries and reads looked through for values a literal may have
/// come from.
const EARLIER_STEPS_SEARCHED: usize = 64;
/// Most anchors suggested for one literal.
const MOST_SUGGESTIONS: usize = 12;
/// Most step anchors suggested for one literal.
const MOST_STEP_SUGGESTIONS: usize = 3;
/// Most fields of one structure looked through.
const MOST_FIELDS_SEARCHED: usize = 10_000;

// ---------------------------------------------------------------------------
// Anchors for what the window knows
// ---------------------------------------------------------------------------

/// The needle of a find anchor for a search of `query` in `mode`, which
/// reads as `bytes`: the text itself for a text search, else the bytes as
/// hex.
pub fn needle_of(mode: SearchMode, query: &str, bytes: &[u8]) -> Needle {
    if mode == SearchMode::Text && query.as_bytes() == bytes {
        Needle::Text(query.to_string())
    } else {
        Needle::Hex(crate::ops::to_compact_hex(bytes))
    }
}

/// A match already counted: the `nth` match of a needle (from 0) is at
/// `at`, in the document as it is now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownMatch {
    pub at: usize,
    pub nth: usize,
}

/// Which match of `needle` (counting from 0, overlapping matches included,
/// as [`crate::search::matches_from`] lists them and a find anchor resolves)
/// is the one at `at`, or `None` when none is there or more than
/// [`MOST_MATCHES_COUNTED`] come before it.
///
/// With `known`, a match of the same needle counted in the document as it
/// is now, the count goes from there when that is nearer than the start
/// (forwards, or back to it), so stepping from match to match with Find
/// next or previous counts the few matches stepped over rather than every
/// match from the start each time.
pub fn nth_match(document: &mut Document, needle: &[u8], at: usize, known: Option<KnownMatch>) -> Option<usize> {
    let nth = match known {
        Some(known) if known.at <= at => known.nth + matches_before(document, needle, known.at, at)?,
        Some(known) if known.at - at < at => {
            if crate::search::find_next(document, needle, at) != Some(at) {
                return None;
            }
            known.nth.checked_sub(matches_before(document, needle, at, known.at)?)?
        }
        _ => matches_before(document, needle, 0, at)?,
    };
    (nth < MOST_MATCHES_COUNTED).then_some(nth)
}

/// How many matches of `needle` start from `from` up to `at`, when one
/// starts at `at` and at most [`MOST_MATCHES_COUNTED`] come before it.
fn matches_before(document: &mut Document, needle: &[u8], from: usize, at: usize) -> Option<usize> {
    crate::search::matches_from(document, needle, from).take(MOST_MATCHES_COUNTED).take_while(|found| *found <= at).position(|found| found == at)
}

/// The anchors of a `[offset, len]` pair at `path` (`selection.range`,
/// `ranges[0]`): `offset` at `path[0]`, and `len`, when given, at `path[1]`.
pub fn pair_anchors(path: &str, offset: Anchor, len: Option<Anchor>) -> DerivedFrom {
    let mut derived_from = DerivedFrom::new();
    derived_from.insert(format!("{path}[0]"), offset);
    if let Some(len) = len {
        derived_from.insert(format!("{path}[1]"), len);
    }
    derived_from
}

/// `anchor` giving `part` of what it finds instead.
pub fn with_part(anchor: &Anchor, part: Part) -> Anchor {
    let mut anchor = anchor.clone();
    match &mut anchor {
        Anchor::Find { part: kept, .. } | Anchor::Structure { part: kept, .. } | Anchor::Finding { part: kept, .. } | Anchor::Selection { part: kept, .. } => *kept = Some(part),
        Anchor::Step { .. } | Anchor::Param { .. } => {}
    }
    anchor
}

/// A finding anchor for `finding` among `findings` (as
/// [`anchors::findings_in`] lists them, in offset order): the nth of those
/// its id names, counted as the anchor resolves. `None` when it is not
/// among them.
pub fn finding_anchor(findings: &[Finding], finding: &Finding) -> Option<Anchor> {
    let mut wanted = FindingMatch { category: None, id: Some(finding.id.clone()), nth: 0 };
    let matching = wanted.matching(findings).ok()?;
    wanted.nth = matching.iter().position(|candidate| candidate.start == finding.start && candidate.len == finding.len)?;
    Some(Anchor::Finding { finding: wanted, part: None })
}

/// The field names of `fields`, as a structure anchor writes them: the name,
/// or `name[n]` for the second and later siblings of the same name.
fn sibling_names(fields: &[Field]) -> Vec<String> {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    fields
        .iter()
        .map(|field| {
            let count = seen.entry(field.name.as_str()).or_insert(0);
            let name = if *count == 0 { field.name.clone() } else { format!("{}[{count}]", field.name) };
            *count += 1;
            name
        })
        .collect()
}

/// Every field of `structure` with its anchor name, outermost first, at
/// most [`MOST_FIELDS_SEARCHED`].
pub fn named_fields(structure: &Finding) -> Vec<(String, &Field)> {
    let mut named = Vec::new();
    let mut pending: Vec<(String, &[Field])> = vec![(String::new(), structure.fields.as_slice())];
    while let Some((prefix, fields)) = pending.pop() {
        for (name, field) in sibling_names(fields).into_iter().zip(fields) {
            if named.len() >= MOST_FIELDS_SEARCHED {
                return named;
            }
            let name = if prefix.is_empty() { name } else { format!("{prefix}.{name}") };
            pending.push((name.clone(), field.children.as_slice()));
            named.push((name, field));
        }
    }
    named
}

/// The anchor name of the field of `structure` spanning `offset` and `len`
/// (the outermost, when a field and its only child share a span).
pub fn field_name(structure: &Finding, offset: usize, len: usize) -> Option<String> {
    let named = named_fields(structure);
    let matching = named.iter().filter(|(_, field)| field.offset == offset && field.len == len);
    matching.min_by_key(|(name, _)| name.matches('.').count()).map(|(name, _)| name.clone())
}

/// A structure anchor for the field of `structure` spanning `offset` and
/// `len`, giving its offset.
pub fn structure_anchor(structure: &Finding, offset: usize, len: usize) -> Option<Anchor> {
    let field = field_name(structure, offset, len)?;
    Some(Anchor::Structure { structure: structure.id.clone(), field, part: None })
}

/// The current selection's offset and length anchors, at `offset_path` and
/// `len_path`.
pub fn selection_anchors(offset_path: &str, len_path: &str) -> DerivedFrom {
    let selection = Anchor::Selection { selection: SelectionWhich::Current, part: Some(Part::Offset) };
    DerivedFrom::from([(offset_path.to_string(), selection.clone()), (len_path.to_string(), with_part(&selection, Part::Len))])
}

// ---------------------------------------------------------------------------
// Editing an entry's derived_from
// ---------------------------------------------------------------------------

impl Journal {
    /// Set (or, with `None`, clear) the anchor at `path` of step `step`'s
    /// `derived_from`. Returns the anchor it replaced.
    pub fn set_anchor(&mut self, step: u64, path: &str, anchor: Option<Anchor>) -> Result<Option<Anchor>, ApiError> {
        let entry = self.entries.iter_mut().find(|entry| entry.step == step).ok_or_else(|| not_a_step(step))?;
        let replaced = match anchor {
            Some(anchor) => entry.derived_from.insert(path.to_string(), anchor),
            None => entry.derived_from.remove(path),
        };
        self.revision += 1;
        Ok(replaced)
    }

    /// Declare the recipe parameter `name` for this session, as
    /// `history.make_parameter` does, replacing one of that name.
    pub fn declare_parameter(&mut self, name: &str, parameter: RecipeParameter) {
        self.parameters.insert(name.to_string(), parameter);
        self.revision += 1;
    }
}

/// The error for a step the journal does not hold.
pub(crate) fn not_a_step(step: u64) -> ApiError {
    ApiError::not_found(format!("there is no step {step} in the journal; history.list shows the steps held (a read becomes a step when a later step cites it)"))
}

/// What turning a literal into an anchor did.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AnchorChange {
    pub step: u64,
    /// The parameter's path, such as `selection.range[0]`.
    pub path: String,
    /// The literal the step was given there.
    pub value: Value,
    /// The anchor now at the path; none when it was cleared.
    pub anchor: Option<Anchor>,
    /// The anchor it replaced, if any.
    pub replaced: Option<Anchor>,
}

/// The literal at `path` of step `step`'s params, checking that a recipe
/// could put an anchor there.
fn literal_at(workspace: &dyn Workspace, step: u64, path: &str) -> Result<Value, ApiError> {
    let entry = workspace.journal().entry(step).ok_or_else(|| not_a_step(step))?;
    if path == "doc" || path.starts_with("doc.") || path.starts_with("doc[") {
        return Err(ApiError::invalid_params("the document a step is about cannot be an anchor: a recipe runs on the document it is given"));
    }
    let value = anchors::value_at(&entry.params, path)?.ok_or_else(|| ApiError::not_found(format!("step {step} ({}) has no parameter at '{path}'", entry.method)))?;
    Ok(value.clone())
}

/// Turn the literal at `path` of step `step` into `anchor`. A step anchor
/// must cite an earlier, successful step whose entry holds a value at its
/// path; a read it cites is moved into the journal first.
pub fn make_anchor(workspace: &mut dyn Workspace, step: u64, path: &str, anchor: Anchor) -> Result<AnchorChange, ApiError> {
    let value = literal_at(workspace, step, path)?;
    match &anchor {
        Anchor::Step { step: cited, path: cited_path } => check_cited(workspace, step, *cited, cited_path)?,
        Anchor::Param { param } => {
            check_parameter_name(param)?;
            parameter_type_of(&value).ok_or_else(|| ApiError::invalid_params(format!("the value at '{path}' is not a string, number or true/false, so it cannot be a parameter")))?;
        }
        _ => {}
    }
    let replaced = workspace.journal_mut().set_anchor(step, path, Some(anchor.clone()))?;
    Ok(AnchorChange { step, path: path.to_string(), value, anchor: Some(anchor), replaced })
}

/// Clear the anchor at `path` of step `step`, leaving the literal.
pub fn clear_anchor(workspace: &mut dyn Workspace, step: u64, path: &str) -> Result<AnchorChange, ApiError> {
    let value = workspace.journal().entry(step).ok_or_else(|| not_a_step(step))?.params.clone();
    let value = anchors::value_at(&value, path)?.cloned().unwrap_or(Value::Null);
    let replaced = workspace.journal_mut().set_anchor(step, path, None)?;
    Ok(AnchorChange { step, path: path.to_string(), value, anchor: None, replaced })
}

/// Check that step `step` may cite `cited_path` of step `cited`, promoting
/// a read it names.
fn check_cited(workspace: &mut dyn Workspace, step: u64, cited: u64, cited_path: &str) -> Result<(), ApiError> {
    if cited >= step {
        return Err(ApiError::invalid_params(format!("step {step} can only take a value from an earlier step, not step {cited}")));
    }
    let in_job = cited_path.starts_with("job.");
    if !(cited_path.starts_with("result.") || cited_path.starts_with("params.") || cited_path == "result" || in_job) {
        return Err(ApiError::invalid_params(format!("a step anchor's path starts with result., params. or job., not '{cited_path}'")));
    }
    let held = workspace.journal().entry(cited).or_else(|| workspace.journal().read(cited)).cloned();
    let Some(cited_entry) = held else { return Err(not_a_step(cited)) };
    if !cited_entry.outcome.is_ok() {
        return Err(ApiError::invalid_params(format!("step {cited} failed, so it has no value to take")));
    }
    // A job's result is not in the journal: the runner keeps it.
    if !in_job && anchors::value_at(&entry_value(&cited_entry), cited_path)?.is_none() {
        return Err(ApiError::not_found(format!("step {cited} ({}) has no value at '{cited_path}'", cited_entry.method)));
    }
    super::promote(workspace, cited);
    Ok(())
}

/// An entry as a step anchor's path reads it: `{"params", "result"}`.
pub fn entry_value(entry: &JournalEntry) -> Value {
    serde_json::json!({ "params": entry.params, "result": entry.result.clone().unwrap_or(Value::Null) })
}

/// Turn the literal at `path` of step `step` into the recipe parameter
/// `name`, of `kind` (the literal's type when omitted), described as
/// `description`. The literal becomes the parameter's default.
pub fn make_parameter(workspace: &mut dyn Workspace, step: u64, path: &str, name: &str, description: Option<String>, kind: Option<ParameterType>) -> Result<(AnchorChange, RecipeParameter), ApiError> {
    check_parameter_name(name)?;
    let value = literal_at(workspace, step, path)?;
    let literal_kind = parameter_type_of(&value).ok_or_else(|| ApiError::invalid_params(format!("the value at '{path}' is not a string, number or true/false, so it cannot be a parameter")))?;
    let kind = kind.unwrap_or(literal_kind);
    if !kind.fits(&value) {
        return Err(ApiError::invalid_params(format!("the value at '{path}', {value}, is not of type {}", kind.name())));
    }
    if let Some(earlier) = workspace.journal().parameters().get(name).filter(|earlier| earlier.kind != kind) {
        return Err(ApiError::invalid_params(format!("the parameter '{name}' is already of type {}", earlier.kind.name())));
    }
    let parameter = RecipeParameter { kind, description: description.unwrap_or_default(), default: Some(value) };
    workspace.journal_mut().declare_parameter(name, parameter.clone());
    let change = make_anchor(workspace, step, path, Anchor::Param { param: name.to_string() })?;
    Ok((change, parameter))
}

fn check_parameter_name(name: &str) -> Result<(), ApiError> {
    let fits = !name.is_empty() && name.chars().count() <= PARAMETER_NAME_LIMIT && name.chars().all(|character| character.is_alphanumeric() || matches!(character, '_' | '-' | ' '));
    if fits {
        return Ok(());
    }
    Err(ApiError::invalid_params(format!("'{name}' cannot name a parameter: use up to {PARAMETER_NAME_LIMIT} letters, digits, spaces, '_' or '-'")))
}

/// The parameter type a literal has: `None` for an object, array or null.
pub fn parameter_type_of(value: &Value) -> Option<ParameterType> {
    match value {
        Value::Bool(_) => Some(ParameterType::Boolean),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some(ParameterType::Integer),
        Value::Number(_) => Some(ParameterType::Number),
        Value::String(_) => Some(ParameterType::String),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The recipe with anchors
// ---------------------------------------------------------------------------

impl Recipe {
    /// A recipe called `name` of the successful calls in `entries`, with
    /// each recorded provenance as an anchor (see the module's rules), and
    /// `declared` describing the parameters named.
    pub fn with_anchors<'a>(name: &str, session: &JournalSession, entries: impl IntoIterator<Item = &'a JournalEntry>, declared: &BTreeMap<String, RecipeParameter>) -> Recipe {
        let mut entries: Vec<&JournalEntry> = entries.into_iter().filter(|entry| entry.outcome.is_ok()).collect();
        entries.sort_by_key(|entry| entry.step);
        let mut recipe = Recipe::from_journal(name, session, entries.iter().copied());
        let recorded_doc = entries.iter().find_map(|entry| entry.doc.clone());
        let numbers: BTreeMap<u64, u64> = entries.iter().zip(1..).map(|(entry, number)| (entry.step, number)).collect();
        for (step, entry) in recipe.steps.iter_mut().zip(&entries) {
            step.step = numbers[&entry.step];
            for (path, anchor) in &entry.derived_from {
                let Some(anchor) = renumbered(anchor, &numbers) else { continue };
                let Ok(Some(literal)) = anchors::value_at(&step.params, path).map(|value| value.cloned()) else { continue };
                if let Anchor::Param { param } = &anchor {
                    let Some(kind) = parameter_type_of(&literal) else { continue };
                    let declared = declared.get(param).cloned();
                    let parameter = declared.unwrap_or(RecipeParameter { kind, description: String::new(), default: Some(literal.clone()) });
                    recipe.parameters.entry(param.clone()).or_insert(parameter);
                }
                let _ = anchors::replace_at(&mut step.params, path, anchors::marked(&anchor));
            }
            drop_recorded_doc(&mut step.params, entry, recorded_doc.as_deref());
            if step.method == "selection.set" {
                drop_default_cursor(&mut step.params, &entry.params);
            }
        }
        recipe
    }

    /// [`Recipe::with_anchors`] of `journal`'s steps numbered `steps` (all
    /// of them when `None`) and the earlier steps they cite, with the
    /// parameters declared in the journal.
    pub fn from_journal_with_anchors(name: &str, journal: &Journal, steps: Option<&[u64]>) -> Recipe {
        let chosen: Vec<u64> = match steps {
            Some(steps) => steps.to_vec(),
            None => journal.entries().map(|entry| entry.step).collect(),
        };
        let entries = with_cited_steps(journal, &chosen);
        Recipe::with_anchors(name, journal.session(), entries, journal.parameters())
    }
}

/// [`Recipe::from_journal_with_anchors`], refusing steps the journal does
/// not hold: how `recipes.save` and `history.recipe` make a recipe of
/// chosen steps.
pub fn checked_recipe(journal: &Journal, name: &str, steps: Option<&[u64]>) -> Result<Recipe, ApiError> {
    if let Some(missing) = steps.into_iter().flatten().find(|step| journal.entry(**step).is_none()) {
        return Err(not_a_step(*missing));
    }
    Ok(Recipe::from_journal_with_anchors(name, journal, steps))
}

/// The entries numbered `steps`, and every earlier entry their step anchors
/// cite (and those cite), in step order.
pub fn with_cited_steps<'a>(journal: &'a Journal, steps: &[u64]) -> Vec<&'a JournalEntry> {
    let mut wanted: BTreeSet<u64> = BTreeSet::new();
    let mut pending: Vec<u64> = steps.to_vec();
    while let Some(step) = pending.pop() {
        let Some(entry) = journal.entry(step) else { continue };
        if !wanted.insert(step) {
            continue;
        }
        for anchor in entry.derived_from.values() {
            if let Anchor::Step { step: cited, .. } = anchor {
                pending.push(*cited);
            }
        }
    }
    wanted.into_iter().filter_map(|step| journal.entry(step)).collect()
}

/// `anchor` with its step renumbered as the recipe numbers it; `None` when
/// it cites a step the recipe does not hold.
fn renumbered(anchor: &Anchor, numbers: &BTreeMap<u64, u64>) -> Option<Anchor> {
    match anchor {
        Anchor::Step { step, path } => numbers.get(step).map(|number| Anchor::Step { step: *number, path: path.clone() }),
        other => Some(other.clone()),
    }
}

/// Drop `doc` from `params` when it names the recorded document.
fn drop_recorded_doc(params: &mut Value, entry: &JournalEntry, recorded_doc: Option<&str>) {
    let names_recorded = entry.doc.is_some() && entry.doc.as_deref() == recorded_doc;
    if let Some(fields) = params.as_object_mut()
        && names_recorded
    {
        fields.remove("doc");
    }
}

/// Drop a `selection.set`'s `cursor` at the end of the last range of
/// `recorded` (where an omitted cursor goes) when its selection is
/// anchored, so the cursor follows the anchored range.
fn drop_default_cursor(params: &mut Value, recorded: &Value) {
    if params.get("cursor").and_then(anchors::as_anchor).is_some() || anchors::anchors_in(params.get("selection").unwrap_or(&Value::Null)).is_empty() {
        return;
    }
    let selection = &recorded["selection"];
    let last_end = if let Some(range) = selection.get("range") {
        Some(range[0].as_u64().unwrap_or(0) + range[1].as_u64().unwrap_or(0))
    } else {
        selection.get("ranges").and_then(Value::as_array).and_then(|ranges| ranges.last()).map(|range| range[0].as_u64().unwrap_or(0) + range[1].as_u64().unwrap_or(0))
    };
    if let (Some(end), Some(fields)) = (last_end, params.as_object_mut())
        && fields.get("cursor").and_then(Value::as_u64) == Some(end)
    {
        fields.remove("cursor");
    }
}

// ---------------------------------------------------------------------------
// Suggesting anchors
// ---------------------------------------------------------------------------

/// An anchor a literal could be, and why.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Suggestion {
    pub anchor: Anchor,
    /// Why it fits, in plain words: "the 1st match of 7EA5".
    pub reason: String,
}

/// The anchors one literal of a step could be.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LiteralSuggestions {
    /// The parameter's path, such as `start`.
    pub path: String,
    /// The literal recorded there.
    pub value: Value,
    /// The anchor it has now, if any.
    pub anchor: Option<Anchor>,
    /// Anchors that give the same value, those that port to other files
    /// first: search matches, structure fields, findings, the selection,
    /// then earlier steps' values.
    pub suggestions: Vec<Suggestion>,
}

/// What `step`'s integer literals (or the literal at `only`) could be
/// anchored to: earlier steps' values, search matches, findings and
/// structure fields at the same offset in the step's document as it is
/// now, and the selection an earlier step set.
pub fn suggest_anchors(workspace: &mut dyn Workspace, step: u64, only: Option<&str>) -> Result<Vec<LiteralSuggestions>, ApiError> {
    let entry = workspace.journal().entry(step).cloned().ok_or_else(|| not_a_step(step))?;
    let literals = match only {
        Some(path) => vec![(path.to_string(), literal_at(workspace, step, path)?)],
        None => integer_literals(&entry.params),
    };
    let numbers: Vec<u64> = literals.iter().filter_map(|(_, value)| value.as_u64()).collect();
    let earlier = earlier_entries(workspace.journal(), step);
    let mut context = SuggestionContext { finds: find_offsets(workspace, &earlier, entry.doc.as_deref()), findings: Vec::new(), selection: earlier_selection(&earlier, entry.doc.as_deref()) };
    if let Some(doc) = entry.doc.as_deref()
        && !numbers.is_empty()
    {
        let len = api::workspace::info(workspace, doc).map_or(0, |info| info.len);
        context.findings = anchors::findings_in(workspace, doc, len, None).unwrap_or_default();
    }
    let mut suggested = Vec::new();
    for (path, value) in literals {
        let mut suggestions = Vec::new();
        if let Some(number) = value.as_u64() {
            context.suggest_finds(number, &numbers, &mut suggestions);
            context.suggest_structures(number, &numbers, &mut suggestions);
            context.suggest_findings(number, &numbers, &mut suggestions);
            context.suggest_selection(number, &mut suggestions);
        }
        suggest_steps(&earlier, &value, &mut suggestions);
        suggestions.truncate(MOST_SUGGESTIONS);
        let anchor = entry.derived_from.get(&path).cloned();
        suggested.push(LiteralSuggestions { path, value, anchor, suggestions });
    }
    Ok(suggested)
}

/// Every integer in `params` with its path, leaving out `doc`.
fn integer_literals(params: &Value) -> Vec<(String, Value)> {
    let mut found = Vec::new();
    anchors::visit_paths(params, "", &mut |path, value| {
        if value.is_u64() && path != "doc" {
            found.push((path.to_string(), value.clone()));
        }
        true
    });
    found
}

/// The successful entries and reads before `step`, the latest first.
fn earlier_entries(journal: &Journal, step: u64) -> Vec<JournalEntry> {
    let mut earlier: Vec<&JournalEntry> = journal.entries().chain(journal.reads()).filter(|entry| entry.step < step && entry.outcome.is_ok()).collect();
    earlier.sort_by_key(|entry| std::cmp::Reverse(entry.step));
    earlier.into_iter().take(EARLIER_STEPS_SEARCHED).cloned().collect()
}

/// A search an earlier step made, and where its needle matches now.
struct FoundNeedle {
    needle: Needle,
    shown: String,
    len: usize,
    /// The match offsets the step found, each with which match it is now.
    matches: Vec<(u64, usize)>,
}

/// What suggestions are drawn from.
struct SuggestionContext {
    finds: Vec<FoundNeedle>,
    findings: Vec<Finding>,
    /// The single range the latest earlier `selection.set` selected.
    selection: Option<(u64, u64)>,
}

impl SuggestionContext {
    fn suggest_finds(&self, number: u64, numbers: &[u64], suggestions: &mut Vec<Suggestion>) {
        for found in &self.finds {
            if let Some(&(_, nth)) = found.matches.iter().find(|(at, _)| *at == number) {
                let anchor = Anchor::Find { find: found.needle.clone(), nth, part: None };
                push_new(suggestions, anchor, format!("the {} match of {}", anchors::ordinal(nth), found.shown));
            } else if number == found.len as u64 && found.matches.iter().any(|(at, _)| numbers.contains(at)) {
                let nth = found.matches.iter().find(|(at, _)| numbers.contains(at)).map_or(0, |(_, nth)| *nth);
                let anchor = Anchor::Find { find: found.needle.clone(), nth, part: Some(Part::Len) };
                push_new(suggestions, anchor, format!("the length of a match of {}", found.shown));
            }
        }
    }

    fn suggest_structures(&self, number: u64, numbers: &[u64], suggestions: &mut Vec<Suggestion>) {
        for structure in self.findings.iter().filter(|finding| !finding.fields.is_empty()) {
            for (name, field) in named_fields(structure) {
                let base = Anchor::Structure { structure: structure.id.clone(), field: name.clone(), part: None };
                if field.offset as u64 == number {
                    push_new(suggestions, base, format!("where {} field {name} starts", structure.id));
                } else if field.len as u64 == number && numbers.contains(&(field.offset as u64)) {
                    push_new(suggestions, with_part(&base, Part::Len), format!("the length of {} field {name}", structure.id));
                } else if anchors::parse_integer(&field.value).and_then(|value| value.as_u64()) == Some(number) {
                    push_new(suggestions, with_part(&base, Part::Value), format!("the value of {} field {name}", structure.id));
                }
            }
        }
    }

    fn suggest_findings(&self, number: u64, numbers: &[u64], suggestions: &mut Vec<Suggestion>) {
        for finding in &self.findings {
            let starts_here = finding.start as u64 == number;
            let spans_here = finding.len as u64 == number && numbers.contains(&(finding.start as u64));
            if !starts_here && !spans_here {
                continue;
            }
            let Some(anchor) = finding_anchor(&self.findings, finding) else { continue };
            let title = if finding.title.is_empty() { finding.id.clone() } else { finding.title.clone() };
            if starts_here {
                push_new(suggestions, anchor, format!("where the finding {title} starts"));
            } else {
                push_new(suggestions, with_part(&anchor, Part::Len), format!("the length of the finding {title}"));
            }
        }
    }

    fn suggest_selection(&self, number: u64, suggestions: &mut Vec<Suggestion>) {
        let Some((start, len)) = self.selection else { return };
        let selection = Anchor::Selection { selection: SelectionWhich::Current, part: Some(Part::Offset) };
        if number == start {
            push_new(suggestions, selection, "where the selection starts".to_string());
        } else if number == len {
            push_new(suggestions, with_part(&selection, Part::Len), "the selection's length".to_string());
        }
    }
}

/// Earlier steps' values equal to `value`, the latest first.
fn suggest_steps(earlier: &[JournalEntry], value: &Value, suggestions: &mut Vec<Suggestion>) {
    let mut offered = 0;
    for entry in earlier {
        let Some(result) = &entry.result else { continue };
        let mut paths = Vec::new();
        anchors::visit_paths(result, "result", &mut |path, found| {
            let is_scalar = !found.is_object() && !found.is_array();
            if is_scalar && found == value {
                paths.push(path.to_string());
            }
            true
        });
        for path in paths {
            if offered == MOST_STEP_SUGGESTIONS {
                return;
            }
            push_new(suggestions, Anchor::Step { step: entry.step, path: path.clone() }, format!("{path} of step {} ({})", entry.step, entry.method));
            offered += 1;
        }
    }
}

fn push_new(suggestions: &mut Vec<Suggestion>, anchor: Anchor, reason: String) {
    if !suggestions.iter().any(|suggestion| suggestion.anchor == anchor) {
        suggestions.push(Suggestion { anchor, reason });
    }
}

/// The searches earlier steps made (`search.find`, `search.find_all`) on
/// document `doc`, with where their matches are now.
fn find_offsets(workspace: &mut dyn Workspace, earlier: &[JournalEntry], doc: Option<&str>) -> Vec<FoundNeedle> {
    let Some(doc) = doc else { return Vec::new() };
    let mut finds = Vec::new();
    for entry in earlier.iter().filter(|entry| entry.doc.as_deref() == Some(doc)) {
        let offsets: Vec<u64> = match entry.method.as_str() {
            "search.find" => entry.result.as_ref().and_then(|result| result["at"].as_u64()).into_iter().collect(),
            "search.find_all" => entry.result.as_ref().and_then(|result| result["matches"].as_array()).map(|matches| matches.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(),
            _ => continue,
        };
        let Some((needle, shown, bytes)) = needle_of_search(&entry.method, &entry.params) else { continue };
        let Ok((_, document)) = api::workspace::document(workspace, Some(doc)) else { break };
        // A page of search.find_all is in document order, so each match is
        // counted on from the one before.
        let mut known = None;
        let mut matches = Vec::new();
        for at in offsets {
            if let Some(nth) = nth_match(document, &bytes, at as usize, known) {
                known = Some(KnownMatch { at: at as usize, nth });
                matches.push((at, nth));
            }
        }
        finds.push(FoundNeedle { needle, shown, len: bytes.len(), matches });
    }
    finds
}

/// The needle of a `search.find` or `search.find_all` call's params, read
/// as the method reads them, how to show it, and its bytes.
fn needle_of_search(method: &str, params: &Value) -> Option<(Needle, String, Vec<u8>)> {
    let (query, mode, little_endian) = match method {
        "search.find" => {
            let params: FindParams = serde_json::from_value(params.clone()).ok()?;
            (params.query, params.mode, params.little_endian)
        }
        "search.find_all" => {
            let params: FindAllParams = serde_json::from_value(params.clone()).ok()?;
            (params.query, params.mode, params.little_endian)
        }
        _ => return None,
    };
    let bytes = api::search::needle(mode, &query, little_endian).ok()?;
    let needle = needle_of(mode, &query, &bytes);
    let shown = match &needle {
        Needle::Text(text) => format!("\"{text}\""),
        Needle::Hex(hex) => hex.clone(),
    };
    Some((needle, shown, bytes))
}

/// The single range the latest earlier `selection.set` on `doc` selected.
fn earlier_selection(earlier: &[JournalEntry], doc: Option<&str>) -> Option<(u64, u64)> {
    let set = earlier.iter().find(|entry| entry.method == "selection.set" && entry.doc.as_deref() == doc)?;
    let range = set.params["selection"].get("range")?;
    Some((range[0].as_u64()?, range[1].as_u64()?))
}

#[cfg(test)]
mod tests;
