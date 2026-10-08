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
//! **Clients** (MCP, Ask, Lua) carry provenance in band by passing anchors
//! in place of literals (`{"$anchor": …}`, `{"$var": name}`, `{"$sheet":
//! N}`), which the call resolves and records (see [`crate::api::call_as`]).
//! A client that passed a literal it took from an earlier result can say so
//! afterwards with `history.make_anchor {step, path, anchor}`, which also
//! promotes a cited read; `history.suggest_anchors` offers the anchors that
//! fit a step's literals, picks from earlier steps' lists among them.
//!
//! **Editing.** [`make_anchor`], [`make_parameter`] and [`clear_anchor`] set
//! or clear one parameter's anchor in an entry's `derived_from`;
//! [`suggest_anchors`] proposes anchors for a step's literals. The History
//! tab calls them directly, clients through the `history.*` methods in
//! `src/api/provenance.rs`.
//!
//! **The recipe with anchors** ([`build_recipe`], the one builder that
//! `history.recipe`, `history.save_recipe`, `recipes.save` and the History
//! tab share) is [`Recipe::from_journal`] of the steps recipes keep (those
//! that make sheets among them, with the steps they cite and the steps that
//! made the sheets they run on), with these rules:
//!
//! * each literal at a `derived_from` path becomes `{"$anchor": …}`; a path
//!   the params no longer hold (summarised, say) stays literal;
//! * steps are numbered 1, 2, 3… in step order, and step anchors (and the
//!   steps of picks and thens) are renumbered to match; an anchor citing a
//!   step the recipe does not hold (failed, left out or dropped) stays
//!   literal;
//! * a step that reads a variable brings the `vars.set` step that bound it,
//!   and a parameter whose default is an anchor brings the steps that
//!   anchor cites;
//! * each [`Anchor::Param`] declares its parameter: the type and default
//!   from the literal (or as `history.make_parameter` gave them), its
//!   description as given;
//! * a step's document is the one the journal recorded it ran on, not what
//!   its params said (often nothing);
//! * the recorded document is the file the steps' documents all descend
//!   from, by the sheets' lineage, not the first one named; it is left out
//!   of a step's `doc`, so the step runs on the run's document, and named
//!   `{"sheet": "input"}` anywhere else;
//! * every other document id, at any path, is a sheet an earlier step of
//!   the recipe made, named by a sheet anchor on that step
//!   (`{"sheet": {"step": 2}}`, or its label); one that is not (opened from
//!   a second file, made by a step left out) fails the recipe, naming the
//!   step and why.
//!
//! The window's own `selection.set` leaves out a cursor at the end of the
//! last range, where an omitted cursor goes, so a recipe whose selection is
//! anchored puts the cursor at the end of the range it finds.
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

use super::anchors::{self, Anchor, FindingMatch, Needle, Part, SelectionWhich, SheetRef};
use super::notes;
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
/// Most pick anchors suggested for one literal.
const MOST_PICK_SUGGESTIONS: usize = 4;
/// Most items of one list looked through for a literal.
const MOST_ITEMS_SEARCHED: usize = 100_000;
/// The shortest text, and the smallest number, a pick is suggested for:
/// shorter or smaller ones turn up in lists by chance.
const SHORTEST_PICKED_TEXT: usize = 3;
const SMALLEST_PICKED_NUMBER: u64 = 16;

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
        Anchor::Step { .. } | Anchor::Param { .. } | Anchor::Sheet { .. } | Anchor::Pick { .. } | Anchor::Then { .. } | Anchor::Var { .. } => {}
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
        let entry = self.entry_mut(step).ok_or_else(|| not_a_step(step))?;
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
/// `description`. The literal becomes the parameter's default; when an
/// anchor found it (a `vars.set` of a value picked from a list, say), that
/// anchor becomes its `default_anchor`, which finds the value again when no
/// value is given.
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
    // A value an anchor found stays found by it unless one is given.
    let default_anchor = workspace.journal().entry(step).and_then(|entry| entry.derived_from.get(path).cloned()).filter(|anchor| !matches!(anchor, Anchor::Param { .. }));
    let parameter = RecipeParameter { kind, description: description.unwrap_or_default(), default: Some(value), default_anchor };
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

/// Which steps of the journal a recipe is made of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipeSteps<'a> {
    /// The steps in effect that recipes keep, up to `through` (all of them
    /// when `None`): what `history.save_recipe` and the History tab save.
    InEffect { through: Option<u64> },
    /// The steps chosen, as `recipes.save {journal_steps}` and
    /// `history.recipe {steps}` take them.
    Chosen(&'a [u64]),
}

/// The one way a recipe is made from the journal, for `history.recipe`,
/// `history.save_recipe`, `recipes.save` and the History tab alike: the
/// steps recipes keep (those that make sheets among them), with the earlier
/// steps they cite and the steps that made the sheets they run on, each
/// recorded provenance as an anchor and each document as the recipe names
/// it (see [`Recipe::with_anchors`]). Notes linked to its steps become their
/// `note`s. It is written in format 2 only when it needs to be.
///
/// Fails, naming the step and why, when a step names a document the recipe
/// could not find again: a step of the journal not held, a second file, or
/// a sheet no step it holds made.
pub fn build_recipe(journal: &Journal, name: &str, steps: RecipeSteps<'_>) -> Result<Recipe, ApiError> {
    let chosen: Vec<u64> = match steps {
        RecipeSteps::InEffect { through } => super::timeline::entries_for_recipe(journal, through).iter().map(|entry| entry.step).collect(),
        RecipeSteps::Chosen(steps) => {
            if let Some(missing) = steps.iter().find(|step| journal.entry(**step).is_none()) {
                return Err(not_a_step(*missing));
            }
            steps.iter().copied().filter(|step| journal.entry(*step).is_some_and(super::timeline::is_kept_by_recipes)).collect()
        }
    };
    let lineage = SheetLineage::of(journal);
    let entries: Vec<&JournalEntry> = with_cited_steps_and_sheets(journal, &chosen, &lineage).into_iter().filter(|entry| !entry.is_note()).collect();
    // The recipe's steps are the successful entries, in step order.
    let recorded: Vec<u64> = entries.iter().filter(|entry| entry.outcome.is_ok()).map(|entry| entry.step).collect();
    let mut recipe = Recipe::with_anchors(name, journal.session(), entries, journal.parameters(), &lineage)?;
    notes::attach_to_recipe(&mut recipe, journal, &recorded);
    recipe.settle_format();
    Ok(recipe)
}

/// Where each sheet of the session came from, as the journal recorded it:
/// the step that made it, from which document, and which of the sheets it
/// made it was; and the documents opened by steps recipes do not repeat.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SheetLineage {
    made: BTreeMap<String, Maker>,
    /// The documents steps opened (a file, a source, a new document), and
    /// by which step and method.
    opened: BTreeMap<String, (u64, String)>,
    /// The parent of each document the session saw that was derived from
    /// another, as the workspace said: a sheet no step made has one too.
    derived: BTreeMap<String, String>,
}

/// The step that made a sheet.
#[derive(Clone, Debug, PartialEq)]
struct Maker {
    step: u64,
    method: String,
    /// The document it was made from.
    parent: Option<String>,
    /// Which of the sheets the step made, from 0.
    nth: usize,
    /// The label the step gave it, if any.
    label: Option<String>,
}

impl SheetLineage {
    /// The lineage of every sheet `journal`'s successful steps made.
    pub fn of(journal: &Journal) -> Self {
        let mut lineage = SheetLineage::default();
        for document in &journal.session().documents {
            if let Some(parent) = &document.parent {
                lineage.derived.insert(document.id.clone(), parent.clone());
            }
        }
        for entry in journal.entries().filter(|entry| entry.outcome.is_ok()) {
            let labels: Vec<Option<String>> = entry.result.as_ref().map(super::sheets_made).unwrap_or_default().into_iter().map(|sheet| sheet.label).collect();
            for (nth, doc) in entry.made.iter().enumerate() {
                let label = labels.get(nth).cloned().flatten();
                lineage.made.insert(doc.clone(), Maker { step: entry.step, method: entry.method.clone(), parent: entry.doc.clone(), nth, label });
            }
            if matches!(super::timeline::replay_of_entry(entry), super::timeline::Replay::OpensDocument { .. })
                && let Some(opened) = entry.result.as_ref().and_then(opened_id)
            {
                lineage.opened.entry(opened).or_insert((entry.step, entry.method.clone()));
            }
        }
        lineage
    }

    /// The document `doc` descends from that no step made: the file (or
    /// source, or new document) it all came from.
    pub fn root_of(&self, doc: &str) -> String {
        let mut current = doc.to_string();
        let mut seen = BTreeSet::new();
        while let Some(parent) = self.made.get(&current).and_then(|maker| maker.parent.clone()).or_else(|| self.derived.get(&current).cloned()) {
            if !seen.insert(current.clone()) {
                break;
            }
            current = parent;
        }
        current
    }

    /// The step that made sheet `doc`, if a step did.
    pub fn maker_of(&self, doc: &str) -> Option<u64> {
        self.made.get(doc).map(|maker| maker.step)
    }

    /// The sheets as a run's anchors name them: by the step that made them,
    /// and by label.
    pub fn as_run_sheets(&self) -> anchors::RunSheets {
        let mut sheets = anchors::RunSheets::default();
        for (doc, maker) in &self.made {
            let made = sheets.made.entry(maker.step).or_default();
            made.push(doc.clone());
            if let Some(label) = &maker.label {
                sheets.labels.insert(label.clone(), doc.clone());
            }
        }
        sheets
    }
}

/// The id of the document a step that opens one opened, as its result
/// gives it: `id`, or `document.id`.
fn opened_id(result: &Value) -> Option<String> {
    let id = result.get("id").or_else(|| result.get("document").and_then(|document| document.get("id")));
    id.and_then(Value::as_str).map(str::to_string)
}

/// Whether a step of `method` called with `params` takes a `doc`: as the
/// method table says, or, for a plugin's method, as its params show.
fn takes_doc(method: &str, params: &Value) -> bool {
    api::method(method).map_or_else(|| params.get("doc").is_some(), |method| method.takes_doc)
}

/// The documents `entry` is about, each with where it names it: its `doc`
/// (from the entry, as the call resolved it, for a method that takes one),
/// and every other document id in its params outside the paths its
/// provenance anchors.
fn documents_named(entry: &JournalEntry) -> Vec<(String, String)> {
    let mut named = Vec::new();
    if takes_doc(&entry.method, &entry.params)
        && let Some(doc) = &entry.doc
    {
        named.push(("doc".to_string(), doc.clone()));
    }
    anchors::visit_paths(&entry.params, "", &mut |path, value| {
        if path == "doc" || entry.derived_from.contains_key(path) || anchors::as_anchor(value).is_some() {
            return false;
        }
        if let Some(id) = value.as_str().filter(|text| anchors::is_document_id(text)) {
            named.push((path.to_string(), id.to_string()));
        }
        true
    });
    named
}

/// Why a step's document could not be named in a recipe.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DocumentProblem {
    /// The session's step.
    pub step: u64,
    pub method: String,
    /// Where in its params it names the document.
    pub path: String,
    pub doc: String,
    /// Why it would not replay.
    pub reason: String,
}

impl DocumentProblem {
    fn describe(&self) -> String {
        format!("step {} ({}) names {} at {}: {}", self.step, self.method, self.doc, self.path, self.reason)
    }
}

impl Recipe {
    /// A recipe called `name` of the successful calls in `entries`, with
    /// each recorded provenance as an anchor and each document named as a
    /// recipe can find it again (see the module's rules), `declared`
    /// describing the parameters named and `lineage` saying where each
    /// sheet came from.
    pub fn with_anchors<'a>(
        name: &str,
        session: &JournalSession,
        entries: impl IntoIterator<Item = &'a JournalEntry>,
        declared: &BTreeMap<String, RecipeParameter>,
        lineage: &SheetLineage,
    ) -> Result<Recipe, ApiError> {
        let mut entries: Vec<&JournalEntry> = entries.into_iter().filter(|entry| entry.outcome.is_ok()).collect();
        entries.sort_by_key(|entry| entry.step);
        let root = recorded_root(&entries, lineage, session)?;
        let mut recipe = Recipe::from_journal(name, session, entries.iter().copied());
        if let Some(root) = &root {
            recipe.recorded_on = session.document(root).map(|document| document.file());
        }
        let numbers: BTreeMap<u64, u64> = entries.iter().zip(1..).map(|(entry, number)| (entry.step, number)).collect();
        let mut problems = Vec::new();
        for (step, entry) in recipe.steps.iter_mut().zip(&entries) {
            step.step = numbers[&entry.step];
            for (path, anchor) in &entry.derived_from {
                let Some(anchor) = renumbered(anchor, &numbers) else { continue };
                let Ok(Some(literal)) = anchors::value_at(&step.params, path).map(|value| value.cloned()) else { continue };
                if let Anchor::Param { param } = &anchor {
                    let Some(kind) = parameter_type_of(&literal) else { continue };
                    let mut parameter = declared.get(param).cloned().unwrap_or(RecipeParameter { kind, description: String::new(), default: Some(literal.clone()), default_anchor: None });
                    parameter.default_anchor = parameter.default_anchor.as_ref().and_then(|default| renumbered(default, &numbers));
                    recipe.parameters.entry(param.clone()).or_insert(parameter);
                }
                let _ = anchors::replace_at(&mut step.params, path, anchors::marked(&anchor));
            }
            if !made_by_a_recipe(&entry.method) {
                step.makes = entry.made.iter().find_map(|doc| lineage.made.get(doc).and_then(|maker| maker.label.clone()));
            }
            name_documents(step, entry, root.as_deref(), lineage, &numbers, &mut problems);
            name_jobs(step, entry, &entries, &numbers);
        }
        if !problems.is_empty() {
            let listed: Vec<String> = problems.iter().map(DocumentProblem::describe).collect();
            let message = format!("the recipe would not replay: {}", listed.join("; "));
            return Err(ApiError::invalid_params(message).with_data(serde_json::json!({ "problems": problems })));
        }
        Ok(recipe)
    }
}

/// The file the recipe's steps all descend from, by the lineage of the
/// documents they name: the run's input. `None` when they name none.
/// Steps that descend from two files cannot make one recipe.
fn recorded_root(entries: &[&JournalEntry], lineage: &SheetLineage, session: &JournalSession) -> Result<Option<String>, ApiError> {
    let mut roots: Vec<(String, &JournalEntry)> = Vec::new();
    for entry in entries {
        for (_, doc) in documents_named(entry) {
            let root = lineage.root_of(&doc);
            if !roots.iter().any(|(known, _)| *known == root) {
                roots.push((root, entry));
            }
        }
    }
    match roots.as_slice() {
        [] => Ok(None),
        [(root, _)] => Ok(Some(root.clone())),
        [(first, _), (second, by), ..] => {
            let named = |doc: &str| session.document(doc).map_or_else(|| doc.to_string(), |document| format!("{} ({doc})", document.file().name));
            let message = format!(
                "the recipe would not replay: its steps run on two files, {} and {} (from step {}, {}); a recipe runs on one, so save the steps about one of them (recipes.save and history.recipe take the steps to keep)",
                named(first),
                named(second),
                by.step,
                by.method
            );
            Err(ApiError::invalid_params(message))
        }
    }
}

/// Name each document `entry` is about in its recipe `step`'s params as a
/// recipe finds it again: the step's own `doc` from the entry, not its
/// params; the input left out of `doc` (the run's document) or a
/// `{"sheet": "input"}` anchor elsewhere; a sheet a step of the recipe made
/// as a sheet anchor on that step (by its label, when it has one). Any
/// other document is a problem, said in `problems`.
fn name_documents(step: &mut super::recipe::RecipeStep, entry: &JournalEntry, root: Option<&str>, lineage: &SheetLineage, numbers: &BTreeMap<u64, u64>, problems: &mut Vec<DocumentProblem>) {
    for (path, doc) in documents_named(entry) {
        let replacement = if Some(doc.as_str()) == root {
            None
        } else {
            match sheet_anchor(&doc, entry, lineage, numbers) {
                Ok(anchor) => Some(anchor),
                Err(reason) => {
                    problems.push(DocumentProblem { step: entry.step, method: entry.method.clone(), path, doc, reason });
                    continue;
                }
            }
        };
        match (replacement, path.as_str()) {
            (None, "doc") => {
                if let Some(fields) = step.params.as_object_mut() {
                    fields.remove("doc");
                }
            }
            (None, _) => {
                let _ = anchors::replace_at(&mut step.params, &path, anchors::marked(&Anchor::Sheet { sheet: SheetRef::Named(anchors::INPUT.to_string()) }));
            }
            (Some(anchor), "doc") => {
                if let Some(fields) = step.params.as_object_mut() {
                    fields.insert("doc".to_string(), anchors::marked(&anchor));
                }
            }
            (Some(anchor), _) => {
                let _ = anchors::replace_at(&mut step.params, &path, anchors::marked(&anchor));
            }
        }
    }
}

/// Name each job `entry`'s params give by its id (`candidate.job` of a
/// `crypto.apply`, say) as a step anchor on the step of the recipe that
/// started it, so a run uses the job its own step started. A job no step
/// of the recipe started stays literal.
fn name_jobs(step: &mut super::recipe::RecipeStep, entry: &JournalEntry, entries: &[&JournalEntry], numbers: &BTreeMap<u64, u64>) {
    let mut jobs = Vec::new();
    anchors::visit_paths(&step.params, "", &mut |path, value| {
        if anchors::as_anchor(value).is_some() {
            return false;
        }
        if (path == "job" || path.ends_with(".job"))
            && let Some(job) = value.as_str()
        {
            jobs.push((path.to_string(), job.to_string()));
        }
        true
    });
    for (path, job) in jobs {
        let started = entries.iter().filter(|earlier| earlier.step < entry.step).find(|earlier| earlier.result.as_ref().and_then(|result| result.get("job")).and_then(Value::as_str) == Some(job.as_str()));
        if let Some(number) = started.and_then(|earlier| numbers.get(&earlier.step)) {
            let _ = anchors::replace_at(&mut step.params, &path, anchors::marked(&Anchor::Step { step: *number, path: "result.job".to_string() }));
        }
    }
}

/// Whether a step of `method` runs a recipe, whose sheets carry the labels
/// that recipe gave them.
fn made_by_a_recipe(method: &str) -> bool {
    method == "recipes.run"
}

/// The sheet anchor that names `doc`, a sheet an earlier step of the recipe
/// made, in `entry`'s step; or why there is none.
fn sheet_anchor(doc: &str, entry: &JournalEntry, lineage: &SheetLineage, numbers: &BTreeMap<u64, u64>) -> Result<Anchor, String> {
    let Some(maker) = lineage.made.get(doc) else {
        return Err(match (lineage.opened.get(doc), lineage.derived.get(doc)) {
            (Some((step, method)), _) => format!("step {step} ({method}) opened it, and a recipe does not open files: it runs on the one it is given"),
            (None, Some(parent)) => format!("it was derived from {parent} outside the history, not by a step, so a recipe cannot make it again"),
            (None, None) => "no step of this session made it, so a recipe cannot make it again".to_string(),
        });
    };
    if maker.step >= entry.step {
        return Err(format!("it was made by step {} ({}), after this one", maker.step, maker.method));
    }
    let Some(number) = numbers.get(&maker.step) else {
        return Err(format!("it was made by step {} ({}), which the recipe does not hold: it was undone, failed or is not among the steps saved", maker.step, maker.method));
    };
    let sheet = match &maker.label {
        // A recipe's labels are its own: they name its sheets only beside
        // the recipes.run step that ran it.
        Some(label) if made_by_a_recipe(&maker.method) => SheetRef::Labelled { step: *number, label: label.clone() },
        Some(label) => SheetRef::Named(label.clone()),
        None => SheetRef::Step { step: *number, nth: maker.nth },
    };
    Ok(Anchor::Sheet { sheet })
}

/// The entries numbered `steps`, and every earlier entry their anchors
/// cite (and those cite), in step order.
pub fn with_cited_steps<'a>(journal: &'a Journal, steps: &[u64]) -> Vec<&'a JournalEntry> {
    with_cited_steps_and_sheets(journal, steps, &SheetLineage::default())
}

/// [`with_cited_steps`], and the steps in effect that made the sheets they
/// name (and those sheets' parents), so a recipe makes them again. An anchor
/// cites the steps its step and pick anchors read, the step that made the
/// sheet a sheet anchor names, the `vars.set` step that
/// bound a variable it reads, and, for a parameter whose default is an
/// anchor, the steps that anchor cites.
fn with_cited_steps_and_sheets<'a>(journal: &'a Journal, steps: &[u64], lineage: &SheetLineage) -> Vec<&'a JournalEntry> {
    let timeline = journal.timeline();
    let sheets = lineage.as_run_sheets();
    let mut wanted: BTreeSet<u64> = BTreeSet::new();
    let mut pending: Vec<u64> = steps.to_vec();
    while let Some(step) = pending.pop() {
        let Some(entry) = journal.entry(step) else { continue };
        if !wanted.insert(step) {
            continue;
        }
        for anchor in entry.derived_from.values() {
            let default = match anchor {
                Anchor::Param { param } => journal.parameters().get(param).and_then(|parameter| parameter.default_anchor.clone()),
                _ => None,
            };
            for anchor in std::iter::once(anchor).chain(default.as_ref()) {
                if let Anchor::Sheet { sheet: SheetRef::Step { step: maker, .. } | SheetRef::Labelled { step: maker, .. } } = anchor {
                    pending.push(*maker);
                }
                pending.extend(anchor.cited_steps(&sheets));
                pending.extend(anchor.variables().iter().filter_map(|name| binding_step(journal, name, step)));
            }
        }
        for (_, doc) in documents_named(entry) {
            if let Some(maker) = lineage.maker_of(&doc).filter(|maker| *maker < step && timeline.is_active(*maker)) {
                pending.push(maker);
            }
        }
    }
    wanted.into_iter().filter_map(|step| journal.entry(step)).collect()
}

/// The latest step in effect before `before` that bound variable `name`
/// with `vars.set`.
fn binding_step(journal: &Journal, name: &str, before: u64) -> Option<u64> {
    let timeline = journal.timeline();
    journal
        .entries()
        .rev()
        .filter(|entry| entry.step < before && entry.method == "vars.set" && entry.outcome.is_ok() && timeline.is_active(entry.step))
        .find(|entry| entry.params.get("name").and_then(Value::as_str) == Some(name))
        .map(|entry| entry.step)
}

/// `anchor` with its steps renumbered as the recipe numbers them; `None`
/// when it cites a step the recipe does not hold.
fn renumbered(anchor: &Anchor, numbers: &BTreeMap<u64, u64>) -> Option<Anchor> {
    anchor.renumbered(&|step| numbers.get(&step).copied())
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
/// now, the selection an earlier step set, and items of lists earlier
/// steps returned (strings, keys, candidates), chosen by what they hold.
/// Its text literals are listed too when an earlier list holds them.
pub fn suggest_anchors(workspace: &mut dyn Workspace, step: u64, only: Option<&str>) -> Result<Vec<LiteralSuggestions>, ApiError> {
    let entry = workspace.journal().entry(step).cloned().ok_or_else(|| not_a_step(step))?;
    let earlier = earlier_entries(workspace.journal(), step);
    let lists = earlier_lists(workspace, &earlier);
    let literals = match only {
        Some(path) => vec![(path.to_string(), literal_at(workspace, step, path)?)],
        None => {
            let mut literals = integer_literals(&entry.params);
            literals.extend(text_literals(&entry.params).into_iter().filter(|(_, value)| lists.iter().any(|list| list.position_of(value).is_some())));
            literals
        }
    };
    let numbers: Vec<u64> = literals.iter().filter_map(|(_, value)| value.as_u64()).collect();
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
        suggest_picks(&lists, &value, &mut suggestions);
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

/// Every text in `params` with its path, leaving out `doc`.
fn text_literals(params: &Value) -> Vec<(String, Value)> {
    let mut found = Vec::new();
    anchors::visit_paths(params, "", &mut |path, value| {
        if value.is_string() && path != "doc" {
            found.push((path.to_string(), value.clone()));
        }
        true
    });
    found
}

/// A list of items an earlier step returned, such as `job.strings`.
struct EarlierList {
    step: u64,
    method: String,
    /// Where it is in the step's `{"params", "result", "job"}`.
    path: String,
    items: Vec<Value>,
}

impl EarlierList {
    /// The first item with a field holding `value`, and that field.
    fn position_of(&self, value: &Value) -> Option<(usize, String)> {
        let picked = match value {
            Value::String(text) => text.chars().count() >= SHORTEST_PICKED_TEXT,
            Value::Number(number) => number.as_u64().is_some_and(|number| number >= SMALLEST_PICKED_NUMBER),
            _ => false,
        };
        if !picked {
            return None;
        }
        self.items.iter().take(MOST_ITEMS_SEARCHED).enumerate().find_map(|(index, item)| {
            let fields = item.as_object()?;
            fields.iter().find(|(_, field)| *field == value).map(|(name, _)| (index, name.clone()))
        })
    }

    /// The first item that passes `condition`, if any.
    fn first_passing(&self, condition: &serde_json::Map<String, Value>) -> Option<usize> {
        self.items.iter().take(MOST_ITEMS_SEARCHED).position(|item| anchors::pick::passes(item, condition).unwrap_or(false))
    }
}

/// The lists of items (objects) in what `earlier` steps were given and
/// returned, a finished job's result among them.
fn earlier_lists(workspace: &mut dyn Workspace, earlier: &[JournalEntry]) -> Vec<EarlierList> {
    let mut lists = Vec::new();
    for entry in earlier {
        let mut value = entry_value(entry);
        if let Some(job) = entry.result.as_ref().and_then(|result| result.get("job")).and_then(Value::as_str)
            && let Some(result) = workspace.bus().jobs().status(job).and_then(|status| status.result)
        {
            value["job"] = result;
        }
        anchors::visit_paths(&value, "", &mut |path, found| {
            if let Some(items) = found.as_array().filter(|items| items.first().is_some_and(Value::is_object)) {
                lists.push(EarlierList { step: entry.step, method: entry.method.clone(), path: path.to_string(), items: items.clone() });
                return false;
            }
            true
        });
    }
    lists
}

/// Pick anchors for `value` from the lists earlier steps returned: by a
/// pattern its text fits, by its item's tag, or by its place in the list.
fn suggest_picks(lists: &[EarlierList], value: &Value, suggestions: &mut Vec<Suggestion>) {
    let mut offered = 0;
    for list in lists {
        let Some((index, field)) = list.position_of(value) else { continue };
        let pick = |condition: Option<serde_json::Map<String, Value>>, nth: usize| Anchor::Pick {
            pick: anchors::Pick { step: anchors::StepRef::Number(list.step), list: list.path.clone(), condition, sort: None, nth, field: Some(field.clone()) },
        };
        let whose = format!("{} of step {} ({})", list.path, list.step, list.method);
        let mut offers = Vec::new();
        if let Some(pattern) = value.as_str().and_then(shape_of) {
            let condition = serde_json::Map::from_iter([(field.clone(), serde_json::json!({ "regex": pattern }))]);
            if list.first_passing(&condition) == Some(index) {
                offers.push((pick(Some(condition), 0), format!("the first {field} in {whose} matching /{pattern}/")));
            }
        }
        if let Some(tag) = list.items[index].get("tag").filter(|tag| tag.is_string()) {
            let condition = serde_json::Map::from_iter([("tag".to_string(), tag.clone())]);
            if list.first_passing(&condition) == Some(index) {
                offers.push((pick(Some(condition), 0), format!("the {field} of the first item in {whose} tagged {}", tag.as_str().unwrap_or_default())));
            }
        }
        offers.push((pick(None, index), format!("the {field} of the {} item in {whose}", anchors::ordinal(index))));
        for (anchor, reason) in offers {
            if offered == MOST_PICK_SUGGESTIONS {
                return;
            }
            push_new(suggestions, anchor, reason);
            offered += 1;
        }
    }
}

/// A pattern for text of the same shape as `text`, which finds such text
/// again in another file: what comes up to its last separator as it is,
/// then the kind and number of characters after it (`NC500-2F357657` is
/// `^NC500-[0-9A-F]{8}$`); or, for hex with no separator, hex of its
/// length. `None` for text with neither.
pub fn shape_of(text: &str) -> Option<String> {
    let separator = text.char_indices().rev().find(|(_, character)| matches!(character, '-' | '_' | ':' | '=' | '/' | '.' | ' ')).map(|(at, character)| at + character.len_utf8());
    let (prefix, tail) = match separator {
        Some(at) => text.split_at(at),
        None => ("", text),
    };
    let count = tail.chars().count();
    if count < 4 || !tail.chars().all(|character| character.is_ascii_alphanumeric()) {
        return None;
    }
    let class = if tail.chars().all(|character| character.is_ascii_digit()) {
        "[0-9]"
    } else if tail.chars().all(|character| character.is_ascii_digit() || ('A'..='F').contains(&character)) {
        "[0-9A-F]"
    } else if tail.chars().all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()) {
        "[0-9a-f]"
    } else if prefix.is_empty() {
        return None;
    } else {
        "[0-9A-Za-z]"
    };
    Some(format!("^{}{class}{{{count}}}$", regex_lite::escape(prefix)))
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
