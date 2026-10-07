//! Message alignment and clustering for protocol reverse engineering, in the
//! style of Netzob.
//!
//! 1. **Clustering.** Messages are compared pairwise by the identity of their
//!    global (Needleman–Wunsch) alignment over a bounded prefix, then grouped
//!    by average-linkage (UPGMA) agglomerative clustering with a threshold.
//!    Each cluster is a guess at one message type.
//! 2. **Multiple alignment.** Within a cluster, messages are added one by one
//!    to a growing alignment, each aligned against the current consensus;
//!    gaps open new columns where needed.
//! 3. **Column classes.** Each aligned column is classed as constant, a
//!    length (its value follows the message length), a counter (it steps by
//!    a fixed amount from message to message) or variable, and runs of one
//!    class are proposed as fields.
//!
//! All work is bounded (messages clustered, messages aligned per cluster,
//! bytes aligned per message, columns) and every cap leaves a note.

use crate::protocol::Message;

/// Score for aligning two equal bytes.
pub const MATCH_SCORE: i32 = 2;
/// Score for aligning two different bytes.
pub const MISMATCH_SCORE: i32 = -1;
/// Score for aligning a byte against a gap.
pub const GAP_SCORE: i32 = -2;

/// Most messages clustered against one another: past it, an even sample
/// across the set is clustered and every other message joins the type it
/// is most like, with a note.
pub const MAX_CLUSTERED_MESSAGES: usize = 256;
/// Most types the messages left out of the sample may add, when one is
/// like none of the types the sample found.
const MAX_ADDED_CLUSTERS: usize = 64;
/// Bytes of each message compared when measuring similarity.
pub const SIMILARITY_PREFIX: usize = 64;
/// Most messages aligned in one cluster.
pub const MAX_ALIGNED_PER_CLUSTER: usize = 64;
/// Bytes of each message aligned.
pub const MAX_ALIGNED_LEN: usize = 512;
/// Most columns an alignment may grow to.
pub const MAX_COLUMNS: usize = 1024;
/// Default similarity (0..=1) above which clusters merge.
pub const DEFAULT_CLUSTER_THRESHOLD: f64 = 0.5;

/// Fewest rows before a column can be called a counter or a length.
const MIN_ROWS_FOR_PATTERN: usize = 3;
/// Share of consecutive steps that must agree for a counter.
const COUNTER_AGREEMENT: f64 = 0.8;
/// Correlation with message length needed for a length field.
const LENGTH_CORRELATION: f64 = 0.95;
/// Distinct byte values.
const BYTE_VALUES: usize = 256;

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// The bytes of each message found by the protocol analysis.
/// `bytes` is the stream the messages' offsets refer to; messages that run
/// past its end are cut short.
pub fn messages_from_protocol(bytes: &[u8], messages: &[Message]) -> Vec<Vec<u8>> {
    messages
        .iter()
        .map(|message| {
            let start = message.offset.min(bytes.len());
            let end = message.offset.saturating_add(message.len).min(bytes.len());
            bytes[start..end].to_vec()
        })
        .collect()
}

/// Cut `bytes` into records of `record_len` bytes (the last may be shorter).
pub fn split_into_records(bytes: &[u8], record_len: usize) -> Vec<Vec<u8>> {
    if record_len == 0 {
        return Vec::new();
    }
    bytes.chunks(record_len).map(<[u8]>::to_vec).collect()
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// What an aligned column looks like across the messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ColumnClass {
    /// The same byte in every message that has one here.
    Constant,
    /// Changes by a fixed step from one message to the next.
    Counter,
    /// Follows the message length.
    Length,
    /// Anything else.
    Variable,
}

impl ColumnClass {
    /// A short name for display.
    pub fn label(self) -> &'static str {
        match self {
            ColumnClass::Constant => "constant",
            ColumnClass::Counter => "counter",
            ColumnClass::Length => "length",
            ColumnClass::Variable => "variable",
        }
    }
}

/// A byte placed in the alignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlignedByte {
    /// Position of the byte within its message.
    pub position: usize,
    pub value: u8,
}

/// One message laid out across the aligned columns; `None` is a gap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlignedRow {
    /// Index of the message in the input list.
    pub message: usize,
    pub cells: Vec<Option<AlignedByte>>,
}

/// A multiple alignment: every row has the same number of cells.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Alignment {
    pub rows: Vec<AlignedRow>,
}

impl Alignment {
    /// Number of aligned columns.
    pub fn columns(&self) -> usize {
        self.rows.first().map_or(0, |row| row.cells.len())
    }

    /// The most common byte in each column, ignoring gaps.
    pub fn consensus(&self) -> Vec<Option<u8>> {
        (0..self.columns()).map(|column| most_common(self.rows.iter().filter_map(|row| row.cells[column].map(|c| c.value)))).collect()
    }
}

/// The class of one aligned column and why.
#[derive(Clone, Debug, PartialEq)]
pub struct ColumnSummary {
    pub class: ColumnClass,
    /// Rows with a byte (not a gap) in this column.
    pub present: usize,
    /// Distinct values among them.
    pub distinct: usize,
    /// Evidence, e.g. "step +2" or "value = length − 4".
    pub detail: String,
}

/// A run of adjacent columns of one class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposedField {
    pub start_column: usize,
    pub len: usize,
    pub class: ColumnClass,
}

/// One cluster (a probable message type) and its alignment.
#[derive(Clone, Debug, PartialEq)]
pub struct ClusterReport {
    /// Indices of every message in the cluster.
    pub members: Vec<usize>,
    /// Alignment of the first `MAX_ALIGNED_PER_CLUSTER` members.
    pub alignment: Alignment,
    pub columns: Vec<ColumnSummary>,
    pub fields: Vec<ProposedField>,
    /// Caps that applied to this cluster.
    pub notes: Vec<String>,
}

/// Clusters, largest first, and caveats.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AlignmentReport {
    pub clusters: Vec<ClusterReport>,
    pub notes: Vec<String>,
}

/// Settings for [`analyse`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AlignmentOptions {
    /// Similarity (0..=1) above which clusters merge; higher splits more.
    pub threshold: f64,
}

impl Default for AlignmentOptions {
    fn default() -> Self {
        AlignmentOptions { threshold: DEFAULT_CLUSTER_THRESHOLD }
    }
}

// ---------------------------------------------------------------------------
// Whole analysis
// ---------------------------------------------------------------------------

/// `count` indices spread evenly over `0..total`, first and last
/// included; every index when there are no more than `count`.
pub fn even_sample(total: usize, count: usize) -> Vec<usize> {
    if total <= count {
        return (0..total).collect();
    }
    if count <= 1 {
        return vec![0; count.min(total)];
    }
    let mut sample: Vec<usize> = (0..count).map(|step| step * (total - 1) / (count - 1)).collect();
    sample.dedup();
    sample
}

/// Cluster the messages, align each cluster and classify its columns.
/// Past [`MAX_CLUSTERED_MESSAGES`], an even sample across the whole set is
/// clustered, and every other message then joins the cluster whose first
/// member it is most like, or starts one of its own when it is like none,
/// so a type that turns up only late in the set is still found.
pub fn analyse(messages: &[Vec<u8>], options: &AlignmentOptions) -> AlignmentReport {
    let mut notes = Vec::new();
    let slices: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    if slices.is_empty() {
        notes.push("No messages to align.".to_string());
        return AlignmentReport { clusters: Vec::new(), notes };
    }
    let sample = even_sample(slices.len(), MAX_CLUSTERED_MESSAGES);
    let sampled: Vec<&[u8]> = sample.iter().map(|&index| slices[index]).collect();
    let mut groups: Vec<Vec<usize>> = cluster(&sampled, options.threshold).into_iter().map(|members| members.into_iter().map(|member| sample[member]).collect()).collect();
    if sample.len() < slices.len() {
        let added = join_the_rest(&slices, &sample, &mut groups, options.threshold);
        let types = if added > 0 { format!(", and {added} that were like none of them started types of their own") } else { String::new() };
        notes.push(format!(
            "Clustered an even sample of {} of the {} messages, from across the whole set; the other {} each joined the type they were most like{types}.",
            sample.len(),
            slices.len(),
            slices.len() - sample.len()
        ));
        for members in &mut groups {
            members.sort_unstable();
        }
        groups.sort_by(|a, b| b.len().cmp(&a.len()).then(a[0].cmp(&b[0])));
    }
    let clusters = groups.into_iter().map(|members| analyse_cluster(&slices, members)).collect();
    AlignmentReport { clusters, notes }
}

/// Put every message not in `sample` into the group whose first member it
/// is most like, or into a new group when it is like none (up to
/// [`MAX_ADDED_CLUSTERS`] new ones). Returns how many groups were added.
fn join_the_rest(messages: &[&[u8]], sample: &[usize], groups: &mut Vec<Vec<usize>>, threshold: f64) -> usize {
    let in_sample: std::collections::HashSet<usize> = sample.iter().copied().collect();
    let mut representatives: Vec<usize> = groups.iter().filter_map(|members| members.first().copied()).collect();
    let mut added = 0;
    for index in (0..messages.len()).filter(|index| !in_sample.contains(index)) {
        let best = representatives.iter().enumerate().map(|(group, &representative)| (group, similarity(messages[index], messages[representative]))).max_by(|a, b| a.1.total_cmp(&b.1));
        match best {
            Some((group, likeness)) if likeness >= threshold || added >= MAX_ADDED_CLUSTERS => groups[group].push(index),
            _ => {
                groups.push(vec![index]);
                representatives.push(index);
                added += 1;
            }
        }
    }
    added
}

fn analyse_cluster(messages: &[&[u8]], members: Vec<usize>) -> ClusterReport {
    let mut notes = Vec::new();
    let aligned: Vec<usize> = even_sample(members.len(), MAX_ALIGNED_PER_CLUSTER).into_iter().map(|position| members[position]).collect();
    if members.len() > aligned.len() {
        notes.push(format!("Aligned an even sample of {} of its {} messages.", aligned.len(), members.len()));
    }
    if aligned.iter().any(|&index| messages[index].len() > MAX_ALIGNED_LEN) {
        notes.push(format!("Messages longer than {MAX_ALIGNED_LEN} bytes were aligned on their first {MAX_ALIGNED_LEN} bytes."));
    }
    let (alignment, alignment_notes) = align_messages(messages, &aligned);
    notes.extend(alignment_notes);
    let lengths: Vec<usize> = alignment.rows.iter().map(|row| messages[row.message].len()).collect();
    let columns = classify_columns(&alignment, &lengths);
    let fields = propose_fields(&columns);
    ClusterReport { members, alignment, columns, fields, notes }
}

// ---------------------------------------------------------------------------
// Similarity and clustering
// ---------------------------------------------------------------------------

/// Share (0..=1) of aligned positions holding equal bytes in the global
/// alignment of the first `SIMILARITY_PREFIX` bytes of each message.
pub fn similarity(a: &[u8], b: &[u8]) -> f64 {
    let a = &a[..a.len().min(SIMILARITY_PREFIX)];
    let b = &b[..b.len().min(SIMILARITY_PREFIX)];
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    // Each DP cell keeps (score, matches, aligned length); best score wins,
    // more matches break ties.
    type Cell = (i32, u32, u32);
    let better = |x: Cell, y: Cell| if (y.0, y.1) > (x.0, x.1) { y } else { x };
    let mut previous: Vec<Cell> = (0..=b.len()).map(|j| (GAP_SCORE * j as i32, 0, j as u32)).collect();
    for (i, &byte_a) in a.iter().enumerate() {
        let mut current: Vec<Cell> = Vec::with_capacity(b.len() + 1);
        current.push((GAP_SCORE * (i as i32 + 1), 0, i as u32 + 1));
        for (j, &byte_b) in b.iter().enumerate() {
            let diagonal = previous[j];
            let matched = byte_a == byte_b;
            let pair_score = if matched { MATCH_SCORE } else { MISMATCH_SCORE };
            let from_diagonal = (diagonal.0 + pair_score, diagonal.1 + u32::from(matched), diagonal.2 + 1);
            let from_above = (previous[j + 1].0 + GAP_SCORE, previous[j + 1].1, previous[j + 1].2 + 1);
            let from_left = (current[j].0 + GAP_SCORE, current[j].1, current[j].2 + 1);
            current.push(better(better(from_diagonal, from_above), from_left));
        }
        previous = current;
    }
    let (_, matches, aligned_len) = previous[b.len()];
    f64::from(matches) / f64::from(aligned_len.max(1))
}

/// Group messages by average-linkage clustering: repeatedly merge the two
/// most similar clusters while their average similarity reaches
/// `threshold`. Clusters come back largest first, members in input order.
pub fn cluster(messages: &[&[u8]], threshold: f64) -> Vec<Vec<usize>> {
    let count = messages.len().min(MAX_CLUSTERED_MESSAGES);
    let mut similarities = vec![vec![0.0f64; count]; count];
    for i in 0..count {
        for j in i + 1..count {
            let value = similarity(messages[i], messages[j]);
            similarities[i][j] = value;
            similarities[j][i] = value;
        }
    }
    let mut clusters: Vec<Option<Vec<usize>>> = (0..count).map(|i| Some(vec![i])).collect();
    while let Some((i, j, value)) = most_similar_pair(&clusters, &similarities) {
        if value < threshold {
            break;
        }
        merge_clusters(&mut clusters, &mut similarities, i, j);
    }
    let mut result: Vec<Vec<usize>> = clusters
        .into_iter()
        .flatten()
        .map(|mut members| {
            members.sort_unstable();
            members
        })
        .collect();
    result.sort_by(|a, b| b.len().cmp(&a.len()).then(a[0].cmp(&b[0])));
    result
}

fn most_similar_pair(clusters: &[Option<Vec<usize>>], similarities: &[Vec<f64>]) -> Option<(usize, usize, f64)> {
    let active: Vec<usize> = (0..clusters.len()).filter(|&i| clusters[i].is_some()).collect();
    let mut best: Option<(usize, usize, f64)> = None;
    for (position, &i) in active.iter().enumerate() {
        for &j in &active[position + 1..] {
            let value = similarities[i][j];
            if best.is_none_or(|(_, _, b)| value > b) {
                best = Some((i, j, value));
            }
        }
    }
    best
}

/// Merge cluster `j` into `i`, updating average-linkage similarities.
fn merge_clusters(clusters: &mut [Option<Vec<usize>>], similarities: &mut [Vec<f64>], i: usize, j: usize) {
    let Some(absorbed) = clusters[j].take() else { return };
    let size_i = clusters[i].as_ref().map_or(0, Vec::len) as f64;
    let size_j = absorbed.len() as f64;
    for k in 0..clusters.len() {
        if k == i || clusters[k].is_none() {
            continue;
        }
        let merged = (size_i * similarities[i][k] + size_j * similarities[j][k]) / (size_i + size_j);
        similarities[i][k] = merged;
        similarities[k][i] = merged;
    }
    if let Some(members) = clusters[i].as_mut() {
        members.extend(absorbed);
    }
}

// ---------------------------------------------------------------------------
// Multiple alignment
// ---------------------------------------------------------------------------

/// One step of a pairwise alignment of a message against the consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Message byte `i` sits in existing column `j`.
    Both(usize, usize),
    /// Message byte `i` needs a new column (a gap in every earlier row).
    NewColumn(usize),
    /// The message has a gap in existing column `j`.
    Gap(usize),
}

/// Progressively align the messages at `indices` (each cut to
/// `MAX_ALIGNED_LEN` bytes): each is aligned against the consensus of those
/// before it. Returns the alignment and notes on any cap that applied.
pub fn align_messages(messages: &[&[u8]], indices: &[usize]) -> (Alignment, Vec<String>) {
    let mut notes = Vec::new();
    let mut alignment = Alignment::default();
    for &index in indices {
        let Some(message) = messages.get(index) else { continue };
        let message = &message[..message.len().min(MAX_ALIGNED_LEN)];
        if alignment.rows.is_empty() {
            alignment.rows.push(seed_row(index, message));
            continue;
        }
        let steps = align_to_consensus(message, &alignment.consensus());
        let new_columns = steps.iter().filter(|s| matches!(s, Step::NewColumn(_))).count();
        if alignment.columns() + new_columns > MAX_COLUMNS {
            notes.push(format!("Stopped at {} messages: the alignment would exceed {MAX_COLUMNS} columns.", alignment.rows.len()));
            break;
        }
        apply_steps(&mut alignment, index, message, &steps);
    }
    (alignment, notes)
}

fn seed_row(index: usize, message: &[u8]) -> AlignedRow {
    let cells = message.iter().enumerate().map(|(position, &value)| Some(AlignedByte { position, value })).collect();
    AlignedRow { message: index, cells }
}

/// Needleman–Wunsch alignment of `message` against the consensus columns.
fn align_to_consensus(message: &[u8], consensus: &[Option<u8>]) -> Vec<Step> {
    const FROM_DIAGONAL: u8 = 0;
    const FROM_ABOVE: u8 = 1; // consumes a message byte: new column
    const FROM_LEFT: u8 = 2; // consumes a column: gap in the message
    let (rows, columns) = (message.len(), consensus.len());
    let width = columns + 1;
    let mut scores = vec![0i32; (rows + 1) * width];
    let mut moves = vec![FROM_DIAGONAL; (rows + 1) * width];
    for i in 1..=rows {
        scores[i * width] = GAP_SCORE * i as i32;
        moves[i * width] = FROM_ABOVE;
    }
    for j in 1..=columns {
        scores[j] = GAP_SCORE * j as i32;
        moves[j] = FROM_LEFT;
    }
    for i in 1..=rows {
        for j in 1..=columns {
            let pair = if consensus[j - 1] == Some(message[i - 1]) { MATCH_SCORE } else { MISMATCH_SCORE };
            let diagonal = scores[(i - 1) * width + j - 1] + pair;
            let above = scores[(i - 1) * width + j] + GAP_SCORE;
            let left = scores[i * width + j - 1] + GAP_SCORE;
            let (score, step) = if diagonal >= above && diagonal >= left {
                (diagonal, FROM_DIAGONAL)
            } else if above >= left {
                (above, FROM_ABOVE)
            } else {
                (left, FROM_LEFT)
            };
            scores[i * width + j] = score;
            moves[i * width + j] = step;
        }
    }
    let mut steps = Vec::with_capacity(rows + columns);
    let (mut i, mut j) = (rows, columns);
    while i > 0 || j > 0 {
        match moves[i * width + j] {
            FROM_DIAGONAL if i > 0 && j > 0 => {
                steps.push(Step::Both(i - 1, j - 1));
                i -= 1;
                j -= 1;
            }
            FROM_ABOVE if i > 0 => {
                steps.push(Step::NewColumn(i - 1));
                i -= 1;
            }
            _ if j > 0 => {
                steps.push(Step::Gap(j - 1));
                j -= 1;
            }
            _ => {
                steps.push(Step::NewColumn(i - 1));
                i -= 1;
            }
        }
    }
    steps.reverse();
    steps
}

/// Rebuild every row with the new message's steps applied.
fn apply_steps(alignment: &mut Alignment, index: usize, message: &[u8], steps: &[Step]) {
    let old_rows = std::mem::take(&mut alignment.rows);
    let mut new_rows: Vec<AlignedRow> = old_rows.iter().map(|row| AlignedRow { message: row.message, cells: Vec::with_capacity(steps.len()) }).collect();
    let mut added = AlignedRow { message: index, cells: Vec::with_capacity(steps.len()) };
    let byte_at = |position: usize| Some(AlignedByte { position, value: message[position] });
    for &step in steps {
        match step {
            Step::Both(position, column) => {
                for (new_row, old_row) in new_rows.iter_mut().zip(&old_rows) {
                    new_row.cells.push(old_row.cells[column]);
                }
                added.cells.push(byte_at(position));
            }
            Step::NewColumn(position) => {
                for new_row in &mut new_rows {
                    new_row.cells.push(None);
                }
                added.cells.push(byte_at(position));
            }
            Step::Gap(column) => {
                for (new_row, old_row) in new_rows.iter_mut().zip(&old_rows) {
                    new_row.cells.push(old_row.cells[column]);
                }
                added.cells.push(None);
            }
        }
    }
    new_rows.push(added);
    alignment.rows = new_rows;
}

fn most_common(values: impl Iterator<Item = u8>) -> Option<u8> {
    let mut counts = [0usize; BYTE_VALUES];
    let mut any = false;
    for value in values {
        counts[value as usize] += 1;
        any = true;
    }
    if !any {
        return None;
    }
    (0..BYTE_VALUES).max_by_key(|&v| (counts[v], std::cmp::Reverse(v))).map(|v| v as u8)
}

// ---------------------------------------------------------------------------
// Column classes and fields
// ---------------------------------------------------------------------------

/// Class every aligned column. `lengths[r]` is the full length of the
/// message in row `r` (before any cut for alignment).
pub fn classify_columns(alignment: &Alignment, lengths: &[usize]) -> Vec<ColumnSummary> {
    (0..alignment.columns())
        .map(|column| {
            let present: Vec<(u8, usize)> = alignment
                .rows
                .iter()
                .enumerate()
                .filter_map(|(row, aligned)| aligned.cells[column].map(|cell| (cell.value, lengths.get(row).copied().unwrap_or(0))))
                .collect();
            classify_column(&present)
        })
        .collect()
}

/// Class one column from its (value, message length) pairs in message order.
fn classify_column(present: &[(u8, usize)]) -> ColumnSummary {
    let mut seen = [false; BYTE_VALUES];
    for &(value, _) in present {
        seen[value as usize] = true;
    }
    let distinct = seen.iter().filter(|&&s| s).count();
    let summary = |class, detail: String| ColumnSummary { class, present: present.len(), distinct, detail };
    if distinct <= 1 {
        let detail = present.first().map(|(value, _)| format!("always {value:02X}")).unwrap_or_default();
        return summary(ColumnClass::Constant, detail);
    }
    if present.len() >= MIN_ROWS_FOR_PATTERN {
        if let Some(detail) = length_evidence(present) {
            return summary(ColumnClass::Length, detail);
        }
        if let Some(detail) = counter_evidence(present) {
            return summary(ColumnClass::Counter, detail);
        }
    }
    summary(ColumnClass::Variable, format!("{distinct} distinct values"))
}

/// Evidence that the values follow the message lengths: an exact offset, or
/// a strong correlation.
fn length_evidence(present: &[(u8, usize)]) -> Option<String> {
    let first_length = present[0].1;
    if present.iter().all(|&(_, length)| length == first_length) {
        return None;
    }
    let offsets: Vec<i64> = present.iter().map(|&(value, length)| length as i64 - value as i64).collect();
    if offsets.iter().all(|&offset| offset == offsets[0]) {
        return Some(match offsets[0] {
            0 => "value = message length".to_string(),
            offset if offset > 0 => format!("value = message length − {offset}"),
            offset => format!("value = message length + {}", offset.unsigned_abs()),
        });
    }
    let values: Vec<f64> = present.iter().map(|&(value, _)| value as f64).collect();
    let lengths: Vec<f64> = present.iter().map(|&(_, length)| length as f64).collect();
    let correlation = pearson(&values, &lengths)?;
    (correlation >= LENGTH_CORRELATION).then(|| format!("correlates with message length (r = {correlation:.2})"))
}

/// Evidence that the values step by a fixed amount (mod 256) from one
/// message to the next.
fn counter_evidence(present: &[(u8, usize)]) -> Option<String> {
    let mut step_counts = [0usize; BYTE_VALUES];
    for pair in present.windows(2) {
        let step = pair[1].0.wrapping_sub(pair[0].0);
        step_counts[step as usize] += 1;
    }
    let steps = present.len() - 1;
    let (step, count) = step_counts.iter().enumerate().skip(1).max_by_key(|&(_, &count)| count)?;
    let agreement = *count as f64 / steps as f64;
    (agreement >= COUNTER_AGREEMENT).then(|| format!("step +{step} in {:.0}% of messages", agreement * 100.0))
}

fn pearson(xs: &[f64], ys: &[f64]) -> Option<f64> {
    let count = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / count;
    let mean_y = ys.iter().sum::<f64>() / count;
    let mut covariance = 0.0;
    let mut variance_x = 0.0;
    let mut variance_y = 0.0;
    for (x, y) in xs.iter().zip(ys) {
        covariance += (x - mean_x) * (y - mean_y);
        variance_x += (x - mean_x).powi(2);
        variance_y += (y - mean_y).powi(2);
    }
    let denominator = (variance_x * variance_y).sqrt();
    (denominator > 0.0).then(|| covariance / denominator)
}

/// Runs of adjacent columns with the same class, as proposed fields.
pub fn propose_fields(columns: &[ColumnSummary]) -> Vec<ProposedField> {
    let mut fields: Vec<ProposedField> = Vec::new();
    for (column, summary) in columns.iter().enumerate() {
        match fields.last_mut() {
            Some(field) if field.class == summary.class => field.len += 1,
            _ => fields.push(ProposedField { start_column: column, len: 1, class: summary.class }),
        }
    }
    fields
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SYNC: u8 = 0x7E;
    const TYPE_TEXT: u8 = 0x01;
    const TYPE_BINARY: u8 = 0x02;
    const HEADER_LEN: usize = 4;

    /// A text reading: sync, type, sequence, payload length, "temp=N;".
    fn text_message(sequence: u8, reading: u32) -> Vec<u8> {
        let payload = format!("temp={reading};").into_bytes();
        let mut message = vec![SYNC, TYPE_TEXT, sequence, payload.len() as u8];
        message.extend(payload);
        message
    }

    /// A fixed-size binary status: sync, type, sequence, length, body.
    fn binary_message(sequence: u8, value: u8) -> Vec<u8> {
        let body = [0x00, 0x10, 0x20, value, 0xFF, 0xFF];
        let mut message = vec![SYNC, TYPE_BINARY, sequence, body.len() as u8];
        message.extend(body);
        message
    }

    /// Forty interleaved messages of the two types with a shared sequence counter.
    fn two_type_stream() -> Vec<Vec<u8>> {
        (0..40u8)
            .map(|index| {
                if index % 2 == 0 {
                    text_message(index, 5 + u32::from(index) * 7)
                } else {
                    binary_message(index, index.wrapping_mul(index).wrapping_mul(37) ^ 0x5A)
                }
            })
            .collect()
    }

    fn cluster_of_type(report: &AlignmentReport, messages: &[Vec<u8>], message_type: u8) -> ClusterReport {
        report.clusters.iter().find(|c| messages[c.members[0]][1] == message_type).expect("cluster of that type").clone()
    }

    #[test]
    fn separates_two_interleaved_message_types_into_two_clusters() {
        let messages = two_type_stream();
        let report = analyse(&messages, &AlignmentOptions::default());
        assert_eq!(report.clusters.len(), 2, "clusters: {:?}", report.clusters.iter().map(|c| c.members.len()).collect::<Vec<_>>());
        for cluster in &report.clusters {
            let message_type = messages[cluster.members[0]][1];
            assert!(cluster.members.iter().all(|&m| messages[m][1] == message_type));
            assert_eq!(cluster.members.len(), 20);
        }
    }

    #[test]
    fn classes_header_columns_of_text_messages_as_constant_counter_and_length() {
        let messages = two_type_stream();
        let report = analyse(&messages, &AlignmentOptions::default());
        let text = cluster_of_type(&report, &messages, TYPE_TEXT);
        let classes: Vec<ColumnClass> = text.columns.iter().take(HEADER_LEN).map(|c| c.class).collect();
        assert_eq!(classes, vec![ColumnClass::Constant, ColumnClass::Constant, ColumnClass::Counter, ColumnClass::Length]);
        assert!(text.columns[2].detail.contains("step +2"), "{}", text.columns[2].detail);
        assert_eq!(text.columns[3].detail, format!("value = message length − {HEADER_LEN}"));
    }

    #[test]
    fn classes_a_fixed_length_field_as_constant_when_all_messages_are_the_same_size() {
        let messages = two_type_stream();
        let report = analyse(&messages, &AlignmentOptions::default());
        let binary = cluster_of_type(&report, &messages, TYPE_BINARY);
        assert_eq!(binary.alignment.columns(), messages[1].len(), "same-size messages align without gaps");
        assert_eq!(binary.columns[3].class, ColumnClass::Constant);
        assert_eq!(binary.columns[2].class, ColumnClass::Counter);
        assert_eq!(binary.columns[7].class, ColumnClass::Variable);
    }

    #[test]
    fn proposes_fields_from_runs_of_one_class() {
        let messages = two_type_stream();
        let report = analyse(&messages, &AlignmentOptions::default());
        let binary = cluster_of_type(&report, &messages, TYPE_BINARY);
        let first = &binary.fields[0];
        assert_eq!((first.start_column, first.len, first.class), (0, 2, ColumnClass::Constant));
        assert_eq!(binary.fields[1].class, ColumnClass::Counter);
        let total: usize = binary.fields.iter().map(|f| f.len).sum();
        assert_eq!(total, binary.alignment.columns());
    }

    #[test]
    fn aligned_cells_point_back_at_their_bytes_in_each_message() {
        let messages = two_type_stream();
        let report = analyse(&messages, &AlignmentOptions::default());
        for cluster in &report.clusters {
            for row in &cluster.alignment.rows {
                let bytes: Vec<AlignedByte> = row.cells.iter().flatten().copied().collect();
                assert_eq!(bytes.len(), messages[row.message].len());
                for (expected_position, cell) in bytes.iter().enumerate() {
                    assert_eq!(cell.position, expected_position);
                    assert_eq!(cell.value, messages[row.message][expected_position]);
                }
            }
        }
    }

    #[test]
    fn inserts_gaps_where_a_message_has_extra_bytes() {
        let short = b"ABCDEF".to_vec();
        let long = b"ABCxyzDEF".to_vec();
        let slices: Vec<&[u8]> = vec![&short, &long];
        let (alignment, notes) = align_messages(&slices, &[0, 1]);
        assert!(notes.is_empty());
        assert_eq!(alignment.columns(), long.len());
        let gaps = alignment.rows[0].cells.iter().filter(|c| c.is_none()).count();
        assert_eq!(gaps, 3);
    }

    #[test]
    fn similarity_is_one_for_identical_messages_and_low_for_unrelated_ones() {
        assert_eq!(similarity(b"hello world", b"hello world"), 1.0);
        assert!(similarity(b"\x01\x02\x03\x04\x05\x06", b"zyxwvu") < 0.2);
        assert_eq!(similarity(b"", b""), 1.0);
        assert_eq!(similarity(b"abc", b""), 0.0);
    }

    #[test]
    fn caps_messages_aligned_per_cluster_with_a_note() {
        let messages: Vec<Vec<u8>> = (0..(MAX_ALIGNED_PER_CLUSTER + 6) as u8).map(|i| vec![SYNC, 0x01, i, 0x00]).collect();
        let report = analyse(&messages, &AlignmentOptions::default());
        assert_eq!(report.clusters.len(), 1);
        let cluster = &report.clusters[0];
        assert_eq!(cluster.members.len(), messages.len());
        assert_eq!(cluster.alignment.rows.len(), MAX_ALIGNED_PER_CLUSTER);
        assert!(cluster.notes.iter().any(|n| n.contains("Aligned an even sample of 64 of its 70")), "{:?}", cluster.notes);
        assert_eq!(cluster.alignment.rows.last().map(|row| row.message), Some(messages.len() - 1), "the sample reaches the last message");
    }

    #[test]
    fn a_type_seen_only_late_in_a_long_set_is_still_clustered_and_the_sampling_is_said() {
        let mut messages: Vec<Vec<u8>> = (0..2000u32).map(|index| binary_message(index as u8, (index % 7) as u8)).collect();
        for late in [1801, 1902, 1999] {
            messages[late] = vec![0x3C, 0x3C, 0x3C, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        }
        let report = analyse(&messages, &AlignmentOptions::default());
        assert!(report.notes.iter().any(|note| note.contains("even sample of 256 of the 2000 messages")), "{:?}", report.notes);
        let late = report.clusters.iter().find(|cluster| messages[cluster.members[0]][0] == 0x3C).expect("the late type has a cluster");
        assert_eq!(late.members, vec![1801, 1902, 1999]);
        let total: usize = report.clusters.iter().map(|cluster| cluster.members.len()).sum();
        assert_eq!(total, 2000, "every message is in a cluster");
    }

    #[test]
    fn an_even_sample_spans_the_whole_range() {
        assert_eq!(even_sample(5, 10), vec![0, 1, 2, 3, 4]);
        assert_eq!(even_sample(101, 3), vec![0, 50, 100]);
        assert!(even_sample(0, 4).is_empty());
    }

    #[test]
    fn handles_empty_and_degenerate_input_without_panicking() {
        assert!(analyse(&[], &AlignmentOptions::default()).clusters.is_empty());
        let degenerate = vec![Vec::new(), Vec::new(), vec![0u8; MAX_ALIGNED_LEN + 10]];
        let report = analyse(&degenerate, &AlignmentOptions::default());
        let rows: usize = report.clusters.iter().map(|c| c.alignment.rows.len()).sum();
        assert_eq!(rows, 3);
        assert!(report.clusters.iter().any(|c| c.notes.iter().any(|n| n.contains("first 512 bytes"))));
    }

    #[test]
    fn takes_message_bytes_from_protocol_framing_and_row_splits() {
        let stream: Vec<u8> = (0..10).collect();
        let framed = messages_from_protocol(&stream, &[Message { offset: 2, len: 3 }, Message { offset: 8, len: 5 }]);
        assert_eq!(framed, vec![vec![2, 3, 4], vec![8, 9]]);
        assert_eq!(split_into_records(&stream, 4), vec![vec![0, 1, 2, 3], vec![4, 5, 6, 7], vec![8, 9]]);
        assert!(split_into_records(&stream, 0).is_empty());
    }
}
