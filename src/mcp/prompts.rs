//! MCP prompts: a few starting points that walk a model through the tools.

use serde_json::{Map, Value, json};

use super::jsonrpc::RpcError;

/// One prompt's argument.
struct Argument {
    name: &'static str,
    description: &'static str,
    required: bool,
}

/// A prompt: its name, what it is for, its arguments and how to write it.
struct Prompt {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    arguments: &'static [Argument],
    write: fn(&Arguments) -> String,
}

/// The arguments a prompt was given, as text.
struct Arguments<'a>(&'a Map<String, Value>);

impl Arguments<'_> {
    fn get(&self, name: &str) -> Option<String> {
        match self.0.get(name)? {
            Value::String(text) if !text.trim().is_empty() => Some(text.trim().to_string()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        }
    }

    /// The document named, or "current".
    fn doc(&self) -> String {
        self.get("doc").unwrap_or_else(|| "current".to_string())
    }
}

const DOC: Argument = Argument { name: "doc", description: "Document id (doc-1), path or \"current\" (the default)", required: false };

static PROMPTS: &[Prompt] = &[
    Prompt {
        name: "triage_file",
        title: "Triage this file",
        description: "Find out what a binary file is: an overview, then its findings, then the structure of its main parts.",
        arguments: &[DOC],
        write: triage_file,
    },
    Prompt {
        name: "find_record_structure",
        title: "Find the record structure",
        description: "Find the fixed-size records a file or region repeats in, and what each field of a record holds.",
        arguments: &[DOC, Argument { name: "start", description: "Offset where the records start, if known", required: false }],
        write: find_record_structure,
    },
    Prompt {
        name: "explain_packet",
        title: "Explain the packet",
        description: "Dissect the packet or frame at an offset and explain each layer and field, citing the specifications.",
        arguments: &[
            DOC,
            Argument { name: "offset", description: "Offset of the packet's first byte (the cursor's when omitted)", required: false },
            Argument { name: "len", description: "Length of the packet in bytes, if known", required: false },
        ],
        write: explain_packet,
    },
];

fn triage_file(arguments: &Arguments) -> String {
    let doc = arguments.doc();
    format!(
        "Work out what the binary file {doc} is and how it is laid out.\n\n\
1. Call analysis_overview with {{\"doc\": \"{doc}\"}} for a summary, its regions with offsets, likely record widths and confident findings.\n\
2. Call findings_query on the document (and on any region that matters, with start and len) for signatures, compressed streams, text, timestamps and structures.\n\
3. For each main region, call structure_parse at its offset; where nothing parses, try analysis_statistics and analysis_compressibility on the span, and codecs_probe where it looks compressed.\n\
4. Use bytes_hexdump to look at headers and boundaries, and reference_lookup for the notes on any format found.\n\n\
Report what the file is, a table of its regions (offset, length, what it is, how sure), and anything left unexplained with your best guess."
    )
}

fn find_record_structure(arguments: &Arguments) -> String {
    let doc = arguments.doc();
    let from = arguments.get("start").map(|start| format!(" starting at offset {start}")).unwrap_or_default();
    format!(
        "Find the record structure of {doc}{from}.\n\n\
1. Call analysis_overview for likely record widths, and analysis_segments to find the region of repeated records.\n\
2. Confirm a width by reading a few records with bytes_hexdump (len a multiple of the width) and checking that fields line up.\n\
3. Call templates_apply with name \"Fixed-size records\" at the start offset to see the records as a table.\n\
4. For each column, call numbers_decode at its offset in several records to decide its type (counter, timestamp, length, float, enum, text), and search_find_all for any constant marker.\n\n\
Report the record width, where the records start and end, and a field table (offset in record, size, type, byte order, meaning, evidence). \
If it helps, write it as a template and check it with templates_apply using source."
    )
}

fn explain_packet(arguments: &Arguments) -> String {
    let doc = arguments.doc();
    let at = match arguments.get("offset") {
        Some(offset) => format!("at offset {offset}"),
        None => "at the cursor (cursor_get gives its offset)".to_string(),
    };
    let len = arguments.get("len").map(|len| format!(", {len} bytes long")).unwrap_or_default();
    format!(
        "Explain the packet in {doc} {at}{len}.\n\n\
1. Call packets_dissect_bytes with that start (and len, if known) to split it into protocol layers and fields. If it does not dissect, \
call packets_detect_frames on the frames around it and structure_parse at the offset.\n\
2. Call reference_lookup for each layer's protocol to explain what its fields mean, with the specification sections.\n\
3. Show the bytes with bytes_hexdump and point out where each field lies.\n\n\
Report each layer in order: its fields with offsets, values and meanings, anything unusual (bad checksums, odd flags, lengths that do not add up), \
and what the packet as a whole is doing."
    )
}

/// Every prompt, as `prompts/list` gives them.
pub fn list() -> Vec<Value> {
    PROMPTS
        .iter()
        .map(|prompt| {
            let arguments: Vec<Value> = prompt.arguments.iter().map(|argument| json!({ "name": argument.name, "description": argument.description, "required": argument.required })).collect();
            json!({ "name": prompt.name, "title": prompt.title, "description": prompt.description, "arguments": arguments })
        })
        .collect()
}

/// The prompt `prompts/get` asks for, with its arguments filled in.
pub fn get(params: &Map<String, Value>) -> Result<Value, RpcError> {
    let name = params.get("name").and_then(Value::as_str).ok_or_else(|| RpcError::invalid_params("prompts/get needs the prompt's name"))?;
    let prompt = PROMPTS.iter().find(|prompt| prompt.name == name).ok_or_else(|| RpcError::invalid_params(format!("there is no prompt '{name}'; prompts/list lists them")))?;
    let empty = Map::new();
    let given = params.get("arguments").and_then(Value::as_object).unwrap_or(&empty);
    let arguments = Arguments(given);
    if let Some(missing) = prompt.arguments.iter().find(|argument| argument.required && arguments.get(argument.name).is_none()) {
        return Err(RpcError::invalid_params(format!("the prompt {name} needs the argument '{}'", missing.name)));
    }
    let text = (prompt.write)(&arguments);
    Ok(json!({ "description": prompt.description, "messages": [{ "role": "user", "content": { "type": "text", "text": text } }] }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn the_prompts_are_triage_record_structure_and_packet() {
        let names: Vec<Value> = list().into_iter().map(|prompt| prompt["name"].clone()).collect();
        assert_eq!(names, [json!("triage_file"), json!("find_record_structure"), json!("explain_packet")]);
    }

    #[test]
    fn a_prompt_names_the_document_and_the_tools_to_use() {
        let triage = get(&params(json!({ "name": "triage_file", "arguments": { "doc": "doc-2" } }))).unwrap();
        let text = triage["messages"][0]["content"]["text"].as_str().unwrap();
        assert!(text.contains("doc-2") && text.contains("analysis_overview") && text.contains("findings_query") && text.contains("structure_parse"), "{text}");
        assert_eq!(triage["messages"][0]["role"], "user");
        let packet = get(&params(json!({ "name": "explain_packet", "arguments": { "offset": "0x40" } }))).unwrap();
        let text = packet["messages"][0]["content"]["text"].as_str().unwrap();
        assert!(text.contains("at offset 0x40") && text.contains("current") && text.contains("packets_dissect_bytes"), "{text}");
    }

    #[test]
    fn every_tool_a_prompt_names_exists() {
        let workspace = crate::api::test_support::workspace_with("a.bin", b"abc");
        let tools: Vec<String> = crate::api::all_methods(&workspace).iter().map(|method| crate::mcp::tools::tool_name(method.name())).collect();
        for prompt in PROMPTS {
            let text = (prompt.write)(&Arguments(&Map::new()));
            for word in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).filter(|word| word.contains('_') && word.chars().all(|c| c.is_ascii_lowercase() || c == '_')) {
                assert!(tools.iter().any(|tool| tool == word), "{} names {word}, which is not a tool", prompt.name);
            }
        }
    }

    #[test]
    fn an_unknown_prompt_is_invalid() {
        assert_eq!(get(&params(json!({ "name": "write_poem" }))).unwrap_err().code, crate::mcp::jsonrpc::INVALID_PARAMS);
    }
}
