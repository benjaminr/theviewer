//! Binary templates: a small declarative language that describes a
//! structure, applied to bytes to produce a field tree and a table of
//! records, plus inference of a first-draft template from repeating records.
//!
//! ```text
//! endian little
//! struct Chunk {
//!     id: char[4]
//!     len: u32
//!     data: bytes[len]
//!     pad: bytes[len % 2]
//! }
//! root Chunk[until_end]
//! ```
//!
//! The full language is documented in `docs/templates.md`. Evaluation never
//! panics on short or hostile data: a field that runs off the end becomes a
//! warning and ends that branch, and every walk is bounded.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use crate::plugin::{Category, Field, Finding};

/// Most fields one application may create.
const MAX_FIELDS: usize = 100_000;
/// Deepest nesting of structs and arrays.
const MAX_DEPTH: usize = 32;
/// Most elements in one array.
const MAX_ARRAY: usize = 1_000_000;
/// Primitive arrays up to this many elements show each element as a field.
const MAX_ELEMENT_FIELDS: usize = 64;
/// Most columns in one record of the records table.
const MAX_RECORD_COLUMNS: usize = 64;
/// Bytes shown in a `bytes[N]` preview.
const PREVIEW_BYTES: usize = 16;
/// Most warnings kept from one application.
const MAX_WARNINGS: usize = 200;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A problem in a template's source, with the line it was found on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateError {
    /// 1-based line number, or 0 when the problem is not tied to a line.
    pub line: usize,
    pub message: String,
}

impl TemplateError {
    fn new(line: usize, message: impl Into<String>) -> Self {
        TemplateError { line, message: message.into() }
    }
}

impl fmt::Display for TemplateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(formatter, "{}", self.message)
        } else {
            write!(formatter, "line {}: {}", self.line, self.message)
        }
    }
}

impl std::error::Error for TemplateError {}

// ---------------------------------------------------------------------------
// Syntax tree
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Primitive {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

impl Primitive {
    fn size(self) -> usize {
        match self {
            Primitive::U8 | Primitive::I8 => 1,
            Primitive::U16 | Primitive::I16 => 2,
            Primitive::U32 | Primitive::I32 | Primitive::F32 => 4,
            Primitive::U64 | Primitive::I64 | Primitive::F64 => 8,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Primitive::U8 => "u8",
            Primitive::U16 => "u16",
            Primitive::U32 => "u32",
            Primitive::U64 => "u64",
            Primitive::I8 => "i8",
            Primitive::I16 => "i16",
            Primitive::I32 => "i32",
            Primitive::I64 => "i64",
            Primitive::F32 => "f32",
            Primitive::F64 => "f64",
        }
    }

    /// `u32`, `u32le` or `u32be` and so on; the endian is `None` when the
    /// name has no suffix and the template's current setting applies.
    fn from_name(name: &str) -> Option<(Primitive, Option<Endian>)> {
        let (stem, endian) = if let Some(stem) = name.strip_suffix("le") {
            (stem, Some(Endian::Little))
        } else if let Some(stem) = name.strip_suffix("be") {
            (stem, Some(Endian::Big))
        } else {
            (name, None)
        };
        let primitive = match stem {
            "u8" => Primitive::U8,
            "u16" => Primitive::U16,
            "u32" => Primitive::U32,
            "u64" => Primitive::U64,
            "i8" => Primitive::I8,
            "i16" => Primitive::I16,
            "i32" => Primitive::I32,
            "i64" => Primitive::I64,
            "f32" => Primitive::F32,
            "f64" => Primitive::F64,
            _ => return None,
        };
        Some((primitive, endian))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operator {
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    /// `==` and `!=`: 1 when the comparison holds, else 0.
    Equal,
    NotEqual,
}

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Number(i128),
    /// A field name, possibly dotted: `header.size`.
    Path(Vec<String>),
    Negate(Box<Expr>),
    Binary(Operator, Box<Expr>, Box<Expr>),
}

#[derive(Clone, Debug, PartialEq)]
enum Count {
    Expr(Expr),
    UntilEnd,
}

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Primitive(Primitive, Endian),
    Char(Expr),
    Bytes(Expr),
    Utf16(Expr, Endian),
    CString,
    Struct(String),
}

#[derive(Clone, Debug, PartialEq)]
struct TypeRef {
    kind: Kind,
    array: Option<Count>,
    line: usize,
}

#[derive(Clone, Debug, PartialEq)]
enum Literal {
    Number(i128),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq)]
struct FieldDef {
    name: String,
    ty: TypeRef,
    expected: Option<Literal>,
    /// Absolute offset from the start of the template's data.
    at: Option<Expr>,
    labels: Vec<(i128, String)>,
    hex: bool,
    /// Read the field only when this is not zero: `if type == 3`.
    condition: Option<Expr>,
    line: usize,
}

#[derive(Clone, Debug, PartialEq)]
struct StructDef {
    name: String,
    fields: Vec<FieldDef>,
}

/// A parsed template, ready to apply to bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct Template {
    structs: HashMap<String, StructDef>,
    root: TypeRef,
    name: String,
}

// ---------------------------------------------------------------------------
// Tokeniser
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Ident(String),
    Number(i128),
    Text(Vec<u8>),
    Symbol(char),
}

#[derive(Clone, Debug)]
struct Located {
    token: Token,
    line: usize,
}

const SYMBOLS: &str = "{}[]():=@+-*/%,.;!";

fn tokenise(source: &str) -> Result<Vec<Located>, TemplateError> {
    let mut tokens = Vec::new();
    for (index, text) in source.lines().enumerate() {
        let line = index + 1;
        let chars: Vec<char> = text.chars().collect();
        let mut at = 0;
        while at < chars.len() {
            let c = chars[at];
            if c.is_whitespace() {
                at += 1;
            } else if c == '/' && chars.get(at + 1) == Some(&'/') {
                break;
            } else if c.is_ascii_digit() {
                let (number, used) = read_number(&chars[at..], line)?;
                tokens.push(Located { token: Token::Number(number), line });
                at += used;
            } else if c.is_alphabetic() || c == '_' {
                let start = at;
                while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                    at += 1;
                }
                tokens.push(Located { token: Token::Ident(chars[start..at].iter().collect()), line });
            } else if c == '"' {
                let (bytes, used) = read_string(&chars[at..], line)?;
                tokens.push(Located { token: Token::Text(bytes), line });
                at += used;
            } else if SYMBOLS.contains(c) {
                tokens.push(Located { token: Token::Symbol(c), line });
                at += 1;
            } else {
                return Err(TemplateError::new(line, format!("unexpected character '{c}'")));
            }
        }
    }
    Ok(tokens)
}

/// A decimal or `0x` hexadecimal number; underscores are allowed as separators.
fn read_number(chars: &[char], line: usize) -> Result<(i128, usize), TemplateError> {
    let hex = chars.len() > 1 && chars[0] == '0' && matches!(chars[1], 'x' | 'X');
    let start = if hex { 2 } else { 0 };
    let mut end = start;
    while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
        end += 1;
    }
    let digits: String = chars[start..end].iter().filter(|&&c| c != '_').collect();
    let radix = if hex { 16 } else { 10 };
    let value = i128::from_str_radix(&digits, radix).map_err(|_| {
        let written: String = chars[..end].iter().collect();
        TemplateError::new(line, format!("'{written}' is not a number"))
    })?;
    Ok((value, end))
}

/// A double-quoted string with `\xNN`, `\n`, `\r`, `\t`, `\0`, `\\` and `\"` escapes.
fn read_string(chars: &[char], line: usize) -> Result<(Vec<u8>, usize), TemplateError> {
    let mut bytes = Vec::new();
    let mut at = 1;
    while at < chars.len() {
        let c = chars[at];
        match c {
            '"' => return Ok((bytes, at + 1)),
            '\\' => {
                let escape = chars.get(at + 1).copied().ok_or_else(|| TemplateError::new(line, "string ends with a lone '\\'"))?;
                at += 2;
                match escape {
                    'n' => bytes.push(b'\n'),
                    'r' => bytes.push(b'\r'),
                    't' => bytes.push(b'\t'),
                    '0' => bytes.push(0),
                    '\\' => bytes.push(b'\\'),
                    '"' => bytes.push(b'"'),
                    'x' => {
                        let hex: String = chars.get(at..at + 2).map(|pair| pair.iter().collect()).unwrap_or_default();
                        let value = u8::from_str_radix(&hex, 16).map_err(|_| TemplateError::new(line, format!("bad escape '\\x{hex}'")))?;
                        bytes.push(value);
                        at += 2;
                    }
                    other => return Err(TemplateError::new(line, format!("unknown escape '\\{other}'"))),
                }
            }
            _ => {
                let mut buffer = [0u8; 4];
                bytes.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
                at += 1;
            }
        }
    }
    Err(TemplateError::new(line, "string is missing its closing '\"'"))
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<Located>,
    position: usize,
    endian: Endian,
    last_line: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position).map(|t| &t.token)
    }

    fn peek_at(&self, ahead: usize) -> Option<&Token> {
        self.tokens.get(self.position + ahead).map(|t| &t.token)
    }

    fn line(&self) -> usize {
        self.tokens.get(self.position).map(|t| t.line).unwrap_or(self.last_line)
    }

    fn advance(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position).map(|t| t.token.clone());
        if token.is_some() {
            self.position += 1;
        }
        token
    }

    fn error(&self, message: impl Into<String>) -> TemplateError {
        TemplateError::new(self.line(), message)
    }

    fn eat_symbol(&mut self, symbol: char) -> bool {
        if self.peek() == Some(&Token::Symbol(symbol)) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect_symbol(&mut self, symbol: char, context: &str) -> Result<(), TemplateError> {
        if self.eat_symbol(symbol) {
            Ok(())
        } else {
            Err(self.error(format!("expected '{symbol}' {context}, found {}", describe(self.peek()))))
        }
    }

    fn expect_ident(&mut self, what: &str) -> Result<String, TemplateError> {
        match self.peek() {
            Some(Token::Ident(name)) => {
                let name = name.clone();
                self.position += 1;
                Ok(name)
            }
            other => Err(self.error(format!("expected {what}, found {}", describe(other)))),
        }
    }

    fn at_word(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Ident(name)) if name == word)
    }

    fn next_is_colon(&self) -> bool {
        self.peek_at(1) == Some(&Token::Symbol(':'))
    }

    fn parse_endian(&mut self) -> Result<(), TemplateError> {
        self.advance();
        let word = self.expect_ident("'little' or 'big' after 'endian'")?;
        self.endian = match word.as_str() {
            "little" => Endian::Little,
            "big" => Endian::Big,
            other => return Err(self.error(format!("endian must be 'little' or 'big', not '{other}'"))),
        };
        Ok(())
    }

    fn parse_struct(&mut self) -> Result<StructDef, TemplateError> {
        self.advance();
        let name = self.expect_ident("a struct name")?;
        self.expect_symbol('{', &format!("after 'struct {name}'"))?;
        let mut fields = Vec::new();
        loop {
            match self.peek() {
                Some(Token::Symbol('}')) => {
                    self.advance();
                    break;
                }
                Some(Token::Symbol(';' | ',')) => {
                    self.advance();
                }
                Some(Token::Ident(word)) if word == "endian" && !self.next_is_colon() => self.parse_endian()?,
                Some(Token::Ident(_)) => fields.push(self.parse_field()?),
                None => return Err(self.error(format!("struct {name} is missing its closing '}}'"))),
                other => return Err(self.error(format!("expected a field or '}}', found {}", describe(other)))),
            }
        }
        Ok(StructDef { name, fields })
    }

    fn parse_field(&mut self) -> Result<FieldDef, TemplateError> {
        let line = self.line();
        let name = self.expect_ident("a field name")?;
        self.expect_symbol(':', &format!("after field name '{name}'"))?;
        let ty = self.parse_type()?;
        let mut field = FieldDef { name, ty, expected: None, at: None, labels: Vec::new(), hex: false, condition: None, line };
        loop {
            match self.peek() {
                Some(Token::Symbol('=')) => {
                    self.advance();
                    field.expected = Some(self.parse_literal()?);
                }
                Some(Token::Symbol('@')) => {
                    self.advance();
                    field.at = Some(self.parse_expr()?);
                }
                Some(Token::Ident(word)) if word == "if" && !self.next_is_colon() => {
                    self.advance();
                    field.condition = Some(self.parse_expr()?);
                }
                Some(Token::Ident(word)) if word == "enum" && self.peek_at(1) == Some(&Token::Symbol('{')) => {
                    field.labels = self.parse_enum()?;
                }
                Some(Token::Ident(word)) if word == "display" && !self.next_is_colon() => {
                    self.advance();
                    match self.expect_ident("'hex' or 'decimal' after 'display'")?.as_str() {
                        "hex" => field.hex = true,
                        "decimal" => field.hex = false,
                        other => return Err(self.error(format!("display must be 'hex' or 'decimal', not '{other}'"))),
                    }
                }
                _ => break,
            }
        }
        Ok(field)
    }

    fn parse_type(&mut self) -> Result<TypeRef, TemplateError> {
        let line = self.line();
        let name = self.expect_ident("a type")?;
        let kind = match name.as_str() {
            "char" => Kind::Char(self.parse_length("char")?),
            "bytes" => Kind::Bytes(self.parse_length("bytes")?),
            "utf16" | "utf16le" => Kind::Utf16(self.parse_length("utf16")?, Endian::Little),
            "utf16be" => Kind::Utf16(self.parse_length("utf16be")?, Endian::Big),
            "cstring" => Kind::CString,
            other => match Primitive::from_name(other) {
                Some((primitive, endian)) => Kind::Primitive(primitive, endian.unwrap_or(self.endian)),
                None => Kind::Struct(other.to_string()),
            },
        };
        let array = if self.eat_symbol('[') {
            let count = if self.at_word("until_end") {
                self.advance();
                Count::UntilEnd
            } else {
                Count::Expr(self.parse_expr()?)
            };
            self.expect_symbol(']', "to close the array count")?;
            Some(count)
        } else {
            None
        };
        Ok(TypeRef { kind, array, line })
    }

    fn parse_length(&mut self, type_name: &str) -> Result<Expr, TemplateError> {
        if !self.eat_symbol('[') {
            return Err(self.error(format!("{type_name} needs a length, e.g. {type_name}[4]")));
        }
        let length = self.parse_expr()?;
        self.expect_symbol(']', &format!("to close the {type_name} length"))?;
        Ok(length)
    }

    fn parse_literal(&mut self) -> Result<Literal, TemplateError> {
        let negative = self.eat_symbol('-');
        match self.advance() {
            Some(Token::Number(value)) => Ok(Literal::Number(if negative { -value } else { value })),
            Some(Token::Text(bytes)) if !negative => Ok(Literal::Bytes(bytes)),
            other => Err(self.error(format!("expected a number or \"text\" after '=', found {}", describe(other.as_ref())))),
        }
    }

    fn parse_enum(&mut self) -> Result<Vec<(i128, String)>, TemplateError> {
        self.advance();
        self.expect_symbol('{', "after 'enum'")?;
        let mut labels = Vec::new();
        loop {
            if self.eat_symbol('}') {
                return Ok(labels);
            }
            if self.eat_symbol(',') {
                continue;
            }
            let negative = self.eat_symbol('-');
            let value = match self.advance() {
                Some(Token::Number(value)) => if negative { -value } else { value },
                other => return Err(self.error(format!("expected a number in enum, found {}", describe(other.as_ref())))),
            };
            self.expect_symbol('=', "between an enum value and its name")?;
            match self.advance() {
                Some(Token::Text(bytes)) => labels.push((value, String::from_utf8_lossy(&bytes).into_owned())),
                other => return Err(self.error(format!("expected a \"name\" in enum, found {}", describe(other.as_ref())))),
            }
        }
    }

    /// An expression, at most one comparison of two sums: `type == 3`.
    fn parse_expr(&mut self) -> Result<Expr, TemplateError> {
        let left = self.parse_sum()?;
        let operator = match (self.peek(), self.peek_at(1)) {
            (Some(Token::Symbol('=')), Some(Token::Symbol('='))) => Operator::Equal,
            (Some(Token::Symbol('!')), Some(Token::Symbol('='))) => Operator::NotEqual,
            _ => return Ok(left),
        };
        self.position += 2;
        let right = self.parse_sum()?;
        Ok(Expr::Binary(operator, Box::new(left), Box::new(right)))
    }

    fn parse_sum(&mut self) -> Result<Expr, TemplateError> {
        let mut left = self.parse_term()?;
        loop {
            let operator = if self.eat_symbol('+') {
                Operator::Add
            } else if self.eat_symbol('-') {
                Operator::Subtract
            } else {
                return Ok(left);
            };
            let right = self.parse_term()?;
            left = Expr::Binary(operator, Box::new(left), Box::new(right));
        }
    }

    fn parse_term(&mut self) -> Result<Expr, TemplateError> {
        let mut left = self.parse_unary()?;
        loop {
            let operator = if self.eat_symbol('*') {
                Operator::Multiply
            } else if self.eat_symbol('/') {
                Operator::Divide
            } else if self.eat_symbol('%') {
                Operator::Remainder
            } else {
                return Ok(left);
            };
            let right = self.parse_unary()?;
            left = Expr::Binary(operator, Box::new(left), Box::new(right));
        }
    }

    fn parse_unary(&mut self) -> Result<Expr, TemplateError> {
        if self.eat_symbol('-') {
            return Ok(Expr::Negate(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, TemplateError> {
        match self.peek().cloned() {
            Some(Token::Number(value)) => {
                self.advance();
                Ok(Expr::Number(value))
            }
            Some(Token::Ident(first)) => {
                self.advance();
                let mut path = vec![first];
                while self.eat_symbol('.') {
                    path.push(self.expect_ident("a field name after '.'")?);
                }
                Ok(Expr::Path(path))
            }
            Some(Token::Symbol('(')) => {
                self.advance();
                let inner = self.parse_expr()?;
                self.expect_symbol(')', "to close '('")?;
                Ok(inner)
            }
            other => Err(self.error(format!("expected a number, a field name or '(', found {}", describe(other.as_ref())))),
        }
    }
}

fn describe(token: Option<&Token>) -> String {
    match token {
        None => "the end of the template".to_string(),
        Some(Token::Ident(name)) => format!("'{name}'"),
        Some(Token::Number(value)) => format!("the number {value}"),
        Some(Token::Text(_)) => "a string".to_string(),
        Some(Token::Symbol(symbol)) => format!("'{symbol}'"),
    }
}

impl Template {
    /// Parse a template's source. Errors carry the line they were found on.
    pub fn parse(source: &str) -> Result<Template, TemplateError> {
        let tokens = tokenise(source)?;
        let last_line = tokens.last().map(|t| t.line).unwrap_or(1);
        let mut parser = Parser { tokens, position: 0, endian: Endian::Little, last_line };
        let mut structs: HashMap<String, StructDef> = HashMap::new();
        let mut last_struct: Option<String> = None;
        let mut root: Option<TypeRef> = None;
        while let Some(token) = parser.peek() {
            match token {
                Token::Ident(word) if word == "endian" => parser.parse_endian()?,
                Token::Ident(word) if word == "struct" => {
                    let line = parser.line();
                    let def = parser.parse_struct()?;
                    if structs.contains_key(&def.name) {
                        return Err(TemplateError::new(line, format!("struct '{}' is defined twice", def.name)));
                    }
                    last_struct = Some(def.name.clone());
                    structs.insert(def.name.clone(), def);
                }
                Token::Ident(word) if word == "root" => {
                    parser.advance();
                    root = Some(parser.parse_type()?);
                }
                Token::Symbol(';') => {
                    parser.advance();
                }
                other => {
                    let found = describe(Some(other));
                    return Err(parser.error(format!("expected 'struct', 'root' or 'endian', found {found}")));
                }
            }
        }
        let root = match root {
            Some(root) => root,
            None => {
                let name = last_struct.ok_or_else(|| TemplateError::new(1, "the template defines no struct"))?;
                TypeRef { kind: Kind::Struct(name), array: None, line: last_line }
            }
        };
        let Kind::Struct(root_name) = &root.kind else {
            return Err(TemplateError::new(root.line, "root must name a struct, e.g. 'root File' or 'root Record[until_end]'"));
        };
        let name = root_name.clone();
        let template = Template { structs, root, name };
        template.check_references()?;
        Ok(template)
    }

    /// Every struct a field or the root refers to must be defined.
    fn check_references(&self) -> Result<(), TemplateError> {
        let mut types: Vec<&TypeRef> = vec![&self.root];
        for def in self.structs.values() {
            types.extend(def.fields.iter().map(|f| &f.ty));
        }
        let mut problems: Vec<&TypeRef> = types
            .into_iter()
            .filter(|ty| matches!(&ty.kind, Kind::Struct(name) if !self.structs.contains_key(name)))
            .collect();
        problems.sort_by_key(|ty| ty.line);
        match problems.first() {
            Some(ty) => {
                let Kind::Struct(name) = &ty.kind else { unreachable!("filtered to structs") };
                Err(TemplateError::new(ty.line, format!("unknown type '{name}'")))
            }
            None => Ok(()),
        }
    }

    /// Name of the root struct, used in the finding's id and title.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Apply the template to `bytes`, whose first byte sits at document
    /// offset `base`.
    pub fn apply(&self, bytes: &[u8], base: usize) -> Applied {
        let mut evaluator = Evaluator::new(self, bytes, base);
        let mut position = 0;
        let label = match self.root.array {
            Some(_) => format!("{}[]", self.name),
            None => self.name.clone(),
        };
        let outcome = evaluator.eval_type(&self.root, &label, &mut position, 0, false);
        let root_field = outcome.field.unwrap_or_else(|| Field::new(label, base, 0, "(nothing parsed)"));
        let len = evaluator.max_end.max(root_field.len);
        let warnings = evaluator.warnings;
        let detail = format!(
            "{} fields, {} bytes{}",
            evaluator.field_count,
            len,
            if warnings.is_empty() { String::new() } else { format!(", {} warnings", warnings.len()) }
        );
        let finding = Finding::new(format!("template:{}", self.name.to_lowercase()), "templates", Category::Structure, base, len.max(1))
            .title(format!("{} (template)", self.name))
            .detail(detail)
            .confidence(if warnings.is_empty() { 1.0 } else { 0.6 })
            .fields(vec![root_field]);
        Applied { finding, records: evaluator.records, warnings }
    }
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// One element of the outermost array of structs, flattened for a table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Document offset of the element.
    pub offset: usize,
    pub len: usize,
    /// Leaf field name (dotted for nested structs) and its displayed value.
    pub values: Vec<(String, String)>,
}

impl Record {
    /// The displayed value of a column, if this record has it.
    pub fn value(&self, column: &str) -> Option<&str> {
        self.values.iter().find(|(name, _)| name == column).map(|(_, value)| value.as_str())
    }
}

/// What applying a template produced.
#[derive(Clone, Debug)]
pub struct Applied {
    /// The whole parse as a finding with a field tree in document offsets.
    pub finding: Finding,
    /// Elements of the outermost array of structs, for a table view.
    pub records: Vec<Record>,
    /// Problems met while applying, each prefixed with its template line.
    pub warnings: Vec<String>,
}

impl Applied {
    /// Column names across all records, in order of first appearance.
    pub fn columns(&self) -> Vec<String> {
        let mut columns: Vec<String> = Vec::new();
        for record in &self.records {
            for (name, _) in &record.values {
                if !columns.contains(name) {
                    columns.push(name.clone());
                }
            }
        }
        columns
    }
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Int(i128),
    Float(f64),
    Text(Vec<u8>),
    Struct(Vec<(String, Value)>),
    Other,
}

/// Why evaluation of a branch stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    /// Ran off the end of the data.
    Truncated,
    /// A bad expression, length or offset.
    Invalid,
    /// The first field of an `until_end` element did not match its expected
    /// value: the array has ended, quietly.
    Sentinel,
    /// The field cap was reached; everything stops.
    Limit,
}

struct Outcome {
    field: Option<Field>,
    value: Value,
    stop: Option<Stop>,
}

impl Outcome {
    fn stopped(stop: Stop) -> Self {
        Outcome { field: None, value: Value::Other, stop: Some(stop) }
    }
}

struct Evaluator<'a> {
    template: &'a Template,
    bytes: &'a [u8],
    base: usize,
    field_count: usize,
    warnings: Vec<String>,
    records: Vec<Record>,
    records_depth: Option<usize>,
    records_owner: Option<usize>,
    next_array: usize,
    max_end: usize,
    scopes: Vec<Vec<(String, Value)>>,
}

impl<'a> Evaluator<'a> {
    fn new(template: &'a Template, bytes: &'a [u8], base: usize) -> Self {
        Evaluator {
            template,
            bytes,
            base,
            field_count: 0,
            warnings: Vec::new(),
            records: Vec::new(),
            records_depth: None,
            records_owner: None,
            next_array: 0,
            max_end: 0,
            scopes: Vec::new(),
        }
    }

    fn warn(&mut self, line: usize, message: impl Into<String>) {
        if self.warnings.len() < MAX_WARNINGS {
            self.warnings.push(format!("line {line}: {}", message.into()));
        }
    }

    /// Create a field at local offset `local`, counting it against the cap.
    fn new_field(&mut self, name: &str, local: usize, len: usize, value: String) -> Result<Field, Stop> {
        self.field_count += 1;
        if self.field_count > MAX_FIELDS {
            if self.field_count == MAX_FIELDS + 1 {
                self.warnings.push(format!("stopped after {MAX_FIELDS} fields"));
            }
            return Err(Stop::Limit);
        }
        self.max_end = self.max_end.max(local + len);
        Ok(Field::new(name, self.base + local, len, value))
    }

    /// Check that `size` bytes are available at `local`, which must itself be
    /// inside the data (or at its very end), even when `size` is zero.
    fn need(&mut self, local: usize, size: usize, name: &str, line: usize) -> Result<(), Stop> {
        let available = self.bytes.len().saturating_sub(local);
        if local > self.bytes.len() || size > available {
            self.warn(line, format!("'{name}' at {:#x} needs {size} bytes but only {available} remain", self.base + local));
            return Err(Stop::Truncated);
        }
        Ok(())
    }

    fn lookup(&self, path: &[String]) -> Result<i128, String> {
        let dotted = path.join(".");
        let (first, rest) = path.split_first().ok_or("empty field name")?;
        for scope in self.scopes.iter().rev() {
            let Some((_, value)) = scope.iter().rev().find(|(name, _)| name == first) else { continue };
            let mut value = value;
            for part in rest {
                value = match value {
                    Value::Struct(members) => {
                        &members.iter().rev().find(|(name, _)| name == part).ok_or_else(|| format!("'{dotted}': no field '{part}'"))?.1
                    }
                    _ => return Err(format!("'{dotted}': '{first}' is not a struct")),
                };
            }
            return match value {
                Value::Int(number) => Ok(*number),
                Value::Float(number) if number.is_finite() => Ok(*number as i128),
                _ => Err(format!("'{dotted}' is not a number")),
            };
        }
        Err(format!("unknown field '{dotted}' (fields must come before they are used)"))
    }

    fn eval_expr(&self, expr: &Expr) -> Result<i128, String> {
        match expr {
            Expr::Number(value) => Ok(*value),
            Expr::Path(path) => self.lookup(path),
            Expr::Negate(inner) => self.eval_expr(inner)?.checked_neg().ok_or_else(|| "arithmetic overflow".to_string()),
            Expr::Binary(operator, left, right) => {
                let (left, right) = (self.eval_expr(left)?, self.eval_expr(right)?);
                let result = match operator {
                    Operator::Add => left.checked_add(right),
                    Operator::Subtract => left.checked_sub(right),
                    Operator::Multiply => left.checked_mul(right),
                    Operator::Divide | Operator::Remainder if right == 0 => return Err("division by zero".to_string()),
                    Operator::Divide => left.checked_div(right),
                    Operator::Remainder => left.checked_rem(right),
                    Operator::Equal => Some(i128::from(left == right)),
                    Operator::NotEqual => Some(i128::from(left != right)),
                };
                result.ok_or_else(|| "arithmetic overflow".to_string())
            }
        }
    }

    /// Evaluate a length or count, which must be a non-negative integer.
    fn eval_length(&mut self, expr: &Expr, name: &str, line: usize) -> Result<usize, Stop> {
        match self.eval_expr(expr) {
            Ok(value) if value < 0 => {
                self.warn(line, format!("'{name}' has a negative length ({value})"));
                Err(Stop::Invalid)
            }
            Ok(value) => Ok(usize::try_from(value).unwrap_or(usize::MAX)),
            Err(message) => {
                self.warn(line, format!("'{name}': {message}"));
                Err(Stop::Invalid)
            }
        }
    }

    fn eval_type(&mut self, ty: &TypeRef, name: &str, position: &mut usize, depth: usize, sentinel_ok: bool) -> Outcome {
        match &ty.array {
            Some(count) => self.eval_array(ty, count, name, position, depth),
            None => self.eval_scalar(ty, name, position, depth, sentinel_ok),
        }
    }

    fn eval_scalar(&mut self, ty: &TypeRef, name: &str, position: &mut usize, depth: usize, sentinel_ok: bool) -> Outcome {
        let template = self.template;
        let result = match &ty.kind {
            Kind::Primitive(primitive, endian) => self.read_primitive(*primitive, *endian, name, position, ty.line),
            Kind::Char(length) => self.read_sized(length, name, position, ty.line, |bytes| (Value::Text(bytes.to_vec()), quote(bytes))),
            Kind::Bytes(length) => self.read_sized(length, name, position, ty.line, |bytes| (Value::Text(bytes.to_vec()), bytes_preview(bytes))),
            Kind::Utf16(units, endian) => self.read_utf16(units, *endian, name, position, ty.line),
            Kind::CString => self.read_cstring(name, position, ty.line),
            Kind::Struct(struct_name) => match template.structs.get(struct_name) {
                Some(def) => return self.eval_struct(def, name, position, depth, sentinel_ok),
                None => Err(Stop::Invalid),
            },
        };
        match result {
            Ok((field, value)) => Outcome { field: Some(field), value, stop: None },
            Err(stop) => Outcome::stopped(stop),
        }
    }

    fn read_primitive(&mut self, primitive: Primitive, endian: Endian, name: &str, position: &mut usize, line: usize) -> Result<(Field, Value), Stop> {
        let size = primitive.size();
        self.need(*position, size, name, line)?;
        let (value, text) = decode_primitive(&self.bytes[*position..*position + size], primitive, endian);
        let field = self.new_field(name, *position, size, text)?;
        *position += size;
        Ok((field, value))
    }

    fn read_sized(
        &mut self,
        length: &Expr,
        name: &str,
        position: &mut usize,
        line: usize,
        describe: impl Fn(&[u8]) -> (Value, String),
    ) -> Result<(Field, Value), Stop> {
        let len = self.eval_length(length, name, line)?;
        self.need(*position, len, name, line)?;
        let (value, text) = describe(&self.bytes[*position..*position + len]);
        let field = self.new_field(name, *position, len, text)?;
        *position += len;
        Ok((field, value))
    }

    fn read_utf16(&mut self, units: &Expr, endian: Endian, name: &str, position: &mut usize, line: usize) -> Result<(Field, Value), Stop> {
        let count = self.eval_length(units, name, line)?;
        let len = count.saturating_mul(2);
        self.need(*position, len, name, line)?;
        let units: Vec<u16> = self.bytes[*position..*position + len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| match endian {
                Endian::Little => u16::from_le_bytes([pair[0], pair[1]]),
                Endian::Big => u16::from_be_bytes([pair[0], pair[1]]),
            })
            .collect();
        let text = String::from_utf16_lossy(&units);
        let trimmed = text.trim_end_matches('\0');
        let field = self.new_field(name, *position, len, format!("{trimmed:?}"))?;
        *position += len;
        Ok((field, Value::Text(trimmed.as_bytes().to_vec())))
    }

    fn read_cstring(&mut self, name: &str, position: &mut usize, line: usize) -> Result<(Field, Value), Stop> {
        let rest = self.bytes.get(*position..).unwrap_or_default();
        let Some(end) = rest.iter().position(|&b| b == 0) else {
            self.warn(line, format!("'{name}' at {:#x} has no terminating NUL", self.base + *position));
            return Err(Stop::Truncated);
        };
        let text = &rest[..end];
        let field = self.new_field(name, *position, end + 1, quote(text))?;
        let value = Value::Text(text.to_vec());
        *position += end + 1;
        Ok((field, value))
    }

    fn eval_struct(&mut self, def: &StructDef, label: &str, position: &mut usize, depth: usize, sentinel_ok: bool) -> Outcome {
        if depth > MAX_DEPTH {
            let line = def.fields.first().map(|f| f.line).unwrap_or(0);
            self.warn(line, format!("'{label}' is nested more than {MAX_DEPTH} deep"));
            return Outcome::stopped(Stop::Invalid);
        }
        let start = *position;
        self.scopes.push(Vec::new());
        let mut children = Vec::new();
        let mut stop = None;
        for (index, field_def) in def.fields.iter().enumerate() {
            if let Some(condition) = &field_def.condition {
                match self.eval_expr(condition) {
                    Ok(0) => continue,
                    Ok(_) => {}
                    Err(message) => {
                        self.warn(field_def.line, format!("'{}': {message}", field_def.name));
                        stop = Some(Stop::Invalid);
                        break;
                    }
                }
            }
            let (mut cursor, moves) = match &field_def.at {
                None => (*position, true),
                Some(at) => match self.eval_expr(at) {
                    Ok(offset) if offset >= 0 => (usize::try_from(offset).unwrap_or(usize::MAX), false),
                    Ok(offset) => {
                        self.warn(field_def.line, format!("'{}' has a negative offset ({offset})", field_def.name));
                        stop = Some(Stop::Invalid);
                        break;
                    }
                    Err(message) => {
                        self.warn(field_def.line, format!("'{}': {message}", field_def.name));
                        stop = Some(Stop::Invalid);
                        break;
                    }
                },
            };
            let mut outcome = self.eval_type(&field_def.ty, &field_def.name, &mut cursor, depth + 1, false);
            if moves {
                *position = cursor;
            }
            let mismatch = match outcome.field.as_mut() {
                Some(field) if outcome.stop.is_none() => decorate(field_def, &outcome.value, field),
                _ => None,
            };
            if let Some(found) = mismatch {
                if index == 0 && sentinel_ok {
                    self.scopes.pop();
                    *position = start;
                    return Outcome::stopped(Stop::Sentinel);
                }
                self.warn(field_def.line, format!("'{}' is {found}, expected {}", field_def.name, describe_literal(field_def.expected.as_ref())));
            }
            if let Some(field) = outcome.field {
                children.push(field);
            }
            if let Some(scope) = self.scopes.last_mut() {
                scope.push((field_def.name.clone(), outcome.value));
            }
            if outcome.stop.is_some() {
                stop = outcome.stop;
                break;
            }
        }
        let members = self.scopes.pop().unwrap_or_default();
        let len = position.saturating_sub(start);
        match self.new_field(label, start, len, format!("{len} bytes")) {
            Ok(field) => Outcome { field: Some(field.with_children(children)), value: Value::Struct(members), stop },
            Err(limit) => Outcome::stopped(limit),
        }
    }

    fn eval_array(&mut self, ty: &TypeRef, count: &Count, name: &str, position: &mut usize, depth: usize) -> Outcome {
        let until_end = *count == Count::UntilEnd;
        let wanted = match count {
            Count::UntilEnd => MAX_ARRAY,
            Count::Expr(expr) => match self.eval_length(expr, name, ty.line) {
                Ok(n) if n > MAX_ARRAY => {
                    self.warn(ty.line, format!("'{name}' asks for {n} elements; only the first {MAX_ARRAY} are read"));
                    MAX_ARRAY
                }
                Ok(n) => n,
                Err(stop) => return Outcome::stopped(stop),
            },
        };
        let element = TypeRef { kind: ty.kind.clone(), array: None, line: ty.line };
        match &ty.kind {
            Kind::Primitive(primitive, endian) => self.eval_primitive_array(*primitive, *endian, wanted, until_end, name, position, ty.line),
            Kind::Struct(_) => self.eval_element_array(&element, wanted, until_end, name, position, depth, true),
            _ => self.eval_element_array(&element, wanted, until_end, name, position, depth, false),
        }
    }

    /// Arrays of numbers are read in one pass; small ones also list each element.
    #[allow(clippy::too_many_arguments)]
    fn eval_primitive_array(
        &mut self,
        primitive: Primitive,
        endian: Endian,
        wanted: usize,
        until_end: bool,
        name: &str,
        position: &mut usize,
        line: usize,
    ) -> Outcome {
        let size = primitive.size();
        let available = self.bytes.len().saturating_sub(*position) / size;
        let count = if until_end { available.min(MAX_ARRAY) } else { wanted.min(available) };
        if !until_end && wanted > available {
            self.warn(line, format!("'{name}' wants {wanted} × {} but only {available} fit", primitive.name()));
        }
        let start = *position;
        let mut children = Vec::new();
        let mut preview = Vec::new();
        for index in 0..count {
            let at = start + index * size;
            let (_, text) = decode_primitive(&self.bytes[at..at + size], primitive, endian);
            if preview.len() < 8 {
                preview.push(text.clone());
            }
            if count <= MAX_ELEMENT_FIELDS {
                match self.new_field(&format!("[{index}]"), at, size, text) {
                    Ok(field) => children.push(field),
                    Err(stop) => return Outcome::stopped(stop),
                }
            }
        }
        *position = start + count * size;
        let ellipsis = if count > preview.len() { ", …" } else { "" };
        let text = format!("{count} × {}: [{}{ellipsis}]", primitive.name(), preview.join(", "));
        match self.new_field(name, start, count * size, text) {
            Ok(field) => Outcome { field: Some(field.with_children(children)), value: Value::Other, stop: None },
            Err(stop) => Outcome::stopped(stop),
        }
    }

    /// Arrays of structs (which feed the records table) and of strings.
    #[allow(clippy::too_many_arguments)]
    fn eval_element_array(
        &mut self,
        element: &TypeRef,
        wanted: usize,
        until_end: bool,
        name: &str,
        position: &mut usize,
        depth: usize,
        of_structs: bool,
    ) -> Outcome {
        let array_id = self.next_array;
        self.next_array += 1;
        if of_structs && self.records_depth.is_none_or(|records_depth| depth < records_depth) {
            self.records_depth = Some(depth);
            self.records_owner = Some(array_id);
            self.records.clear();
        }
        let start = *position;
        let mut children = Vec::new();
        let mut stop = None;
        for index in 0..wanted {
            if until_end && *position >= self.bytes.len() {
                break;
            }
            let element_start = *position;
            let outcome = self.eval_scalar(element, &format!("[{index}]"), position, depth + 1, until_end);
            match outcome.stop {
                Some(Stop::Sentinel) => {
                    *position = element_start;
                    break;
                }
                Some(Stop::Limit) => {
                    stop = Some(Stop::Limit);
                    break;
                }
                Some(_) => {
                    // The warning is already recorded; keep what parsed and end the array.
                    children.extend(outcome.field);
                    break;
                }
                None => {}
            }
            if let Some(field) = outcome.field {
                if self.records_owner == Some(array_id) {
                    self.records.push(record_from(&field));
                }
                children.push(field);
            }
            if *position == element_start {
                // A zero-sized element would repeat for ever.
                break;
            }
        }
        let len = position.saturating_sub(start);
        let text = format!("{} items", children.len());
        match self.new_field(name, start, len, text) {
            Ok(field) => Outcome { field: Some(field.with_children(children)), value: Value::Other, stop },
            Err(limit) => Outcome::stopped(limit),
        }
    }
}

/// Apply enum labels and hex display to a field's text, and compare it with
/// its expected value. Returns the found value's text on a mismatch.
fn decorate(def: &FieldDef, value: &Value, field: &mut Field) -> Option<String> {
    if let Value::Int(number) = value {
        if def.hex {
            field.value = format_int(*number, true);
        }
        if let Some((_, label)) = def.labels.iter().find(|(candidate, _)| candidate == number) {
            field.value = format!("{} ({label})", field.value);
        }
    }
    let expected = def.expected.as_ref()?;
    let matches = match (expected, value) {
        (Literal::Number(want), Value::Int(found)) => want == found,
        (Literal::Bytes(want), Value::Text(found)) => want == found,
        _ => false,
    };
    if matches {
        return None;
    }
    let found = field.value.clone();
    field.value = format!("{found} (expected {})", describe_literal(Some(expected)));
    Some(found)
}

fn describe_literal(literal: Option<&Literal>) -> String {
    match literal {
        Some(Literal::Number(value)) => format_int(*value, *value > 255),
        Some(Literal::Bytes(bytes)) => quote(bytes),
        None => String::new(),
    }
}

fn record_from(field: &Field) -> Record {
    let mut values = Vec::new();
    flatten_leaves(&field.children, "", &mut values);
    Record { offset: field.offset, len: field.len, values }
}

/// Leaf fields as (dotted name, value); arrays become one column.
fn flatten_leaves(children: &[Field], prefix: &str, out: &mut Vec<(String, String)>) {
    for child in children {
        if out.len() >= MAX_RECORD_COLUMNS {
            return;
        }
        let name = if prefix.is_empty() { child.name.clone() } else { format!("{prefix}.{}", child.name) };
        let is_array = child.children.first().is_some_and(|first| first.name.starts_with('['));
        if child.children.is_empty() || is_array {
            out.push((name, child.value.clone()));
        } else {
            flatten_leaves(&child.children, &name, out);
        }
    }
}

// ---------------------------------------------------------------------------
// Value formatting
// ---------------------------------------------------------------------------

fn decode_primitive(bytes: &[u8], primitive: Primitive, endian: Endian) -> (Value, String) {
    let mut raw = [0u8; 8];
    match endian {
        Endian::Little => raw[..bytes.len()].copy_from_slice(bytes),
        Endian::Big => {
            for (index, byte) in bytes.iter().rev().enumerate() {
                raw[index] = *byte;
            }
        }
    }
    let unsigned = u64::from_le_bytes(raw);
    let bits = primitive.size() as u32 * 8;
    let signed = |value: u64| -> i128 {
        let shift = 64 - bits;
        (((value << shift) as i64) >> shift) as i128
    };
    match primitive {
        Primitive::U8 | Primitive::U16 | Primitive::U32 | Primitive::U64 => (Value::Int(unsigned as i128), unsigned.to_string()),
        Primitive::I8 | Primitive::I16 | Primitive::I32 | Primitive::I64 => {
            let value = signed(unsigned);
            (Value::Int(value), value.to_string())
        }
        Primitive::F32 => {
            let value = f32::from_bits(unsigned as u32) as f64;
            (Value::Float(value), format_float(value))
        }
        Primitive::F64 => {
            let value = f64::from_bits(unsigned);
            (Value::Float(value), format_float(value))
        }
    }
}

fn format_int(value: i128, hex: bool) -> String {
    if hex && value >= 0 { format!("{value} ({value:#X})") } else { value.to_string() }
}

fn format_float(value: f64) -> String {
    if value == 0.0 || !value.is_finite() || (1e-4..1e15).contains(&value.abs()) {
        format!("{value}")
    } else {
        format!("{value:e}")
    }
}

/// Text in quotes, trailing NULs trimmed, other non-printables escaped.
fn quote(bytes: &[u8]) -> String {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |last| last + 1);
    let mut text = String::from("\"");
    for &byte in &bytes[..end] {
        match byte {
            b'"' => text.push_str("\\\""),
            b'\\' => text.push_str("\\\\"),
            0x20..=0x7E => text.push(byte as char),
            _ => text.push_str(&format!("\\x{byte:02x}")),
        }
    }
    text.push('"');
    text
}

fn bytes_preview(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(empty)".to_string();
    }
    let hex: Vec<String> = bytes.iter().take(PREVIEW_BYTES).map(|b| format!("{b:02X}")).collect();
    let more = if bytes.len() > PREVIEW_BYTES { " …" } else { "" };
    format!("{}{more} ({} bytes)", hex.join(" "), bytes.len())
}

// ---------------------------------------------------------------------------
// Built-in and user templates
// ---------------------------------------------------------------------------

/// The templates shipped with the viewer, as (name, source).
pub fn builtin_templates() -> Vec<(&'static str, &'static str)> {
    vec![
        ("RIFF", include_str!("../templates/riff.tpl")),
        ("PNG", include_str!("../templates/png.tpl")),
        ("BMP", include_str!("../templates/bmp.tpl")),
        ("ZIP local files", include_str!("../templates/zip_local.tpl")),
        ("ELF64 header", include_str!("../templates/elf64_header.tpl")),
        ("Fixed-size records", include_str!("../templates/records.tpl")),
    ]
}

/// Where user templates live by default.
pub fn default_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config/theviewer/templates"))
}

/// Parse every `*.tpl` file in `dir`, in name order. A missing directory
/// yields an empty list; an unreadable file yields an error for that file.
pub fn load_dir(dir: &Path) -> Vec<(String, Result<Template, TemplateError>)> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut paths: Vec<std::path::PathBuf> =
        entries.filter_map(|entry| entry.ok().map(|e| e.path())).filter(|path| path.extension().is_some_and(|ext| ext == "tpl")).collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let name = path.file_stem().map(|stem| stem.to_string_lossy().into_owned()).unwrap_or_default();
            let parsed = std::fs::read_to_string(&path)
                .map_err(|error| TemplateError::new(0, format!("{}: {error}", path.display())))
                .and_then(|source| Template::parse(&source));
            (name, parsed)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Inference
// ---------------------------------------------------------------------------

/// One inferred field of a record.
struct Inferred {
    name: String,
    ty: String,
    expected: Option<String>,
    comment: String,
}

/// Unique field names: the first `counter`, then `counter_2`, and so on.
#[derive(Default)]
struct NameBook {
    used: HashMap<String, usize>,
}

impl NameBook {
    fn name(&mut self, base: &str) -> String {
        let count = self.used.entry(base.to_string()).or_insert(0);
        *count += 1;
        if *count == 1 { base.to_string() } else { format!("{base}_{count}") }
    }
}

/// Values of a `width`-byte column at `offset` in each of `records` records.
fn column(bytes: &[u8], record_len: usize, records: usize, offset: usize, width: usize, big: bool) -> Vec<u64> {
    (0..records)
        .map(|record| {
            let at = record * record_len + offset;
            let slice = &bytes[at..at + width];
            let mut raw = [0u8; 8];
            if big {
                for (index, byte) in slice.iter().rev().enumerate() {
                    raw[index] = *byte;
                }
            } else {
                raw[..width].copy_from_slice(slice);
            }
            u64::from_le_bytes(raw)
        })
        .collect()
}

/// Length of the run of bytes from `offset` that is printable ASCII in every record.
fn printable_run(bytes: &[u8], record_len: usize, records: usize, offset: usize) -> usize {
    let mut len = 0;
    while offset + len < record_len && (0..records).all(|r| (0x20..0x7F).contains(&bytes[r * record_len + offset + len])) {
        len += 1;
    }
    len
}

fn same_in_every_record(bytes: &[u8], record_len: usize, records: usize, offset: usize, len: usize) -> bool {
    let first = &bytes[offset..offset + len];
    (1..records).all(|r| &bytes[r * record_len + offset..r * record_len + offset + len] == first)
}

/// A timestamp a detector found at the same place in every record, which
/// inference reads as one field rather than guessing at its bytes again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownTime {
    /// Offset within the record.
    pub offset: usize,
    /// Bytes of the time: 4 or 8.
    pub width: usize,
}

/// Template source for one record, inferred from `records` consecutive
/// records of `record_len` bytes at the start of `bytes`. `document_len`
/// bounds what counts as an in-file offset; `times` are timestamps already
/// found in the records.
pub fn infer_struct(bytes: &[u8], record_len: usize, records: usize, document_len: usize, times: &[KnownTime]) -> String {
    let records = bytes.len().checked_div(record_len).map_or(0, |whole| records.min(whole));
    let mut book = NameBook::default();
    let fields = if record_len == 0 || records < 2 {
        let comment = "need at least two whole records to infer anything".to_string();
        vec![Inferred { name: "unknown_0".to_string(), ty: format!("bytes[{record_len}]"), expected: None, comment }]
    } else {
        infer_fields(bytes, record_len, records, document_len, times, &mut book)
    };
    let mut source = format!(
        "// Inferred from {records} records of {record_len} bytes. Rename fields as you learn what they mean.\nendian little\n\nstruct Record {{\n"
    );
    for field in fields {
        let expected = field.expected.map(|value| format!(" = {value}")).unwrap_or_default();
        let declaration = format!("{}: {}{expected}", field.name, field.ty);
        source.push_str(&format!("    {declaration:<36} // {}\n", field.comment));
    }
    source.push_str("}\n\nroot Record[until_end]\n");
    source
}

fn infer_fields(bytes: &[u8], record_len: usize, records: usize, document_len: usize, times: &[KnownTime], book: &mut NameBook) -> Vec<Inferred> {
    let mut fields = Vec::new();
    let mut unknown_start: Option<usize> = None;
    let mut offset = 0;
    while offset < record_len {
        let known_time = times.iter().find(|time| time.offset == offset && offset + time.width <= record_len);
        let found = known_time
            .and_then(|time| infer_time(bytes, record_len, records, *time, book))
            .or_else(|| infer_text(bytes, record_len, records, offset, book))
            .or_else(|| infer_number(bytes, record_len, records, offset, document_len, book));
        match found {
            Some((field, width)) => {
                flush_unknown(&mut fields, &mut unknown_start, offset, book);
                fields.push(field);
                offset += width;
            }
            None => {
                unknown_start.get_or_insert(offset);
                offset += 1;
            }
        }
    }
    flush_unknown(&mut fields, &mut unknown_start, record_len, book);
    fields
}

fn flush_unknown(fields: &mut Vec<Inferred>, unknown_start: &mut Option<usize>, end: usize, book: &mut NameBook) {
    if let Some(start) = unknown_start.take() {
        fields.push(Inferred {
            name: book.name(&format!("unknown_{start}")),
            ty: format!("bytes[{}]", end - start),
            expected: None,
            comment: "no pattern found".to_string(),
        });
    }
}

/// The known timestamp at `time`, in the byte order and format whose every
/// value is a plausible time.
fn infer_time(bytes: &[u8], record_len: usize, records: usize, time: KnownTime, book: &mut NameBook) -> Option<(Inferred, usize)> {
    use crate::patterns::TimeFormat;
    let formats: &[TimeFormat] = match time.width {
        4 => &[TimeFormat::UnixSeconds],
        8 => &[TimeFormat::UnixMillis, TimeFormat::FileTime],
        _ => return None,
    };
    for big in [false, true] {
        let values = column(bytes, record_len, records, time.offset, time.width, big);
        for &format in formats {
            if values.iter().all(|&value| format.to_unix_seconds(value).is_some()) {
                let suffix = if big { "be" } else { "" };
                let field = Inferred {
                    name: book.name("time"),
                    ty: format!("u{}{suffix}", time.width * 8),
                    expected: None,
                    comment: format!("{}, found by the timestamp detector", format.label()),
                };
                return Some((field, time.width));
            }
        }
    }
    None
}

fn infer_text(bytes: &[u8], record_len: usize, records: usize, offset: usize, book: &mut NameBook) -> Option<(Inferred, usize)> {
    const MIN_TEXT: usize = 3;
    let run = printable_run(bytes, record_len, records, offset);
    if run < MIN_TEXT {
        return None;
    }
    let field = if same_in_every_record(bytes, record_len, records, offset, run) {
        Inferred {
            name: book.name("magic"),
            ty: format!("char[{run}]"),
            expected: Some(quote(&bytes[offset..offset + run])),
            comment: "the same text in every record".to_string(),
        }
    } else {
        Inferred { name: book.name("text"), ty: format!("char[{run}]"), expected: None, comment: "printable text that varies".to_string() }
    };
    Some((field, run))
}

fn infer_number(
    bytes: &[u8],
    record_len: usize,
    records: usize,
    offset: usize,
    document_len: usize,
    book: &mut NameBook,
) -> Option<(Inferred, usize)> {
    for width in [4usize, 8, 2, 1] {
        if !offset.is_multiple_of(width) || offset + width > record_len {
            continue;
        }
        let endians: &[bool] = if width == 1 { &[false] } else { &[false, true] };
        for &big in endians {
            let values = column(bytes, record_len, records, offset, width, big);
            if let Some(field) = classify_column(&values, width, big, offset, record_len, records, document_len, book) {
                return Some((field, width));
            }
        }
    }
    None
}

/// Decide what a numeric column is: constant, offset, counter or float.
#[allow(clippy::too_many_arguments)]
fn classify_column(
    values: &[u64],
    width: usize,
    big: bool,
    offset: usize,
    record_len: usize,
    records: usize,
    document_len: usize,
    book: &mut NameBook,
) -> Option<Inferred> {
    const MAX_COUNTER_STEP: i128 = 4096;
    const MIN_FLOAT_RECORDS: usize = 4;
    let suffix = if big { "be" } else { "" };
    let ty = format!("u{}{suffix}", width * 8);
    let first = values[0];
    if values.iter().all(|&v| v == first) {
        return Some(Inferred {
            name: book.name(&format!("constant_{offset}")),
            ty,
            expected: Some(if first > 255 { format!("{first:#x}") } else { first.to_string() }),
            comment: "the same value in every record".to_string(),
        });
    }
    let step = values[1] as i128 - values[0] as i128;
    let constant_step = values.windows(2).all(|pair| pair[1] as i128 - pair[0] as i128 == step);
    let inside_file = values.iter().all(|&v| (v as u128) < document_len as u128);
    if width >= 4 && constant_step && step > 0 && inside_file && (step as usize).is_multiple_of(record_len) {
        let comment = format!("increases by {step} each record and always points inside the file");
        return Some(Inferred { name: book.name("offset"), ty, expected: None, comment });
    }
    // A step that is a multiple of 256 means the low byte never changes:
    // a narrower counter further along explains it better.
    if constant_step && step != 0 && step.abs() <= MAX_COUNTER_STEP && step % 256 != 0 {
        return Some(Inferred { name: book.name("counter"), ty, expected: None, comment: format!("{step:+} each record") });
    }
    let increasing = values.windows(2).all(|pair| pair[1] > pair[0]);
    if width >= 4 && increasing && inside_file && first > 0 {
        let comment = "always increasing and always inside the file".to_string();
        return Some(Inferred { name: book.name("offset"), ty, expected: None, comment });
    }
    if width == 4 && records >= MIN_FLOAT_RECORDS && values.iter().all(|&v| plausible_f32(f32::from_bits(v as u32))) {
        let ty = format!("f32{suffix}");
        return Some(Inferred { name: book.name("value_f32"), ty, expected: None, comment: "varies, always a sensible float".to_string() });
    }
    None
}

fn plausible_f32(value: f32) -> bool {
    value == 0.0 || (value.is_finite() && (1e-6..=1e9).contains(&value.abs()))
}

/// Propose a record length for `bytes` from its strongest repeating period.
pub fn guess_record_length(bytes: &[u8]) -> Option<usize> {
    const MAX_GUESS: usize = 4096;
    let max_lag = (bytes.len() / 4).min(MAX_GUESS);
    if max_lag < 2 {
        return None;
    }
    let scan = crate::analysis::scan_periods(bytes, 0, max_lag);
    scan.candidates.iter().find(|candidate| candidate.multiple_of.is_none()).map(|candidate| candidate.period)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(state: &mut u32) -> u8 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        (*state >> 24) as u8
    }

    /// RIFF/WAVE: a 16-byte fmt chunk, a 5-byte data chunk (padded) and a LIST chunk.
    fn wav() -> Vec<u8> {
        let mut body = b"WAVE".to_vec();
        body.extend_from_slice(b"fmt \x10\x00\x00\x00");
        body.extend_from_slice(&[1, 0, 1, 0, 0x40, 0x1F, 0, 0, 0x80, 0x3E, 0, 0, 2, 0, 16, 0]);
        body.extend_from_slice(b"data\x05\x00\x00\x00");
        body.extend_from_slice(&[1, 2, 3, 4, 5, 0]);
        body.extend_from_slice(b"LIST\x04\x00\x00\x00INFO");
        let mut file = b"RIFF".to_vec();
        file.extend_from_slice(&(body.len() as u32).to_le_bytes());
        file.extend_from_slice(&body);
        file
    }

    fn builtin(name: &str) -> Template {
        let (_, source) = builtin_templates().into_iter().find(|(n, _)| *n == name).unwrap();
        Template::parse(source).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    #[test]
    fn every_builtin_template_parses() {
        for (name, source) in builtin_templates() {
            Template::parse(source).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn parse_errors_name_the_line() {
        let error = Template::parse("struct A {\n    x: u33\n}\n").unwrap_err();
        assert_eq!(error.line, 2);
        assert!(error.message.contains("unknown type 'u33'"), "{error}");
        assert_eq!(error.to_string(), "line 2: unknown type 'u33'");

        let error = Template::parse("struct A {\n    x u8\n}\n").unwrap_err();
        assert_eq!(error.line, 2);
        assert!(error.message.contains("expected ':'"), "{error}");

        let error = Template::parse("endian little\nstruct A {\n    x: u8\n").unwrap_err();
        assert!(error.message.contains("closing '}'"), "{error}");

        let error = Template::parse("struct A {\n    x: char\n}").unwrap_err();
        assert!(error.message.contains("needs a length"), "{error}");

        let error = Template::parse("struct A { x: u8 = 1 enum { 1 = 2 } }").unwrap_err();
        assert!(error.message.contains("expected a \"name\""), "{error}");

        assert!(Template::parse("").is_err());
        assert!(Template::parse("struct A { }\nstruct A { }").unwrap_err().message.contains("defined twice"));
    }

    #[test]
    fn riff_template_lists_chunks_at_document_offsets() {
        let bytes = wav();
        let applied = builtin("RIFF").apply(&bytes, 1000);
        assert!(applied.warnings.is_empty(), "{:?}", applied.warnings);
        let ids: Vec<&str> = applied.records.iter().filter_map(|r| r.value("id")).collect();
        assert_eq!(ids, vec!["\"fmt \"", "\"data\"", "\"LIST\""]);
        assert_eq!(applied.records[0].offset, 1012);
        assert_eq!(applied.records[1].offset, 1036);
        assert_eq!(applied.records[1].len, 14, "header, five bytes and one pad byte");
        assert_eq!(applied.records[1].value("len"), Some("5"));
        assert_eq!(applied.columns(), vec!["id", "len", "data", "pad"]);

        let finding = &applied.finding;
        assert_eq!(finding.id, "template:riff");
        assert_eq!((finding.start, finding.len), (1000, bytes.len()));
        let header = &finding.fields[0].children[0];
        assert_eq!(header.name, "header");
        assert_eq!(header.children[0].offset, 1000);
        assert_eq!(header.children[0].value, "\"RIFF\"");
        let path: Vec<&str> = finding.field_path(1036 + 9).iter().map(|f| f.name.as_str()).collect();
        assert_eq!(path, vec!["Riff", "chunks", "[1]", "data"]);
    }

    #[test]
    fn arithmetic_offsets_and_enums_evaluate() {
        let source = "endian little\nstruct T {\n  count: u8\n  offset: u8\n  values: u16[(count + 1) * 2]\n  table: u8[count] @ offset\n  after: u8\n  kind: u8 enum { 1 = \"Data\", 2 = \"Code\" }\n  word: u16be display hex\n}\nroot T\n";
        let template = Template::parse(source).unwrap();
        let mut bytes = vec![1u8, 10, 1, 0, 2, 0, 3, 0, 4, 0, 0xAA, 2, 0x12, 0x34];
        bytes.extend_from_slice(&[0; 4]);
        let applied = template.apply(&bytes, 0);
        assert!(applied.warnings.is_empty(), "{:?}", applied.warnings);
        let fields = &applied.finding.fields[0].children;
        let get = |name: &str| fields.iter().find(|f| f.name == name).unwrap();
        assert_eq!(get("values").len, 8);
        assert!(get("values").value.starts_with("4 × u16: [1, 2, 3, 4]"), "{}", get("values").value);
        assert_eq!((get("table").offset, get("table").len), (10, 1));
        assert_eq!(get("after").offset, 10, "an @ field does not move the cursor");
        assert_eq!(get("kind").value, "2 (Code)");
        assert_eq!(get("word").value, "4660 (0x1234)");
    }

    #[test]
    fn expected_value_mismatches_warn_but_do_not_stop() {
        let template = Template::parse("struct H {\n  magic: char[4] = \"RIFF\"\n  size: u32\n}").unwrap();
        let applied = template.apply(b"RIFX\x08\x00\x00\x00", 0);
        assert_eq!(applied.warnings.len(), 1);
        assert!(applied.warnings[0].starts_with("line 2:"), "{:?}", applied.warnings);
        assert_eq!(applied.finding.fields[0].children[1].value, "8");
    }

    #[test]
    fn until_end_arrays_stop_at_a_failed_signature() {
        let mut bytes = Vec::new();
        for name in [b"a.txt", b"b.txt"] {
            bytes.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            bytes.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            bytes.extend_from_slice(&3u32.to_le_bytes());
            bytes.extend_from_slice(&3u32.to_le_bytes());
            bytes.extend_from_slice(&5u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(b"abc");
        }
        bytes.extend_from_slice(b"PK\x01\x02 central directory follows");
        let applied = builtin("ZIP local files").apply(&bytes, 0);
        assert!(applied.warnings.is_empty(), "{:?}", applied.warnings);
        assert_eq!(applied.records.len(), 2);
        assert_eq!(applied.records[1].value("name"), Some("\"b.txt\""));
        assert_eq!(applied.records[0].value("method"), Some("0 (stored)"));
    }

    #[test]
    fn an_empty_field_placed_past_the_end_warns_instead_of_crashing() {
        // Like a BMP whose image size is 0 and whose data offset is past the end.
        let template = Template::parse("struct T { offset: u8\n size: u8\n pixels: bytes[size] @ offset\n name: utf16le[size] @ offset }").unwrap();
        let applied = template.apply(&[200, 0], 0);
        assert!(applied.warnings.iter().any(|w| w.contains("needs")), "{:?}", applied.warnings);
    }

    #[test]
    fn truncated_data_becomes_warnings() {
        let bytes = wav();
        let applied = builtin("RIFF").apply(&bytes[..30], 0);
        assert!(!applied.warnings.is_empty());
        assert!(applied.warnings.iter().any(|w| w.contains("needs")), "{:?}", applied.warnings);
        assert!(applied.finding.fields[0].children.len() >= 2);

        let template = Template::parse("struct T { n: u8\n data: bytes[n * 1000] }").unwrap();
        assert!(!template.apply(&[200, 1, 2], 0).warnings.is_empty());
        let template = Template::parse("struct T { n: u8\n data: bytes[10 / (n - n)] }").unwrap();
        assert!(template.apply(&[3], 0).warnings[0].contains("division by zero"));
        let template = Template::parse("struct T { data: bytes[missing] }").unwrap();
        assert!(template.apply(&[3], 0).warnings[0].contains("unknown field 'missing'"));
    }

    #[test]
    fn a_field_only_some_message_types_carry_is_read_only_in_those() {
        let source = "struct Message { kind: u8\n len: u8\n time: u32le if kind == 0x81\n payload: bytes[len - 4 * (kind == 0x81)]\n check: u8 }\nroot Message[until_end]";
        let template = Template::parse(source).unwrap();
        let mut bytes = vec![0x01, 0, 0xEE];
        bytes.extend([0x81, 6, 0x00, 0x2F, 0xE9, 0x68, 0xAA, 0xBB, 0xEE]);
        let applied = template.apply(&bytes, 0);
        assert!(applied.warnings.is_empty(), "{:?}", applied.warnings);
        assert_eq!(applied.records.len(), 2);
        assert_eq!(applied.records[0].value("time"), None, "a poll has no time");
        assert_eq!(applied.records[0].value("check"), Some("238"));
        assert_eq!(applied.records[1].value("time"), Some("1760112384"));
        assert_eq!(applied.records[1].value("check"), Some("238"));
        let not_equal = Template::parse("struct T { kind: u8\n extra: u8 if kind != 1 }").unwrap();
        assert_eq!(not_equal.apply(&[1, 9], 0).finding.fields[0].children.len(), 1);
        assert_eq!(not_equal.apply(&[2, 9], 0).finding.fields[0].children.len(), 2);
    }

    #[test]
    fn nested_fields_are_reachable_by_dotted_names() {
        let source = "struct Head { count: u8 }\nstruct Body { head: Head\n items: u8[head.count] }\nroot Body";
        let applied = Template::parse(source).unwrap().apply(&[3, 7, 8, 9, 10], 0);
        let items = &applied.finding.fields[0].children[1];
        assert_eq!(items.len, 3);
        assert_eq!(items.children.len(), 3);
    }

    #[test]
    fn strings_utf16_and_cstrings_decode() {
        let source = "struct T { name: cstring\n wide: utf16[2]\n raw: bytes[2] }";
        let mut bytes = b"hello\0".to_vec();
        bytes.extend_from_slice(&[b'h', 0, b'i', 0, 0xDE, 0xAD]);
        let applied = Template::parse(source).unwrap().apply(&bytes, 0);
        let fields = &applied.finding.fields[0].children;
        assert_eq!((fields[0].value.as_str(), fields[0].len), ("\"hello\"", 6));
        assert_eq!(fields[1].value, "\"hi\"");
        assert_eq!(fields[2].value, "DE AD (2 bytes)");
    }

    #[test]
    fn builtin_templates_survive_noise() {
        let mut state = 0x2545_F491u32;
        let noise: Vec<u8> = (0..70_000).map(|_| xorshift(&mut state)).collect();
        for (name, source) in builtin_templates() {
            let template = Template::parse(source).unwrap();
            for len in [0usize, 1, 7, 64, 1000, 70_000] {
                let applied = template.apply(&noise[..len], 5);
                let mut count = 0;
                fn walk(fields: &[Field], count: &mut usize) {
                    for field in fields {
                        *count += 1;
                        walk(&field.children, count);
                    }
                }
                walk(&applied.finding.fields, &mut count);
                assert!(count <= MAX_FIELDS + 1, "{name} on {len} bytes made {count} fields");
            }
        }
    }

    #[test]
    fn field_cap_stops_runaway_templates() {
        let template = Template::parse("struct One { b: u8 }\nroot One[until_end]").unwrap();
        let bytes = vec![0u8; MAX_FIELDS * 2];
        let applied = template.apply(&bytes, 0);
        assert!(applied.warnings.iter().any(|w| w.contains("stopped after")), "{:?}", applied.warnings.last());
    }

    /// 24-byte records: "REC1", a u32 counter, a u32 file offset, an f32 and 8 random bytes.
    fn synthetic_records(count: u32) -> Vec<u8> {
        let mut state = 0x9E37_79B9u32;
        let mut bytes = Vec::new();
        for index in 0..count {
            bytes.extend_from_slice(b"REC1");
            bytes.extend_from_slice(&index.to_le_bytes());
            bytes.extend_from_slice(&(4096 + index * 24).to_le_bytes());
            bytes.extend_from_slice(&((index as f32 * 0.37).sin() * 50.0 + 100.0).to_le_bytes());
            bytes.extend((0..8).map(|_| xorshift(&mut state)));
        }
        bytes
    }

    #[test]
    fn inferred_templates_round_trip_and_recover_the_counter() {
        let bytes = synthetic_records(200);
        let source = infer_struct(&bytes, 24, 200, 1_000_000, &[]);
        assert!(source.contains("magic: char[4] = \"REC1\""), "{source}");
        assert!(source.contains("counter: u32"), "{source}");
        assert!(source.contains("offset: u32"), "{source}");
        assert!(source.contains("value_f32: f32"), "{source}");
        assert!(source.contains("unknown_16: bytes[8]"), "{source}");
        let template = Template::parse(&source).unwrap_or_else(|e| panic!("{e}\n{source}"));
        let applied = template.apply(&bytes, 0);
        assert!(applied.warnings.is_empty(), "{:?}", applied.warnings);
        assert_eq!(applied.records.len(), 200);
        for (index, record) in applied.records.iter().enumerate() {
            assert_eq!(record.value("counter"), Some(index.to_string().as_str()));
        }
    }

    #[test]
    fn inference_with_too_few_records_still_parses() {
        let source = infer_struct(&[1, 2, 3], 8, 5, 100, &[]);
        assert!(source.contains("bytes[8]"));
        assert!(Template::parse(&source).is_ok());
        assert!(Template::parse(&infer_struct(&[], 0, 0, 0, &[])).is_ok());
    }

    #[test]
    fn record_length_is_guessed_from_the_period() {
        assert_eq!(guess_record_length(&synthetic_records(300)), Some(24));
        assert_eq!(guess_record_length(&[0u8; 4]), None);
    }

    #[test]
    fn load_dir_reports_each_file() {
        let dir = std::env::temp_dir().join(format!("theviewer-templates-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("good.tpl"), "struct A { x: u8 }").unwrap();
        std::fs::write(dir.join("bad.tpl"), "struct A { x: nope }").unwrap();
        std::fs::write(dir.join("ignored.txt"), "not a template").unwrap();
        let loaded = load_dir(&dir);
        std::fs::remove_dir_all(&dir).ok();
        let names: Vec<&str> = loaded.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["bad", "good"]);
        assert!(loaded[0].1.is_err() && loaded[1].1.is_ok());
        assert!(load_dir(Path::new("/definitely/not/here")).is_empty());
    }
}
