use crate::{Error, Result};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const UCI_ERR_NOTFOUND: libc::c_int = 3;
const MAX_UCI_FILE_LEN: usize = 1_048_576;
const DEFAULT_CONFDIR: &str = "/etc/config";
const DEFAULT_CONF2DIR: &str = "/var/run/uci";
const DEFAULT_SAVEDIR: &str = "/tmp/.uci";

#[derive(Debug)]
enum BoundedReadError {
    Io(io::Error),
    TooLarge,
}

fn read_bounded_regular_file(
    path: &Path,
) -> std::result::Result<Option<Vec<u8>>, BoundedReadError> {
    let metadata = fs::metadata(path).map_err(BoundedReadError::Io)?;
    if !metadata.file_type().is_file() || metadata.len() > (MAX_UCI_FILE_LEN as u64) {
        if metadata.file_type().is_file() {
            return Err(BoundedReadError::TooLarge);
        }
        return Ok(None);
    }

    // O_NONBLOCK closes the FIFO/device race between the path stat and open.
    // The descriptor is checked again after opening, so a swapped path cannot
    // make the daemon wait forever in a configuration read.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(BoundedReadError::Io)?;
    let opened_metadata = file.metadata().map_err(BoundedReadError::Io)?;
    if !opened_metadata.file_type().is_file() {
        return Ok(None);
    }
    if opened_metadata.len() > (MAX_UCI_FILE_LEN as u64) {
        return Err(BoundedReadError::TooLarge);
    }

    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_metadata.len())
            .unwrap_or(MAX_UCI_FILE_LEN)
            .min(MAX_UCI_FILE_LEN + 1),
    );
    file.take((MAX_UCI_FILE_LEN as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(BoundedReadError::Io)?;
    if bytes.len() > MAX_UCI_FILE_LEN {
        return Err(BoundedReadError::TooLarge);
    }
    Ok(Some(bytes))
}

fn bounded_read_error_code(error: &BoundedReadError) -> libc::c_int {
    match error {
        BoundedReadError::Io(error) => error.raw_os_error().unwrap_or(libc::EIO),
        BoundedReadError::TooLarge => libc::EFBIG,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UciValue {
    String(String),
    List(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UciOption {
    pub name: String,
    pub value: UciValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UciSection {
    pub name: String,
    pub kind: String,
    pub anonymous: bool,
    pub options: Vec<UciOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UciPackage {
    pub name: String,
    pub sections: Vec<UciSection>,
}

pub struct UciContext {
    confdir: PathBuf,
    conf2dir: PathBuf,
    savedir: PathBuf,
}

impl UciContext {
    pub fn new() -> Result<Self> {
        Ok(Self {
            confdir: PathBuf::from(DEFAULT_CONFDIR),
            conf2dir: PathBuf::from(DEFAULT_CONF2DIR),
            savedir: PathBuf::from(DEFAULT_SAVEDIR),
        })
    }

    pub fn with_confdir(directory: &Path) -> Result<Self> {
        let mut context = Self::new()?;
        context.set_confdir(directory)?;
        Ok(context)
    }

    pub fn set_confdir(&mut self, directory: &Path) -> Result<()> {
        if directory.as_os_str().is_empty() {
            return Err(Error::InvalidData("empty UCI configuration directory"));
        }
        self.confdir = directory.to_owned();
        Ok(())
    }

    pub fn lookup(&mut self, tuple: &str) -> Result<Option<UciValue>> {
        let mut parts = tuple.split('.');
        let package = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or(Error::InvalidData("invalid UCI tuple"))?;
        let section = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or(Error::InvalidData("invalid UCI tuple"))?;
        let option = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or(Error::InvalidData("invalid UCI tuple"))?;
        if parts.next().is_some() {
            return Err(Error::InvalidData("invalid UCI tuple"));
        }
        let package = match self.load_package(package) {
            Ok(package) => package,
            Err(Error::Platform {
                operation: "uci_load",
                code: UCI_ERR_NOTFOUND,
            }) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(package
            .sections
            .into_iter()
            .find(|candidate| candidate.name == section)
            .and_then(|section| {
                section
                    .options
                    .into_iter()
                    .find(|candidate| candidate.name == option)
            })
            .map(|option| option.value))
    }

    pub fn load_package(&mut self, name: &str) -> Result<UciPackage> {
        if !valid_package_name(name) {
            return Err(Error::InvalidData("invalid UCI package name"));
        }
        let override_path = self.conf2dir.join(name);
        let path = if fs::metadata(&override_path).is_ok() {
            override_path
        } else {
            self.confdir.join(name)
        };
        let bytes = match read_bounded_regular_file(&path) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return Err(Error::Platform {
                    operation: "uci_load",
                    code: UCI_ERR_NOTFOUND,
                });
            }
            Err(BoundedReadError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Error::Platform {
                    operation: "uci_load",
                    code: UCI_ERR_NOTFOUND,
                });
            }
            Err(BoundedReadError::TooLarge) => {
                return Err(Error::InvalidData("UCI package exceeds size limit"));
            }
            Err(error) => {
                return Err(Error::Platform {
                    operation: "uci_load",
                    code: bounded_read_error_code(&error),
                });
            }
        };
        let mut package = parse_package(name, &bytes)?;
        self.apply_saved_delta(&mut package)?;
        Ok(package)
    }

    fn apply_saved_delta(&self, package: &mut UciPackage) -> Result<()> {
        let path = self.savedir.join(&package.name);
        let bytes = match read_bounded_regular_file(&path) {
            Ok(Some(bytes)) => bytes,
            // libuci treats an unavailable saved-delta file as an empty overlay.
            Ok(None) | Err(BoundedReadError::Io(_)) => return Ok(()),
            Err(BoundedReadError::TooLarge) => {
                return Err(Error::InvalidData("UCI delta exceeds size limit"));
            }
        };
        let mut offset = 0;
        while offset < bytes.len() {
            let (argument, next_offset) = parse_delta_argument(&bytes, offset);
            if let Some(delta) = argument.and_then(|argument| parse_delta(&package.name, &argument))
            {
                apply_delta(package, delta);
            }
            offset = next_offset;
        }
        Ok(())
    }
}

fn valid_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_type(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && value.bytes().all(|byte| (33..=126).contains(&byte))
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Newline,
}

fn tokenize(bytes: &[u8]) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' | b'\r' => index += 1,
            b'\n' | b';' => {
                tokens.push(Token::Newline);
                index += 1;
            }
            b'#' => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            _ => {
                let mut word = Vec::new();
                let mut quote = None;
                while index < bytes.len() {
                    let byte = bytes[index];
                    if let Some(delimiter) = quote {
                        if byte == delimiter {
                            quote = None;
                            index += 1;
                        } else if byte == b'\\' && delimiter == b'"' {
                            index += 1;
                            if index >= bytes.len() {
                                return Err(Error::InvalidData("unterminated UCI escape"));
                            }
                            if bytes[index] == b'\n' {
                                index += 1;
                            } else {
                                word.push(bytes[index]);
                                index += 1;
                            }
                        } else {
                            word.push(byte);
                            index += 1;
                        }
                    } else {
                        match byte {
                            b'\'' | b'"' => {
                                quote = Some(byte);
                                index += 1;
                            }
                            b'\\' => {
                                index += 1;
                                if index >= bytes.len() {
                                    return Err(Error::InvalidData("unterminated UCI escape"));
                                }
                                if bytes[index] == b'\n' {
                                    index += 1;
                                } else {
                                    word.push(bytes[index]);
                                    index += 1;
                                }
                            }
                            b' ' | b'\t' | b'\r' | b'\n' | b';' | b'#' => break,
                            _ => {
                                word.push(byte);
                                index += 1;
                            }
                        }
                    }
                }
                if quote.is_some() {
                    return Err(Error::InvalidData("unterminated UCI quote"));
                }
                // libuci stores configuration as bytes.  The former FFI adapter
                // converted every returned C string with `to_string_lossy()`, so
                // preserve that observable behaviour for legacy configurations
                // instead of rejecting the whole package on one non-UTF-8 value.
                let word = String::from_utf8_lossy(&word).into_owned();
                tokens.push(Token::Word(word));
            }
        }
    }
    tokens.push(Token::Newline);
    Ok(tokens)
}

fn parse_package(name: &str, input: &[u8]) -> Result<UciPackage> {
    let tokens = tokenize(input)?;
    let mut lines = Vec::<Vec<String>>::new();
    let mut line = Vec::new();
    for token in tokens {
        match token {
            Token::Word(word) => line.push(word),
            Token::Newline if !line.is_empty() => lines.push(std::mem::take(&mut line)),
            Token::Newline => {}
        }
    }
    let mut sections = Vec::<UciSection>::new();
    let mut current_section = None;
    for words in lines {
        match words.first().map(String::as_str) {
            Some("p" | "package") if words.len() == 2 => {
                if !valid_package_name(&words[1]) {
                    return Err(Error::InvalidData("invalid UCI package statement"));
                }
                // uci_load() imports a single named package, so an in-file
                // package statement is validated and otherwise ignored.
            }
            Some("c" | "config") if matches!(words.len(), 2 | 3) => {
                if !valid_type(&words[1])
                    || words
                        .get(2)
                        .is_some_and(|value| !value.is_empty() && !valid_name(value))
                {
                    return Err(Error::InvalidData("invalid UCI section"));
                }
                if let Some(section_name) = words.get(2).filter(|name| !name.is_empty()) {
                    if let Some(index) = sections
                        .iter()
                        .position(|section| section.name == *section_name)
                    {
                        if sections[index].kind != words[1] {
                            return Err(Error::InvalidData(
                                "section of different type overwrites prior section",
                            ));
                        }
                        current_section = Some(index);
                    } else {
                        sections.push(UciSection {
                            name: section_name.clone(),
                            kind: words[1].clone(),
                            anonymous: false,
                            options: Vec::new(),
                        });
                        current_section = Some(sections.len() - 1);
                    }
                } else {
                    sections.push(UciSection {
                        name: anonymous_section_name(&words[1], sections.len() + 1),
                        kind: words[1].clone(),
                        anonymous: true,
                        options: Vec::new(),
                    });
                    current_section = Some(sections.len() - 1);
                }
            }
            Some("o" | "option") if matches!(words.len(), 2 | 3) => {
                let section = current_section
                    .and_then(|index| sections.get_mut(index))
                    .ok_or(Error::InvalidData("UCI option precedes section"))?;
                if !valid_name(&words[1]) {
                    return Err(Error::InvalidData("invalid UCI option name"));
                }
                let Some(value) = words.get(2).filter(|value| !value.is_empty()) else {
                    // libuci treats an option with no value or an empty value
                    // in a file as a no-op, including when the option exists.
                    continue;
                };
                if let Some(existing) = section
                    .options
                    .iter_mut()
                    .find(|option| option.name == words[1])
                {
                    existing.value = UciValue::String(value.clone());
                } else {
                    section.options.push(UciOption {
                        name: words[1].clone(),
                        value: UciValue::String(value.clone()),
                    });
                }
            }
            Some("l" | "list") if matches!(words.len(), 2 | 3) => {
                let section = current_section
                    .and_then(|index| sections.get_mut(index))
                    .ok_or(Error::InvalidData("UCI list precedes section"))?;
                if !valid_name(&words[1]) {
                    return Err(Error::InvalidData("invalid UCI list name"));
                }
                let value = words.get(2).cloned().unwrap_or_default();
                if let Some(existing) = section
                    .options
                    .iter_mut()
                    .find(|option| option.name == words[1])
                {
                    match &mut existing.value {
                        UciValue::List(values) => values.push(value.clone()),
                        UciValue::String(previous) => {
                            let previous = std::mem::take(previous);
                            existing.value = UciValue::List(vec![previous, value.clone()]);
                        }
                    }
                } else {
                    section.options.push(UciOption {
                        name: words[1].clone(),
                        value: UciValue::List(vec![value]),
                    });
                }
            }
            _ => return Err(Error::InvalidData("invalid UCI statement")),
        }
    }
    Ok(UciPackage {
        name: name.to_owned(),
        sections,
    })
}

fn anonymous_section_name(kind: &str, section_count: usize) -> String {
    let mut hash = 5_381u32;
    for byte in kind.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(byte));
    }
    hash &= 0x7fff_ffff;
    format!("cfg{section_count:02x}{:04x}", hash % (1 << 16))
}

#[derive(Clone, Copy)]
enum DeltaCommand {
    Add,
    Remove,
    Change,
    Rename,
    Reorder,
    ListAdd,
    ListDelete,
}

struct Delta {
    command: DeltaCommand,
    section: String,
    option: Option<String>,
    value: Option<String>,
}

fn is_uci_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn physical_line_end(input: &[u8], offset: usize) -> usize {
    input[offset..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(input.len(), |relative| offset + relative + 1)
}

fn continuation_end(input: &[u8], index: usize, line_end: usize) -> Option<usize> {
    if input.get(index) == Some(&b'\n') && index + 1 == line_end {
        return Some(index + 1);
    }
    if input.get(index) == Some(&b'\r')
        && input.get(index + 1) == Some(&b'\n')
        && index + 2 == line_end
    {
        return Some(index + 2);
    }
    None
}

/// Parse the one shell-style argument accepted by a libuci delta record.
/// The returned offset always points past every physical line consumed by
/// quotes or a backslash continuation, even when the record is malformed.
fn parse_delta_argument(input: &[u8], offset: usize) -> (Option<String>, usize) {
    let mut line_end = physical_line_end(input, offset);
    let mut index = offset;
    while index < line_end && is_uci_whitespace(input[index]) {
        index += 1;
    }

    let mut word = Vec::new();
    let mut quote = None;
    loop {
        if index >= line_end {
            if quote.is_some() {
                return (None, line_end);
            }
            break;
        }

        let byte = input[index];
        if let Some(delimiter) = quote {
            if byte == delimiter {
                quote = None;
                index += 1;
                continue;
            }
            if byte == b'\\' && delimiter == b'"' {
                index += 1;
                if index >= line_end {
                    return (None, line_end);
                }
                if let Some(after) = continuation_end(input, index, line_end) {
                    index = after;
                    line_end = physical_line_end(input, index);
                    continue;
                }
                word.push(input[index]);
                index += 1;
                continue;
            }
            word.push(byte);
            index += 1;
            if byte == b'\n' {
                line_end = physical_line_end(input, index);
            }
            continue;
        }

        match byte {
            b'\'' | b'"' => {
                quote = Some(byte);
                index += 1;
            }
            b'\\' => {
                index += 1;
                if index >= line_end {
                    break;
                }
                if let Some(after) = continuation_end(input, index, line_end) {
                    index = after;
                    line_end = physical_line_end(input, index);
                } else {
                    word.push(input[index]);
                    index += 1;
                }
            }
            b'#' => {
                index = line_end;
                break;
            }
            b';' => break,
            byte if is_uci_whitespace(byte) => {
                index += 1;
                break;
            }
            _ => {
                word.push(byte);
                index += 1;
            }
        }
    }

    let argument = (index == line_end).then(|| String::from_utf8_lossy(&word).into_owned());
    (argument, line_end)
}

fn valid_delta_text(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte >= 32 || matches!(byte, b'\t' | b'\n' | b'\r'))
}

fn parse_delta(package: &str, word: &str) -> Option<Delta> {
    let (command, tuple) = match word.as_bytes().first().copied() {
        Some(b'+') => (DeltaCommand::Add, &word[1..]),
        Some(b'-') => (DeltaCommand::Remove, &word[1..]),
        Some(b'@') => (DeltaCommand::Rename, &word[1..]),
        Some(b'^') => (DeltaCommand::Reorder, &word[1..]),
        Some(b'|') => (DeltaCommand::ListAdd, &word[1..]),
        Some(b'~') => (DeltaCommand::ListDelete, &word[1..]),
        _ => (DeltaCommand::Change, word),
    };
    let (path, value) = tuple
        .split_once('=')
        .map_or((tuple, None), |(path, value)| {
            (path, Some(value.to_owned()))
        });
    if !matches!(command, DeltaCommand::Remove) && value.is_none() {
        return None;
    }
    let mut parts = path.split('.');
    if parts.next()? != package {
        return None;
    }
    let section = parts.next()?.to_owned();
    let option = parts.next().map(str::to_owned);
    if parts.next().is_some()
        || !valid_name(&section)
        || option.as_deref().is_some_and(|name| !valid_name(name))
    {
        return None;
    }
    if matches!(command, DeltaCommand::Rename) && !value.as_deref().is_some_and(valid_name) {
        return None;
    }
    if value
        .as_deref()
        .is_some_and(|value| !valid_delta_text(value))
    {
        return None;
    }
    Some(Delta {
        command,
        section,
        option,
        value,
    })
}

fn parse_c_decimal_prefix(value: &str) -> Option<i128> {
    let bytes = value.as_bytes();
    let mut index = bytes
        .iter()
        .take_while(|byte| is_uci_whitespace(**byte))
        .count();
    let negative = match bytes.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };
    let mut parsed = 0i128;
    let mut found = false;
    while let Some(digit) = bytes.get(index).filter(|digit| digit.is_ascii_digit()) {
        found = true;
        parsed = parsed
            .saturating_mul(10)
            .saturating_add(i128::from(*digit - b'0'));
        index += 1;
    }
    found.then_some(if negative { -parsed } else { parsed })
}

fn apply_delta(package: &mut UciPackage, delta: Delta) {
    match delta.command {
        DeltaCommand::Add => {
            if delta.option.is_some() {
                apply_change(package, delta);
                return;
            }
            let Some(kind) = delta.value.filter(|value| valid_type(value)) else {
                return;
            };
            if let Some(section) = package
                .sections
                .iter_mut()
                .find(|section| section.name == delta.section)
            {
                section.kind = kind;
                section.anonymous = true;
            } else {
                package.sections.push(UciSection {
                    name: delta.section,
                    kind,
                    anonymous: true,
                    options: Vec::new(),
                });
            }
        }
        DeltaCommand::Remove => {
            let Some(section_index) = package
                .sections
                .iter()
                .position(|section| section.name == delta.section)
            else {
                return;
            };
            let Some(option_name) = delta.option else {
                package.sections.remove(section_index);
                return;
            };
            let section = &mut package.sections[section_index];
            let Some(option_index) = section
                .options
                .iter()
                .position(|option| option.name == option_name)
            else {
                return;
            };
            if let UciValue::List(values) = &mut section.options[option_index].value {
                match delta.value {
                    None => {
                        section.options.remove(option_index);
                    }
                    Some(value) if value.is_empty() => {
                        section.options.remove(option_index);
                    }
                    Some(value) => {
                        let Some(index) = parse_c_decimal_prefix(&value)
                            .filter(|index| *index >= 0)
                            .and_then(|index| usize::try_from(index).ok())
                        else {
                            return;
                        };
                        if index < values.len() {
                            values.remove(index);
                        }
                    }
                }
            } else {
                section.options.remove(option_index);
            }
        }
        DeltaCommand::Change => apply_change(package, delta),
        DeltaCommand::Rename => {
            let Some(new_name) = delta.value else {
                return;
            };
            let Some(section_index) = package
                .sections
                .iter()
                .position(|section| section.name == delta.section)
            else {
                return;
            };
            if let Some(option_name) = delta.option {
                let section = &mut package.sections[section_index];
                if let Some(option) = section
                    .options
                    .iter_mut()
                    .find(|option| option.name == option_name)
                {
                    option.name = new_name;
                }
            } else {
                package.sections[section_index].name = new_name;
                package.sections[section_index].anonymous = false;
            }
        }
        DeltaCommand::Reorder => {
            if delta.option.is_some() {
                return;
            }
            let Some(index) = package
                .sections
                .iter()
                .position(|section| section.name == delta.section)
            else {
                return;
            };
            let position = delta
                .value
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let section = package.sections.remove(index);
            let position = position.min(package.sections.len());
            package.sections.insert(position, section);
        }
        DeltaCommand::ListAdd => {
            let (Some(option_name), Some(value)) = (delta.option, delta.value) else {
                return;
            };
            let Some(section) = package
                .sections
                .iter_mut()
                .find(|section| section.name == delta.section)
            else {
                return;
            };
            if let Some(option) = section
                .options
                .iter_mut()
                .find(|option| option.name == option_name)
            {
                match &mut option.value {
                    UciValue::List(values) => values.push(value),
                    UciValue::String(previous) => {
                        let previous = std::mem::take(previous);
                        option.value = UciValue::List(vec![previous, value]);
                    }
                }
            } else {
                section.options.push(UciOption {
                    name: option_name,
                    value: UciValue::List(vec![value]),
                });
            }
        }
        DeltaCommand::ListDelete => {
            let (Some(option_name), Some(value)) = (delta.option, delta.value) else {
                return;
            };
            let Some(option) = package
                .sections
                .iter_mut()
                .find(|section| section.name == delta.section)
                .and_then(|section| {
                    section
                        .options
                        .iter_mut()
                        .find(|option| option.name == option_name)
                })
            else {
                return;
            };
            if let UciValue::List(values) = &mut option.value {
                values.retain(|candidate| candidate != &value);
            }
        }
    }
}

fn apply_change(package: &mut UciPackage, delta: Delta) {
    let Some(value) = delta.value else {
        return;
    };
    let section_index = package
        .sections
        .iter()
        .position(|section| section.name == delta.section);
    let Some(option_name) = delta.option else {
        if value.is_empty() {
            if let Some(index) = section_index {
                package.sections.remove(index);
            }
        } else if !valid_type(&value) {
            return;
        } else if let Some(index) = section_index {
            package.sections[index].kind = value;
        } else {
            package.sections.push(UciSection {
                name: delta.section,
                kind: value,
                anonymous: false,
                options: Vec::new(),
            });
        }
        return;
    };
    let Some(section) = section_index.map(|index| &mut package.sections[index]) else {
        return;
    };
    if value.is_empty() {
        if let Some(index) = section
            .options
            .iter()
            .position(|option| option.name == option_name)
        {
            section.options.remove(index);
        }
    } else if let Some(option) = section
        .options
        .iter_mut()
        .find(|option| option.name == option_name)
    {
        option.value = UciValue::String(value);
    } else {
        section.options.push(UciOption {
            name: option_name,
            value: UciValue::String(value),
        });
    }
}

#[cfg(test)]
include!("pure_uci_tests.rs");
