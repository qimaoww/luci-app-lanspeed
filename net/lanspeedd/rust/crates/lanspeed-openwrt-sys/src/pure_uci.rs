use crate::{Error, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

const UCI_ERR_NOTFOUND: libc::c_int = 3;

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
}

impl UciContext {
    pub fn new() -> Result<Self> {
        Ok(Self {
            confdir: PathBuf::from("/etc/config"),
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
        if !valid_identifier(name) {
            return Err(Error::InvalidData("invalid UCI package name"));
        }
        let path = self.confdir.join(name);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Platform {
                    operation: "uci_load",
                    code: UCI_ERR_NOTFOUND,
                });
            }
            Err(error) => {
                return Err(Error::Platform {
                    operation: "uci_load",
                    code: error.raw_os_error().unwrap_or(libc::EIO),
                });
            }
        };
        if bytes.len() > 1_048_576 {
            return Err(Error::InvalidData("UCI package exceeds size limit"));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::InvalidData("UCI package is not UTF-8"))?;
        parse_package(name, text)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Newline,
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let bytes = input.as_bytes();
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
                let word = String::from_utf8(word)
                    .map_err(|_| Error::InvalidData("UCI token is not UTF-8"))?;
                tokens.push(Token::Word(word));
            }
        }
    }
    tokens.push(Token::Newline);
    Ok(tokens)
}

fn parse_package(name: &str, input: &str) -> Result<UciPackage> {
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
    for words in lines {
        match words.first().map(String::as_str) {
            Some("config") if matches!(words.len(), 2 | 3) => {
                if !valid_identifier(&words[1])
                    || words.get(2).is_some_and(|value| !valid_identifier(value))
                {
                    return Err(Error::InvalidData("invalid UCI section"));
                }
                let anonymous = words.len() == 2;
                let section_name = words
                    .get(2)
                    .cloned()
                    .unwrap_or_else(|| format!("cfg{:06x}", sections.len() + 1));
                sections.push(UciSection {
                    name: section_name,
                    kind: words[1].clone(),
                    anonymous,
                    options: Vec::new(),
                });
            }
            Some("option") if words.len() == 3 => {
                let section = sections
                    .last_mut()
                    .ok_or(Error::InvalidData("UCI option precedes section"))?;
                if !valid_identifier(&words[1]) {
                    return Err(Error::InvalidData("invalid UCI option name"));
                }
                if let Some(existing) = section
                    .options
                    .iter_mut()
                    .find(|option| option.name == words[1])
                {
                    existing.value = UciValue::String(words[2].clone());
                } else {
                    section.options.push(UciOption {
                        name: words[1].clone(),
                        value: UciValue::String(words[2].clone()),
                    });
                }
            }
            Some("list") if words.len() == 3 => {
                let section = sections
                    .last_mut()
                    .ok_or(Error::InvalidData("UCI list precedes section"))?;
                if !valid_identifier(&words[1]) {
                    return Err(Error::InvalidData("invalid UCI list name"));
                }
                if let Some(existing) = section
                    .options
                    .iter_mut()
                    .find(|option| option.name == words[1])
                {
                    match &mut existing.value {
                        UciValue::List(values) => values.push(words[2].clone()),
                        UciValue::String(previous) => {
                            let previous = std::mem::take(previous);
                            existing.value = UciValue::List(vec![previous, words[2].clone()]);
                        }
                    }
                } else {
                    section.options.push(UciOption {
                        name: words[1].clone(),
                        value: UciValue::List(vec![words[2].clone()]),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn reads_named_sections_strings_lists_comments_and_escapes() {
        let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("lanspeed-pure-uci-{}-{suffix}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("lanspeed"), "# comment\nconfig main 'main'\n option mode 'auto'\n list ifname 'br-lan'\n list ifname \"eth\\ 1\"\n").unwrap();
        let mut context = UciContext::with_confdir(&directory).unwrap();
        assert_eq!(
            context.lookup("lanspeed.main.mode").unwrap(),
            Some(UciValue::String("auto".into()))
        );
        assert_eq!(
            context.lookup("lanspeed.main.ifname").unwrap(),
            Some(UciValue::List(vec!["br-lan".into(), "eth 1".into()]))
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_package_uses_the_libuci_not_found_contract() {
        let directory =
            std::env::temp_dir().join(format!("lanspeed-pure-uci-missing-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let mut context = UciContext::with_confdir(&directory).unwrap();
        assert!(matches!(
            context.load_package("missing"),
            Err(Error::Platform {
                operation: "uci_load",
                code: 3
            })
        ));
        assert_eq!(context.lookup("missing.main.value").unwrap(), None);
        fs::remove_dir_all(directory).unwrap();
    }
}
