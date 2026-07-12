use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

pub const DEFAULT_FILE_CAP: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedFile {
    pub source: String,
    pub path: String,
    pub present: bool,
    pub value: Option<String>,
    pub truncated: bool,
}

pub fn read_bounded(path: &Path, cap: usize) -> io::Result<BoundedFile> {
    let path_text = path.to_string_lossy().into_owned();
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(BoundedFile {
                source: format!("file:{path_text}"),
                path: path_text,
                present: false,
                value: None,
                truncated: false,
            });
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::with_capacity(cap.min(DEFAULT_FILE_CAP));
    file.by_ref()
        .take(cap.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    let truncated = bytes.len() > cap;
    bytes.truncate(cap);
    Ok(BoundedFile {
        source: format!("file:{path_text}"),
        path: path_text,
        present: true,
        value: Some(String::from_utf8_lossy(&bytes).trim().to_owned()),
        truncated,
    })
}

pub fn exists(path: &Path) -> BoundedFile {
    let path_text = path.to_string_lossy().into_owned();
    BoundedFile {
        source: format!("file:{path_text}"),
        path: path_text,
        present: path.exists(),
        value: None,
        truncated: false,
    }
}
