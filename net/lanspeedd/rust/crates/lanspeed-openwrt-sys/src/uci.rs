use crate::{raw, Error, Result};
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::rc::Rc;

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
    context: *mut raw::uci_context,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl UciContext {
    pub fn new() -> Result<Self> {
        let context = unsafe { raw::uci_alloc_context() };
        if context.is_null() {
            return Err(Error::Allocation("UCI context"));
        }
        Ok(Self {
            context,
            _not_send_or_sync: PhantomData,
        })
    }

    pub fn with_confdir(directory: &Path) -> Result<Self> {
        let mut context = Self::new()?;
        context.set_confdir(directory)?;
        Ok(context)
    }

    pub fn set_confdir(&mut self, directory: &Path) -> Result<()> {
        let directory = CString::new(directory.as_os_str().as_bytes())?;
        platform_result("uci_set_confdir", unsafe {
            raw::uci_set_confdir(self.context, directory.as_ptr())
        })
    }

    pub fn lookup(&mut self, tuple: &str) -> Result<Option<UciValue>> {
        let mut tuple = CString::new(tuple)?.into_bytes_with_nul();
        let mut lookup = raw::uci_ptr::default();
        let result = unsafe {
            raw::uci_lookup_ptr(self.context, &mut lookup, tuple.as_mut_ptr().cast(), true)
        };
        let loaded = (!lookup.p.is_null()).then_some(LoadedPackage {
            context: self.context,
            package: lookup.p,
        });
        if result == UCI_ERR_NOTFOUND {
            drop(loaded);
            return Ok(None);
        }
        if result != 0 {
            return Err(Error::Platform {
                operation: "uci_lookup_ptr",
                code: result,
            });
        }
        if lookup.o.is_null() {
            drop(loaded);
            return Ok(None);
        }
        let value = unsafe { clone_option_value(lookup.o).map(Some) };
        drop(loaded);
        value
    }

    pub fn load_package(&mut self, name: &str) -> Result<UciPackage> {
        let name_c = CString::new(name)?;
        let mut package = ptr::null_mut();
        platform_result("uci_load", unsafe {
            raw::uci_load(self.context, name_c.as_ptr(), &mut package)
        })?;
        if package.is_null() {
            return Err(Error::InvalidData("uci_load returned a null package"));
        }
        let guard = LoadedPackage {
            context: self.context,
            package,
        };
        let snapshot = unsafe { clone_package(name, guard.package) };
        drop(guard);
        snapshot
    }
}

impl Drop for UciContext {
    fn drop(&mut self) {
        unsafe { raw::uci_free_context(self.context) };
    }
}

struct LoadedPackage {
    context: *mut raw::uci_context,
    package: *mut raw::uci_package,
}

impl Drop for LoadedPackage {
    fn drop(&mut self) {
        let _ = unsafe { raw::uci_unload(self.context, self.package) };
    }
}

fn platform_result(operation: &'static str, code: libc::c_int) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Platform { operation, code })
    }
}

unsafe fn clone_package(name: &str, package: *mut raw::uci_package) -> Result<UciPackage> {
    let section_elements = unsafe { element_pointers(&mut (*package).sections) }?;
    let mut sections = Vec::with_capacity(section_elements.len());
    for element in section_elements {
        if unsafe { (*element).type_ } != raw::uci_type_UCI_TYPE_SECTION {
            continue;
        }
        let section = element.cast::<raw::uci_section>();
        let option_elements = unsafe { element_pointers(&mut (*section).options) }?;
        let mut options = Vec::with_capacity(option_elements.len());
        for option_element in option_elements {
            if unsafe { (*option_element).type_ } != raw::uci_type_UCI_TYPE_OPTION {
                continue;
            }
            let option = option_element.cast::<raw::uci_option>();
            options.push(UciOption {
                name: unsafe { clone_c_string((*option).e.name) }?,
                value: unsafe { clone_option_value(option) }?,
            });
        }
        sections.push(UciSection {
            name: unsafe { clone_c_string((*section).e.name) }?,
            kind: unsafe { clone_c_string((*section).type_) }?,
            anonymous: unsafe { (*section).anonymous },
            options,
        });
    }
    Ok(UciPackage {
        name: name.to_owned(),
        sections,
    })
}

unsafe fn clone_option_value(option: *mut raw::uci_option) -> Result<UciValue> {
    let option_type = unsafe { (*option).type_ };
    if option_type == raw::uci_option_type_UCI_TYPE_STRING {
        return unsafe { clone_c_string((*option).v.string) }.map(UciValue::String);
    }
    if option_type == raw::uci_option_type_UCI_TYPE_LIST {
        let head = unsafe { &mut (*option).v.list };
        let values = unsafe { element_pointers(head) }?
            .into_iter()
            .map(|element| unsafe { clone_c_string((*element).name) })
            .collect::<Result<Vec<_>>>()?;
        return Ok(UciValue::List(values));
    }
    Err(Error::InvalidData("unknown UCI option type"))
}

unsafe fn element_pointers(head: *mut raw::uci_list) -> Result<Vec<*mut raw::uci_element>> {
    if head.is_null() {
        return Err(Error::InvalidData("null UCI list head"));
    }
    let mut current = unsafe { (*head).next };
    let mut elements = Vec::new();
    while current != head {
        if current.is_null() {
            return Err(Error::InvalidData("null UCI list link"));
        }
        if elements.len() == 65_536 {
            return Err(Error::InvalidData("UCI list does not terminate"));
        }
        elements.push(current.cast::<raw::uci_element>());
        current = unsafe { (*current).next };
    }
    Ok(elements)
}

unsafe fn clone_c_string(pointer: *const libc::c_char) -> Result<String> {
    if pointer.is_null() {
        return Err(Error::InvalidData("null UCI string"));
    }
    Ok(unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn temporary_confdir_clones_string_list_and_package_values() {
        let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("lanspeed-uci-{}-{suffix}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("lanspeed"),
            "config main 'main'\n\toption mode 'auto'\n\tlist ifname 'br-lan'\n\tlist ifname 'eth1'\n",
        )
        .unwrap();

        let (mode, interfaces, package) = {
            let mut context = UciContext::with_confdir(&directory).unwrap();
            let mode = context.lookup("lanspeed.main.mode").unwrap();
            let interfaces = context.lookup("lanspeed.main.ifname").unwrap();
            let package = context.load_package("lanspeed").unwrap();
            (mode, interfaces, package)
        };

        assert_eq!(mode, Some(UciValue::String("auto".into())));
        assert_eq!(
            interfaces,
            Some(UciValue::List(vec!["br-lan".into(), "eth1".into()]))
        );
        assert_eq!(package.name, "lanspeed");
        assert_eq!(package.sections.len(), 1);
        assert_eq!(package.sections[0].name, "main");
        assert_eq!(package.sections[0].kind, "main");
        assert_eq!(package.sections[0].options.len(), 2);
        assert!(package.sections[0].options.contains(&UciOption {
            name: "mode".into(),
            value: UciValue::String("auto".into()),
        }));
        assert!(package.sections[0].options.contains(&UciOption {
            name: "ifname".into(),
            value: UciValue::List(vec!["br-lan".into(), "eth1".into()]),
        }));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_package_is_an_absent_value() {
        let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "lanspeed-uci-missing-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();

        let mut context = UciContext::with_confdir(&directory).unwrap();
        assert_eq!(context.lookup("lanspeed.main.enabled").unwrap(), None);

        fs::remove_dir_all(directory).unwrap();
    }
}
