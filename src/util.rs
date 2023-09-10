use std::{path::PathBuf, ptr};

use region::Protection;
use retour::GenericDetour;
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
};

use windows::Win32::Foundation::HMODULE;

use crate::HookModule;

// llvm return address binding
extern "C" {
    #[link_name = "llvm.returnaddress"]
    pub fn return_address(level: i32) -> *const u8;
}

/// Helper macro to get the return address of the current function.
#[macro_export]
macro_rules! ret_addr {
    () => {
        unsafe { $crate::return_address(0) as usize }
    };
    (level: $level:expr) => {
        unsafe { $crate::return_address($level) as usize }
    };
}

/// Memset function, with overwriting memory protection
pub unsafe fn ms_memset(mut addr: *mut u8, b: u8, cnt: usize) -> region::Result<()> {
    let _handle = region::protect_with_handle(addr, cnt, Protection::READ_WRITE_EXECUTE)?;

    for _ in 0..cnt {
        addr.write_volatile(b);
        addr = addr.offset(1);
    }

    Ok(())
}

/// Memcpy function, with overwriting memory protection
pub unsafe fn ms_memcpy(addr: *mut u8, src: *const u8, cnt: usize) -> region::Result<()> {
    let _handle = region::protect_with_handle(addr, cnt, Protection::READ_WRITE_EXECUTE)?;

    ptr::copy(src, addr, cnt);
    Ok(())
}

/// Writes n NOPs to addr
pub unsafe fn nop(addr: *mut u8, n: usize) -> region::Result<()> {
    ms_memset(addr, 0x90, n)
}


/// Simple mem patch, which saves the bytes before patching it
pub struct MemPatch<const N: usize> {
    addr: *const u8,
    patch: [u8; N],
    orig: [u8; N]
}

impl<const N: usize> MemPatch<N> {
    pub unsafe fn new(addr: *const u8, patch: [u8; N]) -> Self {
        let mut orig = [0; N];
        unsafe { addr.copy_to_nonoverlapping(orig.as_mut_ptr(), N) } ;

        Self {
            addr,
            patch,
            orig
        }
    }
}

impl<const N: usize> HookModule for MemPatch<N> {
    unsafe fn enable(&self) -> anyhow::Result<()> {
        ms_memcpy(self.addr as *mut u8, self.patch.as_ptr(), N)?;
        Ok(())
    }

    unsafe fn disable(&self) -> anyhow::Result<()> {
        ms_memcpy(self.addr as *mut u8, self.orig.as_ptr(), N)?;
        Ok(())
    }
}

#[macro_export]
macro_rules! fn_ref {
    ($name:ident, $addr:expr, $($fn_ty:tt)*) => {
        paste::paste! {
            #[allow(non_upper_case_globals)]
            pub const [<$name _addr>]: *const () = $addr as *const ();
            pub type [<$name:camel>] = $($fn_ty)*;
            #[allow(non_upper_case_globals)]
            pub static $name: std::sync::LazyLock<[<$name:camel>]> = std::sync::LazyLock::new(|| unsafe {
                std::mem::transmute([<$name _addr>])
            });
        }
    };
}

#[macro_export]
macro_rules! fn_ref_hook {
    ($hook_name:ident, $fn_ty:ty) => {
        retour::static_detour! {
            static $hook_name: $fn_ty;
        }
    };
}

pub unsafe fn ms_fn_hook<F: retour::Function + Sized>(addr: usize, detour: F) -> GenericDetour<F> {
    let f: F = std::mem::transmute_copy(&addr);
    GenericDetour::new(f, detour).expect("MS detour")
}

//TODO impl hookable trait for unsafe fns
#[macro_export]
macro_rules! static_ms_fn_hook {
    ($name:ident, $addr:expr, $detour:ident, type $fnty:ident = $($fn_ty:tt)*) => {
        pub type $fnty = $($fn_ty)*;
        static $name: std::sync::LazyLock<retour::GenericDetour<$fnty>> =
            std::sync::LazyLock::new(|| unsafe { $crate::util::ms_fn_hook::<$fnty>($addr, $detour) });
    };
}

#[macro_export]
macro_rules! static_ms_fn_ref_hook {
    ($hook_name:ident, $fn:ident, $($fn_ty:tt)*, $detour:ident) => {
        static $hook_name: std::sync::LazyLock<retour::GenericDetour<$($fn_ty)*>> =
            std::sync::LazyLock::new(|| unsafe { $crate::util::ms_fn_hook($fn, $detour) });
    };
}

pub type LazyHook<T> = std::sync::LazyLock<GenericDetour<T>>;

#[macro_export]
macro_rules! lazy_hook {
    ($target:path, $hook:path) => {
        std::sync::LazyLock::new(move || unsafe {
            retour::GenericDetour::new(*$target, $hook).unwrap()
        })
    };
}

pub unsafe fn win32_fn_hook<F: retour::Function + Sized>(
    module: PCWSTR,
    fn_name: PCSTR,
    detour: F,
) -> GenericDetour<F> {
    let handle = GetModuleHandleW(module).expect("Module");
    let proc = GetProcAddress(handle, fn_name);
    let Some(proc) = proc else {
        panic!("Unknown function {fn_name:?} for module: {module:?}");
    };

    let win_fn: F = std::mem::transmute_copy(&proc);
    GenericDetour::new(win_fn, detour).expect("Win32 detour")
}

#[macro_export]
macro_rules! static_win32_fn_hook {
    ($name:ident, $mod:expr, $fn_name:expr, $detour:ident, type $fnty:ident = $($fn_ty:tt)*) => {
        pub type $fnty = $($fn_ty)*;
        static $name: std::sync::LazyLock<GenericDetour<$fnty>> =
            std::sync::LazyLock::new(|| unsafe { $crate::util::win32_fn_hook::<$fnty>($mod, $fn_name, $detour) });
    };
}

#[macro_export]
macro_rules! static_assert { ($($t:tt)*) => { const _: () = assert!($($t)*); }; }

#[macro_export]
macro_rules! static_assert_size {
    ($l:ty, $r:ty) => {
        static_assert!(std::mem::size_of::<$l>() == std::mem::size_of::<$r>());
    };
}

#[cfg(windows)]
pub fn load_sys_dll(library: &str) -> anyhow::Result<HMODULE> {
    use windows::core::HSTRING;
    use windows::Win32::System::LibraryLoader::LoadLibraryW;

    let sys_dir = get_sys_path()?.join(library);
    unsafe {
        LoadLibraryW(&HSTRING::from(sys_dir.as_os_str()))
            .map_err(|e| anyhow::anyhow!("Unable to load {}: {:?}", library, e))
    }
}

#[cfg(not(windows))]
pub fn load_sys_dll(library: &str) -> anyhow::Result<HMODULE> {
    anyhow::bail!("Not implemented");
}

#[cfg(windows)]
pub fn get_sys_path() -> anyhow::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::{Foundation::MAX_PATH, System::SystemInformation::GetSystemDirectoryW};
    let mut buf = [0; (MAX_PATH + 1) as usize];
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 {
        anyhow::bail!("Unable to get sys dir");
    }

    Ok(OsString::from_wide(&buf[..n]).into())
}

#[cfg(not(windows))]
pub fn get_sys_path() -> anyhow::Result<PathBuf> {
    anyhow::bail!("Not implemented");
}
