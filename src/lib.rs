#![feature(
    link_llvm_intrinsics,
    pointer_byte_offsets,
    naked_functions,
    strict_provenance,
    asm_const,
    lazy_cell
)]
#![recursion_limit = "512"]
// The whole library is unsafe no need to document the behaviour for now
#![allow(clippy::missing_safety_doc)]

pub mod exception;
pub mod login;
pub mod net;

pub mod config;
pub mod ffi;
pub mod packet_struct;
pub mod socket;
pub mod strings;
pub mod util;
pub mod wz_img;

#[cfg(feature = "overlay")]
pub mod overlay;

use config::addr;
use log::LevelFilter;
use packet_struct::RECV_PACKET_CTX;
use retour::GenericDetour;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode, WriteLogger};
use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{atomic::AtomicBool, LazyLock};
use std::time::Duration;
use util::LazyHook;
use windows::core::{s, w};
use windows::core::{IUnknown, GUID, HRESULT, PCSTR};
use windows::Win32::Foundation::{BOOL, HANDLE, HMODULE};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAA;
use windows::Win32::System::Console::AllocConsole;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

use crate::config::addr::{AES_BASIC_KEY, AES_USER_KEY, IG_CIPHER_SEED, IG_SHUFFLE_KEY};
use crate::config::{DATA_DIR, DUMP_KEYS};
use crate::exception::setup_exception_handler;
use crate::packet_struct::SEND_PACKET_CTX;
use crate::strings::StringPool;
use crate::util::return_address;

pub trait HookModule {
    unsafe fn enable(&self) -> anyhow::Result<()>;
    unsafe fn disable(&self) -> anyhow::Result<()>;
}

// Proxy DLL stuff

static_win32_fn_hook!(
    FIND_FIRST_FILE_A_HOOK,
    w!("kernel32.dll"),
    s!("FindFirstFileA"),
    find_first_file_detour,
    type FnFindFirstFileA = extern "system" fn(PCSTR, *mut WIN32_FIND_DATAA) -> HANDLE
);

// Spoof the first call to FindFirstFileA, to 'hide' our dinput8.dll
extern "system" fn find_first_file_detour(
    file_name: PCSTR,
    find_file_data: *mut WIN32_FIND_DATAA,
) -> HANDLE {
    static SPOOFED_PROXY_DLL: AtomicBool = AtomicBool::new(false);

    if !file_name.is_null() && unsafe { file_name.as_bytes() } == b"*" {
        //Only spoof once at start
        if !SPOOFED_PROXY_DLL.fetch_or(true, Ordering::SeqCst) {
            log::info!("Spoofing FindFirstFileA for proxy dll");
            // Let it iterate over wz files
            return FIND_FIRST_FILE_A_HOOK.call(s!("*.wz"), find_file_data);
        }
    }
    FIND_FIRST_FILE_A_HOOK.call(file_name, find_file_data)
}

type FDirectInput8Create = unsafe extern "stdcall" fn(
    hinst: HMODULE,
    dwversion: u32,
    riidltf: *const GUID,
    ppvout: *mut *mut c_void,
    punkouter: IUnknown,
) -> HRESULT;

static DINPUT8_CREATE: LazyLock<FDirectInput8Create> = LazyLock::new(|| unsafe {
    let dinput8 = util::load_sys_dll("dinput8.dll").expect("Dinput8.dll");
    let directinput8create =
        GetProcAddress(dinput8, s!("DirectInput8Create")).expect("DirectInput8Create");

    std::mem::transmute(directinput8create)
});

#[no_mangle]
unsafe extern "stdcall" fn DirectInput8Create(
    hinst: HMODULE,
    dwversion: u32,
    riidltf: *const GUID,
    ppvout: *mut *mut c_void,
    punkouter: IUnknown,
) -> HRESULT {
    (*DINPUT8_CREATE)(hinst, dwversion, riidltf, ppvout, punkouter)
}

// Multi client support by simply appending the process ID to each Mutex name
static_win32_fn_hook!(
    CREATE_MUTEX_A_HOOK,
    w!("kernel32.dll"),
    s!("CreateMutexA"),
    create_mutex_a_detour,
    type FnCreateMutexA = extern "system" fn(*const SECURITY_ATTRIBUTES, BOOL, PCSTR) -> HANDLE
);

extern "system" fn create_mutex_a_detour(
    lpmutexattributes: *const SECURITY_ATTRIBUTES,
    binitialowner: BOOL,
    name: PCSTR,
) -> HANDLE {
    if config::MULTI_CLIENT && !name.is_null() {
        let name_s = unsafe { name.display() };
        let pid = std::process::id();
        let spoofed_mtx_name = format!("{name_s}_{pid}\0");

        log::info!("Spoofing Mutex to: {}", spoofed_mtx_name);
        return CREATE_MUTEX_A_HOOK.call(
            lpmutexattributes,
            binitialowner,
            PCSTR::from_raw(spoofed_mtx_name.as_ptr()),
        );
    }
    CREATE_MUTEX_A_HOOK.call(lpmutexattributes, binitialowner, name)
}

// Prevents an early overflow after 49.7h sytem uptime
// Still overflows after 49.7 days uptime for the client itself :<


struct RefTime(AtomicU32);


impl RefTime {
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }
    
    pub fn get_time(&self, real_time: u32) -> u32 {
        let ref_t = self.
            0
            .compare_exchange(0, real_time, Ordering::Acquire, Ordering::Relaxed)
            .err()
            .unwrap_or(0);

        real_time.wrapping_sub(ref_t) + config::TIME_OFFSET
    }
}

static_win32_fn_hook!(
    GET_TICK_COUNT_HOOK,
    w!("kernel32.dll"),
    s!("GetTickCount"),
    get_tick_count_hook,
    type FnGetTickCount = extern "system" fn() -> u32
);

extern "system" fn get_tick_count_hook() -> u32 {
    static REF_TICKS: RefTime = RefTime::new();
    let orig = GET_TICK_COUNT_HOOK.call();
    REF_TICKS.get_time(orig)
}

static_win32_fn_hook!(
    TIME_GET_TIME_HOOK,
    w!("Winmm.dll"),
    s!("timeGetTime"),
    time_get_time_hook,
    type FnTimeGetTime = extern "system" fn() -> u32
);

extern "system" fn time_get_time_hook() -> u32 {
    static REF_TICKS: RefTime = RefTime::new();
    let orig = TIME_GET_TIME_HOOK.call();
    REF_TICKS.get_time(orig)
}

// Exception Handler hook to log exceptions
static_ms_fn_hook!(
    CXX_THROW_EXCEPTION_8_HOOK,
    addr::CXX_EXCEPTION,
    cxx_throw_exception_8_detour,
    type FCxxException = unsafe extern "cdecl" fn(*const c_void, *const c_void) -> u8
);
extern "cdecl" fn cxx_throw_exception_8_detour(
    ex_obj: *const c_void,
    throw_info: *const c_void,
) -> u8 {
    let ret = ret_addr!();
    log::error!("Exception at: {ret:X}");
    RECV_PACKET_CTX.finish_incomplete(0, ret);

    unsafe { CXX_THROW_EXCEPTION_8_HOOK.call(ex_obj, throw_info) }
}

static_ms_fn_hook!(
    ZAPI_LOADER_INIT_HOOK,
    addr::ZAPI_LOADER_INIT,
    zapi_loader_hook,
    type FZApiLoaderInit = unsafe extern "cdecl" fn()
);
extern "cdecl" fn zapi_loader_hook() {
    unsafe { ZAPI_LOADER_INIT_HOOK.call() };
    log::info!("Initialized api loader");

    if config::FIX_TIME {
        unsafe {
            GET_TICK_COUNT_HOOK.enable().expect("GetTickCount");
            TIME_GET_TIME_HOOK.enable().expect("timeGetTime");
            *(addr::ZAPI_GET_TIME as *mut u32) =  time_get_time_hook as *const u8 as u32;
        }
        log::info!("Fixed API Loader time");
    }

}

fn dump_str_pool() -> anyhow::Result<()> {
    let str_pool = StringPool::instance();
    str_pool.dump_ascii_string_pool(config::STR_POOL_FILE)?;
    str_pool.dump_utf16_string_pool(config::STR_POOL_UTF16_FILE)?;
    Ok(())
}

pub fn dump_keys() -> anyhow::Result<()> {
    fn dump_key(key_name: &str, addr: usize, len: usize) -> anyhow::Result<()> {
        let key = unsafe { std::slice::from_raw_parts(addr as *const u8, len) };

        let file = format!("{}/{key_name}.bin", DATA_DIR);
        let mut f = File::create(file)?;
        f.write_all(key)?;
        Ok(())
    }

    dump_key("aes_user_key", AES_USER_KEY, 4 * 32)?;
    dump_key("aes_basic_key", AES_BASIC_KEY, 32)?;
    dump_key("ig_seed", IG_CIPHER_SEED, 4)?;
    dump_key("ig_shuffle", IG_SHUFFLE_KEY, 0x100)?;

    Ok(())
}

fn dump_stuff() {
    if DUMP_KEYS {
        if let Err(err) = dump_keys() {
            log::error!("Unable to dump keys: {}", err);
        }
    }

    // TODO dumping the thread pool from another thread
    // CAN be critical due to the cache which is use behind the scenes
    if config::DUMP_STR_POOL {
        if let Err(err) = dump_str_pool() {
            log::error!("Unable to dump string pool: {}", err);
        }
    }
}

fn setup_logs<T: AsRef<Path>>(file: Option<T>) -> anyhow::Result<()> {
    let filter = LevelFilter::Trace;
    let cfg = simplelog::Config::default();

    if let Some(file) = file {
        let file = File::create(file.as_ref())?;
        WriteLogger::init(filter, cfg, file)?;
    } else {
        unsafe { AllocConsole()?; };
        TermLogger::init(
            LevelFilter::Trace,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )?;
    }

    Ok(())
}

fn init_hooks() -> anyhow::Result<()> {
    #[cfg(feature = "overlay")]
    overlay::init_hooks();

    unsafe {
        if config::PACKET_TRACING {
            socket::init_hooks()?;
        }

        CXX_THROW_EXCEPTION_8_HOOK.enable()?;
    }

    Ok(())
}

static SKIP_LOGO_HOOK: LazyHook<ffi::ClogoInit> = lazy_hook!(ffi::clogo_init, clogo_init_hook);
unsafe extern "thiscall" fn clogo_init_hook(this: *mut ffi::CLogo, _param: *const c_void) {
    ffi::clogo_end(this);
}

fn exec() {
    let data_dir = Path::new(DATA_DIR);
    if !data_dir.exists() {
        std::fs::create_dir(data_dir).expect("Data dir");
    }

    LazyLock::force(&SEND_PACKET_CTX);
    LazyLock::force(&RECV_PACKET_CTX);
    let login = LazyLock::force(&login::LOGIN);
    
    if let Ok(token) = std::env::var("SHROOM_TOKEN") {
        log::info!("Login token: {token}");
        if let Some((id, pw)) = token.split_once(':') {
            login.set_auto_login_data(id, pw);
        } else {
            log::info!("Invalid token format, expected id:pw");
        }
    } else {
        log::info!("No Shroom token :(");
    }

    log::info!("Applying hooks and patches");
    if config::SKIP_LOGO {
        unsafe {
            SKIP_LOGO_HOOK.enable().expect("Skip logo");
        }
    }

   

    if config::AUTO_LOGIN {
        unsafe {
            login::LoginModule.enable().expect("Login");
        }
    }

    init_hooks().unwrap();

    

    // Wait for the instances to be initialized, maybe should wait for the window to be created rather
    std::thread::sleep(Duration::from_secs(1));

    dump_stuff();
    std::thread::sleep(Duration::from_secs(1));

    log::info!("Setting up exception handler");
    setup_exception_handler();


}

/// Essential hooks at first stage
unsafe fn stage_0_hooks() -> anyhow::Result<()> {
    FIND_FIRST_FILE_A_HOOK.enable()?;
    CREATE_MUTEX_A_HOOK.enable()?;
    ZAPI_LOADER_INIT_HOOK.enable()?;
    Ok(())
}

fn initialize() {
    setup_logs::<&str>(None).expect("Logging");
    log::info!("{} - {}", config::NAME, config::VERSION);

    // Load the original dinput8.dll
    LazyLock::force(&DINPUT8_CREATE);

    // Patch findfirstfile and createmutex
    if let Err(err) = unsafe { stage_0_hooks() } {
        log::error!("Unable to apply stage 0 hooks: {}", err);
        panic!("Unable to apply stage 0 hooks: {}", err);
    }

    std::thread::spawn(exec);
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HMODULE, call_reason: u32, reserved: *mut c_void) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            #[cfg(feature = "overlay")]
            overlay::init_module(dll_module);

            initialize();
        }
        DLL_PROCESS_DETACH => (),
        _ => (),
    }

    BOOL::from(true)
}
