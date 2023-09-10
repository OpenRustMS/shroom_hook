pub mod ztl;

pub use ztl::zarr::*;
pub use ztl::zxstr::*;

use std::ffi::c_void;

use windows::core::PCSTR;

use crate::fn_ref;
use crate::addr;

#[derive(Debug)]
#[repr(C)]
pub struct ComPtr<T>(pub *mut T);

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ZtlBstr(pub *mut c_void);

fn_ref!(
    bstr_ctor,
    0x404890,
    // this, s
    unsafe extern "thiscall" fn(*mut ZtlBstr, PCSTR)
);


fn_ref!(
    zapi_loader_init,
    0x404890,
    // this, s
    unsafe extern "cdecl" fn()
);

pub type CLogo = c_void;

fn_ref!(
    clogo_init,
    addr::CLOGO_INIT,
    unsafe extern "thiscall" fn(*mut CLogo, param: *const c_void)
);

fn_ref!(
    clogo_end,
    addr::CLOGO_END,
    unsafe extern "thiscall" fn(*mut CLogo)
);

pub mod login {
    use std::ffi::c_void;

    use windows::core::PCSTR;

    use crate::fn_ref;

    pub type CLogin = c_void;

    fn_ref!(
        clogin_send_check_password_packet,
        0x5db9d0,
        unsafe extern "thiscall" fn(*const CLogin, PCSTR, PCSTR) -> i32
    );

    fn_ref!(
        clogin_init,
        0x5d8010,
        unsafe extern "thiscall" fn(*const CLogin, *const c_void)
    );
}

pub mod string_pool {
    use std::ffi::c_void;

    use crate::{addr, fn_ref};

    use super::{ZXString16, ZXString8};

    pub type PStringPool = *mut c_void;

    fn_ref!(
        string_pool_get_instance,
        addr::STRING_POOL_GET_INSTANCE,
        unsafe extern "cdecl" fn() -> PStringPool
    );

    fn_ref!(
        string_pool_get_string,
        addr::STRING_POOL_GET_STR,
        unsafe extern "thiscall" fn(PStringPool, *mut ZXString8, u32) -> *mut ZXString8
    );

    fn_ref!(
        string_pool_get_string_w,
        addr::STRING_POOL_GET_STRW,
        unsafe extern "thiscall" fn(PStringPool, *mut ZXString16, u32) -> *mut ZXString16
    );
}

pub mod client_socket {
    use std::ffi::{c_void, c_int};

    use windows::Win32::Networking::WinSock::SOCKADDR_IN;

    use crate::fn_ref;

    type CClientSocket = c_void;

    fn_ref!(
        cclient_socket_connect,
        0x4ae720,
        unsafe extern "thiscall" fn(*const CClientSocket, addr: *const SOCKADDR_IN) -> c_void
    );

    fn_ref!(
        cclient_socket_connect_login,
        0x4b0590,
        unsafe extern "thiscall" fn(*const CClientSocket) -> c_void
    );

    fn_ref!(
        cclient_socket_on_connect,
        0x4aef10,
        unsafe extern "thiscall" fn(*const CClientSocket, bSuccess: c_int) -> c_void
    );

    fn_ref!(
        cclient_socket_close,
        0x4ae990,
        unsafe extern "thiscall" fn(*const CClientSocket) -> c_void
    );

    fn_ref!(
        cclient_socket_flush,
        0x4af6a0,
        unsafe extern "thiscall" fn(*const CClientSocket) -> c_void
    );

    fn_ref!(
        cclient_socket_on_close,
        0x4af620,
        unsafe extern "thiscall" fn(*const CClientSocket) -> c_void
    );

    fn_ref!(
        cclient_socket_on_error,
        0x4af590,
        unsafe extern "thiscall" fn(*const CClientSocket, bSuccess: c_int) -> c_void
    );

    fn_ref!(
        cclient_socket_clear_send_recv_ctx,
        0x4ae1a0,
        unsafe extern "thiscall" fn(*const CClientSocket) -> i32
    );

    fn_ref!(
        cclient_socket_set_timeout,
        0x4acba0,
        unsafe extern "thiscall" fn(*const CClientSocket) -> i32
    );
}

pub mod wz {
    use std::ffi::c_void;

    use bitflags::bitflags;
    use windows::core::PCWSTR;

    use crate::fn_ref;

    use super::{ComPtr, ZtlBstr};

    pub type CWvsApp = c_void;
    pub type IResMan = c_void;
    pub type IWzNameSpace = c_void;
    pub type IWzFileSystem = c_void;

    fn_ref!(
        pc_create_obj_iwz_res_man,
        0x9c2eb0,
        // sUOL, pObj, pUnkOuter
        unsafe extern "cdecl" fn(PCWSTR, *mut ComPtr<IResMan>, *const c_void)
    );

    fn_ref!(
        pc_create_obj_iwz_namespace,
        0x9c2eb0,
        // sUOL, pObj, pUnkOuter
        unsafe extern "cdecl" fn(PCWSTR, *mut ComPtr<IWzNameSpace>, *const c_void)
    );

    fn_ref!(
        pc_create_obj_iwz_filesystem,
        0x9c2eb0,
        // sUOL, pObj, pUnkOuter
        unsafe extern "cdecl" fn(PCWSTR, *mut ComPtr<IWzFileSystem>, *const c_void)
    );

    fn_ref!(
        pc_set_root_namespace,
        0x9c2eb0,
        // sUOL, pObj, pUnkOuter
        unsafe extern "cdecl" fn(*const IWzNameSpace)
    );

    bitflags! {
        #[repr(transparent)]
        pub struct ResManParam: u32 {
            const AUTO_SERIALIZE = 1;
            const AUTO_SERIALIZE_NO_CACHE = 2;
            const NO_AUTO_SERIALIZE = 4;
            const AUTO_REPARSE = 0x10;
            const NO_AUTO_REPARSE = 0x20;
            const AUTO_REPARSE_MASK = 0x30;
            const DEFAULT_AUTO_SERIALIZE = 0;
            const DEFAULT_AUTO_REPARSE = 0;
            const RC_AUTO_SERIALIZE_MASK =  (Self::AUTO_SERIALIZE.bits() | Self::AUTO_SERIALIZE_NO_CACHE.bits() | Self::NO_AUTO_SERIALIZE.bits());
        }
    }
    fn_ref!(
        iwz_res_man_set_param,
        0x9c0920,
        // this, nParam, nRetaintime, nNameSpaceCacheTime
        unsafe extern "thiscall" fn(*const IResMan, ResManParam, i32, i32)
    );

    fn_ref!(
        iwz_namespace_mount,
        0x9c8db0,
        // this, sPath, pDown, nPriority
        unsafe extern "thiscall" fn(*const IWzNameSpace, ZtlBstr, *const IWzNameSpace, i32)
    );

    fn_ref!(
        iwz_filesystem_init,
        0x9c8e40,
        // this, sPath
        unsafe extern "thiscall" fn(*const IWzFileSystem, ZtlBstr)
    );

    fn_ref!(
        cwvs_app_init_res_man,
        0x009c9540,
        unsafe extern "thiscall" fn(*const CWvsApp)
    );
}
