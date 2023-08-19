use std::ffi::c_void;

use crate::{fn_ref2, fn_ref_hook};
use bitflags::bitflags;
use detour::static_detour;
use windows::core::{s, w, PCSTR, PCWSTR};

pub type CWvsApp = c_void;
pub type IResMan = c_void;
pub type IWzNameSpace = c_void;
pub type IWzFileSystem = c_void;

#[derive(Debug)]
#[repr(C)]
pub struct ComPtr<T>(pub *mut T);

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ZtlBstr(pub *mut c_void);

//void __thiscall `CWvsApp::InitializeResMan`(class CWvsApp* `this`)
fn_ref_hook!(
    cwvs_app_init_res_man,
    CWvsAppInitializeResMan,
    cwvs_app_init_res_man_addr,
    0x009c9540,
    CWvsAppInitializeResManHook,
    unsafe extern "thiscall" fn(*const CWvsApp)
);

fn_ref2!(
    pc_create_obj_iwz_res_man,
    0x9c2eb0,
    // sUOL, pObj, pUnkOuter
    unsafe extern "cdecl" fn(PCWSTR, *mut ComPtr<IResMan>, *const c_void)
);

fn_ref2!(
    pc_create_obj_iwz_namespace,
    0x9c2eb0,
    // sUOL, pObj, pUnkOuter
    unsafe extern "cdecl" fn(PCWSTR, *mut ComPtr<IWzNameSpace>, *const c_void)
);

fn_ref2!(
    pc_create_obj_iwz_filesystem,
    0x9c2eb0,
    // sUOL, pObj, pUnkOuter
    unsafe extern "cdecl" fn(PCWSTR, *mut ComPtr<IWzFileSystem>, *const c_void)
);

fn_ref2!(
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
fn_ref2!(
    iwz_res_man_set_param,
    0x9c0920,
    // this, nParam, nRetaintime, nNameSpaceCacheTime
    unsafe extern "thiscall" fn(*const IResMan, ResManParam, i32, i32)
);

fn_ref2!(
    iwz_namespace_mount,
    0x9c8db0,
    // this, sPath, pDown, nPriority
    unsafe extern "thiscall" fn(*const IWzNameSpace, ZtlBstr, *const IWzNameSpace, i32)
);

fn_ref2!(
    iwz_filesystem_init,
    0x9c8e40,
    // this, sPath
    unsafe extern "thiscall" fn(*const IWzFileSystem, ZtlBstr)
);

fn_ref2!(
    bstr_ctor,
    0x404890,
    // this, s
    unsafe extern "thiscall" fn(*mut ZtlBstr, PCSTR)
);

fn cwvs_app_init_res_man_hook(_app: *const CWvsApp) {
    let g_resman: *mut ComPtr<IResMan> = std::ptr::null_mut();
    let g_root: *mut ComPtr<IResMan> = std::ptr::null_mut();
    let p_fs: *mut ComPtr<IWzFileSystem> = std::ptr::null_mut();
    let mut path = ZtlBstr(std::ptr::null_mut());

    let r_name = w!("ResMan");
    let ns_name = w!("NameSpace");
    let fs_name = w!("NameSpace#FileSystem");
    let unk_outer: *const c_void = std::ptr::null();

    let prio = 0;

    //TODO path with forward slashes
    let img_path = "/";

    unsafe {
        pc_create_obj_iwz_res_man(r_name, g_resman, unk_outer);

        // TODO: add bitflags and use AutoReparse | AutoSerialize
        iwz_res_man_set_param(
            (*g_resman).0,
            ResManParam::AUTO_REPARSE | ResManParam::AUTO_SERIALIZE,
            -1,
            -1,
        );
        pc_create_obj_iwz_namespace(ns_name, g_root, unk_outer);

        pc_set_root_namespace((*g_root).0);

        // Game File System
        pc_create_obj_iwz_filesystem(fs_name, p_fs, unk_outer);

        bstr_ctor(&mut path, PCSTR(img_path.as_bytes().as_ptr()));
        iwz_filesystem_init((*p_fs).0, path);
        //TODO free bstr

        bstr_ctor(&mut path, s!("/"));
        iwz_namespace_mount((*g_root).0, path, (*p_fs).0, prio);

        // Data File System
        pc_create_obj_iwz_filesystem(fs_name, p_fs, unk_outer);

        bstr_ctor(&mut path, s!("./Data"));
        iwz_filesystem_init((*p_fs).0, path);
        //TODO free bstr

        bstr_ctor(&mut path, s!("/"));
        iwz_namespace_mount((*g_root).0, path, (*p_fs).0, prio);
    };
}
