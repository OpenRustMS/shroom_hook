use std::ffi::c_void;

use windows::core::{s, w, PCSTR};

use crate::{
    ffi::{
        bstr_ctor,
        wz::{self, CWvsApp, IResMan, IWzFileSystem},
        ComPtr, ZtlBstr,
    },
    lazy_hook,
    util::LazyHook,
    HookModule,
};

static CWVS_APP_INIT_RES_MAN_HOOK: LazyHook<wz::CwvsAppInitResMan> =
    lazy_hook!(wz::cwvs_app_init_res_man, cwvs_app_init_res_man_hook);

#[allow(dead_code)]
unsafe extern "thiscall" fn cwvs_app_init_res_man_hook(_app: *const CWvsApp) {
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
        wz::pc_create_obj_iwz_res_man(r_name, g_resman, unk_outer);

        // TODO: add bitflags and use AutoReparse | AutoSerialize
        wz::iwz_res_man_set_param(
            (*g_resman).0,
            wz::ResManParam::AUTO_REPARSE | wz::ResManParam::AUTO_SERIALIZE,
            -1,
            -1,
        );
        wz::pc_create_obj_iwz_namespace(ns_name, g_root, unk_outer);

        wz::pc_set_root_namespace((*g_root).0);

        // Game File System
        wz::pc_create_obj_iwz_filesystem(fs_name, p_fs, unk_outer);

        bstr_ctor(&mut path, PCSTR(img_path.as_bytes().as_ptr()));
        wz::iwz_filesystem_init((*p_fs).0, path);
        //TODO free bstr

        bstr_ctor(&mut path, s!("/"));
        wz::iwz_namespace_mount((*g_root).0, path, (*p_fs).0, prio);

        // Data File System
        wz::pc_create_obj_iwz_filesystem(fs_name, p_fs, unk_outer);

        bstr_ctor(&mut path, s!("./Data"));
        wz::iwz_filesystem_init((*p_fs).0, path);
        //TODO free bstr

        bstr_ctor(&mut path, s!("/"));
        wz::iwz_namespace_mount((*g_root).0, path, (*p_fs).0, prio);
    };
}

pub struct WzImageLoader;

impl HookModule for WzImageLoader {
    unsafe fn enable(&self) -> anyhow::Result<()> {
        CWVS_APP_INIT_RES_MAN_HOOK.enable()?;

        Ok(())
    }

    unsafe fn disable(&self) -> anyhow::Result<()> {
        CWVS_APP_INIT_RES_MAN_HOOK.disable()?;

        Ok(())
    }
}
