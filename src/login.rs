use std::{
    ffi::{c_void, CString},
    sync::{LazyLock, Mutex},
};

use crate::{ffi, lazy_hook, util::LazyHook, HookModule};
use windows::core::PCSTR;

pub type CLogin = c_void;

pub struct Login {
    auto_login_data: Mutex<Option<AutoLoginData>>,
}

pub struct AutoLoginData {
    pub username: CString,
    pub password: CString,
}

pub static LOGIN: LazyLock<Login> = LazyLock::new(|| Login {
    auto_login_data: Mutex::new(None),
});

impl Login {
    pub fn set_auto_login_data(&self, id: &str, pw: &str) {
        *self.auto_login_data.lock().expect("msg") = Some(AutoLoginData {
            username: CString::new(id).expect("id"),
            password: CString::new(pw).expect("pw"),
        });
    }
}

static CLOGIN_INIT_HOOK: LazyHook<ffi::login::CloginInit> =
    lazy_hook!(ffi::login::clogin_init, clogin_init_hook);

unsafe extern "thiscall" fn clogin_init_hook(this: *const CLogin, param: *const c_void) {
    unsafe { CLOGIN_INIT_HOOK.call(this, param) }

    if let Some(data) = &*LOGIN.auto_login_data.lock().expect("msg") {
        unsafe {
            ffi::login::clogin_send_check_password_packet(
                this,
                PCSTR::from_raw(data.username.as_ptr() as *const u8),
                PCSTR::from_raw(data.password.as_ptr() as *const u8),
            );
        }
    }
}

pub struct LoginModule;

impl HookModule for LoginModule {
    unsafe fn enable(&self) -> anyhow::Result<()> {
        CLOGIN_INIT_HOOK.enable()?;
        Ok(())
    }

    unsafe fn disable(&self) -> anyhow::Result<()> {
        CLOGIN_INIT_HOOK.disable()?;
        Ok(())
    }
}