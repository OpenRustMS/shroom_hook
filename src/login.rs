use std::{
    ffi::{c_void, CStr, CString},
    sync::{LazyLock, Mutex},
};

use crate::{fn_ref2, static_ms_fn_hook};
use windows::core::{s, PCSTR};

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

    pub fn init(&self) -> anyhow::Result<()> {
        unsafe {
            CLOGIN_INIT_HOOK.enable()?;
        }

        Ok(())
    }
}

static_ms_fn_hook!(
    CLOGIN_INIT_HOOK,
    0x5d8010,
    clogin_init_hook,
    type CLoginInit = unsafe extern "thiscall" fn(*const CLogin, *const c_void)
);

fn_ref2!(
    clogin_send_check_password_packet,
    0x5db9d0,
    unsafe extern "thiscall" fn(*const CLogin, PCSTR, PCSTR) -> i32
);

extern "thiscall" fn clogin_init_hook(this: *const CLogin, param: *const c_void) {
    unsafe { CLOGIN_INIT_HOOK.call(this, param) }

    if let Some(data) = &*LOGIN.auto_login_data.lock().expect("msg") {
        unsafe {
            clogin_send_check_password_packet(
                this,
                PCSTR::from_raw(data.username.as_ptr() as *const u8),
                PCSTR::from_raw(data.password.as_ptr() as *const u8),
            );
        }
    }
}
