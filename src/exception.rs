use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::time::{Duration, SystemTime};
use std::{ffi::c_void, fs::File};

use std::io::Write;
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD;
use windows::core::HRESULT;
use windows::{
    core::{Error, PCWSTR},
    Win32::{
        Foundation::{HANDLE, NTSTATUS},
        System::{
            Diagnostics::Debug::{
                AddVectoredExceptionHandler, GetThreadContext, RtlCaptureContext,
                SymGetLineFromAddrW64, SymGetSymFromAddr64, SymInitializeW, CONTEXT,
                CONTEXT_ALL_X86, CONTEXT_FULL_X86, EXCEPTION_POINTERS, IMAGEHLP_LINEW64,
                IMAGEHLP_SYMBOL64, STACKFRAME_EX,
            },
            Kernel::ExceptionContinueSearch,
            Threading::{
                GetCurrentProcess, GetCurrentThread, GetCurrentThreadId, GetThreadId, ResumeThread,
                SuspendThread,
            },
        },
    },
};

use crate::{static_assert, static_assert_size};

use self::arch::AddrTy;

const MAX_RECURSIONS: usize = 3;
const MAX_BUF_LEN: usize = 512;

#[cfg(target_arch = "x86_64")]
mod arch {
    use std::ffi::c_void;

    use windows::Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::{
                AddrModeFlat, StackWalkEx, SymFunctionTableAccess64, SymGetModuleBase64, CONTEXT,
                STACKFRAME_EX,
            },
            SystemInformation::IMAGE_FILE_MACHINE_AMD64,
        },
    };

    pub type AddrTy = u64;
    pub type StackFrameTy = STACKFRAME_EX;

    pub unsafe extern "system" fn get_module_base(hproc: HANDLE, addr: AddrTy) -> AddrTy {
        SymGetModuleBase64(hproc, addr)
    }

    pub unsafe extern "system" fn ftable_access(hproc: HANDLE, addr: AddrTy) -> *mut c_void {
        SymFunctionTableAccess64(hproc, addr)
    }

    pub unsafe fn get_first_frame(ctx: *mut CONTEXT) -> STACKFRAME_EX {
        let mut stack_frame = STACKFRAME_EX::default();
        stack_frame.AddrPC.Offset = (*ctx).Rip as AddrTy;
        stack_frame.AddrPC.Mode = AddrModeFlat;

        stack_frame.AddrPC.Offset = (*ctx).Rbp as AddrTy;
        stack_frame.AddrPC.Mode = AddrModeFlat;

        stack_frame.AddrPC.Offset = (*ctx).Rsp as AddrTy;
        stack_frame.AddrPC.Mode = AddrModeFlat;

        stack_frame
    }

    pub unsafe fn stack_walk(
        proc: HANDLE,
        thread: HANDLE,
        frame: &mut STACKFRAME_EX,
        ctx: *mut CONTEXT,
    ) -> bool {
        StackWalkEx(
            IMAGE_FILE_MACHINE_AMD64.0 as u32,
            proc,
            thread,
            frame,
            ctx as *mut c_void,
            None,
            Some(ftable_access),
            Some(get_module_base),
            None,
            0,
        )
        .as_bool()
    }
}

#[cfg(target_arch = "x86")]
mod arch {
    use std::ffi::c_void;

    use windows::Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::{
                AddrModeFlat, StackWalk, SymFunctionTableAccess, SymGetModuleBase, CONTEXT,
                STACKFRAME,
            },
            SystemInformation::IMAGE_FILE_MACHINE_I386,
        },
    };

    pub type StackFrameTy = STACKFRAME;
    pub type AddrTy = u32;

    pub unsafe extern "system" fn get_module_base(hproc: HANDLE, addr: AddrTy) -> AddrTy {
        SymGetModuleBase(hproc, addr)
    }

    pub unsafe extern "system" fn ftable_access(hproc: HANDLE, addr: AddrTy) -> *mut c_void {
        SymFunctionTableAccess(hproc, addr)
    }

    pub unsafe fn get_first_frame(ctx: *mut CONTEXT) -> STACKFRAME {
        let mut stack_frame = STACKFRAME::default();
        stack_frame.AddrPC.Offset = (*ctx).Eip as AddrTy;
        stack_frame.AddrPC.Mode = AddrModeFlat;

        stack_frame.AddrPC.Offset = (*ctx).Ebp as AddrTy;
        stack_frame.AddrPC.Mode = AddrModeFlat;

        stack_frame.AddrPC.Offset = (*ctx).Esp as AddrTy;
        stack_frame.AddrPC.Mode = AddrModeFlat;

        stack_frame
    }

    pub unsafe fn stack_walk(
        proc: HANDLE,
        thread: HANDLE,
        frame: &mut STACKFRAME,
        ctx: *mut CONTEXT,
    ) -> bool {
        StackWalk(
            IMAGE_FILE_MACHINE_I386.0 as u32,
            proc,
            thread,
            frame,
            ctx as *mut c_void,
            None,
            Some(ftable_access),
            Some(get_module_base),
            None,
        )
        .as_bool()
    }
}

unsafe fn _capture_thread_context(thread: HANDLE) -> windows::core::Result<CONTEXT> {
    if GetThreadId(thread) == GetCurrentThreadId() {
        let mut ctx = CONTEXT {
            ContextFlags: CONTEXT_ALL_X86,
            ..Default::default()
        };
        RtlCaptureContext(&mut ctx);
        Ok(ctx)
    } else {
        if SuspendThread(thread) == u32::MAX {
            return Err(Error::from_win32());
        }
        let mut ctx = CONTEXT {
            ContextFlags: CONTEXT_FULL_X86,
            ..Default::default()
        };
        let res = GetThreadContext(thread, &mut ctx);
        if ResumeThread(thread) == u32::MAX {
            return Err(Error::from_win32());
        }

        res.map(|_| ctx)
    }
}

#[derive(Debug)]
pub struct StackFrame {
    pub pc: AddrTy,
    pub ret: AddrTy,
    pub frame: AddrTy,
}

pub trait FrameHandler {
    fn handle_frame(&mut self, frame: &StackFrame);
}

pub struct StackWalker {
    name_buf: [u16; MAX_BUF_LEN],
    proc: HANDLE,
    thread: HANDLE,
    recursions: usize,
    last_frame: arch::StackFrameTy,
    ctx: CONTEXT,
}

impl StackWalker {
    pub unsafe fn new(proc: HANDLE, thread: HANDLE, mut ctx: CONTEXT) -> Self {
        let last_frame = arch::get_first_frame(&mut ctx);
        Self {
            name_buf: [0; MAX_BUF_LEN],
            proc,
            thread,
            last_frame,
            ctx,
            recursions: 0,
        }
    }

    pub fn from_current(ctx: CONTEXT) -> Self {
        unsafe {
            let proc = GetCurrentProcess();
            let thread = GetCurrentThread();
            Self::new(proc, thread, ctx)
        }
    }

    pub unsafe fn init_sym(&self) -> windows::core::Result<()> {
        SymInitializeW(self.proc, PCWSTR::null(), true)
    }

    unsafe fn get_symbol_line(&mut self, frame: &STACKFRAME_EX) -> windows::core::Result<()> {
        let pc = frame.AddrPC.Offset;

        // Get symbol
        let mut sym_offset = 0;
        let mut sym = IMAGEHLP_SYMBOL64 {
            SizeOfStruct: std::mem::size_of::<IMAGEHLP_SYMBOL64>() as u32,
            MaxNameLength: 1,
            ..Default::default()
        };
        SymGetSymFromAddr64(self.proc, pc, Some(&mut sym_offset), std::ptr::null_mut())?;

        // Get Line
        let mut line_offset = 0;
        let mut line = IMAGEHLP_LINEW64 {
            SizeOfStruct: std::mem::size_of::<IMAGEHLP_LINEW64>() as u32,
            ..Default::default()
        };
        SymGetLineFromAddrW64(self.proc, pc, &mut line_offset, &mut line)?;

        Ok(())
    }

    fn next_frame(&mut self) -> windows::core::Result<Option<StackFrame>> {
        let res = unsafe {
            arch::stack_walk(self.proc, self.thread, &mut self.last_frame, &mut self.ctx)
        };

        if !res {
            return Ok(None);
        }

        if self.last_frame.AddrPC.Offset == self.last_frame.AddrReturn.Offset {
            if self.recursions > MAX_RECURSIONS {
                // TODO: maybe use an actual error later
                return Ok(None);
            }
            self.recursions += 1;
        } else {
            self.recursions = 0;
        }

        Ok(Some(StackFrame {
            pc: self.last_frame.AddrPC.Offset,
            ret: self.last_frame.AddrReturn.Offset,
            frame: self.last_frame.AddrFrame.Offset,
        }))
    }
}


#[derive(Copy, Clone)]
#[repr(C)]
pub struct CxxPMD {
    pub mdisp: i32,
    pub pdisp: i32,
    pub vdisp: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CxxTypeDescriptor {
    pub hash: u32,
    pub spare: *const c_void,
    pub name: [u8; 0],
}

impl CxxTypeDescriptor {
    fn get_name(&self) -> Option<&CStr> {
        const MAX_TYPE_NAME: usize = 64;
        unsafe {
            let data = std::slice::from_raw_parts(self.name.as_ptr(), MAX_TYPE_NAME);
            CStr::from_bytes_until_nul(data).ok()
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
struct CxxCatchableType {
    pub properties: u32,
    pub ty: *mut CxxTypeDescriptor,
    pub this_displacement: CxxPMD,
    pub size_or_offset: u32,
    pub copy_fn: *mut c_void,
}

#[repr(C)]
struct CxxCatchableTypeArray {
    pub count: i32,
    pub types: *mut CxxCatchableType,
}

impl CxxCatchableTypeArray {
    pub unsafe fn as_slice(&self) -> &[CxxCatchableType] {
        std::slice::from_raw_parts(self.types, self.count as usize)
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
struct CxxThrowInfo {
    pub attributes: u32,
    pub unwind_fn: *mut c_void,
    pub forward_compat_fn: *mut c_void,
    pub catchable_type_array: *mut CxxCatchableTypeArray,
}

#[derive(Copy, Clone)]
#[repr(C)]
struct CxxThrowException {
    pub magic: u32,
    pub obj: *mut c_void,
    pub throw_info: *mut CxxThrowInfo,
}



const MSVCXX_EXCEPTION_CODE: NTSTATUS = NTSTATUS(0xe06d7363u32 as i32);
const ZEXCEPTION_MAGIC: u32 = 0x19930520;

impl CxxThrowException {
    pub fn from_record(record: &EXCEPTION_RECORD) -> Option<Self> {
        if record.ExceptionCode == MSVCXX_EXCEPTION_CODE && record.NumberParameters == 3 {
            let params: [usize; 3] = record.ExceptionInformation[..3].try_into().unwrap();
           Some(CxxThrowException::from(params))
        } else {
            None
        }
    }


    pub unsafe fn get_first_type_name(&self) -> Option<&CStr> {
        self
                .throw_info
                .as_ref()
                .and_then(|info| info.catchable_type_array.as_ref())
                .and_then(|arr| arr.as_slice().first())
                .and_then(|ty| ty.ty.as_ref())
                .and_then(|ty| ty.get_name())
    }

    pub fn as_zexception(&self) -> Option<&ZException> {
        if self.magic == ZEXCEPTION_MAGIC {
            unsafe { std::mem::transmute::<_, *mut ZException>(self.obj).as_ref() }
        } else {
            None
        }
    }
}

#[repr(C)]
struct ZException {
    pub res: HRESULT,
}

static_assert_size!(CxxThrowException, [u32; 3]);

impl From<[usize; 3]> for CxxThrowException {
    fn from(value: [usize; 3]) -> Self {
        unsafe { std::mem::transmute_copy(&value) }
    }
}


fn write_trace(file: &str, zex: Option<HRESULT>, first_type_name: &Option<CString>, frames: &[StackFrame]) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).append(true).open(file)?;
    writeln!(f, "----------\nException at {:?}", SystemTime::now())?;
    if let Some(zex) = zex {
        writeln!(f, "ZException: {:X}", zex.0)?;
    }
    if let Some(name) = first_type_name {
        writeln!(f, "Type: {:?}", name)?;
    }
    if !frames.is_empty() {
        writeln!(f, "Trace:")?;
        for frame in frames {
            writeln!(f, "{:X}", frame.ret)?;
        }
    }
    Ok(())
}

unsafe extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let Some(info) = exception_info.as_ref() else {
        return ExceptionContinueSearch.0;
    };

    let Some(record) = info.ExceptionRecord.as_ref() else {
        return ExceptionContinueSearch.0;
    };

    if record.ExceptionCode == NTSTATUS(1080890248) {
        return ExceptionContinueSearch.0;
    }

    log::info!("Got exception: {:?}", record);
    std::thread::sleep(Duration::from_secs(3));

    let mut zex_result = None;
    let mut first_type_name = None;
    let mut frames = Vec::with_capacity(16);

    // CXX Exception
    if let Some(cxx_ex) = CxxThrowException::from_record(record) {

        zex_result = cxx_ex.as_zexception().map(|zex| zex.res);
        first_type_name = cxx_ex.get_first_type_name().map(|s| s.to_owned());
    }

    // Walk the stack
    if let Some(ctx) = info.ContextRecord.as_ref() {
        let mut walker = StackWalker::from_current(*ctx);
        let _ = walker.init_sym();
        let mut i = 0;
        while let Ok(Some(frame)) = walker.next_frame() {
            if i > 6 {
                break;
            }
            frames.push(frame);
            i += 1;
        }
    }

    let _ = write_trace("exception_log.txt", zex_result, &first_type_name, &frames);

    ExceptionContinueSearch.0
}

pub fn setup_exception_handler() {
    unsafe {
        AddVectoredExceptionHandler(1, Some(exception_handler));
    }
}
