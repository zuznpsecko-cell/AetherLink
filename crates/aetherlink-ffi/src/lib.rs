//! AetherLink FFI C ABI exports (+ JNI for Android)
//!
//! Provides stable C ABI for .NET, Android, and CLI consumers.
//! All functions use C-compatible types and error handling.
//!
//! The `jni` module adds `Java_link_aether_client_AetherCore_*` entry points
//! so the same core `.so` serves both the C ABI and Kotlin/JNI.

pub mod jni;

use once_cell::sync::Lazy;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::Mutex;

use aetherlink_client::Client;
use aetherlink_server::Server;

/// Opaque handle type for FFI
pub type AetherHandle = usize;

/// Error codes for FFI functions
#[repr(i32)]
pub enum AetherError {
    Success = 0,
    InvalidHandle = -1,
    InvalidConfig = -2,
    AlreadyRunning = -3,
    NotRunning = -4,
    NetworkError = -5,
    DnsError = -6,
    AuthError = -7,
    InternalError = -8,
    InvalidArgument = -9,
    PermissionDenied = -10,
}

/// Global handle storage
static HANDLES: Lazy<Mutex<HandleMap>> = Lazy::new(|| Mutex::new(HandleMap::new()));

struct HandleMap {
    clients: std::collections::HashMap<usize, Client>,
    servers: std::collections::HashMap<usize, Server>,
    next_id: usize,
}

impl HandleMap {
    fn new() -> Self {
        Self {
            clients: std::collections::HashMap::new(),
            servers: std::collections::HashMap::new(),
            next_id: 1,
        }
    }

    fn insert_client(&mut self, client: Client) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.clients.insert(id, client);
        id
    }

    fn insert_server(&mut self, server: Server) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.servers.insert(id, server);
        id
    }

    fn get_client(&mut self, handle: usize) -> Option<&mut Client> {
        self.clients.get_mut(&handle)
    }

    fn get_server(&mut self, handle: usize) -> Option<&mut Server> {
        self.servers.get_mut(&handle)
    }

    fn remove_client(&mut self, handle: usize) -> Option<Client> {
        self.clients.remove(&handle)
    }

    fn remove_server(&mut self, handle: usize) -> Option<Server> {
        self.servers.remove(&handle)
    }
}

/// Thread-local last error message
thread_local! {
    static LAST_ERROR: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.to_string());
}

/// Log callback type: `level` (0 info, higher = more severe), nul-terminated message.
pub type LogCallback = extern "C" fn(level: c_int, message: *const c_char);

/// Registered log callback (none by default).
static LOG_CALLBACK: Lazy<Mutex<Option<LogCallback>>> = Lazy::new(|| Mutex::new(None));

/// Emit one operational log line. Messages are static text plus numeric
/// codes only — config content and secrets never flow through here.
fn ffi_log(level: c_int, message: &str) {
    // Copy out under the lock, call without holding it: a callback that
    // re-enters the FFI must never deadlock us.
    let callback = *LOG_CALLBACK.lock().expect("log callback");
    if let Some(callback) = callback {
        if let Ok(line) = CString::new(message) {
            callback(level, line.as_ptr());
        }
    }
}

/// Parse a config document via the shared core boundary (JSON→YAML).
fn parse_config(config_str: &str) -> std::result::Result<serde_json::Value, String> {
    aetherlink_core::config::parse_document(config_str).map_err(|e| e.to_string())
}

#[no_mangle]
pub extern "C" fn aether_version() -> *const c_char {
    static VERSION: &str = "AetherLink 1.5.0\0";
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn aether_last_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        let msg = e.borrow();
        if msg.is_empty() {
            std::ptr::null()
        } else {
            // Leak the string for C caller (they must not free)
            let cstr = CString::new(msg.as_str()).unwrap();
            cstr.into_raw()
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aether_server_start(config_json: *const c_char) -> AetherHandle {
    if config_json.is_null() {
        set_last_error("config_json is null");
        return 0;
    }

    let config_str = unsafe { CStr::from_ptr(config_json).to_str().unwrap_or("") };

    let config = match parse_config(config_str) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&e);
            return 0;
        }
    };

    let server = match Server::new(config) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Server creation failed: {}", e));
            return 0;
        }
    };

    let handle = HANDLES.lock().unwrap().insert_server(server);
    handle
}

#[no_mangle]
pub extern "C" fn aether_server_stop(handle: AetherHandle) -> c_int {
    let mut handles = HANDLES.lock().unwrap();
    if handles.remove_server(handle).is_some() {
        AetherError::Success as c_int
    } else {
        set_last_error("Invalid server handle");
        AetherError::InvalidHandle as c_int
    }
}

#[no_mangle]
pub unsafe extern "C" fn aether_client_create(config_json: *const c_char) -> AetherHandle {
    if config_json.is_null() {
        set_last_error("config_json is null");
        return 0;
    }

    let config_str = unsafe { CStr::from_ptr(config_json).to_str().unwrap_or("") };

    let config = match parse_config(config_str) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&e);
            return 0;
        }
    };

    let client = match Client::new(config) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("Client creation failed: {}", e));
            ffi_log(2, "client create failed");
            return 0;
        }
    };

    let handle = HANDLES.lock().unwrap().insert_client(client);
    ffi_log(0, "client create ok");
    handle
}

#[no_mangle]
pub extern "C" fn aether_client_up(handle: AetherHandle) -> c_int {
    let mut handles = HANDLES.lock().unwrap();
    let client = match handles.get_client(handle) {
        Some(c) => c,
        None => {
            set_last_error("Invalid client handle");
            return AetherError::InvalidHandle as c_int;
        }
    };

    match client.up() {
        Ok(_) => AetherError::Success as c_int,
        Err(e) => {
            set_last_error(&format!("Client up failed: {}", e));
            AetherError::NetworkError as c_int
        }
    }
}

#[no_mangle]
pub extern "C" fn aether_client_down(handle: AetherHandle) -> c_int {
    let mut handles = HANDLES.lock().unwrap();
    let client = match handles.get_client(handle) {
        Some(c) => c,
        None => {
            set_last_error("Invalid client handle");
            return AetherError::InvalidHandle as c_int;
        }
    };

    match client.down() {
        Ok(_) => AetherError::Success as c_int,
        Err(e) => {
            set_last_error(&format!("Client down failed: {}", e));
            AetherError::NetworkError as c_int
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aether_client_status(
    handle: AetherHandle,
    out_json: *mut c_char,
    out_len: usize,
) -> c_int {
    if out_json.is_null() || out_len == 0 {
        return AetherError::InvalidArgument as c_int;
    }

    let mut handles = HANDLES.lock().unwrap();
    let client = match handles.get_client(handle) {
        Some(c) => c,
        None => {
            set_last_error("Invalid client handle");
            return AetherError::InvalidHandle as c_int;
        }
    };

    let json = match client.status() {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!("Status failed: {}", e));
            return AetherError::InternalError as c_int;
        }
    };

    if json.len() + 1 > out_len {
        set_last_error("Output buffer too small");
        return AetherError::InvalidArgument as c_int;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), out_json as *mut u8, json.len());
        *out_json.add(json.len()) = 0; // null terminator
    }

    AetherError::Success as c_int
}

#[no_mangle]
pub extern "C" fn aether_client_force_cleanup() -> c_int {
    // Load state from persistent file and restore network
    match aetherlink_client::cleanup::force_cleanup() {
        Ok(_) => AetherError::Success as c_int,
        Err(e) => {
            set_last_error(&format!("Force cleanup failed: {}", e));
            AetherError::InternalError as c_int
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aether_client_rules_list(
    handle: AetherHandle,
    out_json: *mut c_char,
    out_len: usize,
) -> c_int {
    if out_json.is_null() || out_len == 0 {
        return AetherError::InvalidArgument as c_int;
    }

    let handles = HANDLES.lock().unwrap();
    let client = match handles.clients.get(&handle) {
        Some(c) => c,
        None => {
            set_last_error("Invalid client handle");
            return AetherError::InvalidHandle as c_int;
        }
    };

    let json = match client.rules_json() {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!("Rules list failed: {}", e));
            return AetherError::InternalError as c_int;
        }
    };

    if json.len() + 1 > out_len {
        set_last_error("Output buffer too small");
        return AetherError::InvalidArgument as c_int;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), out_json as *mut u8, json.len());
        *out_json.add(json.len()) = 0; // null terminator
    }

    AetherError::Success as c_int
}

#[no_mangle]
pub unsafe extern "C" fn aether_client_rules_set(
    handle: AetherHandle,
    rules_json: *const c_char,
) -> c_int {
    if rules_json.is_null() {
        set_last_error("rules_json is null");
        return AetherError::InvalidArgument as c_int;
    }

    let raw = unsafe { CStr::from_ptr(rules_json).to_str().unwrap_or("") };
    let doc: serde_json::Value = match serde_json::from_str(raw) {
        Ok(doc) => doc,
        Err(e) => {
            set_last_error(&format!("Invalid rules JSON: {e}"));
            return AetherError::InvalidArgument as c_int;
        }
    };

    let mut handles = HANDLES.lock().unwrap();
    let client = match handles.get_client(handle) {
        Some(c) => c,
        None => {
            set_last_error("Invalid client handle");
            return AetherError::InvalidHandle as c_int;
        }
    };

    match client.set_rules(&doc) {
        Ok(()) => {
            ffi_log(0, "client rules set ok");
            AetherError::Success as c_int
        }
        Err(e) => {
            set_last_error(&format!("Rules set failed: {e}"));
            AetherError::InvalidArgument as c_int
        }
    }
}

#[no_mangle]
pub extern "C" fn aether_client_rules_reload(handle: AetherHandle) -> c_int {
    let handles = HANDLES.lock().unwrap();
    let client = match handles.clients.get(&handle) {
        Some(c) => c,
        None => {
            set_last_error("Invalid client handle");
            return AetherError::InvalidHandle as c_int;
        }
    };

    match client.reload_rules() {
        Ok(()) => AetherError::Success as c_int,
        Err(e) => {
            set_last_error(&format!("Rules reload failed: {e}"));
            AetherError::InternalError as c_int
        }
    }
}

#[no_mangle]
pub extern "C" fn aether_client_android_set_tun_fd(
    handle: AetherHandle,
    fd: c_int,
    mtu: c_int,
) -> c_int {
    {
        let handles = HANDLES.lock().unwrap();
        if !handles.clients.contains_key(&handle) {
            set_last_error("Invalid client handle");
            return AetherError::InvalidHandle as c_int;
        }
    }
    if fd < 0 || mtu <= 0 {
        set_last_error("Invalid tun fd or mtu");
        return AetherError::InvalidArgument as c_int;
    }
    // Validated + staged; the platform task applies it at bring-up.
    crate::jni::stage_tun(handle, fd, mtu);
    AetherError::Success as c_int
}

#[no_mangle]
pub unsafe extern "C" fn aether_client_set_split_config(
    handle: AetherHandle,
    config_json: *const c_char,
) -> c_int {
    {
        let handles = HANDLES.lock().unwrap();
        if !handles.clients.contains_key(&handle) {
            set_last_error("Invalid client handle");
            return AetherError::InvalidHandle as c_int;
        }
    }
    if config_json.is_null() {
        set_last_error("config_json is null");
        return AetherError::InvalidArgument as c_int;
    }
    let raw = unsafe { CStr::from_ptr(config_json).to_str().unwrap_or("") };
    let doc = match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(doc) if doc.is_object() => doc,
        _ => {
            set_last_error("Invalid split config JSON");
            return AetherError::InvalidArgument as c_int;
        }
    };
    // Validated + staged; enforced at dial time on Android only.
    crate::jni::stage_split(handle, doc.to_string());
    AetherError::Success as c_int
}

#[no_mangle]
pub extern "C" fn aether_set_log_callback(
    callback: extern "C" fn(level: c_int, message: *const c_char),
) -> c_int {
    *LOG_CALLBACK.lock().expect("log callback") = Some(callback);
    AetherError::Success as c_int
}
