use std::ffi::{CStr, CString};
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;

// -----------------------------------------------------------------------
// FFI declarations (raw bindings to libssm.so)
// -----------------------------------------------------------------------
#[allow(non_camel_case_types, dead_code)]
mod ffi {
    use super::*;

    pub const SSM_OK: c_int = 0;
    pub const SSM_ERR_AUTH: c_int = 1;
    pub const SSM_ERR_NOT_FOUND: c_int = 2;
    pub const SSM_ERR_EXPIRED: c_int = 3;
    pub const SSM_ERR_INTEGRITY: c_int = 4;
    pub const SSM_ERR_INTERNAL: c_int = 5;

    pub const SSM_EXPORT_JSON: c_int = 0;
    pub const SSM_EXPORT_CSV: c_int = 1;

    pub type ssm_secret_list_cb = unsafe extern "C" fn(
        *const c_char, *const c_char, *const c_char, usize, *mut c_void,
    );

    pub type ssm_export_cb = unsafe extern "C" fn(*const c_char, usize, *mut c_void);

    pub type ssm_audit_log_cb = unsafe extern "C" fn(
        i64, i64, *const c_char, *const c_char, *const c_char,
        *const c_char, *const c_char, *const c_char, *mut c_void,
    );

    #[repr(C)]
    pub struct ssm_cache_stats {
        pub total_entries: usize,
        pub valid_entries: usize,
        pub hit_count: usize,
        pub miss_count: usize,
    }

    extern "C" {
        pub fn ssm_init(
            out: *mut *mut c_void, db_path: *const c_char,
            db_key: *const c_uchar, db_key_len: usize,
        ) -> c_int;
        pub fn ssm_destroy(h: *mut c_void) -> c_int;
        pub fn ssm_user_register(
            h: *mut c_void, username: *const c_char, password: *const c_char,
        ) -> c_int;
        pub fn ssm_user_authenticate(
            h: *mut c_void, username: *const c_char, password: *const c_char,
            is_valid: *mut c_int,
        ) -> c_int;
        pub fn ssm_user_delete(
            h: *mut c_void, username: *const c_char, password: *const c_char,
        ) -> c_int;
        pub fn ssm_user_change_password(
            h: *mut c_void, username: *const c_char,
            old_password: *const c_char, new_password: *const c_char,
        ) -> c_int;
        pub fn ssm_secret_store(
            h: *mut c_void, username: *const c_char,
            private_key: *const c_uchar, private_key_len: usize,
            public_key: *const c_uchar, public_key_len: usize,
            name: *const c_char, description: *const c_char,
        ) -> c_int;
        pub fn ssm_secret_get(
            h: *mut c_void, username: *const c_char, name: *const c_char,
            private_key_out: *mut c_uchar, private_key_len_out: *mut usize,
            public_key_out: *mut c_uchar, public_key_len_out: *mut usize,
        ) -> c_int;
        pub fn ssm_secret_delete(
            h: *mut c_void, username: *const c_char, name: *const c_char,
        ) -> c_int;
        pub fn ssm_secret_list(
            h: *mut c_void, username: *const c_char,
            callback: ssm_secret_list_cb, user_data: *mut c_void,
        ) -> c_int;
        pub fn ssm_kek_rotate(
            h: *mut c_void, username: *const c_char,
        ) -> c_int;
        pub fn ssm_cache_get_stats(
            h: *mut c_void, out: *mut ssm_cache_stats,
        ) -> c_int;
        pub fn ssm_audit_log_query(
            h: *mut c_void, username: *const c_char, operation: *const c_char,
            result: *const c_char, limit: i64, offset: i64,
            callback: ssm_audit_log_cb, user_data: *mut c_void,
        ) -> c_int;
        pub fn ssm_backup_create(
            h: *mut c_void, backup_path: *const c_char,
            backup_key: *const c_uchar, backup_key_len: usize,
        ) -> c_int;
        pub fn ssm_backup_restore(
            h: *mut c_void, backup_path: *const c_char,
            backup_key: *const c_uchar, backup_key_len: usize,
        ) -> c_int;
        pub fn ssm_export(
            h: *mut c_void, format: c_int, redact_pii: c_int,
            callback: ssm_export_cb, user_data: *mut c_void,
        ) -> c_int;
        pub fn ssm_db_version(
            h: *mut c_void, version_out: *mut c_int,
        ) -> c_int;
        pub fn ssm_db_migrate(h: *mut c_void) -> c_int;
        pub fn ssm_status_to_string(status: c_int) -> *const c_char;
    }
}

// -----------------------------------------------------------------------
// Safe API
// -----------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    ErrAuth = 1,
    ErrNotFound = 2,
    ErrExpired = 3,
    ErrIntegrity = 4,
    ErrInternal = 5,
}

impl Status {
    fn from_raw(raw: c_int) -> Self {
        match raw {
            0 => Status::Ok,
            1 => Status::ErrAuth,
            2 => Status::ErrNotFound,
            3 => Status::ErrExpired,
            4 => Status::ErrIntegrity,
            _ => Status::ErrInternal,
        }
    }

    pub fn to_str(self) -> &'static str {
        unsafe {
            let ptr = ffi::ssm_status_to_string(self as c_int);
            if ptr.is_null() { "UNKNOWN" } else {
                CStr::from_ptr(ptr).to_str().unwrap_or("UNKNOWN")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json = 0,
    Csv = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub total_entries: usize,
    pub valid_entries: usize,
    pub hit_count: usize,
    pub miss_count: usize,
}

#[derive(Debug, Clone)]
pub struct SecretInfo {
    pub name: String,
    pub description: Option<String>,
    pub updated_at: String,
    pub public_key_len: usize,
}

#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub operation: String,
    pub operation_target: Option<String>,
    pub details: Option<String>,
    pub result: String,
    pub timestamp: String,
}

#[derive(Debug)]
pub struct Error {
    pub status: Status,
    pub operation: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.operation, self.status.to_str())
    }
}

impl std::error::Error for Error {}

fn check(status: c_int, operation: &str) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error { status: Status::from_raw(status), operation: operation.to_string() })
    }
}

fn to_cstring(s: &str) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error {
        status: Status::ErrInternal,
        operation: "string contains null byte".to_string(),
    })
}

unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() { None } else {
        CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string())
    }
}

/// A Vaultine handle wrapping `ssm_init` / `ssm_destroy`.
pub struct Vaultine {
    handle: *mut c_void,
    _marker: PhantomData<*mut c_void>,
}

unsafe impl Send for Vaultine {}
unsafe impl Sync for Vaultine {}

impl Vaultine {
    /// Open a Vaultine database. Wraps `ssm_init`.
    pub fn new(db_path: &str, db_key: Option<&[u8]>) -> Result<Self, Error> {
        let cpath = to_cstring(db_path)?;
        let mut handle: *mut c_void = ptr::null_mut();
        let (key_ptr, key_len) = match db_key {
            Some(k) => (k.as_ptr() as *const c_uchar, k.len()),
            None => (ptr::null(), 0),
        };
        let rc = unsafe { ffi::ssm_init(&mut handle, cpath.as_ptr(), key_ptr, key_len) };
        check(rc, "ssm_init")?;
        Ok(Vaultine { handle, _marker: PhantomData })
    }

    fn raw(&self) -> *mut c_void {
        self.handle
    }

    pub fn user_register(&self, username: &str, password: &str) -> Result<(), Error> {
        let u = to_cstring(username)?;
        let p = to_cstring(password)?;
        let rc = unsafe { ffi::ssm_user_register(self.raw(), u.as_ptr(), p.as_ptr()) };
        check(rc, "user_register")
    }

    pub fn user_authenticate(&self, username: &str, password: &str) -> Result<bool, Error> {
        let u = to_cstring(username)?;
        let p = to_cstring(password)?;
        let mut valid: c_int = 0;
        let rc = unsafe { ffi::ssm_user_authenticate(self.raw(), u.as_ptr(), p.as_ptr(), &mut valid) };
        check(rc, "user_authenticate")?;
        Ok(valid != 0)
    }

    pub fn user_delete(&self, username: &str, password: &str) -> Result<(), Error> {
        let u = to_cstring(username)?;
        let p = to_cstring(password)?;
        let rc = unsafe { ffi::ssm_user_delete(self.raw(), u.as_ptr(), p.as_ptr()) };
        check(rc, "user_delete")
    }

    pub fn user_change_password(&self, username: &str, old: &str, new: &str) -> Result<(), Error> {
        let u = to_cstring(username)?;
        let o = to_cstring(old)?;
        let n = to_cstring(new)?;
        let rc = unsafe { ffi::ssm_user_change_password(self.raw(), u.as_ptr(), o.as_ptr(), n.as_ptr()) };
        check(rc, "user_change_password")
    }

    pub fn secret_store(
        &self, username: &str, private_key: &[u8],
        public_key: Option<&[u8]>, name: &str,
        description: Option<&str>,
    ) -> Result<(), Error> {
        let u = to_cstring(username)?;
        let n = to_cstring(name)?;
        let d = description.map(to_cstring).transpose()?;
        let (pub_ptr, pub_len) = match public_key {
            Some(pk) => (pk.as_ptr() as *const c_uchar, pk.len()),
            None => (ptr::null(), 0),
        };
        let rc = unsafe {
            ffi::ssm_secret_store(
                self.raw(), u.as_ptr(),
                private_key.as_ptr() as *const c_uchar, private_key.len(),
                pub_ptr, pub_len,
                n.as_ptr(), d.as_ref().map(|x| x.as_ptr()).unwrap_or(ptr::null()),
            )
        };
        check(rc, "secret_store")
    }

    pub fn secret_get(
        &self, username: &str, name: &str,
        buf_size: usize,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
        let u = to_cstring(username)?;
        let n = to_cstring(name)?;
        let mut priv_buf = vec![0u8; buf_size];
        let mut priv_len = buf_size;
        let mut pub_buf = vec![0u8; buf_size];
        let mut pub_len = buf_size;

        let rc = unsafe {
            ffi::ssm_secret_get(
                self.raw(), u.as_ptr(), n.as_ptr(),
                priv_buf.as_mut_ptr() as *mut c_uchar, &mut priv_len,
                pub_buf.as_mut_ptr() as *mut c_uchar, &mut pub_len,
            )
        };

        // Retry with larger buffer if needed
        if rc == ffi::SSM_ERR_INTERNAL && priv_len > buf_size {
            return self.secret_get(username, name, priv_len);
        }

        check(rc, "secret_get")?;
        priv_buf.truncate(priv_len);
        let pub_out = if pub_len > 0 {
            pub_buf.truncate(pub_len);
            Some(pub_buf)
        } else {
            None
        };
        Ok((priv_buf, pub_out))
    }

    pub fn secret_delete(&self, username: &str, name: &str) -> Result<(), Error> {
        let u = to_cstring(username)?;
        let n = to_cstring(name)?;
        let rc = unsafe { ffi::ssm_secret_delete(self.raw(), u.as_ptr(), n.as_ptr()) };
        check(rc, "secret_delete")
    }

    pub fn secret_list(&self, username: &str) -> Result<Vec<SecretInfo>, Error> {
        let u = to_cstring(username)?;
        let results = std::cell::UnsafeCell::new(Vec::new());

        unsafe extern "C" fn cb(
            name: *const c_char, desc: *const c_char,
            updated: *const c_char, pub_len: usize, user: *mut c_void,
        ) {
            let vec = &mut *(user as *mut Vec<SecretInfo>);
            vec.push(SecretInfo {
                name: cstr_to_string(name).unwrap_or_default(),
                description: cstr_to_string(desc),
                updated_at: cstr_to_string(updated).unwrap_or_default(),
                public_key_len: pub_len,
            });
        }

        let rc = unsafe {
            ffi::ssm_secret_list(
                self.raw(), u.as_ptr(),
                cb as ffi::ssm_secret_list_cb,
                results.get() as *mut c_void,
            )
        };
        check(rc, "secret_list")?;
        Ok(results.into_inner())
    }

    pub fn kek_rotate(&self, username: &str) -> Result<(), Error> {
        let u = to_cstring(username)?;
        let rc = unsafe { ffi::ssm_kek_rotate(self.raw(), u.as_ptr()) };
        check(rc, "kek_rotate")
    }

    pub fn cache_get_stats(&self) -> Result<CacheStats, Error> {
        let mut raw = ffi::ssm_cache_stats {
            total_entries: 0, valid_entries: 0, hit_count: 0, miss_count: 0,
        };
        let rc = unsafe { ffi::ssm_cache_get_stats(self.raw(), &mut raw) };
        check(rc, "cache_get_stats")?;
        Ok(CacheStats {
            total_entries: raw.total_entries,
            valid_entries: raw.valid_entries,
            hit_count: raw.hit_count,
            miss_count: raw.miss_count,
        })
    }

    pub fn audit_log_query(
        &self, username: Option<&str>, operation: Option<&str>,
        result: Option<&str>, limit: i64, offset: i64,
    ) -> Result<Vec<AuditLogEntry>, Error> {
        let u = username.map(to_cstring).transpose()?;
        let op = operation.map(to_cstring).transpose()?;
        let r = result.map(to_cstring).transpose()?;
        let entries = std::cell::UnsafeCell::new(Vec::new());

        unsafe extern "C" fn audit_cb(
            id: i64, user_id: i64, username: *const c_char,
            operation: *const c_char, op_target: *const c_char,
            details: *const c_char, result: *const c_char,
            timestamp: *const c_char, user: *mut c_void,
        ) {
            let vec = &mut *(user as *mut Vec<AuditLogEntry>);
            vec.push(AuditLogEntry {
                id,
                user_id,
                username: cstr_to_string(username).unwrap_or_default(),
                operation: cstr_to_string(operation).unwrap_or_default(),
                operation_target: cstr_to_string(op_target),
                details: cstr_to_string(details),
                result: cstr_to_string(result).unwrap_or_default(),
                timestamp: cstr_to_string(timestamp).unwrap_or_default(),
            });
        }

        let rc = unsafe {
            ffi::ssm_audit_log_query(
                self.raw(),
                u.as_ref().map(|x| x.as_ptr()).unwrap_or(ptr::null()),
                op.as_ref().map(|x| x.as_ptr()).unwrap_or(ptr::null()),
                r.as_ref().map(|x| x.as_ptr()).unwrap_or(ptr::null()),
                limit, offset,
                audit_cb as ffi::ssm_audit_log_cb,
                entries.get() as *mut c_void,
            )
        };
        check(rc, "audit_log_query")?;
        Ok(entries.into_inner())
    }

    pub fn backup_create(&self, path: &str, key: &[u8]) -> Result<(), Error> {
        let p = to_cstring(path)?;
        let rc = unsafe {
            ffi::ssm_backup_create(self.raw(), p.as_ptr(), key.as_ptr() as *const c_uchar, key.len())
        };
        check(rc, "backup_create")
    }

    pub fn backup_restore(&self, path: &str, key: &[u8]) -> Result<(), Error> {
        let p = to_cstring(path)?;
        let rc = unsafe {
            ffi::ssm_backup_restore(self.raw(), p.as_ptr(), key.as_ptr() as *const c_uchar, key.len())
        };
        check(rc, "backup_restore")
    }

    pub fn export_metadata(
        &self, format: ExportFormat, redact_pii: bool,
    ) -> Result<String, Error> {
        let buf = std::cell::UnsafeCell::new(Vec::<u8>::new());

        unsafe extern "C" fn export_cb(
            chunk: *const c_char, len: usize, user: *mut c_void,
        ) {
            let vec = &mut *(user as *mut Vec<u8>);
            let slice = std::slice::from_raw_parts(chunk as *const u8, len);
            vec.extend_from_slice(slice);
        }

        let rc = unsafe {
            ffi::ssm_export(
                self.raw(), format as c_int, redact_pii as c_int,
                export_cb as ffi::ssm_export_cb,
                buf.get() as *mut c_void,
            )
        };
        check(rc, "export")?;
        let bytes = buf.into_inner();
        String::from_utf8(bytes).map_err(|_| Error {
            status: Status::ErrInternal, operation: "export utf-8".to_string(),
        })
    }

    pub fn db_version(&self) -> Result<i32, Error> {
        let mut v: c_int = 0;
        let rc = unsafe { ffi::ssm_db_version(self.raw(), &mut v) };
        check(rc, "db_version")?;
        Ok(v)
    }

    pub fn db_migrate(&self) -> Result<(), Error> {
        let rc = unsafe { ffi::ssm_db_migrate(self.raw()) };
        check(rc, "db_migrate")
    }
}

impl Drop for Vaultine {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { ffi::ssm_destroy(self.handle); }
        }
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_destroy() {
        let v = Vaultine::new(":memory:", None).unwrap();
        assert!(!v.handle.is_null());
        drop(v); // explicit drop to verify no crash
    }

    #[test]
    fn test_user_register_and_auth() {
        let v = Vaultine::new(":memory:", None).unwrap();
        v.user_register("alice", "p@ss").unwrap();
        assert!(v.user_authenticate("alice", "p@ss").unwrap());
        assert!(!v.user_authenticate("alice", "wrong").unwrap());
    }

    #[test]
    fn test_secret_store_get_delete() {
        let v = Vaultine::new(":memory:", None).unwrap();
        v.user_register("bob", "pass").unwrap();

        let priv_key = b"my-secret-key-data";
        v.secret_store("bob", priv_key, None, "k1", Some("test key")).unwrap();

        let (got, pub_key) = v.secret_get("bob", "k1", 4096).unwrap();
        assert_eq!(got, priv_key);
        assert!(pub_key.is_none());

        v.secret_delete("bob", "k1").unwrap();
        assert_eq!(v.secret_get("bob", "k1", 4096).unwrap_err().status, Status::ErrNotFound);
    }

    #[test]
    fn test_secret_list() {
        let v = Vaultine::new(":memory:", None).unwrap();
        v.user_register("carol", "pass").unwrap();
        v.secret_store("carol", b"k1data", None, "k1", None).unwrap();
        v.secret_store("carol", b"k2data", None, "k2", Some("desc")).unwrap();

        let list = v.secret_list("carol").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "k1");
        assert_eq!(list[1].description.as_deref(), Some("desc"));
    }

    #[test]
    fn test_kek_rotate() {
        let v = Vaultine::new(":memory:", None).unwrap();
        v.user_register("dave", "pass").unwrap();
        v.secret_store("dave", b"data", None, "s1", None).unwrap();
        v.kek_rotate("dave").unwrap();

        let (got, _) = v.secret_get("dave", "s1", 4096).unwrap();
        assert_eq!(got, b"data");
    }

    #[test]
    fn test_cache_stats() {
        let v = Vaultine::new(":memory:", None).unwrap();
        v.user_register("eve", "pass").unwrap();
        let stats = v.cache_get_stats().unwrap();
        assert!(stats.total_entries > 0);
    }

    #[test]
    fn test_db_version() {
        let v = Vaultine::new(":memory:", None).unwrap();
        let ver = v.db_version().unwrap();
        assert!(ver >= 1);
    }

    #[test]
    fn test_error_display() {
        let e = Error { status: Status::ErrAuth, operation: "test".into() };
        let s = e.to_string();
        assert!(s.contains("SSM_ERR_AUTH"));
    }
}
