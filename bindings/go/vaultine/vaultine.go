package vaultine

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include
#cgo LDFLAGS: -L${SRCDIR}/../../../build/src -lssm
#include <ssm/ssm.h>
#include <stdlib.h>

void secretListBridge(const char*, const char*, const char*, size_t, void*);
void exportBridge(const char*, size_t, void*);
void auditLogBridge(int64_t, int64_t, const char*, const char*,
                     const char*, const char*, const char*,
                     const char*, void*);
*/
import "C"
import (
	"errors"
	"runtime"
	"runtime/cgo"
	"time"
	"unsafe"
)

var (
	ErrAuth       = errors.New("authentication failed")
	ErrNotFound   = errors.New("not found")
	ErrExpired    = errors.New("key expired")
	ErrIntegrity  = errors.New("integrity check failed")
	ErrInternal   = errors.New("internal error")
	ErrUnknown    = errors.New("unknown error")
)

type Status int

const (
	StatusOK        Status = 0
	StatusErrAuth   Status = 1
	StatusErrNotFound Status = 2
	StatusErrExpired  Status = 3
	StatusErrIntegrity Status = 4
	StatusErrInternal Status = 5
)

func (s Status) Error() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusErrAuth:
		return "authentication failed"
	case StatusErrNotFound:
		return "not found"
	case StatusErrExpired:
		return "key expired"
	case StatusErrIntegrity:
		return "integrity check failed"
	case StatusErrInternal:
		return "internal error"
	default:
		return "unknown error"
	}
}

type ExportFormat int

const (
	ExportJSON ExportFormat = 0
	ExportCSV  ExportFormat = 1
)

type SecretEntry struct {
	Name        string
	Description *string
	UpdatedAt   string
	PubKeyLen   int
}

type AuditEntry struct {
	ID             int64
	UserID         int64
	Username       string
	Operation      string
	OperationTarget string
	Details        string
	Result         string
	Timestamp      string
}

type CacheStats struct {
	TotalEntries  int
	ValidEntries  int
	HitCount      int
	MissCount     int
}

type Vaultine struct {
	handle unsafe.Pointer
}

func New(dbPath string, dbKey []byte) (*Vaultine, error) {
	h := &Vaultine{}
	var cDBKey *C.uchar
	var cDBKeyLen C.size_t
	if len(dbKey) > 0 {
		cDBKey = (*C.uchar)(unsafe.Pointer(&dbKey[0]))
		cDBKeyLen = C.size_t(len(dbKey))
	}
	cPath := C.CString(dbPath)
	defer C.free(unsafe.Pointer(cPath))

	var out unsafe.Pointer
	rc := C.ssm_init(
		(**C.ssm_handle)(unsafe.Pointer(&out)),
		cPath, cDBKey, cDBKeyLen,
	)
	if rc != 0 {
		return nil, statusError(Status(rc))
	}
	h.handle = out
	runtime.SetFinalizer(h, (*Vaultine).close)
	return h, nil
}

func (v *Vaultine) close() {
	if v.handle != nil {
		C.ssm_destroy((*C.ssm_handle)(v.handle))
		v.handle = nil
	}
}

func (v *Vaultine) Destroy() {
	if v.handle != nil {
		C.ssm_destroy((*C.ssm_handle)(v.handle))
		v.handle = nil
	}
}

func (v *Vaultine) checkDestroyed() {
	if v.handle == nil {
		panic("vaultine: use of destroyed handle")
	}
}

func (v *Vaultine) UserRegister(username, password string) error {
	v.checkDestroyed()
	cu := C.CString(username)
	cp := C.CString(password)
	defer C.free(unsafe.Pointer(cu))
	defer C.free(unsafe.Pointer(cp))
	return statusError(Status(C.ssm_user_register(
		(*C.ssm_handle)(v.handle), cu, cp,
	)))
}

func (v *Vaultine) UserAuthenticate(username, password string) (bool, error) {
	v.checkDestroyed()
	cu := C.CString(username)
	cp := C.CString(password)
	defer C.free(unsafe.Pointer(cu))
	defer C.free(unsafe.Pointer(cp))
	var valid C.int
	rc := C.ssm_user_authenticate(
		(*C.ssm_handle)(v.handle), cu, cp, &valid,
	)
	if rc != 0 {
		return false, statusError(Status(rc))
	}
	return valid != 0, nil
}

func (v *Vaultine) UserDelete(username, password string) error {
	v.checkDestroyed()
	cu := C.CString(username)
	cp := C.CString(password)
	defer C.free(unsafe.Pointer(cu))
	defer C.free(unsafe.Pointer(cp))
	return statusError(Status(C.ssm_user_delete(
		(*C.ssm_handle)(v.handle), cu, cp,
	)))
}

func (v *Vaultine) UserChangePassword(username, oldPassword, newPassword string) error {
	v.checkDestroyed()
	cu := C.CString(username)
	co := C.CString(oldPassword)
	cn := C.CString(newPassword)
	defer C.free(unsafe.Pointer(cu))
	defer C.free(unsafe.Pointer(co))
	defer C.free(unsafe.Pointer(cn))
	return statusError(Status(C.ssm_user_change_password(
		(*C.ssm_handle)(v.handle), cu, co, cn,
	)))
}

func (v *Vaultine) SecretStore(username string, privateKey, publicKey []byte,
	name, description string) error {
	v.checkDestroyed()
	cu := C.CString(username)
	cn := C.CString(name)
	var cd *C.char
	if description != "" {
		cd = C.CString(description)
		defer C.free(unsafe.Pointer(cd))
	}
	defer C.free(unsafe.Pointer(cu))
	defer C.free(unsafe.Pointer(cn))

	var privPtr *C.uchar
	var privLen C.size_t
	if len(privateKey) > 0 {
		privPtr = (*C.uchar)(unsafe.Pointer(&privateKey[0]))
		privLen = C.size_t(len(privateKey))
	}
	var pubPtr *C.uchar
	var pubLen C.size_t
	if len(publicKey) > 0 {
		pubPtr = (*C.uchar)(unsafe.Pointer(&publicKey[0]))
		pubLen = C.size_t(len(publicKey))
	}
	return statusError(Status(C.ssm_secret_store(
		(*C.ssm_handle)(v.handle), cu,
		privPtr, privLen, pubPtr, pubLen, cn, cd,
	)))
}

func (v *Vaultine) SecretGet(username, name string, maxSize int) ([]byte, []byte, error) {
	v.checkDestroyed()
	cu := C.CString(username)
	cn := C.CString(name)
	defer C.free(unsafe.Pointer(cu))
	defer C.free(unsafe.Pointer(cn))

	if maxSize <= 0 {
		maxSize = 65536
	}
	privBuf := make([]byte, maxSize)
	pubBuf := make([]byte, maxSize)
	privLen := C.size_t(maxSize)
	pubLen := C.size_t(maxSize)

	rc := C.ssm_secret_get(
		(*C.ssm_handle)(v.handle), cu, cn,
		(*C.uchar)(unsafe.Pointer(&privBuf[0])), &privLen,
		(*C.uchar)(unsafe.Pointer(&pubBuf[0])), &pubLen,
	)
	if Status(rc) == StatusErrInternal && int(privLen) > maxSize {
		return v.SecretGet(username, name, int(privLen))
	}
	if rc != 0 {
		return nil, nil, statusError(Status(rc))
	}
	privOut := make([]byte, int(privLen))
	copy(privOut, privBuf[:privLen])
	var pubOut []byte
	if pubLen > 0 {
		pubOut = make([]byte, int(pubLen))
		copy(pubOut, pubBuf[:pubLen])
	}
	return privOut, pubOut, nil
}

func (v *Vaultine) SecretDelete(username, name string) error {
	v.checkDestroyed()
	cu := C.CString(username)
	cn := C.CString(name)
	defer C.free(unsafe.Pointer(cu))
	defer C.free(unsafe.Pointer(cn))
	return statusError(Status(C.ssm_secret_delete(
		(*C.ssm_handle)(v.handle), cu, cn,
	)))
}

// secretListRequest carries the callback for secret_list.
type secretListRequest struct {
	fn  func(SecretEntry)
	err error
}

//export goSecretListCB
func goSecretListCB(name, desc, updated *C.char, pubLen C.size_t, userData unsafe.Pointer) {
	h := cgo.Handle(userData)
	req := h.Value().(*secretListRequest)
	entry := SecretEntry{
		Name:      C.GoString(name),
		UpdatedAt: C.GoString(updated),
		PubKeyLen: int(pubLen),
	}
	if desc != nil {
		s := C.GoString(desc)
		entry.Description = &s
	}
	req.fn(entry)
}

func (v *Vaultine) SecretList(username string, callback func(SecretEntry)) error {
	v.checkDestroyed()
	cu := C.CString(username)
	defer C.free(unsafe.Pointer(cu))

	req := &secretListRequest{fn: callback}
	h := cgo.NewHandle(req)
	defer h.Delete()
	rc := C.ssm_secret_list(
		(*C.ssm_handle)(v.handle), cu,
		C.ssm_secret_list_cb(C.secretListBridge),
		unsafe.Pointer(h),
	)
	return statusError(Status(rc))
}

func (v *Vaultine) KEKRotate(username string) error {
	v.checkDestroyed()
	cu := C.CString(username)
	defer C.free(unsafe.Pointer(cu))
	return statusError(Status(C.ssm_kek_rotate(
		(*C.ssm_handle)(v.handle), cu,
	)))
}

type auditLogRequest struct {
	fn  func(AuditEntry)
	err error
}

//export goAuditLogCB
func goAuditLogCB(id, userID C.int64_t, username, operation, target, details, result, timestamp *C.char, userData unsafe.Pointer) {
	h := cgo.Handle(userData)
	req := h.Value().(*auditLogRequest)
	req.fn(AuditEntry{
		ID:              int64(id),
		UserID:          int64(userID),
		Username:        C.GoString(username),
		Operation:       C.GoString(operation),
		OperationTarget: C.GoString(target),
		Details:         C.GoString(details),
		Result:          C.GoString(result),
		Timestamp:       C.GoString(timestamp),
	})
}

func (v *Vaultine) AuditLogQuery(username, operation, result string,
	limit, offset int64, callback func(AuditEntry)) error {
	v.checkDestroyed()
	var cu, co, cr *C.char
	if username != "" {
		cu = C.CString(username)
		defer C.free(unsafe.Pointer(cu))
	}
	if operation != "" {
		co = C.CString(operation)
		defer C.free(unsafe.Pointer(co))
	}
	if result != "" {
		cr = C.CString(result)
		defer C.free(unsafe.Pointer(cr))
	}

	req := &auditLogRequest{fn: callback}
	h := cgo.NewHandle(req)
	defer h.Delete()
	rc := C.ssm_audit_log_query(
		(*C.ssm_handle)(v.handle), cu, co, cr,
		C.int64_t(limit), C.int64_t(offset),
		C.ssm_audit_log_cb(C.auditLogBridge),
		unsafe.Pointer(h),
	)
	return statusError(Status(rc))
}

func (v *Vaultine) CacheStats() (*CacheStats, error) {
	v.checkDestroyed()
	var cs C.ssm_cache_stats
	rc := C.ssm_cache_get_stats(
		(*C.ssm_handle)(v.handle), &cs,
	)
	if rc != 0 {
		return nil, statusError(Status(rc))
	}
	return &CacheStats{
		TotalEntries: int(cs.total_entries),
		ValidEntries: int(cs.valid_entries),
		HitCount:     int(cs.hit_count),
		MissCount:    int(cs.miss_count),
	}, nil
}

// exportRequest carries the export callback.
type exportRequest struct {
	buf []byte
	err error
}

//export goExportCB
func goExportCB(chunk *C.char, length C.size_t, userData unsafe.Pointer) {
	h := cgo.Handle(userData)
	req := h.Value().(*exportRequest)
	req.buf = append(req.buf, C.GoBytes(unsafe.Pointer(chunk), C.int(length))...)
}

func (v *Vaultine) Export(format ExportFormat, redactPII bool) (string, error) {
	v.checkDestroyed()
	req := &exportRequest{}
	h := cgo.NewHandle(req)
	defer h.Delete()
	redact := 0
	if redactPII {
		redact = 1
	}
	rc := C.ssm_export(
		(*C.ssm_handle)(v.handle), C.ssm_export_format(format), C.int(redact),
		C.ssm_export_cb(C.exportBridge),
		unsafe.Pointer(h),
	)
	if rc != 0 {
		return "", statusError(Status(rc))
	}
	return string(req.buf), nil
}

func (v *Vaultine) DBVersion() (int, error) {
	v.checkDestroyed()
	var ver C.int
	rc := C.ssm_db_version(
		(*C.ssm_handle)(v.handle), &ver,
	)
	if rc != 0 {
		return 0, statusError(Status(rc))
	}
	return int(ver), nil
}

func (v *Vaultine) DBMigrate() error {
	v.checkDestroyed()
	return statusError(Status(C.ssm_db_migrate(
		(*C.ssm_handle)(v.handle),
	)))
}

func (v *Vaultine) BackupCreate(backupPath string, backupKey []byte) error {
	v.checkDestroyed()
	cp := C.CString(backupPath)
	defer C.free(unsafe.Pointer(cp))
	var keyPtr *C.uchar
	var keyLen C.size_t
	if len(backupKey) > 0 {
		keyPtr = (*C.uchar)(unsafe.Pointer(&backupKey[0]))
		keyLen = C.size_t(len(backupKey))
	}
	return statusError(Status(C.ssm_backup_create(
		(*C.ssm_handle)(v.handle), cp, keyPtr, keyLen,
	)))
}

func (v *Vaultine) BackupRestore(backupPath string, backupKey []byte) error {
	v.checkDestroyed()
	cp := C.CString(backupPath)
	defer C.free(unsafe.Pointer(cp))
	var keyPtr *C.uchar
	var keyLen C.size_t
	if len(backupKey) > 0 {
		keyPtr = (*C.uchar)(unsafe.Pointer(&backupKey[0]))
		keyLen = C.size_t(len(backupKey))
	}
	return statusError(Status(C.ssm_backup_restore(
		(*C.ssm_handle)(v.handle), cp, keyPtr, keyLen,
	)))
}

func statusError(s Status) error {
	switch s {
	case StatusOK:
		return nil
	case StatusErrAuth:
		return ErrAuth
	case StatusErrNotFound:
		return ErrNotFound
	case StatusErrExpired:
		return ErrExpired
	case StatusErrIntegrity:
		return ErrIntegrity
	case StatusErrInternal:
		return ErrInternal
	default:
		return ErrUnknown
	}
}

// Helper for time.Time conversion of returned timestamps.
func ParseTimestamp(s string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05Z", s)
}
