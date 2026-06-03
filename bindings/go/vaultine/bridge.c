#include <stddef.h>
#include <stdint.h>

extern void goSecretListCB(char*, char*, char*, size_t, void*);
extern void goExportCB(char*, size_t, void*);
extern void goAuditLogCB(int64_t, int64_t, char*, char*, char*, char*, char*, char*, void*);

void secretListBridge(const char* n, const char* d, const char* u,
                       size_t pl, void* ud) {
    goSecretListCB((char*)n, (char*)d, (char*)u, pl, ud);
}
void exportBridge(const char* c, size_t l, void* ud) {
    goExportCB((char*)c, l, ud);
}
void auditLogBridge(int64_t id, int64_t uid, const char* u,
                     const char* op, const char* t,
                     const char* det, const char* r,
                     const char* ts, void* ud) {
    goAuditLogCB(id, uid, (char*)u, (char*)op, (char*)t, (char*)det, (char*)r, (char*)ts, ud);
}
