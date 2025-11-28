//
//  sandbox.h
//
//


#ifndef sandbox_h
#define sandbox_h

enum sandbox_filter_type {
    SANDBOX_FILTER_NONE,
    SANDBOX_FILTER_PATH,
    SANDBOX_FILTER_GLOBAL_NAME,
    SANDBOX_FILTER_LOCAL_NAME,
    SANDBOX_FILTER_APPLEEVENT_DESTINATION,
    SANDBOX_FILTER_RIGHT_NAME,
    SANDBOX_FILTER_PREFERENCE_DOMAIN,
    SANDBOX_FILTER_KEXT_BUNDLE_ID,
    SANDBOX_FILTER_INFO_TYPE,
    SANDBOX_FILTER_NOTIFICATION,
    SANDBOX_FILTER_XPC_SERVICE_NAME = 12,
    SANDBOX_FILTER_IOKIT_CONNECTION,
};

enum sandbox_extension_flags {
    FS_EXT_DEFAULTS =              0,
    FS_EXT_FOR_PATH =       (1 << 0),
    FS_EXT_FOR_FILE =       (1 << 1),
    FS_EXT_READ =           (1 << 2),
    FS_EXT_WRITE =          (1 << 3),
    FS_EXT_PREFER_FILEID =  (1 << 4),
};

typedef struct sbParams sbParams_t;

extern sbParams_t *sandbox_create_params(void);
int    sandbox_set_param (sbParams_t    *params, char *param, char *value);


typedef struct sbProfile {
        char    *name;
        void    *blob;
        int32_t  len;

} sbProfile_t;

char *operation_names[] = {
    "default",
    "appleevent-send",
    "authorization-right-obtain",
    "device*",
    "device-camera",
    "device-microphone",
    "distributed-notification-post",
    "file*",
    "file-chroot",
    "file-ioctl",
    "file-issue-extension",
    "file-map-executable",
    "file-mknod",
    "file-mount",
    "file-read*",
    "file-read-data",
    "file-read-metadata",
    "file-read-xattr",
    "file-revoke",
    "file-search",
    "file-unmount",
    "file-write*",
    "file-write-create",
    "file-write-data",
    "file-write-flags",
    "file-write-mode",
    "file-write-owner",
    "file-write-setugid",
    "file-write-times",
    "file-write-unlink",
    "file-write-xattr",
    "generic-issue-extension",
    "qtn-user",
    "qtn-download",
    "qtn-sandbox",
    "hid-control",
    "iokit*",
    "iokit-issue-extension",
    "iokit-open",
    "iokit-set-properties",
    "iokit-get-properties",
    "ipc*",
    "ipc-posix*",
    "ipc-posix-issue-extension",
    "ipc-posix-sem",
    "ipc-posix-shm*",
    "ipc-posix-shm-read*",
    "ipc-posix-shm-read-data",
    "ipc-posix-shm-read-metadata",
    "ipc-posix-shm-write*",
    "ipc-posix-shm-write-create",
    "ipc-posix-shm-write-data",
    "ipc-posix-shm-write-unlink",
    "ipc-sysv*",
    "ipc-sysv-msg",
    "ipc-sysv-sem",
    "ipc-sysv-shm",
    "job-creation",
    "load-unsigned-code",
    "lsopen",
    "mach*",
    "mach-bootstrap",
    "mach-issue-extension",
    "mach-lookup",
    "mach-per-user-lookup",
    "mach-priv*",
    "mach-priv-host-port",
    "mach-priv-task-port",
    "mach-register",
    "mach-task-name",
    "network*",
    "network-inbound",
    "network-bind",
    "network-outbound",
    "user-preference*",
    "user-preference-read",
    "user-preference-write",
    "process*",
    "process-exec*",
    "process-exec-interpreter",
    "process-fork",
    "process-info*",
    "process-info-listpids",
    "process-info-pidinfo",
    "process-info-pidfdinfo",
    "process-info-pidfileportinfo",
    "process-info-setcontrol",
    "process-info-dirtycontrol",
    "process-info-rusage",
    "pseudo-tty",
    "signal",
    "sysctl*",
    "sysctl-read",
    "sysctl-write",
    "system*",
    "system-acct",
    "system-audit",
    "system-chud",
    "system-debug",
    "system-fsctl",
    "system-info",
    "system-kext*",
    "system-kext-load",
    "system-kext-unload",
    "system-lcid",
    "system-mac-label",
    "system-nfssvc",
    "system-privilege",
    "system-reboot",
    "system-sched",
    "system-set-time",
    "system-socket",
    "system-suspend-resume",
    "system-swap",
    "system-write-bootstrap",
    NULL};

extern const char * APP_SANDBOX_IOKIT_CLIENT;
extern const char * APP_SANDBOX_MACH;
extern const char * APP_SANDBOX_READ;
extern const char * APP_SANDBOX_READ_WRITE;

extern const char * IOS_SANDBOX_APPLICATION_GROUP;
extern const char * IOS_SANDBOX_CONTAINER;

extern const enum sandbox_filter_type SANDBOX_CHECK_ALLOW_APPROVAL;
extern const enum sandbox_filter_type SANDBOX_CHECK_CANONICAL;
extern const enum sandbox_filter_type SANDBOX_CHECK_NOFOLLOW;
extern const enum sandbox_filter_type SANDBOX_CHECK_NO_APPROVAL;
extern const enum sandbox_filter_type SANDBOX_CHECK_NO_REPORT;

extern const uint32_t SANDBOX_EXTENSION_CANONICAL;
extern const uint32_t SANDBOX_EXTENSION_DEFAULT;
extern const uint32_t SANDBOX_EXTENSION_MAGIC;
extern const uint32_t SANDBOX_EXTENSION_NOFOLLOW;
extern const uint32_t SANDBOX_EXTENSION_NO_REPORT;
extern const uint32_t SANDBOX_EXTENSION_NO_STORAGE_CLASS;
extern const uint32_t SANDBOX_EXTENSION_PREFIXMATCH;
extern const uint32_t SANDBOX_EXTENSION_UNRESOLVED;

int sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);
int sandbox_container_path_for_pid (int Pid, char *Buf, int Len);
int sandbox_check_by_audit_token(audit_token_t, const char *operation, enum sandbox_filter_type, ...);
int sandbox_check_by_uniqueid(uid_t, pid_t, const char *operation, enum sandbox_filter_type, ...);
int64_t sandbox_extension_consume(const char *extension_token);
char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);
char *sandbox_extension_issue_file_to_process(const char *extension_class, const char *path, uint32_t flags, audit_token_t);
char *sandbox_extension_issue_file_to_process_by_pid(const char *extension_class, const char *path, uint32_t flags, pid_t);
char *sandbox_extension_issue_file_to_self(const char *extension_class, const char *path, uint32_t flags);
char *sandbox_extension_issue_generic(const char *extension_class, uint32_t flags);
char *sandbox_extension_issue_generic_to_process(const char *extension_class, uint32_t flags, audit_token_t);
char *sandbox_extension_issue_generic_to_process_by_pid(const char *extension_class, uint32_t flags, pid_t);
char *sandbox_extension_issue_iokit_registry_entry_class(const char *extension_class, const char *registry_entry_class, uint32_t flags);
char *sandbox_extension_issue_iokit_registry_entry_class_to_process(const char *extension_class, const char *registry_entry_class, uint32_t flags, audit_token_t);
char *sandbox_extension_issue_iokit_registry_entry_class_to_process_by_pid(const char *extension_class, const char *registry_entry_class, uint32_t flags, pid_t);
char *sandbox_extension_issue_iokit_user_client_class(const char *extension_class, const char *registry_entry_class, uint32_t flags);
char *sandbox_extension_issue_mach(const char *extension_class, const char *name, uint32_t flags);
char *sandbox_extension_issue_mach_to_process(const char *extension_class, const char *name, uint32_t flags, audit_token_t);
char *sandbox_extension_issue_mach_to_process_by_pid(const char *extension_class, const char *name, uint32_t flags, pid_t);
char *sandbox_extension_issue_posix_ipc(const char *extension_class, const char *name, uint32_t flags);
void sandbox_extension_reap(void);
int sandbox_extension_release(int64_t extension_handle);
int sandbox_extension_release_file(int64_t extension_handle, const char *path);
int sandbox_extension_update_file(int64_t extension_handle, const char *path);
int sandbox_suspend(int Pid);
int sandbox_unsuspend(int Pid);
int __sandbox_ms(char *Label, int Op, void *ptr,...);
sbProfile_t *sandbox_compile_file(char *filename, sbParams_t *params, char **err);
sbProfile_t *sandbox_compile_string(char *profile_string, sbParams_t *params, char **err);
sbProfile_t *sandbox_compile_entitlements(char *ents, sbParams_t *params, char **err);
sbProfile_t *sandbox_compile_named(char *profile_name, sbParams_t *params, char **err);
int sandbox_set_trace_path (sbProfile_t *, char *Path) __attribute__((weak_import));;
int sandbox_vtrace_enable(void);
char *sandbox_vtrace_report(void);
void sandbox_free_profile(sbProfile_t *);
int sandbox_apply_container(sbProfile_t *, uint32_t);
#endif /* sandbox_h */
