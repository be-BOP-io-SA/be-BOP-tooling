/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Roosembert Palacios <roos@be-bop.io>, 2025
 *
 * be-bop-cli-wrapper.c
 *
 * SUID wrapper for be-bop-cli to execute the script as the be-bop-cli user.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>

/* Use lonesha256 in static mode */
#define LONESHA256_STATIC
#include "lonesha256.h"

/* Compile-time constants - must be provided via -D flags during compilation */
#ifndef SCRIPT_EXPECTED_SHA256_HEX
#error "SCRIPT_EXPECTED_SHA256_HEX must be defined at compile time"
#endif

#ifndef SCRIPT_SIZE_BYTES
#error "SCRIPT_SIZE_BYTES must be defined at compile time"
#endif

#ifndef WRAPPER_FINGERPRINT
#error "WRAPPER_FINGERPRINT must be defined at compile time"
#endif

/* Validate that the defines are reasonable at compile time */
#if SCRIPT_SIZE_BYTES <= 0
#error "SCRIPT_SIZE_BYTES must be positive"
#endif

/* Security limits */
#define MAX_PATH_LEN 4096
#define MAX_ARGS 1024

/* Fixed paths */
#define REAL_SCRIPT_PATH "/usr/local/libexec/be-bop-cli.real"
#define TARGET_USER "be-bop-cli"
#define WORKING_DIR "/var/lib/be-BOP"
#define BASH_PATH "/bin/bash"

/* Version fingerprint block (embedded in binary for identification) */
__attribute__((used))
static const char be_bop_cli_version_block[] =
    "be-bop-cli-wrapper-fingerprint:" WRAPPER_FINGERPRINT "\n";

/* Convert binary hash to hex string */
static void hash_to_hex(const uint8_t hash[32], char hex[65]) {
    int i;
    for (i = 0; i < 32; i++) {
        snprintf(hex + (i * 2), 3, "%02x", hash[i]);
    }
    hex[64] = '\0';
}

/* Constant-time string comparison */
static int secure_compare(const char *a, const char *b, size_t len) {
    int result = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/* Error reporting with user-friendly message + technical details */
static void die_with_error(const char *technical_reason) {
    fprintf(stderr, "ERROR: be-bop-cli could not be executed. Please run be-bop-wizard to fix this.\n");
    fprintf(stderr, "Technical details: %s\n", technical_reason);
    exit(126);
}

/* 1) Resolve service account */
static struct passwd *resolve_target_user(void) {
    struct passwd *pw = getpwnam(TARGET_USER);
    if (!pw) {
        die_with_error("be-bop-cli user does not exist");
    }
    return pw;
}

/* 2) Validate wrapper binary (self-check) */
static void validate_wrapper_suid(uid_t target_uid) {
    if (geteuid() != target_uid) {
        die_with_error("wrapper is not properly configured as SUID to be-bop-cli user");
    }
}

/* 3) Open and validate real script */
static int open_and_validate_script(uid_t target_uid) {
    int fd = open(REAL_SCRIPT_PATH, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        die_with_error("could not open real script file");
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        die_with_error("could not stat real script file");
    }

    /* Must be regular file */
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        die_with_error("real script is not a regular file");
    }

    /* Must not be group/other writable */
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        close(fd);
        die_with_error("real script is writable by group or others");
    }

    /* Expected size check */
    if (st.st_size != SCRIPT_SIZE_BYTES) {
        close(fd);
        die_with_error("real script size does not match expected size");
    }

    /* Trusted ownership: target_uid or root */
    if (st.st_uid != target_uid && st.st_uid != 0) {
        close(fd);
        die_with_error("real script has untrusted ownership");
    }

    return fd;
}

/* 4) Hash pinning over the opened fd */
static void validate_script_hash(int script_fd) {
    uint8_t hash[32];
    char hex[65];
    uint8_t *file_content;
    struct stat st;
    ssize_t bytes_read;

    /* Validate expected hash string length at runtime */
    if (strlen(SCRIPT_EXPECTED_SHA256_HEX) != 64) {
        die_with_error("be-bop-cli script compile-time hash string has invalid length");
    }

    /* Get file size */
    if (fstat(script_fd, &st) != 0) {
        die_with_error("failed to stat script file for hashing");
    }

    /* Allocate buffer for entire file */
    file_content = malloc(st.st_size);
    if (!file_content) {
        die_with_error("failed to allocate memory for script hashing");
    }

    /* Read entire file */
    bytes_read = read(script_fd, file_content, st.st_size);
    if (bytes_read != st.st_size) {
        free(file_content);
        die_with_error("failed to read entire script for hashing");
    }

    /* Hash the file content using lonesha256 */
    if (lonesha256(hash, file_content, st.st_size) != 0) {
        free(file_content);
        die_with_error("failed to compute script hash");
    }

    free(file_content);
    hash_to_hex(hash, hex);

    /* Constant-time comparison */
    if (!secure_compare(hex, SCRIPT_EXPECTED_SHA256_HEX, 64)) {
        die_with_error("real script hash does not match expected value");
    }

    /* Reset file position for execution */
    if (lseek(script_fd, 0, SEEK_SET) != 0) {
        die_with_error("failed to reset script file position");
    }
}

/* 5) Reset signal state */
static void reset_signal_state(void) {
    int sig;
    sigset_t emptyset;

    /* Reset all catchable signals to default */
    for (sig = 1; sig < NSIG; sig++) {
        if (sig != SIGKILL && sig != SIGSTOP) {
            signal(sig, SIG_DFL);
        }
    }

    /* Clear signal mask */
    sigemptyset(&emptyset);
    if (sigprocmask(SIG_SETMASK, &emptyset, NULL) != 0) {
        die_with_error("failed to clear signal mask");
    }
}

/* 6) Process hygiene */
static void cleanup_process_state(int script_fd) {
    DIR *proc_fd_dir;
    struct dirent *entry;
    int fd, keep_fds[] = {script_fd, 1, 2}; /* script_fd, stdout, stderr */
    int keep_count = sizeof(keep_fds) / sizeof(keep_fds[0]);
    int i, should_keep;

    /* Set umask */
    umask(022);

    /* Change working directory */
    if (chdir(WORKING_DIR) != 0) {
        die_with_error("failed to change to working directory");
    }

    /* Close stdin */
    close(0);

    /* Close all other file descriptors using /proc/self/fd */
    proc_fd_dir = opendir("/proc/self/fd");
    if (!proc_fd_dir) {
        die_with_error("failed to open /proc/self/fd for cleanup");
    }

    while ((entry = readdir(proc_fd_dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        fd = atoi(entry->d_name);
        if (fd <= 0) continue;

        /* Check if this fd should be kept */
        should_keep = 0;
        for (i = 0; i < keep_count; i++) {
            if (fd == keep_fds[i]) {
                should_keep = 1;
                break;
            }
        }

        /* Also keep the directory fd itself */
        if (fd == dirfd(proc_fd_dir)) {
            should_keep = 1;
        }

        if (!should_keep) {
            close(fd);
        }
    }

    closedir(proc_fd_dir);
}

/* 7) Construct clean environment */
static void setup_clean_environment(const char *target_home) {
    char path_buffer[4096];
    const char *dbus_addr;

    /* Clear environment */
    if (clearenv() != 0) {
        die_with_error("failed to clear environment");
    }

    /* Construct PATH */
    size_t path_len = confstr(_CS_PATH, path_buffer, sizeof(path_buffer));
    if (path_len == 0 || path_len >= sizeof(path_buffer)) {
        /* Fallback to basic PATH */
        strcpy(path_buffer, "/bin:/usr/bin");
    }

    /* Ensure required directories are in PATH */
    const char *required_dirs[] = {"/bin", "/usr/bin", "/sbin", "/usr/sbin"};
    for (int i = 0; i < 4; i++) {
        if (!strstr(path_buffer, required_dirs[i])) {
            if (strlen(path_buffer) + strlen(required_dirs[i]) + 2 < sizeof(path_buffer)) {
                strcat(path_buffer, ":");
                strcat(path_buffer, required_dirs[i]);
            }
        }
    }

    /* Set minimal environment */
    setenv("PATH", path_buffer, 1);
    setenv("HOME", target_home, 1);
    setenv("USER", TARGET_USER, 1);
    setenv("LOGNAME", TARGET_USER, 1);
    setenv("LANG", "C", 1);

    /* Pass through DBUS_SESSION_BUS_ADDRESS if it exists */
    dbus_addr = getenv("DBUS_SESSION_BUS_ADDRESS");
    if (dbus_addr) {
        setenv("DBUS_SESSION_BUS_ADDRESS", dbus_addr, 1);
    }
}

/* 8) Exec bash via /proc/self/fd/<n> and forward args */
static void exec_script(int script_fd, int argc, char *argv[], struct passwd *target_pw) {
    char fdpath[64];
    char *bash_argv[MAX_ARGS];
    int bash_argc = 0;

    /* Build fdpath */
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", script_fd);

    /* Build bash arguments */
    bash_argv[bash_argc++] = BASH_PATH;
    bash_argv[bash_argc++] = "--noprofile";
    bash_argv[bash_argc++] = "--norc";
    bash_argv[bash_argc++] = "-p";
    bash_argv[bash_argc++] = "-c";
    bash_argv[bash_argc++] = "set -euo pipefail; script=\"$1\"; shift; source \"$script\"";
    bash_argv[bash_argc++] = argv[0]; /* $0 for bash */
    bash_argv[bash_argc++] = fdpath;  /* $1 for the script path */

    /* Forward remaining arguments */
    for (int i = 1; i < argc && bash_argc < MAX_ARGS - 1; i++) {
        bash_argv[bash_argc++] = argv[i];
    }
    bash_argv[bash_argc] = NULL;

    /* Execute */
    if (setresgid(target_pw->pw_gid, target_pw->pw_gid, target_pw->pw_gid) != 0) {
        die_with_error("Failed to setresgid");
    }
    if (setresuid(target_pw->pw_uid, target_pw->pw_uid, target_pw->pw_uid) != 0) {
        die_with_error("Failed to setresuid");
    }
    execv(BASH_PATH, bash_argv);
    die_with_error("failed to execute bash");
}

int main(int argc, char *argv[]) {
    struct passwd *target_pw;
    int script_fd;

    /* 1) Resolve service account */
    target_pw = resolve_target_user();

    /* 2) Validate wrapper binary (self-check) */
    validate_wrapper_suid(target_pw->pw_uid);

    /* 3) Open and validate real script */
    script_fd = open_and_validate_script(target_pw->pw_uid);

    /* 4) Hash pinning over the opened fd */
    validate_script_hash(script_fd);

    /* 5) Reset signal state */
    reset_signal_state();

    /* 6) Process hygiene */
    cleanup_process_state(script_fd);

    /* 7) Construct clean environment */
    setup_clean_environment(target_pw->pw_dir);

    /* 8) Exec bash via /proc/self/fd/<n> and forward args */
    exec_script(script_fd, argc, argv, target_pw);

    /* Should never reach here */
    die_with_error("unexpected execution path");
    return 1;
}
