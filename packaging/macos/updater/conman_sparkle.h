#ifndef CONMAN_SPARKLE_H
#define CONMAN_SPARKLE_H

/*
 * C ABI for ConMan's macOS Sparkle adapter.
 *
 * The event strings are borrowed for the duration of the callback only.  The
 * Rust consumer must copy them before returning from the callback.  Error
 * strings are written to caller-owned storage and are always NUL terminated
 * when message_capacity is non-zero.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ConManSparkle ConManSparkle;

typedef enum ConManSparkleChannel {
    CONMAN_SPARKLE_CHANNEL_STABLE = 0,
    CONMAN_SPARKLE_CHANNEL_DEV = 1,
} ConManSparkleChannel;

typedef enum ConManSparkleEventKind {
    CONMAN_SPARKLE_CHECK_STARTED = 1,
    CONMAN_SPARKLE_CANDIDATE_FOUND = 2,
    CONMAN_SPARKLE_NO_CANDIDATE = 3,
    CONMAN_SPARKLE_DOWNLOAD_STARTED = 4,
    CONMAN_SPARKLE_DOWNLOAD_PROGRESS = 5,
    CONMAN_SPARKLE_PREPARING = 6,
    CONMAN_SPARKLE_READY_TO_INSTALL = 7,
    CONMAN_SPARKLE_CANCELLED = 8,
    CONMAN_SPARKLE_FAILED = 9,
    CONMAN_SPARKLE_INSTALL_STARTED = 10,
    CONMAN_SPARKLE_OPEN_RELEASE_PAGE = 11,
} ConManSparkleEventKind;

typedef struct ConManSparkleConfig {
    uint32_t channel;
    uint8_t automatic_download;
    uint8_t reserved[3];
} ConManSparkleConfig;

typedef struct ConManSparkleEvent {
    uint64_t generation;
    uint32_t kind;
    uint8_t manual;
    uint8_t reserved[3];
    uint64_t received;
    uint64_t total;
    uint64_t revision;
    uint64_t staging_token;
    const char *version;
    const char *display_version;
    const char *release_notes_url;
    const char *info_url;
    uint32_t error_code;
    const char *error_message;
} ConManSparkleEvent;

typedef struct ConManSparkleError {
    uint32_t code;
    char *message;
    size_t message_capacity;
    size_t message_length;
} ConManSparkleError;

typedef void (*ConManSparkleEventFn)(void *context,
                                     const ConManSparkleEvent *event);

ConManSparkle *conman_sparkle_create(const ConManSparkleConfig *config,
                                     ConManSparkleEventFn callback,
                                     void *context,
                                     ConManSparkleError *error);
bool conman_sparkle_start(ConManSparkle *, ConManSparkleError *error);
bool conman_sparkle_set_channel(ConManSparkle *, uint32_t channel,
                                ConManSparkleError *error);
bool conman_sparkle_set_automatic_download(ConManSparkle *, bool enabled,
                                           ConManSparkleError *error);
bool conman_sparkle_check(ConManSparkle *, bool manual,
                          ConManSparkleError *error);
bool conman_sparkle_cancel(ConManSparkle *, ConManSparkleError *error);
bool conman_sparkle_install_and_relaunch(ConManSparkle *,
                                         ConManSparkleError *error);
void conman_sparkle_destroy(ConManSparkle *);

#ifdef __cplusplus
}
#endif

#endif /* CONMAN_SPARKLE_H */
