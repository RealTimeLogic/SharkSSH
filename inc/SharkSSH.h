/**
 * @file SharkSSH.h
 * @brief Public API for the compact, callback-driven SharkSSH server.
 *
 * SharkSSH runs one protocol engine per connection. Applications provide the
 * host key, authentication policy, services, platform hooks, and optionally a
 * filesystem through callback tables. The same API works with standalone
 * SharkSSL and `selib`, or with BAS/BWS and `SoDisp`.
 *
 * Callback arguments described as spans are temporary counted byte strings;
 * they are not NUL terminated and must be copied if retained. Unless a
 * callback says otherwise, returning zero accepts an operation and returning
 * a nonzero value rejects or fails it.
 *
 *                 SharkSSH Embedded SSH Server
 ****************************************************************************
 *   PUBLIC API
 *
 *   Copyright (C) Real Time Logic LLC. All rights reserved.
 *
 *   This software may only be used in accordance with the applicable
 *   license agreement.
 ****************************************************************************
 */

#ifndef _SharkSSH_h
#define _SharkSSH_h

/** @defgroup SharkSshApi SharkSSH public API
 *  @brief Types and functions used to embed the SSH server.
 *  @{
 */

#include <SharkSSL.h>
#if !(SHARKSSL_USE_ECC && SHARKSSL_ECC_USE_CURVE25519 && \
      SHARKSSL_ENABLE_X25519_API)
#error SharkSSH requires the SharkSSL X25519 public API
#endif /* SharkSSL X25519 requirement */
#if SHARKSSL_BA
#include <SoDispCon.h>
#include <HttpServCon.h>
#include <HttpServer.h>
#else
#include <selib.h>
#endif /* SHARKSSL_BA */

#ifndef SHARKSSH_MAX_PACKET_LEN
/** Largest SSH packet payload retained by one connection, in bytes. */
#define SHARKSSH_MAX_PACKET_LEN       2048
#endif /* SHARKSSH_MAX_PACKET_LEN */

#ifndef SHARKSSH_MAX_KEXINIT_LEN
/** Largest peer or server key-exchange proposal retained in memory. */
#define SHARKSSH_MAX_KEXINIT_LEN      2048
#endif /* SHARKSSH_MAX_KEXINIT_LEN */

#ifndef SHARKSSH_MAX_HOST_KEY_LEN
/** Largest encoded SSH host-key blob retained during key exchange. */
#define SHARKSSH_MAX_HOST_KEY_LEN      544
#endif /* SHARKSSH_MAX_HOST_KEY_LEN */

#ifndef SHARKSSH_MAX_PATH_LEN
/** Maximum canonical client-visible filesystem path, including terminator. */
#define SHARKSSH_MAX_PATH_LEN          256
#endif /* SHARKSSH_MAX_PATH_LEN */

#ifndef SHARKSSH_MAX_AUTH_ATTEMPTS
/** Default number of failed credential attempts allowed per connection. */
#define SHARKSSH_MAX_AUTH_ATTEMPTS       3
#endif /* SHARKSSH_MAX_AUTH_ATTEMPTS */

#ifndef SHARKSSH_MAX_AUTH_REQUESTS
/** Default total number of authentication requests allowed per connection. */
#define SHARKSSH_MAX_AUTH_REQUESTS       8
#endif /* SHARKSSH_MAX_AUTH_REQUESTS */

#ifndef SHARKSSH_MAX_GLOBAL_REQUESTS
/** Default global-request limit; zero disables this lifetime limit. */
#define SHARKSSH_MAX_GLOBAL_REQUESTS     0
#endif /* SHARKSSH_MAX_GLOBAL_REQUESTS */

#ifndef SHARKSSH_DEFAULT_REKEY_BYTES
/** Default directional byte count that triggers a new key exchange. */
#define SHARKSSH_DEFAULT_REKEY_BYTES 0x40000000U
#endif /* SHARKSSH_DEFAULT_REKEY_BYTES */

#ifndef SHARKSSH_DEFAULT_KEEPALIVE_MISSES
/** Default unanswered keepalive count before a connection is closed. */
#define SHARKSSH_DEFAULT_KEEPALIVE_MISSES 3
#endif /* SHARKSSH_DEFAULT_KEEPALIVE_MISSES */

#ifndef SHARKSSH_CHANNEL_WINDOW
/** Initial receive window advertised for the single session channel. */
#define SHARKSSH_CHANNEL_WINDOW       32768
#endif /* SHARKSSH_CHANNEL_WINDOW */

#ifndef SHARKSSH_CHANNEL_PACKET_LEN
/** Largest channel-data payload SharkSSH advertises to the peer. */
#define SHARKSSH_CHANNEL_PACKET_LEN    1024
#endif /* SHARKSSH_CHANNEL_PACKET_LEN */

#if SHARKSSL_BA
#ifndef SHARKSSH_THREAD_STACK_SIZE
/** Stack size requested for each BAS/BWS connection worker. */
#define SHARKSSH_THREAD_STACK_SIZE    10000
#endif /* SHARKSSH_THREAD_STACK_SIZE */
#ifndef SHARKSSH_DEFAULT_MAX_CONNECTIONS
/** Default number of simultaneous BAS/BWS SSH connections. */
#define SHARKSSH_DEFAULT_MAX_CONNECTIONS 4
#endif /* SHARKSSH_DEFAULT_MAX_CONNECTIONS */
#endif /* SHARKSSL_BA */

/** Timeout value that tells SharkSSH to wait without a deadline. */
#define SHARKSSH_TIMEOUT_INFINITE (~((U32)0))

/** Status values returned by the core, transport, and service APIs. */
typedef enum
{
   SharkSshOk             =  0, /**< Operation completed successfully. */
   SharkSshTimeout        =  1, /**< A configured wait period expired. */
   SharkSshClosed         =  2, /**< The peer or local endpoint closed. */
   SharkSshErrArgument    = -1, /**< A required argument was invalid. */
   SharkSshErrSocket      = -2, /**< The TCP transport reported an error. */
   SharkSshErrProtocol    = -3, /**< The peer sent invalid SSH data. */
   SharkSshErrBounds      = -4, /**< A fixed buffer or resource limit was hit. */
   SharkSshErrCrypto      = -5, /**< A cryptographic operation failed. */
   SharkSshErrAuth        = -6, /**< Authentication or authorization failed. */
   SharkSshErrService     = -7, /**< The requested channel service failed. */
   SharkSshErrState       = -8  /**< The object is not in the required state. */
} SharkSshStatus;

/** A temporary counted byte string that is not NUL terminated. */
typedef struct
{
   const U8* ptr; /**< First byte, or `NULL` when @ref len is zero. */
   U32 len;       /**< Number of readable bytes at @ref ptr. */
} SharkSshSpan;

/** Severity supplied to the optional platform log callback. */
typedef enum
{
   SharkSshLogTrace,   /**< Detailed diagnostic information. */
   SharkSshLogInfo,    /**< Normal lifecycle information. */
   SharkSshLogWarning, /**< Recoverable or suspicious condition. */
   SharkSshLogError,   /**< Operation or connection failure. */
   SharkSshLogAudit    /**< Security-relevant activity. */
} SharkSshLogLevel;

/** Security and lifecycle event types delivered to the audit callback. */
typedef enum
{
   SharkSshAuditSessionStart,          /**< SSH session processing began. */
   SharkSshAuditAuthenticationFailure, /**< A credential check failed. */
   SharkSshAuditAuthenticationSuccess, /**< A user was authenticated. */
   SharkSshAuditServiceDenied,         /**< Service policy rejected a request. */
   SharkSshAuditServiceStarted,        /**< Shell, exec, or subsystem started. */
   SharkSshAuditRekey,                 /**< New transport keys became active. */
   SharkSshAuditTimeout,               /**< A configured deadline expired. */
   SharkSshAuditSessionEnd,            /**< SSH session processing ended. */
   SharkSshAuditServerStarted,         /**< Listener successfully bound. */
   SharkSshAuditServerStopped,         /**< Listener stopped accepting clients. */
   SharkSshAuditConnectionAccepted,    /**< A connection entered processing. */
   SharkSshAuditConnectionRejected,    /**< A connection could not be admitted. */
   SharkSshAuditNegotiationFailure,    /**< Algorithm negotiation failed. */
   SharkSshAuditProtocolFailure,       /**< Invalid SSH protocol data arrived. */
   SharkSshAuditResourceRejected,      /**< A configured resource limit rejected work. */
   SharkSshAuditChannelOpened,         /**< The session channel opened. */
   SharkSshAuditChannelRejected,       /**< The session channel was rejected. */
   SharkSshAuditChannelClosed,         /**< The session channel closed. */
   SharkSshAuditServiceStopped,        /**< The active service finished. */
   SharkSshAuditDisconnect             /**< An SSH disconnect was sent or received. */
} SharkSshAuditType;

/** Resource-limit reason stored in @ref SharkSshAuditEvent.reason. */
typedef enum
{
   SharkSshResourceUnspecified,           /**< No more specific reason exists. */
   SharkSshResourceConnectionLimit,       /**< Concurrent connection limit. */
   SharkSshResourceConnectionAllocation,  /**< Connection storage unavailable. */
   SharkSshResourceAuthenticationAttempts,/**< Failed credential-attempt limit. */
   SharkSshResourceAuthenticationRequests,/**< Total authentication-request limit. */
   SharkSshResourceGlobalRequests,        /**< Global-request lifetime limit. */
   SharkSshResourceChannelLimit           /**< Only one session channel is supported. */
} SharkSshResourceType;

/** Timeout reason stored in @ref SharkSshAuditEvent.reason. */
typedef enum
{
   SharkSshTimeoutIo,             /**< A socket read or write timed out. */
   SharkSshTimeoutHandshake,      /**< Version exchange or initial KEX timed out. */
   SharkSshTimeoutAuthentication, /**< User authentication timed out. */
   SharkSshTimeoutIdle,           /**< No useful session activity was observed. */
   SharkSshTimeoutSession,        /**< Maximum session lifetime elapsed. */
   SharkSshTimeoutKeepAlive       /**< Too many keepalives went unanswered. */
} SharkSshTimeoutType;

/** Action returned by @ref SharkSshPlatform.shouldCancel. */
typedef enum
{
   SharkSshCancelNone,      /**< Continue normal processing. */
   SharkSshCancelImmediate, /**< Stop as soon as the core polls cancellation. */
   SharkSshCancelGraceful   /**< Send disconnect when possible, then stop. */
} SharkSshCancelMode;

/** Bit flags passed to @ref SharkSshFileSystem.open. */
typedef enum
{
   SharkSshFsOpenRead      = 0x01, /**< Open for reading. */
   SharkSshFsOpenWrite     = 0x02, /**< Open for writing. */
   SharkSshFsOpenCreate    = 0x04, /**< Create the file when absent. */
   SharkSshFsOpenTruncate  = 0x08, /**< Replace existing contents with an empty file. */
   SharkSshFsOpenAppend    = 0x10, /**< Place writes at the current end of file. */
   SharkSshFsOpenExclusive = 0x20  /**< Atomically fail if the target already exists. */
} SharkSshFsOpenFlags;

/** Portable entry type returned by filesystem stat operations. */
typedef enum
{
   SharkSshFsTypeFile,      /**< Regular file. */
   SharkSshFsTypeDirectory, /**< Directory. */
   SharkSshFsTypeOther      /**< Unsupported or special entry type. */
} SharkSshFsType;

/** Authentication method selected for the connection. */
typedef enum
{
   SharkSshAuthNone,      /**< No user has authenticated yet. */
   SharkSshAuthPassword,  /**< Password authentication succeeded. */
   SharkSshAuthPublicKey  /**< RSA public-key authentication succeeded. */
} SharkSshAuthMethod;

/** Session-channel service requested by the SSH client. */
typedef enum
{
   SharkSshServiceShell = 1, /**< Interactive shell. */
   SharkSshServiceExec,      /**< One command supplied by the client. */
   SharkSshServiceSubsystem  /**< Named subsystem such as `sftp`. */
} SharkSshServiceType;

/** Portable result values returned by filesystem callbacks. */
typedef enum
{
   SharkSshFsOk          =  0, /**< Filesystem operation succeeded. */
   SharkSshFsEnd         =  1, /**< Directory iterator has no more entries. */
   SharkSshFsNotFound    = -20, /**< Path or handle target was not found. */
   SharkSshFsExists      = -21, /**< Exclusive create found an existing entry. */
   SharkSshFsDenied      = -22, /**< Policy or filesystem denied the operation. */
   SharkSshFsNoSpace     = -23, /**< Storage cannot accept more data. */
   SharkSshFsUnsupported = -24, /**< Adapter cannot provide this operation. */
   SharkSshFsInvalidName = -25 /**< Path cannot be represented safely. */
} SharkSshFsStatus;

/** Bit flags selecting fields changed by @ref SharkSshFileSystem.setStat. */
typedef enum
{
   SharkSshFsSetSize         = 0x01, /**< Change the 64-bit file size. */
   SharkSshFsSetPermissions  = 0x02, /**< Change portable permission bits. */
   SharkSshFsSetModifiedTime = 0x04  /**< Change the modification timestamp. */
} SharkSshFsSetFlags;

/** Portable metadata used by shell and SFTP filesystem operations. */
typedef struct
{
   U32 sizeHi;       /**< High 32 bits of the unsigned file size. */
   U32 sizeLo;       /**< Low 32 bits of the unsigned file size. */
   U32 modifiedTime; /**< Seconds since 1970-01-01 UTC, when available. */
   U16 permissions;  /**< Portable Unix-style permission bits. */
   U8 type;          /**< One of @ref SharkSshFsType. */
} SharkSshFsStat;

/**
 * @brief Generic filesystem operations used by optional SharkSSH services.
 *
 * A path is a counted UTF-8 byte string and is never assumed to be NUL
 * terminated. The application owns every returned handle and must keep this
 * table and its context valid for all sessions that use it. Callbacks run
 * synchronously in the connection task, but different connections can call a
 * shared table concurrently.
 *
 * Return @ref SharkSshFsOk on success. `readDirectory` returns
 * @ref SharkSshFsEnd after its final entry. Unsupported optional operations
 * should return @ref SharkSshFsUnsupported. Services close every successfully
 * opened handle, including during connection cleanup.
 */
typedef struct
{
   /** Application value passed unchanged to every filesystem callback. */
   void* context;

   /**
    * Open a file and return an opaque application-owned handle.
    * @param context The table's context.
    * @param path Canonical path supplied by the calling service.
    * @param flags Bitwise combination of @ref SharkSshFsOpenFlags.
    * @param file Receives the handle on success.
    * @return A @ref SharkSshFsStatus value.
    */
   int (*open)(void* context, SharkSshSpan path, U8 flags, void** file);

   /** Close a file handle returned by @ref open. */
   int (*close)(void* context, void* file);

   /**
    * Read up to `capacity` bytes at the handle's current position.
    * @param size Receives the number of bytes read; zero means end of file.
    */
   int (*read)(void* context, void* file, U8* data, U32 capacity,
               U32* size);

   /**
    * Write bytes at the handle's current position.
    * @param written Receives the number of bytes accepted; partial writes are
    *        valid and will be retried by the caller.
    */
   int (*write)(void* context, void* file, const U8* data, U32 size,
                U32* written);

   /** Set the current position to the supplied unsigned 64-bit offset. */
   int (*seek)(void* context, void* file, U32 offsetHi, U32 offsetLo);

   /** Read metadata for a path into `stat`. */
   int (*stat)(void* context, SharkSshSpan path, SharkSshFsStat* stat);

   /** Remove a non-directory entry. */
   int (*remove)(void* context, SharkSshSpan path);

   /** Rename or move an entry without escaping the adapter's root. */
   int (*rename)(void* context, SharkSshSpan oldPath,
                 SharkSshSpan newPath);

   /** Create a directory with the requested portable permission bits. */
   int (*makeDirectory)(void* context, SharkSshSpan path,
                        U16 permissions);

   /** Remove an empty directory. */
   int (*removeDirectory)(void* context, SharkSshSpan path);

   /** Open a directory and return an opaque iterator handle. */
   int (*openDirectory)(void* context, SharkSshSpan path,
                        void** directory);

   /**
    * Return the next directory entry.
    * @param name Receives a non-NUL-terminated entry name.
    * @param capacity Available bytes in `name`.
    * @param size Receives the entry-name length.
    * @param stat Receives metadata for the same entry.
    * @return @ref SharkSshFsOk, @ref SharkSshFsEnd, or an error status.
    */
   int (*readDirectory)(void* context, void* directory, U8* name,
                        U16 capacity, U16* size, SharkSshFsStat* stat);

   /** Close a directory handle returned by @ref openDirectory. */
   int (*closeDirectory)(void* context, void* directory);

   /** Change the metadata fields selected by @ref SharkSshFsSetFlags. */
   int (*setStat)(void* context, SharkSshSpan path,
                  const SharkSshFsStat* stat, U8 flags);
} SharkSshFileSystem;

/** Opaque per-connection protocol object; applications provide its storage. */
typedef struct SharkSshCon SharkSshCon;
/** Session-channel object passed to service callbacks and channel APIs. */
typedef struct SharkSshChannel SharkSshChannel;
/** Transport listener and connection-admission owner. */
typedef struct SharkSshServer SharkSshServer;

/**
 * Snapshot passed to abuse-control callbacks for one authentication request.
 * All spans are read-only and valid only until the callback returns.
 */
typedef struct
{
   SharkSshSpan user;   /**< Username offered by the client. */
   U8 authMethod;       /**< Requested @ref SharkSshAuthMethod. */
   U8 requestCount;     /**< Total authentication requests seen so far. */
   U8 failedAttempts;   /**< Credential attempts that have failed so far. */
   U8 publicKeyProbe;   /**< Nonzero for an unsigned public-key query. */
} SharkSshAuthenticationAttempt;

/**
 * Optional connection and authentication throttling policy.
 *
 * These callbacks run synchronously in the connection task. Shared state must
 * be protected by the application when multiple clients are possible.
 */
typedef struct
{
   void* context; /**< Application value passed to each callback. */

   /** Admit a newly accepted connection; return zero to continue. */
   int (*admit)(void* context, SharkSshCon* connection);

   /**
    * Apply rate limits before credential verification.
    * Set `delay` to a requested delay in milliseconds. Returning nonzero
    * rejects this authentication request without checking credentials.
    */
   int (*authentication)(void* context, SharkSshCon* connection,
                         const SharkSshAuthenticationAttempt* attempt,
                         U32* delay);

   /** Observe the final status of a credential or public-key probe request. */
   void (*authenticationResult)(
      void* context, SharkSshCon* connection,
      const SharkSshAuthenticationAttempt* attempt, int status);

   /** Release state created by `admit`; called only after successful admit. */
   void (*release)(void* context, SharkSshCon* connection);
} SharkSshAbuseControl;

#if SHARKSSL_BA
/** Optional allocation boundary for BAS/BWS connection workers. */
typedef struct
{
   void* context; /**< Application allocator or fixed-pool context. */

   /** Return suitably aligned storage for `size` bytes, or `NULL`. */
   void* (*allocate)(void* context, U32 size);

   /** Release connection storage after transport and worker teardown. */
   void (*release)(void* context, void* memory);
} SharkSshConnectionAllocator;
#endif /* SHARKSSL_BA */

/**
 * @brief Server host-key operations.
 *
 * Host keys are callback based so a TPM or secure element can sign without
 * exporting its private key. publicKey writes an RFC 4253 public-key blob.
 * signHash signs a precomputed SHA-256 digest and writes the raw RSA
 * signature bytes for rsa-sha2-256.
 */
typedef struct
{
   void* context; /**< Software key, secure-element, or application context. */

   /** Encode the RSA public key as an RFC 4253 SSH key blob. */
   int (*publicKey)(void* context, U8* data, U16 capacity, U16* size);

   /** Sign a 32-byte SHA-256 exchange hash using RSA/SHA-256. */
   int (*signHash)(void* context, const U8 hash[32], U8* signature,
                   U16 capacity, U16* size);
} SharkSshHostKey;

/** Credential verification callbacks offered during SSH user authentication. */
typedef struct
{
   void* context; /**< Account database or application authentication context. */

   /** Verify a username and password; return zero only for a valid pair. */
   int (*password)(void* context, SharkSshSpan user,
                   SharkSshSpan password);

   /**
    * Authorize an offered `rsa-sha2-256` user key.
    *
    * On success, `verificationKey` receives an application-owned SharkSSL RSA
    * key matching `keyBlob`. SharkSSH checks the match and verifies the
    * client's signature. The callback retains ownership of the returned key.
    * `fingerprint` contains 32 raw SHA-256 bytes.
    */
   int (*publicKey)(void* context, SharkSshSpan user,
                    SharkSshSpan algorithm, SharkSshSpan keyBlob,
                    const U8 fingerprint[32],
                    SharkSslRSAKey* verificationKey);
} SharkSshAuthenticator;

/** Request passed to the service-authorization callback after login. */
typedef struct
{
   SharkSshSpan user; /**< Authenticated username. */
   SharkSshSpan publicKeyFingerprint; /**< Empty for password login. */
   SharkSshSpan request; /**< Command, subsystem name, or empty for shell. */
   U8 authMethod;  /**< Successful @ref SharkSshAuthMethod. */
   U8 serviceType; /**< Requested @ref SharkSshServiceType. */
} SharkSshAuthorization;

/**
 * Security event delivered synchronously to @ref SharkSshPlatform.audit.
 * All spans and the event itself are read-only and callback-lifetime only.
 */
typedef struct
{
   SharkSshCon* connection; /**< Connection, or `NULL` for server events. */
   SharkSshSpan user; /**< Relevant authenticated or offered username. */
   SharkSshSpan publicKeyFingerprint; /**< Raw SHA-256 user-key fingerprint. */
   SharkSshSpan request; /**< Command or subsystem for service events. */
   U32 bytesReceived; /**< SSH transport bytes received by this connection. */
   U32 bytesSent; /**< SSH transport bytes sent by this connection. */
   U32 value; /**< Port, disconnect reason, or service exit status. */
   int status; /**< SharkSSH result associated with the event. */
   U8 type; /**< One of @ref SharkSshAuditType. */
   U8 authMethod; /**< @ref SharkSshAuthMethod, or zero when not applicable. */
   U8 serviceType; /**< @ref SharkSshServiceType, or zero when not applicable. */
   U8 reason; /**< Timeout or resource type when applicable. */
   U8 hasValue; /**< Nonzero when @ref value is meaningful. */
} SharkSshAuditEvent;

/**
 * Application implementation of shell, exec, and subsystem channels.
 *
 * The core calls these functions synchronously from the connection task. A
 * channel supports one active service. `open` creates per-channel state before
 * a service starts, and `close` must release that state after any exit path.
 */
typedef struct
{
   void* context; /**< Service registry or application context. */

   /** Authorize a shell, command, or subsystem after authentication. */
   int (*authorize)(void* context, SharkSshChannel* channel,
                    const SharkSshAuthorization* request);

   /** Prepare application state for a newly opened session channel. */
   int (*open)(void* context, SharkSshChannel* channel,
               SharkSshSpan user);

   /** Release per-channel state; safe after partial service startup. */
   void (*close)(void* context, SharkSshChannel* channel);

   /** Accept and apply a client's PTY request and terminal modes. */
   int (*pty)(void* context, SharkSshChannel* channel,
              SharkSshSpan terminal, U32 columns, U32 rows,
              U32 width, U32 height, SharkSshSpan modes);

   /** Apply a PTY window-size change to the active service. */
   int (*windowChange)(void* context, SharkSshChannel* channel,
                       U32 columns, U32 rows, U32 width, U32 height);

   /** Start an interactive shell on an authorized channel. */
   int (*shell)(void* context, SharkSshChannel* channel);

   /** Start one authorized command supplied as a counted span. */
   int (*exec)(void* context, SharkSshChannel* channel,
               SharkSshSpan command);

   /** Start a named subsystem, commonly `sftp`. */
   int (*subsystem)(void* context, SharkSshChannel* channel,
                    SharkSshSpan name,
                    const SharkSshFileSystem* fileSystem);

   /** Deliver channel data to the active service. */
   int (*data)(void* context, SharkSshChannel* channel, SharkSshSpan data);

   /** Notify the service that the peer will send no more channel data. */
   int (*eof)(void* context, SharkSshChannel* channel);

   /** Resume service output after peer channel-window credit becomes available. */
   int (*writable)(void* context, SharkSshChannel* channel);
} SharkSshServices;

/** Optional RTOS/platform integration callbacks used by the core. */
typedef struct
{
   void* context; /**< Platform or application context passed to every hook. */

   /** Receive a transient, human-readable diagnostic message. */
   void (*log)(void* context, SharkSshLogLevel level, const char* message);

   /** Receive a transient structured security event. */
   void (*audit)(void* context, const SharkSshAuditEvent* event);

   /** Return monotonic milliseconds; unsigned 32-bit wrap is supported. */
   U32 (*now)(void* context);

   /** Return a @ref SharkSshCancelMode when the core polls cancellation. */
   int (*shouldCancel)(void* context);

   /** Yield to other RTOS work during long but progress-making operations. */
   void (*cooperate)(void* context);

   /** Delay the connection task for the requested milliseconds. */
   void (*delay)(void* context, U32 milliseconds);
} SharkSshPlatform;

/**
 * Complete, persistent configuration shared by a server and its connections.
 *
 * Call @ref SharkSshConfig_constructor first, then replace the desired
 * callbacks and limits. This object and every referenced context must remain
 * valid until the listener and all connections have finished.
 */
typedef struct
{
   SharkSshHostKey hostKey; /**< Required server identity and signing callbacks. */
   SharkSshAuthenticator authenticator; /**< Password and/or user-key verifier. */
   SharkSshServices services; /**< Application channel-service callbacks. */
   SharkSshPlatform platform; /**< Optional clock, audit, logging, and RTOS hooks. */
   SharkSshAbuseControl abuse; /**< Optional admission and throttling policy. */
   const SharkSshFileSystem* fileSystem; /**< Optional service filesystem. */
   U32 ioTimeout; /**< Per-socket I/O timeout in milliseconds, or infinite. */
   U32 handshakeTimeout; /**< Version and initial-KEX deadline in milliseconds. */
   U32 authenticationTimeout; /**< Login-phase deadline in milliseconds. */
   U32 idleTimeout; /**< Inactivity deadline; zero disables it. */
   U32 sessionTimeout; /**< Total connection lifetime; zero disables it. */
   U32 rekeyBytes; /**< Directional byte threshold; zero disables byte rekeying. */
   U32 rekeyTime; /**< Millisecond rekey interval; zero disables time rekeying. */
   U32 rekeyPackets; /**< Directional packet threshold; zero disables it. */
   U32 keepAliveInterval; /**< Idle milliseconds between keepalive probes. */
   U32 cancelPollInterval; /**< Maximum wait between cancellation polls. */
   U8 maxAuthAttempts; /**< Failed credential attempts allowed. */
   U8 maxAuthRequests; /**< Total authentication requests allowed. */
   U8 maxGlobalRequests; /**< Lifetime global-request limit; zero disables it. */
   U8 keepAliveMaxMissed; /**< Unanswered keepalives allowed before closing. */
} SharkSshConfig;

/** High-level phase of one SSH connection. */
typedef enum
{
   SharkSshStateNew,            /**< Constructed but not started. */
   SharkSshStateVersion,        /**< Exchanging SSH identification strings. */
   SharkSshStateKeyExchange,    /**< Negotiating and deriving transport keys. */
   SharkSshStateAuthentication, /**< Authenticating the client user. */
   SharkSshStateConnection,     /**< Processing the authenticated channel. */
   SharkSshStateClosed          /**< Processing has ended. */
} SharkSshState;

/**
 * One SSH session channel.
 *
 * Service callbacks may store per-session state only in @ref userData. Other
 * fields are readable protocol state and must not be modified by applications.
 */
struct SharkSshChannel
{
   SharkSshCon* connection; /**< Owning connection. */
   void* userData; /**< Application-owned per-session state. */
   U32 localId; /**< Server-side SSH channel number. */
   U32 remoteId; /**< Client-side SSH channel number. */
   U32 localWindow; /**< Receive credit still available to the peer. */
   U32 remoteWindow; /**< Send credit currently granted by the peer. */
   U32 remotePacketLen; /**< Largest channel packet accepted by the peer. */
   U32 exitStatus; /**< Service exit status selected by the application. */
   U8 open; /**< Nonzero after the channel-open handshake succeeds. */
   U8 serviceType; /**< Zero or a @ref SharkSshServiceType value. */
   U8 remoteEof; /**< Nonzero after receiving peer EOF. */
   U8 localEof; /**< Nonzero after sending local EOF. */
   U8 closeSent; /**< Nonzero after sending channel close. */
   U8 closeNotified; /**< Internal guard for one close callback. */
   U8 exitStatusSent; /**< Nonzero after sending an exit-status request. */
};

/**
 * @brief Fixed-size protocol state for one SSH connection.
 *
 * One task owns an instance and all
 * callbacks run synchronously in that task. Barracuda listeners allocate an
 * instance for each accepted connection; standalone applications provide it.
 * No internal lock is held when an application callback is called.
 * Applications should treat every field except `abuseData` and
 * `channel.userData` as read-only internal state.
 */
struct SharkSshCon
{
#if SHARKSSL_BA
   Thread thread; /**< Internal worker; first for the callback downcast. */
#endif /* SHARKSSL_BA */
   const SharkSshConfig* config; /**< Persistent configuration, not owned. */
   void* abuseData; /**< Application state for abuse-control callbacks. */
#if SHARKSSL_BA
   SoDispCon socket; /**< Moved BAS/BWS connection socket. */
   SharkSshServer* server; /**< Server that owns admission counters. */
#else
   SOCKET socket; /**< Standalone selib connection socket. */
#endif /* SHARKSSL_BA */
   SharkSshChannel channel; /**< The connection's single session channel. */
   SharkSshState state; /**< Current high-level protocol phase. */

   U32 receiveSequence; /**< Internal inbound SSH packet sequence. */
   U32 sendSequence; /**< Internal outbound SSH packet sequence. */
   U32 bytesReceived; /**< Encrypted transport bytes received. */
   U32 bytesSent; /**< Encrypted transport bytes sent. */
   U32 startedAt; /**< Monotonic start time. */
   U32 phaseStartedAt; /**< Monotonic start time of the current phase. */
   U32 lastActivityAt; /**< Monotonic time of last useful activity. */
   U32 rekeyReceivedAt; /**< Inbound byte count at the last completed KEX. */
   U32 rekeySentAt; /**< Outbound byte count at the last completed KEX. */
   U32 packetsReceived; /**< Total inbound SSH packets. */
   U32 packetsSent; /**< Total outbound SSH packets. */
   U32 rekeyPacketsReceivedAt; /**< Inbound packet count at the last KEX. */
   U32 rekeyPacketsSentAt; /**< Outbound packet count at the last KEX. */
   U32 rekeyStartedAt; /**< Monotonic time at the last completed KEX. */
   U32 keepAliveAt; /**< Monotonic time used to schedule keepalives. */

   U16 clientKexSize; /**< Bytes retained from the client's KEXINIT. */
   U16 serverKexSize; /**< Bytes retained from the server's KEXINIT. */
   U16 hostKeySize; /**< Bytes in the encoded server public key. */
   U16 clientVersionSize; /**< Length of the client identification string. */
   U16 serverVersionSize; /**< Length of the server identification string. */
   U8 encryptedInput; /**< Nonzero after inbound keys become active. */
   U8 encryptedOutput; /**< Nonzero after outbound keys become active. */
   U8 authenticated; /**< Nonzero after successful user authentication. */
   U8 authAttempts; /**< Failed credential-attempt counter. */
   U8 authRequests; /**< Total authentication-request counter. */
   U8 globalRequests; /**< Global-request counter. */
   U8 authMethod; /**< Successful @ref SharkSshAuthMethod. */
   U8 initialKexDone; /**< Nonzero after initial key exchange completes. */
   U8 strictKex; /**< Nonzero when strict key-exchange rules apply. */
   U8 timeoutReason; /**< Pending @ref SharkSshTimeoutType. */
   U8 keepAliveOutstanding; /**< Unanswered keepalive count. */
   U8 cancelMode; /**< Current @ref SharkSshCancelMode. */
   U8 sendingDisconnect; /**< Prevents recursive disconnect handling. */
   U8 abuseAdmitted; /**< Tracks whether abuse `release` is required. */
   U8 resourceAudited; /**< Prevents duplicate resource audit events. */

   SharkSslAesCtx receiveAes; /**< Internal inbound AES-CTR state. */
   SharkSslAesCtx sendAes; /**< Internal outbound AES-CTR state. */
   U8 receiveCounter[16]; /**< Inbound AES-CTR counter. */
   U8 sendCounter[16]; /**< Outbound AES-CTR counter. */
   U8 receiveMacKey[32]; /**< Inbound HMAC-SHA-256 key. */
   U8 sendMacKey[32]; /**< Outbound HMAC-SHA-256 key. */
   U8 sessionId[32]; /**< Stable SSH session identifier. */
   U8 publicKeyFingerprint[32]; /**< Authenticated user-key fingerprint. */
   U8 user[64]; /**< Authenticated username bytes. */
   U8 userSize; /**< Number of valid bytes in @ref user. */

   U8 input[SHARKSSH_MAX_PACKET_LEN + 64]; /**< Fixed inbound packet workspace. */
   U8 output[SHARKSSH_MAX_PACKET_LEN + 64]; /**< Fixed outbound packet workspace. */
   U8 clientKex[SHARKSSH_MAX_KEXINIT_LEN]; /**< Retained client KEXINIT payload. */
   U8 serverKex[SHARKSSH_MAX_KEXINIT_LEN]; /**< Retained server KEXINIT payload. */
   U8 hostKey[SHARKSSH_MAX_HOST_KEY_LEN]; /**< Encoded host-key workspace. */
   char clientVersion[256]; /**< Client identification line. */
   char serverVersion[64]; /**< Server identification line. */
};

/**
 * Listener object for standalone selib or BAS/BWS SoDisp integration.
 * Construct, bind, stop, and destroy it through the public functions below.
 */
struct SharkSshServer
{
#if SHARKSSL_BA
   HttpServCon listener; /**< Internal listener; first for callback downcast. */
   HttpServer* httpServer; /**< Application-owned BAS/BWS server. */
   SoDisp* dispatcher; /**< Dispatcher obtained from @ref httpServer. */
   SharkSshConnectionAllocator allocator; /**< Optional worker allocator. */
   volatile U32 activeConnections; /**< Currently running workers. */
   volatile U32 completedConnections; /**< Workers that have finished. */
   volatile U32 rejectedConnections; /**< Connections rejected before a worker. */
   volatile U32 peakConnections; /**< Highest observed active count. */
   U16 maxConnections; /**< Configured concurrent worker limit. */
#else
   SOCKET socket; /**< Standalone listening socket. */
#endif /* SHARKSSL_BA */
   const SharkSshConfig* config; /**< Persistent configuration, not owned. */
   U16 port; /**< Bound TCP port. */
   U8 listening; /**< Nonzero while accepting new clients. */
};

/** Software RSA adapter that implements @ref SharkSshHostKey with SharkSSL. */
typedef struct
{
   SharkSslRSAKey privateKey; /**< Application-owned SharkSSL private key. */
} SharkSshRsaHostKey;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Initialize a configuration with conservative embedded-server defaults.
 *
 * The function clears every callback table, selects an infinite socket I/O
 * wait, and installs the documented default authentication, keepalive, and
 * rekey limits. Fill in the required host-key, authentication, and service
 * callbacks after this call. Passing `NULL` has no effect.
 *
 * @param config Application-owned configuration to initialize.
 */
void SharkSshConfig_constructor(SharkSshConfig* config);

#if SHARKSSL_BA
/**
 * Initialize a BAS/BWS listener that uses an existing socket dispatcher.
 *
 * The function does not create, start, or own `httpServer`. The HTTP server,
 * its dispatcher, `config`, and every context referenced by `config` must
 * outlive this object and all accepted SSH connections.
 *
 * @param server Application-owned listener storage.
 * @param config Persistent SSH configuration.
 * @param httpServer Existing, initialized BAS/BWS HTTP server.
 */
void SharkSshServer_constructor(SharkSshServer* server,
                                const SharkSshConfig* config,
                                HttpServer* httpServer);
/**
 * Select how BAS/BWS connection workers are allocated and released.
 *
 * SharkSSH copies the callback table. Both callbacks must be present. Call
 * this before binding and while no SSH connections are active. Passing
 * `NULL` restores the built-in allocator.
 *
 * @param server Constructed server that is not listening.
 * @param allocator Allocator to copy, or `NULL` for the default allocator.
 * @return @ref SharkSshOk, or a negative @ref SharkSshStatus value.
 */
int SharkSshServer_setConnectionAllocator(
   SharkSshServer* server, const SharkSshConnectionAllocator* allocator);
/**
 * Set the BAS/BWS concurrent-connection admission limit.
 *
 * @param server Constructed server that is not listening or active.
 * @param maxConnections Nonzero maximum number of connection workers.
 * @return @ref SharkSshOk, or a negative @ref SharkSshStatus value.
 */
int SharkSshServer_setMaxConnections(SharkSshServer* server,
                                     U16 maxConnections);
/**
 * Read the current number of SSH connection workers.
 * @param server Constructed BAS/BWS SSH server.
 * @return The number of SSH connections currently being processed.
 */
U32 SharkSshServer_activeConnections(SharkSshServer* server);
/**
 * Read the completed-connection counter.
 * @param server Constructed BAS/BWS SSH server.
 * @return The cumulative number of admitted connections that finished.
 */
U32 SharkSshServer_completedConnections(SharkSshServer* server);
/**
 * Read the rejected-connection counter.
 * @param server Constructed BAS/BWS SSH server.
 * @return The cumulative number of connections rejected before admission.
 */
U32 SharkSshServer_rejectedConnections(SharkSshServer* server);
/**
 * Read the peak connection-worker count.
 * @param server Constructed BAS/BWS SSH server.
 * @return The highest simultaneous active-connection count observed.
 */
U32 SharkSshServer_peakConnections(SharkSshServer* server);
#else
/**
 * Initialize a standalone listener that uses SharkSSL `selib` sockets.
 *
 * The function constructs the listening socket but does not bind it. `config`,
 * `socketContext`, and every referenced callback context must remain valid
 * through server destruction.
 *
 * @param server Application-owned listener storage.
 * @param config Persistent SSH configuration.
 * @param socketContext Initialized `selib` platform context.
 */
void SharkSshServer_constructor(SharkSshServer* server,
                                const SharkSshConfig* config,
                                SeCtx* socketContext);
#endif /* SHARKSSL_BA */
/**
 * Bind the listener and start accepting SSH clients on a TCP port.
 *
 * @param server Constructed listener that is not already listening.
 * @param port Host-order TCP port, normally 22.
 * @return @ref SharkSshOk, or a negative @ref SharkSshStatus value.
 */
int SharkSshServer_bind(SharkSshServer* server, U16 port);
/**
 * Stop accepting new clients without canceling established sessions.
 *
 * Calling this function more than once is safe.
 *
 * @param server Constructed listener to stop.
 */
void SharkSshServer_stop(SharkSshServer* server);
#if ! SHARKSSL_BA
/**
 * Wait for and attach one standalone client connection.
 *
 * On success, the caller gives `connection` to exactly one task, calls
 * @ref SharkSshCon_run, and then calls @ref SharkSshCon_destructor. A timeout
 * leaves the listener ready for another call.
 *
 * @param server Listening standalone server.
 * @param connection Application-owned connection storage to initialize.
 * @param socketContext Initialized `selib` context used by the connection.
 * @param timeout Maximum wait in milliseconds, or
 *        @ref SHARKSSH_TIMEOUT_INFINITE.
 * @return @ref SharkSshOk, @ref SharkSshTimeout, or a negative status.
 */
int SharkSshServer_accept(SharkSshServer* server, SharkSshCon* connection,
                          SeCtx* socketContext, U32 timeout);
#endif /* !SHARKSSL_BA */
/**
 * Release listener transport resources.
 *
 * The function stops the listener first. In BAS/BWS mode all connection
 * workers must have finished before destruction.
 *
 * @param server Constructed server to destroy.
 */
void SharkSshServer_destructor(SharkSshServer* server);

#if SHARKSSL_BA
/**
 * Initialize BAS/BWS connection storage.
 *
 * Applications normally let @ref SharkSshServer manage these objects.
 *
 * @param connection Connection storage to initialize.
 * @param config Persistent configuration used by the connection.
 */
void SharkSshCon_constructor(SharkSshCon* connection,
                             const SharkSshConfig* config);
#else
/**
 * Initialize standalone connection storage and its `selib` socket.
 *
 * @param connection Application-owned connection storage.
 * @param config Persistent configuration used by the connection.
 * @param socketContext Initialized `selib` platform context.
 */
void SharkSshCon_constructor(SharkSshCon* connection,
                             const SharkSshConfig* config,
                             SeCtx* socketContext);
#endif /* SHARKSSL_BA */
/**
 * Run one SSH connection synchronously until it ends.
 *
 * Exactly one task may own a connection while this function is running. The
 * function returns after peer close, local cancellation, timeout, or error.
 * Always follow it with @ref SharkSshCon_destructor.
 *
 * @param connection Constructed connection with an attached client socket.
 * @return @ref SharkSshClosed, @ref SharkSshTimeout, or another status that
 *         explains why processing stopped.
 */
int SharkSshCon_run(SharkSshCon* connection);
/**
 * Close a connection and erase its transient protocol and secret storage.
 *
 * The active service receives its `close` callback when necessary. Reuse the
 * object only after calling the matching constructor again.
 *
 * @param connection Constructed connection to destroy.
 */
void SharkSshCon_destructor(SharkSshCon* connection);

/**
 * Send an entire standard-output buffer through a session channel.
 *
 * This all-or-nothing helper returns @ref SharkSshTimeout without sending when
 * the peer's current channel window cannot hold the complete buffer. Use
 * @ref SharkSshChannel_writeSome for resumable output.
 *
 * @param channel Open channel supplied to a service callback.
 * @param data Bytes to send; may be `NULL` only when `size` is zero.
 * @param size Number of bytes to send.
 * @return @ref SharkSshOk, @ref SharkSshTimeout, or a negative status.
 */
int SharkSshChannel_write(SharkSshChannel* channel,
                          const void* data, U32 size);
/**
 * Send an entire standard-error buffer through a session channel.
 *
 * Ownership and all-or-nothing behavior match @ref SharkSshChannel_write.
 *
 * @param channel Open channel supplied to a service callback.
 * @param data Bytes to send; may be `NULL` only when `size` is zero.
 * @param size Number of bytes to send.
 * @return @ref SharkSshOk, @ref SharkSshTimeout, or a negative status.
 */
int SharkSshChannel_writeError(SharkSshChannel* channel,
                               const void* data, U32 size);
/**
 * Send as much standard output as the peer's window currently permits.
 *
 * Retain only the unsent suffix when this returns @ref SharkSshTimeout, then
 * continue from the service `writable` callback. Never resend the reported
 * prefix.
 *
 * @param channel Open channel supplied to a service callback.
 * @param data Bytes to send; may be `NULL` only when `size` is zero.
 * @param size Number of available bytes.
 * @param written Receives the exact number of bytes accepted.
 * @return @ref SharkSshOk when all bytes were sent, @ref SharkSshTimeout when
 *         bytes remain, or a negative status.
 */
int SharkSshChannel_writeSome(SharkSshChannel* channel,
                              const void* data, U32 size, U32* written);
/**
 * Resumable standard-error form of @ref SharkSshChannel_writeSome.
 *
 * Standard output and standard error consume the same peer channel window.
 *
 * @param channel Open channel supplied to a service callback.
 * @param data Bytes to send; may be `NULL` only when `size` is zero.
 * @param size Number of available bytes.
 * @param written Receives the exact number of bytes accepted.
 * @return @ref SharkSshOk when all bytes were sent, @ref SharkSshTimeout when
 *         bytes remain, or a negative status.
 */
int SharkSshChannel_writeErrorSome(SharkSshChannel* channel,
                                   const void* data, U32 size,
                                   U32* written);
/**
 * Send a process-style exit status for the active service.
 *
 * An exec service normally calls this once after producing all output.
 *
 * @param channel Open channel with an accepted service.
 * @param status Application-selected process exit status.
 * @return @ref SharkSshOk, or @ref SharkSshErrState for an invalid phase.
 */
int SharkSshChannel_sendExitStatus(SharkSshChannel* channel, U32 status);
/**
 * Tell the peer that the service will send no more channel data.
 *
 * Repeated calls after a successful send are harmless. The channel remains
 * open so the peer can finish its side of the exchange.
 *
 * @param channel Open channel to half-close.
 * @return @ref SharkSshOk, or a negative @ref SharkSshStatus value.
 */
int SharkSshChannel_sendEof(SharkSshChannel* channel);
/**
 * Send end-of-file and request an orderly channel close.
 *
 * The connection loop continues until the peer acknowledges the close or
 * connection teardown cancels the wait. Do not send more output afterward.
 * Repeated calls after a successful send are harmless.
 *
 * @param channel Open channel to close.
 * @return @ref SharkSshOk, or a negative @ref SharkSshStatus value.
 */
int SharkSshChannel_close(SharkSshChannel* channel);

/**
 * Associate a SharkSSL software RSA private key with a host-key adapter.
 *
 * The key remains application-owned and must outlive all listeners and
 * connections that use the adapter.
 *
 * @param hostKey Application-owned adapter to initialize.
 * @param privateKey Parsed SharkSSL RSA private key.
 */
void SharkSshRsaHostKey_constructor(SharkSshRsaHostKey* hostKey,
                                    SharkSslRSAKey privateKey);
/**
 * Install the RSA adapter in a generic host-key callback table.
 *
 * @param target Table to populate, commonly `&config.hostKey`.
 * @param hostKey Initialized adapter that outlives every use of `target`.
 */
void SharkSshRsaHostKey_set(SharkSshHostKey* target,
                            SharkSshRsaHostKey* hostKey);
/**
 * Calculate the raw SHA-256 fingerprint of an SSH host public key.
 *
 * The application may encode the 32-byte result as Base64 or hexadecimal for
 * a commissioning display.
 *
 * @param hostKey Initialized host-key callback table.
 * @param fingerprint Receives exactly 32 raw SHA-256 bytes.
 * @return @ref SharkSshOk, or a negative @ref SharkSshStatus value.
 */
int SharkSshHostKey_fingerprint(const SharkSshHostKey* hostKey,
                                U8 fingerprint[32]);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */

#endif /* _SharkSSH_h */
