/*
 *                 SharkSSH Embedded SSH Server
 ****************************************************************************
 *   MINIMAL SSH-2 SERVER
 *
 *   One suite: curve25519-sha256, rsa-sha2-256, aes128-ctr,
 *   hmac-sha2-256, no compression. One session channel per connection.
 ****************************************************************************
 */

#include "SharkSshPriv.h"
#if SHARKSSL_BA
#include <BaErrorCodes.h>
#endif

#define SHARKSSH_VERSION "SSH-2.0-SharkSSH_0.1"
#define SHARKSSH_CHANNEL_COMPLETE 3
#define SHARKSSH_MAINTENANCE 4
#define SHARKSSH_TIMEOUT_WAKEUP 0xFF

static const char kexAlgorithm[] = "curve25519-sha256";
static const char kexAlgorithms[] =
   "curve25519-sha256,ext-info-s,kex-strict-s,"
   "kex-strict-s-v00@openssh.com";
static const char hostKeyAlgorithm[] = "rsa-sha2-256";
static const char cipherAlgorithm[] = "aes128-ctr";
static const char macAlgorithm[] = "hmac-sha2-256";
static const char noCompression[] = "none";
static const char extInfoClient[] = "ext-info-c";
static const char strictKexClient[] = "kex-strict-c";
static const char strictKexClientV00[] =
   "kex-strict-c-v00@openssh.com";
static const char publicKeyAlgorithm[] = "rsa-sha2-256";
static const char publicKeyBlobAlgorithm[] = "ssh-rsa";

typedef struct
{
   U8 strictKex;
   U8 sendExtInfo;
   U8 ignoreNextPacket;
} SharkSshKexOptions;

static int sharkSshHandleTransportMessage(SharkSshCon* connection,
                                           U8 message,
                                           SharkSshReader* reader);
static int sharkSshHandleConnectionPacket(SharkSshCon* connection,
                                          U8* payload, U32 payloadSize);

static void
sharkSshZero(void* data, U32 size)
{
   volatile U8* ptr = (volatile U8*)data;
   while(size--)
      *ptr++ = 0;
}

static U32
sharkSshReadU32(const U8* data)
{
   return ((U32)data[0] << 24) | ((U32)data[1] << 16) |
          ((U32)data[2] << 8) | data[3];
}

static void
sharkSshWriteU32(U8* data, U32 value)
{
   data[0] = (U8)(value >> 24);
   data[1] = (U8)(value >> 16);
   data[2] = (U8)(value >> 8);
   data[3] = (U8)value;
}

static int
sharkSshSpanEqual(SharkSshSpan span, const char* text)
{
   U32 len = (U32)strlen(text);
   return span.len == len && ! memcmp(span.ptr, text, len);
}

static int
sharkSshNameListValid(SharkSshSpan list, int allowEmpty)
{
   U32 nameSize = 0;
   U32 i;
   if( ! list.len)
      return allowEmpty;
   for(i = 0; i < list.len; ++i)
   {
      U8 ch = list.ptr[i];
      if(ch == ',')
      {
         if( ! nameSize)
            return 0;
         nameSize = 0;
      }
      else
      {
         if(ch < 33 || ch > 126 || ++nameSize > 64)
            return 0;
      }
   }
   return nameSize != 0;
}

static SharkSshSpan
sharkSshNameListFirst(SharkSshSpan list)
{
   SharkSshSpan first;
   first.ptr = list.ptr;
   first.len = 0;
   while(first.len < list.len && list.ptr[first.len] != ',')
      ++first.len;
   return first;
}

static int
sharkSshNameListContains(SharkSshSpan list, const char* name)
{
   U32 nameLen = (U32)strlen(name);
   U32 start = 0;
   U32 i;
   for(i = 0; i <= list.len; ++i)
   {
      if(i == list.len || list.ptr[i] == ',')
      {
         if(i - start == nameLen &&
            ! memcmp(list.ptr + start, name, nameLen))
            return 1;
         start = i + 1;
      }
   }
   return 0;
}

static void
sharkSshLog(SharkSshCon* connection, SharkSshLogLevel level,
             const char* message)
{
   if(connection->config->platform.log)
      connection->config->platform.log(
          connection->config->platform.context, level, message);
}

static U32
sharkSshNow(SharkSshCon* connection)
{
   return connection->config->platform.now ?
      connection->config->platform.now(
         connection->config->platform.context) : 0;
}

static void
sharkSshAuditEx(SharkSshCon* connection, U8 type, int status, U8 reason,
                U8 authMethod, U8 serviceType, SharkSshSpan user,
                const U8* fingerprint, SharkSshSpan request,
                U32 value, U8 hasValue)
{
   SharkSshAuditEvent event;
   if( ! connection->config->platform.audit)
      return;
   memset(&event, 0, sizeof(event));
   event.connection = connection;
   event.type = type;
   event.status = status;
   event.reason = reason;
   event.authMethod = authMethod;
   event.serviceType = serviceType;
   event.user = user;
   event.request = request;
   event.value = value;
   event.hasValue = hasValue;
   event.bytesReceived = connection->bytesReceived;
   event.bytesSent = connection->bytesSent;
   if(fingerprint)
   {
      event.publicKeyFingerprint.ptr = fingerprint;
      event.publicKeyFingerprint.len = 32;
   }
   connection->config->platform.audit(
      connection->config->platform.context, &event);
}

static void
sharkSshAudit(SharkSshCon* connection, U8 type, int status, U8 reason,
              U8 authMethod, U8 serviceType, SharkSshSpan user,
              const U8* fingerprint)
{
   SharkSshSpan empty;
   empty.ptr = 0;
   empty.len = 0;
   sharkSshAuditEx(connection, type, status, reason, authMethod,
                   serviceType, user, fingerprint, empty, 0, 0);
}

static void
sharkSshAuditConfigEx(const SharkSshConfig* config, U8 type, int status,
                      U8 reason, U32 value, U8 hasValue)
{
   SharkSshAuditEvent event;
   if( ! config || ! config->platform.audit)
      return;
   memset(&event, 0, sizeof(event));
   event.type = type;
   event.status = status;
   event.reason = reason;
   event.value = value;
   event.hasValue = hasValue;
   config->platform.audit(config->platform.context, &event);
}

#if SHARKSSL_BA
static void
sharkSshAuditConfig(const SharkSshConfig* config, U8 type, int status,
                    U8 reason)
{
   sharkSshAuditConfigEx(config, type, status, reason, 0, 0);
}
#endif /* SHARKSSL_BA */

static void
sharkSshAuditResourceUser(SharkSshCon* connection, int status,
                          U8 resource, SharkSshSpan user)
{
   connection->resourceAudited = 1;
   sharkSshAudit(connection, SharkSshAuditResourceRejected, status,
                 resource, connection->authMethod,
                 connection->channel.serviceType, user,
                 connection->authMethod == SharkSshAuthPublicKey ?
                    connection->publicKeyFingerprint : 0);
}

static void
sharkSshAuditResource(SharkSshCon* connection, int status, U8 resource)
{
   SharkSshSpan user;
   user.ptr = connection->user;
   user.len = connection->userSize;
   sharkSshAuditResourceUser(connection, status, resource, user);
}

static int
sharkSshSetEarlierTimeout(U32 now, U32 started, U32 limit, U8 reason,
                          U32* timeout, U8* timeoutReason)
{
   U32 elapsed;
   U32 remaining;
   if( ! limit)
      return 0;
   elapsed = now - started;
   if(elapsed >= limit)
   {
      *timeout = 0;
      *timeoutReason = reason;
      return 1;
   }
   remaining = limit - elapsed;
   if(*timeout == SHARKSSH_TIMEOUT_INFINITE || remaining < *timeout)
   {
      *timeout = remaining;
      *timeoutReason = reason;
   }
   return 0;
}

static int
sharkSshReadTimeout(SharkSshCon* connection, U32* timeout,
                    int allowMaintenance)
{
   U8 reason = SharkSshTimeoutIo;
   *timeout = connection->config->ioTimeout;
   if(connection->config->platform.now)
   {
      U32 now = sharkSshNow(connection);
      if((connection->state == SharkSshStateVersion ||
          (connection->state == SharkSshStateKeyExchange &&
           ! connection->initialKexDone)) &&
         sharkSshSetEarlierTimeout(
            now, connection->startedAt,
            connection->config->handshakeTimeout,
            SharkSshTimeoutHandshake, timeout, &reason))
         goto expired;
      if(connection->state == SharkSshStateAuthentication &&
         sharkSshSetEarlierTimeout(
            now, connection->phaseStartedAt,
            connection->config->authenticationTimeout,
            SharkSshTimeoutAuthentication, timeout, &reason))
         goto expired;
      if(connection->state == SharkSshStateConnection)
      {
         if(sharkSshSetEarlierTimeout(
               now, connection->lastActivityAt,
               connection->config->idleTimeout,
               SharkSshTimeoutIdle, timeout, &reason) ||
            sharkSshSetEarlierTimeout(
               now, connection->startedAt,
               connection->config->sessionTimeout,
               SharkSshTimeoutSession, timeout, &reason))
            goto expired;
      }
      if(allowMaintenance && connection->state == SharkSshStateConnection)
      {
         if(sharkSshSetEarlierTimeout(
               now, connection->rekeyStartedAt,
               connection->config->rekeyTime,
               SHARKSSH_TIMEOUT_WAKEUP, timeout, &reason) ||
            sharkSshSetEarlierTimeout(
               now, connection->keepAliveAt,
               connection->config->keepAliveInterval,
               SHARKSSH_TIMEOUT_WAKEUP, timeout, &reason))
            goto expired;
      }
   }
   if(connection->config->cancelPollInterval &&
      (*timeout == SHARKSSH_TIMEOUT_INFINITE ||
       connection->config->cancelPollInterval < *timeout))
   {
      *timeout = connection->config->cancelPollInterval;
      reason = SHARKSSH_TIMEOUT_WAKEUP;
   }
   connection->timeoutReason = reason;
   return SharkSshOk;

expired:
   connection->timeoutReason = reason;
   return SharkSshTimeout;
}

static int
sharkSshReportTimeout(SharkSshCon* connection)
{
   SharkSshSpan user;
   user.ptr = connection->user;
   user.len = connection->userSize;
   sharkSshAudit(connection, SharkSshAuditTimeout, SharkSshTimeout,
                 connection->timeoutReason, connection->authMethod,
                 connection->channel.serviceType, user,
                 connection->authMethod == SharkSshAuthPublicKey ?
                    connection->publicKeyFingerprint : 0);
   return SharkSshTimeout;
}

static int
sharkSshCanceled(SharkSshCon* connection)
{
   int mode;
   if(connection->sendingDisconnect)
      return SharkSshCancelNone;
   if(connection->cancelMode)
      return connection->cancelMode;
   if(connection->config->platform.cooperate)
      connection->config->platform.cooperate(
         connection->config->platform.context);
   if( ! connection->config->platform.shouldCancel)
      return SharkSshCancelNone;
   mode = connection->config->platform.shouldCancel(
      connection->config->platform.context);
   if(mode)
      connection->cancelMode = mode == SharkSshCancelGraceful ?
         SharkSshCancelGraceful : SharkSshCancelImmediate;
   return connection->cancelMode;
}

void
sharkSshWriter_constructor(SharkSshWriter* writer, U8* data, U32 size)
{
   writer->begin = data;
   writer->ptr = data;
   writer->end = data + size;
   writer->status = SharkSshOk;
}

void
sharkSshWriter_byte(SharkSshWriter* writer, U8 value)
{
   if(writer->status)
      return;
   if(writer->ptr == writer->end)
   {
      writer->status = SharkSshErrBounds;
      return;
   }
   *writer->ptr++ = value;
}

void
sharkSshWriter_u32(SharkSshWriter* writer, U32 value)
{
   if(writer->status)
      return;
   if((U32)(writer->end - writer->ptr) < 4)
   {
      writer->status = SharkSshErrBounds;
      return;
   }
   sharkSshWriteU32(writer->ptr, value);
   writer->ptr += 4;
}

void
sharkSshWriter_data(SharkSshWriter* writer, const void* data, U32 size)
{
   if(writer->status)
      return;
   if(size > (U32)(writer->end - writer->ptr))
   {
      writer->status = SharkSshErrBounds;
      return;
   }
   if(size)
      memcpy(writer->ptr, data, size);
   writer->ptr += size;
}

void
sharkSshWriter_string(SharkSshWriter* writer, const void* data, U32 size)
{
   sharkSshWriter_u32(writer, size);
   sharkSshWriter_data(writer, data, size);
}

void
sharkSshWriter_cstring(SharkSshWriter* writer, const char* value)
{
   sharkSshWriter_string(writer, value, (U32)strlen(value));
}

void
sharkSshWriter_mpint(SharkSshWriter* writer, const U8* data, U32 size)
{
   while(size && ! *data)
   {
      ++data;
      --size;
   }
   if( ! size)
   {
      sharkSshWriter_u32(writer, 0);
      return;
   }
   sharkSshWriter_u32(writer, size + ((*data & 0x80) ? 1 : 0));
   if(*data & 0x80)
      sharkSshWriter_byte(writer, 0);
   sharkSshWriter_data(writer, data, size);
}

U32
sharkSshWriter_size(const SharkSshWriter* writer)
{
   return (U32)(writer->ptr - writer->begin);
}

void
sharkSshReader_constructor(SharkSshReader* reader,
                           const U8* data, U32 size)
{
   reader->ptr = data;
   reader->end = data + size;
   reader->status = SharkSshOk;
}

U8
sharkSshReader_byte(SharkSshReader* reader)
{
   if(reader->status || reader->ptr == reader->end)
   {
      reader->status = SharkSshErrProtocol;
      return 0;
   }
   return *reader->ptr++;
}

U32
sharkSshReader_u32(SharkSshReader* reader)
{
   U32 value;
   if(reader->status || (U32)(reader->end - reader->ptr) < 4)
   {
      reader->status = SharkSshErrProtocol;
      return 0;
   }
   value = sharkSshReadU32(reader->ptr);
   reader->ptr += 4;
   return value;
}

SharkSshSpan
sharkSshReader_string(SharkSshReader* reader)
{
   SharkSshSpan span;
   span.ptr = 0;
   span.len = 0;
   if(reader->status)
      return span;
   span.len = sharkSshReader_u32(reader);
   if(reader->status || span.len > (U32)(reader->end - reader->ptr))
   {
      reader->status = SharkSshErrProtocol;
      span.len = 0;
      return span;
   }
   span.ptr = reader->ptr;
   reader->ptr += span.len;
   return span;
}

int
sharkSshReader_done(const SharkSshReader* reader)
{
   return ! reader->status && reader->ptr == reader->end;
}

static int
sharkSshSendAll(SharkSshCon* connection, const U8* data, U32 size)
{
#if SHARKSSL_BA
   if(sharkSshCanceled(connection))
      return SharkSshClosed;
   if(size > 0x7FFFFFFFU ||
      SoDispCon_sendData(&connection->socket, data, (int)size))
      return SharkSshErrSocket;
   connection->bytesSent += size;
   if(connection->config->platform.now)
      connection->lastActivityAt = sharkSshNow(connection);
   return SharkSshOk;
#else
   while(size)
   {
      S32 sent;
      if(sharkSshCanceled(connection))
         return SharkSshClosed;
      sent = se_send(&connection->socket, data, size);
      if(sent <= 0)
         return SharkSshErrSocket;
      data += sent;
      size -= (U32)sent;
      connection->bytesSent += (U32)sent;
      if(connection->config->platform.now)
         connection->lastActivityAt = sharkSshNow(connection);
   }
   return SharkSshOk;
#endif
}

static int
sharkSshReceiveAll(SharkSshCon* connection, U8* data, U32 size,
                   int allowMaintenance)
{
   while(size)
   {
      U32 timeout;
      if(sharkSshReadTimeout(connection, &timeout, allowMaintenance))
         return connection->timeoutReason == SHARKSSH_TIMEOUT_WAKEUP ?
            SHARKSSH_MAINTENANCE : sharkSshReportTimeout(connection);
#if SHARKSSL_BA
      int received;
      if(sharkSshCanceled(connection))
         return SharkSshClosed;
      if(timeout == SHARKSSH_TIMEOUT_INFINITE)
         connection->socket.rtmo = 0;
      else
      {
         if(timeout < 50)
            timeout = 50;
         if(timeout > 0xFFFFU * 50U)
            timeout = 0xFFFFU * 50U;
         SoDispCon_setReadTmo(&connection->socket, timeout);
      }
      received = SoDispCon_blockRead(&connection->socket, data, (int)size);
      if(received == E_TIMEOUT)
      {
         if(connection->timeoutReason == SHARKSSH_TIMEOUT_WAKEUP)
         {
            if(allowMaintenance)
               return SHARKSSH_MAINTENANCE;
            continue;
         }
         return sharkSshReportTimeout(connection);
      }
      if(received <= 0)
         return SharkSshErrSocket;
#else
      S32 received;
      if(sharkSshCanceled(connection))
         return SharkSshClosed;
      received = se_recv(&connection->socket, data, size,
                         timeout);
      if(received == 0)
      {
         if(connection->timeoutReason == SHARKSSH_TIMEOUT_WAKEUP)
         {
            if(allowMaintenance)
               return SHARKSSH_MAINTENANCE;
            continue;
         }
         return sharkSshReportTimeout(connection);
      }
      if(received < 0)
         return SharkSshErrSocket;
#endif
      data += received;
      size -= (U32)received;
      allowMaintenance = 0;
      connection->bytesReceived += (U32)received;
      if(connection->config->platform.now)
         connection->lastActivityAt = sharkSshNow(connection);
   }
   return SharkSshOk;
}

static void
sharkSshMac(const U8 key[32], U32 sequence,
            const U8* packet, U32 packetSize, U8 mac[32])
{
   SharkSslHMACCtx hmac;
   U8 seq[4];
   sharkSshWriteU32(seq, sequence);
   SharkSslHMACCtx_constructor(&hmac, SHARKSSL_HASHID_SHA256, key, 32);
   SharkSslHMACCtx_append(&hmac, seq, sizeof(seq));
   SharkSslHMACCtx_append(&hmac, packet, packetSize);
   SharkSslHMACCtx_finish(&hmac, mac);
   SharkSslHMACCtx_destructor(&hmac);
}

static void
sharkSshAesCtr(SharkSslAesCtx* aes, U8 counter[16],
               U8* data, U32 size)
{
   U8 stream[16];
   U32 offset;
   int i;
   baAssert((size & 15) == 0);
   for(offset = 0; offset < size; offset += 16)
   {
      SharkSslAesCtx_encrypt(aes, counter, stream);
      for(i = 0; i < 16; ++i)
         data[offset + i] ^= stream[i];
      for(i = 15; i >= 0 && ++counter[i] == 0; --i)
         ;
   }
   sharkSshZero(stream, sizeof(stream));
}

static int
sharkSshSendPacket(SharkSshCon* connection, const U8* payload,
                   U32 payloadSize)
{
   U8 mac[32];
   U8 randomPadding[32];
   U32 blockSize = connection->encryptedOutput ? 16 : 8;
   U32 paddingSize = blockSize - ((payloadSize + 5) % blockSize);
   U32 packetSize;
   U32 packetLen;
   int status;

   if(connection->sendSequence == 0xFFFFFFFFU)
      return SharkSshErrProtocol;
   if(paddingSize < 4)
      paddingSize += blockSize;
   packetLen = payloadSize + paddingSize + 1;
   packetSize = packetLen + 4;
   if(packetSize + sizeof(mac) > sizeof(connection->output))
      return SharkSshErrBounds;

   if(payload != connection->output + 5)
      memmove(connection->output + 5, payload, payloadSize);
   sharkSshWriteU32(connection->output, packetLen);
   connection->output[4] = (U8)paddingSize;
   if(sharkssl_rng(randomPadding, sizeof(randomPadding)) < 0)
      return SharkSshErrCrypto;
   memcpy(connection->output + 5 + payloadSize, randomPadding, paddingSize);
   sharkSshZero(randomPadding, sizeof(randomPadding));

   if(connection->encryptedOutput)
   {
      sharkSshMac(connection->sendMacKey, connection->sendSequence,
                  connection->output, packetSize, mac);
      sharkSshAesCtr(&connection->sendAes, connection->sendCounter,
                     connection->output, packetSize);
   }
   status = sharkSshSendAll(connection, connection->output, packetSize);
   if( ! status && connection->encryptedOutput)
      status = sharkSshSendAll(connection, mac, sizeof(mac));
   ++connection->sendSequence;
   if( ! status)
      ++connection->packetsSent;
   sharkSshZero(mac, sizeof(mac));
   return status;
}

static int
sharkSshReceivePacketEx(SharkSshCon* connection, U8** payload,
                        U32* payloadSize, int allowMaintenance)
{
   U8 expectedMac[32];
   U32 packetLen;
   U32 packetSize;
   U32 firstSize = connection->encryptedInput ? 16 : 4;
   U8 paddingSize;
   int status;

   if(connection->receiveSequence == 0xFFFFFFFFU)
      return SharkSshErrProtocol;
   status = sharkSshReceiveAll(connection, connection->input, firstSize,
                               allowMaintenance);
   if(status)
      return status;
   if(connection->encryptedInput)
      sharkSshAesCtr(&connection->receiveAes, connection->receiveCounter,
                     connection->input, firstSize);
   packetLen = sharkSshReadU32(connection->input);
   if(packetLen < 5 || packetLen > sizeof(connection->input) - 36)
      return SharkSshErrProtocol;
   packetSize = packetLen + 4;
   if((connection->encryptedInput && (packetSize & 15)) ||
      ( ! connection->encryptedInput && (packetSize & 7)))
      return SharkSshErrProtocol;

   if(packetSize > firstSize)
   {
      status = sharkSshReceiveAll(connection, connection->input + firstSize,
                                  packetSize - firstSize, 0);
      if(status)
         return status;
      if(connection->encryptedInput)
         sharkSshAesCtr(&connection->receiveAes,
                        connection->receiveCounter,
                        connection->input + firstSize,
                        packetSize - firstSize);
   }

   if(connection->encryptedInput)
   {
      status = sharkSshReceiveAll(connection,
                                  connection->input + packetSize, 32, 0);
      if(status)
         return status;
      sharkSshMac(connection->receiveMacKey, connection->receiveSequence,
                  connection->input, packetSize, expectedMac);
      if(sharkssl_kmemcmp(expectedMac,
                         connection->input + packetSize, 32))
      {
         sharkSshZero(expectedMac, sizeof(expectedMac));
         return SharkSshErrCrypto;
      }
      sharkSshZero(expectedMac, sizeof(expectedMac));
   }

   ++connection->receiveSequence;
   paddingSize = connection->input[4];
   if(paddingSize < 4 || (U32)paddingSize + 1 > packetLen)
      return SharkSshErrProtocol;
   *payloadSize = packetLen - paddingSize - 1;
   if( ! *payloadSize)
      return SharkSshErrProtocol;
   *payload = connection->input + 5;
   ++connection->packetsReceived;
   if(connection->config->platform.now)
      connection->keepAliveAt = sharkSshNow(connection);
   return SharkSshOk;
}

static int
sharkSshReceivePacket(SharkSshCon* connection, U8** payload,
                      U32* payloadSize)
{
   return sharkSshReceivePacketEx(connection, payload, payloadSize, 0);
}

static int
sharkSshSendDisconnect(SharkSshCon* connection, U32 reason,
                       const char* message)
{
   SharkSshWriter writer;
   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_DISCONNECT);
   sharkSshWriter_u32(&writer, reason);
   sharkSshWriter_cstring(&writer, message);
   sharkSshWriter_cstring(&writer, "");
   return writer.status ? writer.status :
      sharkSshSendPacket(connection, writer.begin,
                         sharkSshWriter_size(&writer));
}

static int
sharkSshIdentification(SharkSshCon* connection)
{
   const char* serverId = SHARKSSH_VERSION "\r\n";
   U32 lineSize = 0;
   int lines = 0;
   int status;

   connection->serverVersionSize = (U16)strlen(SHARKSSH_VERSION);
   memcpy(connection->serverVersion, SHARKSSH_VERSION,
          connection->serverVersionSize + 1);
   status = sharkSshSendAll(connection, (const U8*)serverId,
                            (U32)strlen(serverId));
   if(status)
      return status;

   while(lines++ < 16)
   {
      lineSize = 0;
      for(;;)
      {
         U8 ch;
         status = sharkSshReceiveAll(connection, &ch, 1, 0);
         if(status)
            return status;
         if(ch == '\n')
            break;
         if(ch != '\r')
         {
            if(lineSize >= sizeof(connection->clientVersion) - 1)
               return SharkSshErrProtocol;
            connection->clientVersion[lineSize++] = (char)ch;
         }
      }
      connection->clientVersion[lineSize] = 0;
      if(lineSize >= 8 &&
         ! memcmp(connection->clientVersion, "SSH-2.0-", 8))
      {
         connection->clientVersionSize = (U16)lineSize;
         return SharkSshOk;
      }
   }
   return SharkSshErrProtocol;
}

static int
sharkSshBuildServerKex(SharkSshCon* connection)
{
   SharkSshWriter writer;
   U8 cookie[16];
   int i;

   if(sharkssl_rng(cookie, sizeof(cookie)) < 0)
      return SharkSshErrCrypto;
   sharkSshWriter_constructor(&writer, connection->serverKex,
                              sizeof(connection->serverKex));
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_KEXINIT);
   sharkSshWriter_data(&writer, cookie, sizeof(cookie));
   sharkSshWriter_cstring(&writer, kexAlgorithms);
   sharkSshWriter_cstring(&writer, hostKeyAlgorithm);
   for(i = 0; i < 2; ++i)
      sharkSshWriter_cstring(&writer, cipherAlgorithm);
   for(i = 0; i < 2; ++i)
      sharkSshWriter_cstring(&writer, macAlgorithm);
   for(i = 0; i < 2; ++i)
      sharkSshWriter_cstring(&writer, noCompression);
   sharkSshWriter_cstring(&writer, "");
   sharkSshWriter_cstring(&writer, "");
   sharkSshWriter_byte(&writer, 0);
   sharkSshWriter_u32(&writer, 0);
   sharkSshZero(cookie, sizeof(cookie));
   if(writer.status)
      return writer.status;
   connection->serverKexSize = (U16)sharkSshWriter_size(&writer);
   return SharkSshOk;
}

static int
sharkSshCheckClientKex(SharkSshCon* connection,
                       const U8* payload, U32 size,
                       SharkSshKexOptions* options)
{
   SharkSshReader reader;
   SharkSshSpan lists[10];
   SharkSshSpan firstKex;
   SharkSshSpan firstHostKey;
   static const char* required[] = {
      kexAlgorithm, hostKeyAlgorithm,
      cipherAlgorithm, cipherAlgorithm,
      macAlgorithm, macAlgorithm,
      noCompression, noCompression
   };
   U8 firstPacketFollows;
   U32 reserved;
   int i;

   memset(options, 0, sizeof(*options));
   sharkSshReader_constructor(&reader, payload, size);
   if(sharkSshReader_byte(&reader) != SHARKSSH_MSG_KEXINIT)
      return SharkSshErrProtocol;
   if((U32)(reader.end - reader.ptr) < 16)
      return SharkSshErrProtocol;
   reader.ptr += 16;
   for(i = 0; i < 10; ++i)
      lists[i] = sharkSshReader_string(&reader);
   firstPacketFollows = sharkSshReader_byte(&reader);
   reserved = sharkSshReader_u32(&reader);
   if( ! sharkSshReader_done(&reader) || firstPacketFollows > 1 || reserved)
      return SharkSshErrProtocol;

   for(i = 0; i < 8; ++i)
   {
      if( ! sharkSshNameListValid(lists[i], 0))
         return SharkSshErrProtocol;
      if( ! sharkSshNameListContains(lists[i], required[i]))
      {
         SharkSshSpan user;
         user.ptr = connection->user;
         user.len = connection->userSize;
         sharkSshAudit(connection, SharkSshAuditNegotiationFailure,
                       SharkSshErrCrypto, 0, connection->authMethod,
                       connection->channel.serviceType, user,
                       connection->authMethod == SharkSshAuthPublicKey ?
                          connection->publicKeyFingerprint : 0);
         return SharkSshErrCrypto;
      }
   }
   for(i = 8; i < 10; ++i)
   {
      if( ! sharkSshNameListValid(lists[i], 1))
         return SharkSshErrProtocol;
   }

   options->sendExtInfo =
      (U8)sharkSshNameListContains(lists[0], extInfoClient);
   options->strictKex = (U8)(
      sharkSshNameListContains(lists[0], strictKexClient) ||
      sharkSshNameListContains(lists[0], strictKexClientV00));
   if(options->strictKex && connection->receiveSequence != 1)
      return SharkSshErrProtocol;

   firstKex = sharkSshNameListFirst(lists[0]);
   firstHostKey = sharkSshNameListFirst(lists[1]);
   if(firstPacketFollows &&
      ( ! sharkSshSpanEqual(firstKex, kexAlgorithm) ||
        ! sharkSshSpanEqual(firstHostKey, hostKeyAlgorithm)))
      options->ignoreNextPacket = 1;
   return SharkSshOk;
}

static void
sharkSshHashU32(SharkSslSha256Ctx* hash, U32 value)
{
   U8 data[4];
   sharkSshWriteU32(data, value);
   SharkSslSha256Ctx_append(hash, data, sizeof(data));
}

static void
sharkSshHashString(SharkSslSha256Ctx* hash, const void* data, U32 size)
{
   sharkSshHashU32(hash, size);
   SharkSslSha256Ctx_append(hash, (const U8*)data, size);
}

static void
sharkSshHashMpint(SharkSslSha256Ctx* hash, const U8* data, U32 size)
{
   while(size && ! *data)
   {
      ++data;
      --size;
   }
   if( ! size)
   {
      sharkSshHashU32(hash, 0);
      return;
   }
   sharkSshHashU32(hash, size + ((*data & 0x80) ? 1 : 0));
   if(*data & 0x80)
   {
      U8 zero = 0;
      SharkSslSha256Ctx_append(hash, &zero, 1);
   }
   SharkSslSha256Ctx_append(hash, data, size);
}

static void
sharkSshExchangeHash(SharkSshCon* connection,
                     const U8 clientPublic[32], const U8 serverPublic[32],
                     const U8 sharedSecret[32], U8 hashValue[32])
{
   SharkSslSha256Ctx hash;
   SharkSslSha256Ctx_constructor(&hash);
   sharkSshHashString(&hash, connection->clientVersion,
                      connection->clientVersionSize);
   sharkSshHashString(&hash, connection->serverVersion,
                      connection->serverVersionSize);
   sharkSshHashString(&hash, connection->clientKex,
                      connection->clientKexSize);
   sharkSshHashString(&hash, connection->serverKex,
                      connection->serverKexSize);
   sharkSshHashString(&hash, connection->hostKey,
                      connection->hostKeySize);
   sharkSshHashString(&hash, clientPublic, 32);
   sharkSshHashString(&hash, serverPublic, 32);
   sharkSshHashMpint(&hash, sharedSecret, 32);
   SharkSslSha256Ctx_finish(&hash, hashValue);
}

static void
sharkSshDerive(SharkSshCon* connection, const U8 sharedSecret[32],
               const U8 exchangeHash[32], U8 letter, U8 output[32])
{
   SharkSslSha256Ctx hash;
   SharkSslSha256Ctx_constructor(&hash);
   sharkSshHashMpint(&hash, sharedSecret, 32);
   SharkSslSha256Ctx_append(&hash, exchangeHash, 32);
   SharkSslSha256Ctx_append(&hash, &letter, 1);
   SharkSslSha256Ctx_append(&hash, connection->sessionId, 32);
   SharkSslSha256Ctx_finish(&hash, output);
}

static int
sharkSshSendExtInfo(SharkSshCon* connection)
{
   SharkSshWriter writer;
   int publicKey = connection->config->authenticator.publicKey != 0;
   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_EXT_INFO);
   sharkSshWriter_u32(&writer, publicKey ? 1 : 0);
   if(publicKey)
   {
      sharkSshWriter_cstring(&writer, "server-sig-algs");
      sharkSshWriter_cstring(&writer, publicKeyAlgorithm);
   }
   return writer.status ? writer.status :
      sharkSshSendPacket(connection, writer.begin,
                         sharkSshWriter_size(&writer));
}

static int
sharkSshCheckPeerDisconnect(SharkSshCon* connection,
                            const U8* payload, U32 payloadSize)
{
   SharkSshReader reader;
   if(payload[0] != SHARKSSH_MSG_DISCONNECT)
      return SharkSshOk;
   sharkSshReader_constructor(&reader, payload, payloadSize);
   (void)sharkSshReader_byte(&reader);
   return sharkSshHandleTransportMessage(
      connection, SHARKSSH_MSG_DISCONNECT, &reader);
}

static int
sharkSshParseExtInfo(const U8* payload, U32 payloadSize)
{
   SharkSshReader reader;
   U32 count;
   U32 i;
   sharkSshReader_constructor(&reader, payload, payloadSize);
   if(sharkSshReader_byte(&reader) != SHARKSSH_MSG_EXT_INFO)
      return SharkSshErrProtocol;
   count = sharkSshReader_u32(&reader);
   if(reader.status || count > payloadSize / 8)
      return SharkSshErrProtocol;
   for(i = 0; i < count; ++i)
   {
      SharkSshSpan name = sharkSshReader_string(&reader);
      (void)sharkSshReader_string(&reader);
      if(reader.status || ! sharkSshNameListValid(name, 0) ||
         sharkSshNameListFirst(name).len != name.len)
         return SharkSshErrProtocol;
   }
   return sharkSshReader_done(&reader) ? SharkSshOk : SharkSshErrProtocol;
}

static int
sharkSshKeyExchange(SharkSshCon* connection,
                    const U8* offeredKex, U32 offeredKexSize)
{
   U8* payload;
   U32 payloadSize;
   SharkSshReader reader;
   SharkSshSpan clientPublicSpan;
   U8 privateKey[32];
   U8 serverPublic[32];
   U8 sharedSecret[32];
   U8 exchangeHash[32];
   U8 signatureHash[32];
   U8 signature[512];
   U8 signatureBlob[SHARKSSH_MAX_HOST_KEY_LEN];
   U8 newReceiveCounter[16];
   U8 newSendCounter[16];
   U8 newReceiveMacKey[32];
   U8 newSendMacKey[32];
   U16 signatureSize = 0;
   U16 hostKeySize = 0;
   U8 key[32];
   SharkSshWriter writer;
   SharkSshWriter signatureWriter;
   SharkSshKexOptions kexOptions;
   SharkSslAesCtx newReceiveAes;
   SharkSslAesCtx newSendAes;
   U8 newContextsReady = 0;
   U8 rekey = connection->initialKexDone;
   int status;

   if(offeredKex)
   {
      if(offeredKexSize > sizeof(connection->clientKex))
         return SharkSshErrBounds;
      status = sharkSshCheckClientKex(
         connection, offeredKex, offeredKexSize, &kexOptions);
      if(status)
         return status;
      memcpy(connection->clientKex, offeredKex, offeredKexSize);
      connection->clientKexSize = (U16)offeredKexSize;
   }
   status = sharkSshBuildServerKex(connection);
   if(status)
      return status;
   status = sharkSshSendPacket(connection, connection->serverKex,
                               connection->serverKexSize);
   if(status)
      return status;

   if( ! offeredKex)
   {
      for(;;)
      {
         status = sharkSshReceivePacket(connection, &payload, &payloadSize);
         if(status)
            return status;
         if(payload[0] == SHARKSSH_MSG_KEXINIT)
            break;
         if( ! rekey)
         {
            status = sharkSshCheckPeerDisconnect(
               connection, payload, payloadSize);
            return status ? status : SharkSshErrProtocol;
         }
         status = sharkSshHandleConnectionPacket(
            connection, payload, payloadSize);
         if(status)
            return status == SHARKSSH_CHANNEL_COMPLETE ?
               SharkSshClosed : status;
      }
      if(payloadSize > sizeof(connection->clientKex))
         return SharkSshErrBounds;
      status = sharkSshCheckClientKex(connection, payload, payloadSize,
                                      &kexOptions);
      if(status)
         return status;
      memcpy(connection->clientKex, payload, payloadSize);
      connection->clientKexSize = (U16)payloadSize;
   }
   if(rekey)
      kexOptions.strictKex = connection->strictKex;
   else
      connection->strictKex = kexOptions.strictKex;

   if(kexOptions.ignoreNextPacket)
   {
      status = sharkSshReceivePacket(connection, &payload, &payloadSize);
      if(status)
         return status;
      status = sharkSshCheckPeerDisconnect(connection, payload, payloadSize);
      if(status)
         return status;
      if(kexOptions.strictKex &&
         (payload[0] < 30 || payload[0] > 49))
         return SharkSshErrProtocol;
   }

   status = sharkSshReceivePacket(connection, &payload, &payloadSize);
   if(status)
      return status;
   status = sharkSshCheckPeerDisconnect(connection, payload, payloadSize);
   if(status)
      return status;
   sharkSshReader_constructor(&reader, payload, payloadSize);
   if(sharkSshReader_byte(&reader) != SHARKSSH_MSG_KEX_ECDH_INIT)
      return SharkSshErrProtocol;
   clientPublicSpan = sharkSshReader_string(&reader);
   if( ! sharkSshReader_done(&reader) || clientPublicSpan.len != 32)
      return SharkSshErrProtocol;

   if( ! connection->config->hostKey.publicKey ||
       ! connection->config->hostKey.signHash)
      return SharkSshErrArgument;
   status = connection->config->hostKey.publicKey(
      connection->config->hostKey.context, connection->hostKey,
      SHARKSSH_MAX_HOST_KEY_LEN, &hostKeySize);
   if(status || ! hostKeySize || hostKeySize > SHARKSSH_MAX_HOST_KEY_LEN)
      return status ? status : SharkSshErrCrypto;
   connection->hostKeySize = hostKeySize;

   status = sharkSshX25519(privateKey, serverPublic,
                           clientPublicSpan.ptr, sharedSecret);
   if(status)
      goto cleanup;
   sharkSshExchangeHash(connection, clientPublicSpan.ptr, serverPublic,
                         sharedSecret, exchangeHash);
   if( ! rekey)
      memcpy(connection->sessionId, exchangeHash,
             sizeof(connection->sessionId));

   /* RSA/SHA-256 hashes the SSH exchange hash as its signature input. */
   {
      SharkSslSha256Ctx hash;
      SharkSslSha256Ctx_constructor(&hash);
      SharkSslSha256Ctx_append(&hash, exchangeHash, sizeof(exchangeHash));
      SharkSslSha256Ctx_finish(&hash, signatureHash);
   }

   status = connection->config->hostKey.signHash(
      connection->config->hostKey.context, signatureHash,
      signature, sizeof(signature), &signatureSize);
   if(status)
      goto cleanup;

   sharkSshWriter_constructor(&signatureWriter, signatureBlob,
                              sizeof(signatureBlob));
   sharkSshWriter_cstring(&signatureWriter, hostKeyAlgorithm);
   sharkSshWriter_string(&signatureWriter, signature, signatureSize);
   if(signatureWriter.status)
   {
      status = signatureWriter.status;
      goto cleanup;
   }

   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_KEX_ECDH_REPLY);
   sharkSshWriter_string(&writer, connection->hostKey, hostKeySize);
   sharkSshWriter_string(&writer, serverPublic, sizeof(serverPublic));
   sharkSshWriter_string(&writer, signatureWriter.begin,
                         sharkSshWriter_size(&signatureWriter));
   if(writer.status)
   {
      status = writer.status;
      goto cleanup;
   }
   status = sharkSshSendPacket(connection, writer.begin,
                               sharkSshWriter_size(&writer));
   if(status)
      goto cleanup;

   sharkSshDerive(connection, sharedSecret, exchangeHash, 'A', key);
   memcpy(newReceiveCounter, key, sizeof(newReceiveCounter));
   sharkSshDerive(connection, sharedSecret, exchangeHash, 'B', key);
   memcpy(newSendCounter, key, sizeof(newSendCounter));
   sharkSshDerive(connection, sharedSecret, exchangeHash, 'C', key);
   SharkSslAesCtx_constructor(&newReceiveAes,
                              SharkSslAesCtx_Encrypt, key, 16);
   sharkSshDerive(connection, sharedSecret, exchangeHash, 'D', key);
   SharkSslAesCtx_constructor(&newSendAes,
                              SharkSslAesCtx_Encrypt, key, 16);
   newContextsReady = 1;
   sharkSshDerive(connection, sharedSecret, exchangeHash, 'E',
                   newReceiveMacKey);
   sharkSshDerive(connection, sharedSecret, exchangeHash, 'F',
                   newSendMacKey);

   connection->output[5] = SHARKSSH_MSG_NEWKEYS;
   status = sharkSshSendPacket(connection, connection->output + 5, 1);
   if(status)
      goto cleanup;
   if(kexOptions.strictKex)
      connection->sendSequence = 0;
   SharkSslAesCtx_destructor(&connection->sendAes);
   memcpy(&connection->sendAes, &newSendAes,
          sizeof(connection->sendAes));
   memcpy(connection->sendCounter, newSendCounter,
          sizeof(connection->sendCounter));
   memcpy(connection->sendMacKey, newSendMacKey,
          sizeof(connection->sendMacKey));
   connection->encryptedOutput = 1;

   status = sharkSshReceivePacket(connection, &payload, &payloadSize);
   if(status)
      goto cleanup;
   status = sharkSshCheckPeerDisconnect(connection, payload, payloadSize);
   if(status)
      goto cleanup;
   if(payloadSize != 1 || payload[0] != SHARKSSH_MSG_NEWKEYS)
   {
      status = SharkSshErrProtocol;
      goto cleanup;
   }
   if(kexOptions.strictKex)
      connection->receiveSequence = 0;
   SharkSslAesCtx_destructor(&connection->receiveAes);
   memcpy(&connection->receiveAes, &newReceiveAes,
          sizeof(connection->receiveAes));
   memcpy(connection->receiveCounter, newReceiveCounter,
          sizeof(connection->receiveCounter));
   memcpy(connection->receiveMacKey, newReceiveMacKey,
          sizeof(connection->receiveMacKey));
   connection->encryptedInput = 1;
   if(kexOptions.sendExtInfo && ! rekey)
   {
      status = sharkSshSendExtInfo(connection);
      if(status)
         goto cleanup;
   }
   if(kexOptions.strictKex && ! rekey)
      sharkSshLog(connection, SharkSshLogInfo, "SSH Strict KEX enabled");
   if(kexOptions.sendExtInfo && ! rekey)
      sharkSshLog(connection, SharkSshLogInfo,
                  "SSH extension negotiation enabled");
   connection->initialKexDone = 1;
   connection->rekeyReceivedAt = connection->bytesReceived;
   connection->rekeySentAt = connection->bytesSent;
   connection->rekeyPacketsReceivedAt = connection->packetsReceived;
   connection->rekeyPacketsSentAt = connection->packetsSent;
   if(connection->config->platform.now)
      connection->rekeyStartedAt = sharkSshNow(connection);
   if(rekey)
   {
      SharkSshSpan user;
      user.ptr = connection->user;
      user.len = connection->userSize;
      sharkSshLog(connection, SharkSshLogInfo, "SSH keys replaced");
      sharkSshAudit(connection, SharkSshAuditRekey, SharkSshOk, 0,
                    connection->authMethod,
                    connection->channel.serviceType, user,
                    connection->authMethod == SharkSshAuthPublicKey ?
                       connection->publicKeyFingerprint : 0);
   }

cleanup:
   sharkSshZero(privateKey, sizeof(privateKey));
   sharkSshZero(sharedSecret, sizeof(sharedSecret));
   sharkSshZero(exchangeHash, sizeof(exchangeHash));
   sharkSshZero(signatureHash, sizeof(signatureHash));
   sharkSshZero(signature, sizeof(signature));
   sharkSshZero(signatureBlob, sizeof(signatureBlob));
   sharkSshZero(newReceiveCounter, sizeof(newReceiveCounter));
   sharkSshZero(newSendCounter, sizeof(newSendCounter));
   sharkSshZero(newReceiveMacKey, sizeof(newReceiveMacKey));
   sharkSshZero(newSendMacKey, sizeof(newSendMacKey));
   sharkSshZero(key, sizeof(key));
   if(newContextsReady)
   {
      SharkSslAesCtx_destructor(&newReceiveAes);
      SharkSslAesCtx_destructor(&newSendAes);
   }
   return status;
}

static int
sharkSshSendServiceAccept(SharkSshCon* connection, SharkSshSpan service)
{
   SharkSshWriter writer;
   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_SERVICE_ACCEPT);
   sharkSshWriter_string(&writer, service.ptr, service.len);
   return writer.status ? writer.status :
      sharkSshSendPacket(connection, writer.begin,
                         sharkSshWriter_size(&writer));
}

static int
sharkSshSendAuthFailure(SharkSshCon* connection)
{
   SharkSshWriter writer;
   const char* methods;
   if(connection->config->authenticator.publicKey)
      methods = connection->config->authenticator.password ?
         "publickey,password" : "publickey";
   else
      methods = connection->config->authenticator.password ?
         "password" : "";
   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_USERAUTH_FAILURE);
   sharkSshWriter_cstring(&writer, methods);
   sharkSshWriter_byte(&writer, 0);
   return writer.status ? writer.status :
      sharkSshSendPacket(connection, writer.begin,
                         sharkSshWriter_size(&writer));
}

static int
sharkSshPositiveMpint(SharkSshSpan value)
{
   if( ! value.len || (value.ptr[0] & 0x80))
      return 0;
   if(value.ptr[0] == 0)
      return value.len > 1 && (value.ptr[1] & 0x80);
   return 1;
}

static int
sharkSshParseRsaBlob(SharkSshSpan keyBlob, SharkSshSpan* exponent,
                     SharkSshSpan* modulus)
{
   SharkSshReader reader;
   SharkSshSpan algorithm;
   sharkSshReader_constructor(&reader, keyBlob.ptr, keyBlob.len);
   algorithm = sharkSshReader_string(&reader);
   *exponent = sharkSshReader_string(&reader);
   *modulus = sharkSshReader_string(&reader);
   return sharkSshReader_done(&reader) &&
          sharkSshSpanEqual(algorithm, publicKeyBlobAlgorithm) &&
          sharkSshPositiveMpint(*exponent) &&
          sharkSshPositiveMpint(*modulus);
}

static SharkSshSpan
sharkSshUnsignedInteger(SharkSshSpan value)
{
   while(value.len > 1 && *value.ptr == 0)
   {
      ++value.ptr;
      --value.len;
   }
   return value;
}

static int
sharkSshRsaKeyMatches(SharkSslRSAKey key, SharkSshSpan exponent,
                      SharkSshSpan modulus)
{
   U8 keyType;
   U8 isPrivate;
   U8* keyModulus;
   U8* keyExponent;
   U16 modulusLen;
   U16 exponentLen;
   SharkSshSpan actualExponent;
   SharkSshSpan actualModulus;
   if( ! key || ! SharkSslKey_vectSize_keyInfo(
         (SharkSslKey)key, &keyType, &isPrivate, &keyModulus, &modulusLen,
         &keyExponent, &exponentLen) || keyType != SHARKSSL_KEYTYPE_RSA)
      return 0;
   (void)isPrivate;
   actualExponent.ptr = keyExponent;
   actualExponent.len = exponentLen;
   actualModulus.ptr = keyModulus;
   actualModulus.len = modulusLen;
   actualExponent = sharkSshUnsignedInteger(actualExponent);
   actualModulus = sharkSshUnsignedInteger(actualModulus);
   exponent = sharkSshUnsignedInteger(exponent);
   modulus = sharkSshUnsignedInteger(modulus);
   return actualExponent.len == exponent.len &&
          actualModulus.len == modulus.len &&
          ! memcmp(actualExponent.ptr, exponent.ptr, exponent.len) &&
          ! memcmp(actualModulus.ptr, modulus.ptr, modulus.len);
}

static void
sharkSshPublicKeyFingerprint(SharkSshSpan keyBlob, U8 fingerprint[32])
{
   SharkSslSha256Ctx hash;
   SharkSslSha256Ctx_constructor(&hash);
   SharkSslSha256Ctx_append(&hash, keyBlob.ptr, keyBlob.len);
   SharkSslSha256Ctx_finish(&hash, fingerprint);
}

static int
sharkSshSendPublicKeyOk(SharkSshCon* connection,
                        SharkSshSpan algorithm, SharkSshSpan keyBlob)
{
   SharkSshWriter writer;
   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_USERAUTH_PK_OK);
   sharkSshWriter_string(&writer, algorithm.ptr, algorithm.len);
   sharkSshWriter_string(&writer, keyBlob.ptr, keyBlob.len);
   return writer.status ? writer.status :
      sharkSshSendPacket(connection, writer.begin,
                         sharkSshWriter_size(&writer));
}

static int
sharkSshAcceptUser(SharkSshCon* connection, SharkSshSpan user,
                   U8 authMethod, const U8* fingerprint)
{
   int status;
   if( ! user.len || user.len > sizeof(connection->user))
      return SharkSshErrAuth;
   memcpy(connection->user, user.ptr, user.len);
   connection->userSize = (U8)user.len;
   connection->authMethod = authMethod;
   if(fingerprint)
      memcpy(connection->publicKeyFingerprint, fingerprint, 32);
   else
      sharkSshZero(connection->publicKeyFingerprint,
                   sizeof(connection->publicKeyFingerprint));
   connection->output[5] = SHARKSSH_MSG_USERAUTH_SUCCESS;
   status = sharkSshSendPacket(connection, connection->output + 5, 1);
   if( ! status)
   {
      connection->authenticated = 1;
      sharkSshLog(connection, SharkSshLogAudit, "SSH user authenticated");
      sharkSshAudit(connection, SharkSshAuditAuthenticationSuccess,
                    SharkSshOk, 0, authMethod, 0, user, fingerprint);
   }
   return status;
}

static int
sharkSshPasswordAuthentication(SharkSshCon* connection,
                               SharkSshReader* reader, SharkSshSpan user,
                               int verify)
{
   SharkSshSpan password;
   U8 changePassword = sharkSshReader_byte(reader);
   int status;
   if(changePassword > 1)
      return SharkSshErrProtocol;
   password = sharkSshReader_string(reader);
   if(changePassword)
   {
      SharkSshSpan newPassword = sharkSshReader_string(reader);
      if( ! sharkSshReader_done(reader))
         status = SharkSshErrProtocol;
      else
         status = SharkSshErrAuth;
      sharkSshZero((void*)password.ptr, password.len);
      sharkSshZero((void*)newPassword.ptr, newPassword.len);
      return status;
   }
   if( ! sharkSshReader_done(reader))
   {
      sharkSshZero((void*)password.ptr, password.len);
      return SharkSshErrProtocol;
   }
   status = verify && user.len && user.len <= sizeof(connection->user) &&
            connection->config->authenticator.password ?
      connection->config->authenticator.password(
         connection->config->authenticator.context, user, password) :
      SharkSshErrAuth;
   sharkSshZero((void*)password.ptr, password.len);
   return status;
}

static int
sharkSshPublicKeyAuthentication(SharkSshCon* connection,
                                SharkSshReader* reader, const U8* payload,
                                SharkSshSpan user, int* isProbe,
                                U8 fingerprint[32], int verify)
{
   SharkSshSpan algorithm;
   SharkSshSpan keyBlob;
   SharkSshSpan exponent;
   SharkSshSpan modulus;
   SharkSshSpan signatureBlob;
   SharkSshSpan signatureAlgorithm;
   SharkSshSpan signature = {0, 0};
   SharkSshReader signatureReader;
   SharkSslRSAKey verificationKey = 0;
   SharkSslSha256Ctx hash;
   U8 signedHash[32];
   U32 signedDataSize;
   U8 hasSignature = sharkSshReader_byte(reader);
   int status = SharkSshErrAuth;

   *isProbe = 0;
   if(hasSignature > 1)
      return SharkSshErrProtocol;
   algorithm = sharkSshReader_string(reader);
   keyBlob = sharkSshReader_string(reader);
   signedDataSize = (U32)(reader->ptr - payload);
   if(reader->status ||
      ! sharkSshSpanEqual(algorithm, publicKeyAlgorithm) ||
      ! sharkSshParseRsaBlob(keyBlob, &exponent, &modulus))
      return reader->status ? SharkSshErrProtocol : SharkSshErrAuth;

   if(hasSignature)
   {
      signatureBlob = sharkSshReader_string(reader);
      if( ! sharkSshReader_done(reader))
         return SharkSshErrProtocol;
      sharkSshReader_constructor(&signatureReader, signatureBlob.ptr,
                                 signatureBlob.len);
      signatureAlgorithm = sharkSshReader_string(&signatureReader);
      signature = sharkSshReader_string(&signatureReader);
      if( ! sharkSshReader_done(&signatureReader) ||
          ! sharkSshSpanEqual(signatureAlgorithm, publicKeyAlgorithm))
         return SharkSshErrAuth;
   }
   else if( ! sharkSshReader_done(reader))
      return SharkSshErrProtocol;

   if( ! verify)
      return SharkSshErrAuth;
   sharkSshPublicKeyFingerprint(keyBlob, fingerprint);
   if(user.len && user.len <= sizeof(connection->user) &&
      connection->config->authenticator.publicKey)
      status = connection->config->authenticator.publicKey(
         connection->config->authenticator.context, user, algorithm,
         keyBlob, fingerprint, &verificationKey);
   if(status || ! sharkSshRsaKeyMatches(verificationKey, exponent, modulus))
      return SharkSshErrAuth;
   if( ! hasSignature)
   {
      *isProbe = 1;
      return sharkSshSendPublicKeyOk(connection, algorithm, keyBlob);
   }
   if(signature.len != SharkSslRSAKey_size(verificationKey))
      return SharkSshErrAuth;

   SharkSslSha256Ctx_constructor(&hash);
   sharkSshHashString(&hash, connection->sessionId,
                      sizeof(connection->sessionId));
   SharkSslSha256Ctx_append(&hash, payload, signedDataSize);
   SharkSslSha256Ctx_finish(&hash, signedHash);
   status = sharkssl_RSA_PKCS1V1_5_verify_hash(
      verificationKey, (U8*)signature.ptr, (U16)signature.len,
      signedHash, SHARKSSL_HASHID_SHA256) == SHARKSSL_RSA_OK ?
         SharkSshOk : SharkSshErrAuth;
   sharkSshZero(signedHash, sizeof(signedHash));
   return status;
}

static int
sharkSshReceiveAuthenticationPacket(SharkSshCon* connection,
                                     U8** payload, U32* payloadSize)
{
   int status;
   for(;;)
   {
      SharkSshReader reader;
      U8 message;
      status = sharkSshReceivePacket(connection, payload, payloadSize);
      if(status)
         return status;
      message = (*payload)[0];
      if(message == SHARKSSH_MSG_KEXINIT)
      {
         status = sharkSshKeyExchange(
            connection, *payload, *payloadSize);
         if(status)
            return status;
         continue;
      }
      if(message != SHARKSSH_MSG_DISCONNECT &&
         message != SHARKSSH_MSG_IGNORE && message != SHARKSSH_MSG_DEBUG)
         return SharkSshOk;
      sharkSshReader_constructor(&reader, *payload, *payloadSize);
      (void)sharkSshReader_byte(&reader);
      status = sharkSshHandleTransportMessage(connection, message, &reader);
      if(status)
         return status;
   }
}

static int
sharkSshControlAuthentication(
   SharkSshCon* connection, const SharkSshAuthenticationAttempt* attempt,
   U32* delay)
{
   *delay = 0;
   if( ! connection->config->abuse.authentication)
      return SharkSshOk;
   return connection->config->abuse.authentication(
      connection->config->abuse.context, connection, attempt, delay) ?
         SharkSshErrAuth : SharkSshOk;
}

static int
sharkSshDelayAuthentication(SharkSshCon* connection, U32 delay)
{
   U32 timeout;
   if( ! delay)
      return SharkSshOk;
   if( ! connection->config->platform.delay)
      return SharkSshErrArgument;
   connection->config->platform.delay(
      connection->config->platform.context, delay);
   if(sharkSshCanceled(connection))
      return SharkSshClosed;
   if(sharkSshReadTimeout(connection, &timeout, 0))
      return sharkSshReportTimeout(connection);
   return SharkSshOk;
}

static void
sharkSshAuthenticationResult(
   SharkSshCon* connection, const SharkSshAuthenticationAttempt* attempt,
   int status)
{
   if(connection->config->abuse.authenticationResult)
      connection->config->abuse.authenticationResult(
         connection->config->abuse.context, connection, attempt, status);
}

static int
sharkSshAuthenticate(SharkSshCon* connection)
{
   U8* payload;
   U32 payloadSize;
   SharkSshReader reader;
   SharkSshSpan service;
   SharkSshSpan user;
   SharkSshSpan method;
   U8 fingerprint[32];
   U8 maxAttempts = connection->config->maxAuthAttempts ?
      connection->config->maxAuthAttempts : SHARKSSH_MAX_AUTH_ATTEMPTS;
   U8 maxRequests = connection->config->maxAuthRequests ?
      connection->config->maxAuthRequests : SHARKSSH_MAX_AUTH_REQUESTS;
   int status;

   status = sharkSshReceiveAuthenticationPacket(
      connection, &payload, &payloadSize);
   if(status)
      return status;
   if(payload[0] == SHARKSSH_MSG_EXT_INFO)
   {
      status = sharkSshParseExtInfo(payload, payloadSize);
      if(status)
         return status;
      sharkSshLog(connection, SharkSshLogInfo,
                  "SSH peer extension information received");
      status = sharkSshReceiveAuthenticationPacket(
         connection, &payload, &payloadSize);
      if(status)
         return status;
   }
   sharkSshReader_constructor(&reader, payload, payloadSize);
   if(sharkSshReader_byte(&reader) != SHARKSSH_MSG_SERVICE_REQUEST)
      return SharkSshErrProtocol;
   service = sharkSshReader_string(&reader);
   if( ! sharkSshReader_done(&reader) ||
       ! sharkSshSpanEqual(service, "ssh-userauth"))
      return SharkSshErrService;
   status = sharkSshSendServiceAccept(connection, service);
   if(status)
      return status;

   while(connection->authAttempts < maxAttempts)
   {
      SharkSshAuthenticationAttempt attempt;
      U32 delay;
      int controlStatus;
      int controlDenied;
      int delayStatus;
      int requestAllowed;
      int isProbe = 0;
      status = sharkSshReceiveAuthenticationPacket(
         connection, &payload, &payloadSize);
      if(status)
         return status;
      sharkSshReader_constructor(&reader, payload, payloadSize);
      if(sharkSshReader_byte(&reader) != SHARKSSH_MSG_USERAUTH_REQUEST)
         return SharkSshErrProtocol;
      user = sharkSshReader_string(&reader);
      service = sharkSshReader_string(&reader);
      method = sharkSshReader_string(&reader);
      if(reader.status || ! sharkSshSpanEqual(service, "ssh-connection"))
         return SharkSshErrProtocol;

      requestAllowed = connection->authRequests < maxRequests;
      if(requestAllowed)
         ++connection->authRequests;
      memset(fingerprint, 0, sizeof(fingerprint));
      memset(&attempt, 0, sizeof(attempt));
      attempt.user = user;
      attempt.requestCount = requestAllowed ?
         connection->authRequests : maxRequests;
      attempt.failedAttempts = connection->authAttempts;
      if(sharkSshSpanEqual(method, "password"))
         attempt.authMethod = SharkSshAuthPassword;
      else if(sharkSshSpanEqual(method, "publickey"))
      {
         attempt.authMethod = SharkSshAuthPublicKey;
         attempt.publicKeyProbe = reader.ptr < reader.end &&
                                  *reader.ptr == 0;
      }
      controlStatus = requestAllowed ?
         sharkSshControlAuthentication(connection, &attempt, &delay) :
         SharkSshErrAuth;
      if( ! requestAllowed)
         delay = 0;
      controlDenied = controlStatus != SharkSshOk;

      if(sharkSshSpanEqual(method, "password"))
         status = sharkSshPasswordAuthentication(
            connection, &reader, user, controlStatus == SharkSshOk);
      else if(sharkSshSpanEqual(method, "publickey"))
      {
         status = sharkSshPublicKeyAuthentication(
            connection, &reader, payload, user, &isProbe, fingerprint,
            controlStatus == SharkSshOk);
      }
      else if(sharkSshSpanEqual(method, "none"))
      {
         status = sharkSshReader_done(&reader) ?
            SharkSshErrAuth : SharkSshErrProtocol;
      }
      else
         status = SharkSshErrAuth;

      if( ! requestAllowed)
      {
         if(status != SharkSshErrProtocol)
            sharkSshAuditResourceUser(
               connection, SharkSshErrAuth,
               SharkSshResourceAuthenticationRequests, user);
         sharkSshZero(fingerprint, sizeof(fingerprint));
         return status == SharkSshErrProtocol ? status : SharkSshErrAuth;
      }
      if(controlDenied && status != SharkSshErrProtocol)
         status = SharkSshErrAuth;
      delayStatus = sharkSshDelayAuthentication(connection, delay);
      if(delayStatus)
      {
         sharkSshAuthenticationResult(
            connection, &attempt, delayStatus);
         sharkSshZero(fingerprint, sizeof(fingerprint));
         return delayStatus;
      }
      if(status == SharkSshErrProtocol)
      {
         sharkSshAuthenticationResult(connection, &attempt, status);
         sharkSshZero(fingerprint, sizeof(fingerprint));
         return status;
      }
      if(isProbe || (attempt.publicKeyProbe &&
                     controlDenied))
      {
         sharkSshAuthenticationResult(
            connection, &attempt, status);
         sharkSshZero(fingerprint, sizeof(fingerprint));
         if(status && isProbe)
            return status;
         if(status)
         {
            status = sharkSshSendAuthFailure(connection);
            if(status)
               return status;
         }
         continue;
      }
      if(sharkSshSpanEqual(method, "none"))
      {
         sharkSshAuthenticationResult(
            connection, &attempt, SharkSshErrAuth);
         status = sharkSshSendAuthFailure(connection);
         if(status)
            return status;
         continue;
      }

      ++connection->authAttempts;
      if(status == SharkSshOk)
      {
         status = sharkSshAcceptUser(
            connection, user,
            sharkSshSpanEqual(method, "publickey") ?
               SharkSshAuthPublicKey : SharkSshAuthPassword,
            sharkSshSpanEqual(method, "publickey") ? fingerprint : 0);
         sharkSshAuthenticationResult(connection, &attempt, status);
         sharkSshZero(fingerprint, sizeof(fingerprint));
         return status;
      }
      sharkSshAuthenticationResult(connection, &attempt, status);
      sharkSshAudit(
         connection, SharkSshAuditAuthenticationFailure, status, 0,
         sharkSshSpanEqual(method, "publickey") ?
            SharkSshAuthPublicKey : SharkSshAuthPassword,
         0, user,
         sharkSshSpanEqual(method, "publickey") ? fingerprint : 0);
      sharkSshZero(fingerprint, sizeof(fingerprint));
      status = sharkSshSendAuthFailure(connection);
      if(status)
         return status;
   }
   sharkSshAuditResourceUser(
      connection, SharkSshErrAuth,
      SharkSshResourceAuthenticationAttempts, user);
   return SharkSshErrAuth;
}

static int
sharkSshHandleGlobalRequest(SharkSshCon* connection,
                            SharkSshReader* reader)
{
   SharkSshSpan request = sharkSshReader_string(reader);
   U8 wantReply = sharkSshReader_byte(reader);
   U8 maxRequests = connection->config->maxGlobalRequests ?
      connection->config->maxGlobalRequests : SHARKSSH_MAX_GLOBAL_REQUESTS;
   if(reader->status || ! sharkSshNameListValid(request, 0) ||
      sharkSshNameListFirst(request).len != request.len || wantReply > 1)
      return SharkSshErrProtocol;
   if(maxRequests && connection->globalRequests >= maxRequests)
   {
      sharkSshAuditResource(
         connection, SharkSshErrBounds, SharkSshResourceGlobalRequests);
      return SharkSshErrBounds;
   }
   if(maxRequests)
      ++connection->globalRequests;
   if(wantReply)
   {
      connection->output[5] = SHARKSSH_MSG_REQUEST_FAILURE;
      return sharkSshSendPacket(connection, connection->output + 5, 1);
   }
   return SharkSshOk;
}

static int
sharkSshHandleGlobalReply(SharkSshCon* connection,
                          SharkSshReader* reader)
{
   if( ! sharkSshReader_done(reader) ||
      ! connection->keepAliveOutstanding)
      return SharkSshErrProtocol;
   --connection->keepAliveOutstanding;
   sharkSshLog(connection, SharkSshLogTrace,
               "SSH keepalive reply received");
   return SharkSshOk;
}

static int
sharkSshSendKeepAlive(SharkSshCon* connection)
{
   SharkSshWriter writer;
   U8 maxMissed = connection->config->keepAliveMaxMissed ?
      connection->config->keepAliveMaxMissed :
      SHARKSSH_DEFAULT_KEEPALIVE_MISSES;
   U32 activity = connection->lastActivityAt;
   int status;

   if(connection->keepAliveOutstanding >= maxMissed)
   {
      connection->timeoutReason = SharkSshTimeoutKeepAlive;
      return sharkSshReportTimeout(connection);
   }
   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_GLOBAL_REQUEST);
   sharkSshWriter_cstring(&writer, "keepalive@openssh.com");
   sharkSshWriter_byte(&writer, 1);
   status = writer.status ? writer.status :
      sharkSshSendPacket(connection, writer.begin,
                         sharkSshWriter_size(&writer));
   if(connection->config->platform.now)
   {
      connection->lastActivityAt = activity;
      if( ! status)
         connection->keepAliveAt = sharkSshNow(connection);
   }
   if( ! status)
   {
      ++connection->keepAliveOutstanding;
      sharkSshLog(connection, SharkSshLogTrace,
                  "SSH keepalive request sent");
   }
   return status;
}

static int
sharkSshHandleTransportMessage(SharkSshCon* connection, U8 message,
                               SharkSshReader* reader)
{
   if(message == SHARKSSH_MSG_IGNORE)
   {
      (void)sharkSshReader_string(reader);
      return sharkSshReader_done(reader) ? SharkSshOk : SharkSshErrProtocol;
   }
   if(message == SHARKSSH_MSG_DEBUG)
   {
      U8 alwaysDisplay = sharkSshReader_byte(reader);
      (void)sharkSshReader_string(reader);
      (void)sharkSshReader_string(reader);
      return alwaysDisplay <= 1 && sharkSshReader_done(reader) ?
         SharkSshOk : SharkSshErrProtocol;
   }
   if(message == SHARKSSH_MSG_DISCONNECT)
   {
      U32 reason = sharkSshReader_u32(reader);
      (void)sharkSshReader_string(reader);
      (void)sharkSshReader_string(reader);
      if(sharkSshReader_done(reader))
      {
         SharkSshSpan empty;
         SharkSshSpan user;
         empty.ptr = 0;
         empty.len = 0;
         user.ptr = connection->user;
         user.len = connection->userSize;
         sharkSshAuditEx(
            connection, SharkSshAuditDisconnect, SharkSshClosed, 0,
            connection->authMethod, connection->channel.serviceType,
            user, connection->authMethod == SharkSshAuthPublicKey ?
               connection->publicKeyFingerprint : 0,
            empty, reason, 1);
         return SharkSshClosed;
      }
      return SharkSshErrProtocol;
   }
   return SharkSshErrProtocol;
}

static int
sharkSshSendChannelReply(SharkSshCon* connection, U8 message)
{
   SharkSshWriter writer;
   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, message);
   sharkSshWriter_u32(&writer, connection->channel.remoteId);
   return writer.status ? writer.status :
      sharkSshSendPacket(connection, writer.begin,
                         sharkSshWriter_size(&writer));
}

static void
sharkSshAuditChannel(SharkSshCon* connection, U8 type, int status)
{
   SharkSshSpan user;
   user.ptr = connection->user;
   user.len = connection->userSize;
   sharkSshAudit(connection, type, status, 0, connection->authMethod,
                 connection->channel.serviceType, user,
                 connection->authMethod == SharkSshAuthPublicKey ?
                    connection->publicKeyFingerprint : 0);
}

static void
sharkSshAuditServiceStopped(SharkSshCon* connection, int status)
{
   SharkSshSpan empty;
   SharkSshSpan user;
   if( ! connection->channel.serviceType)
      return;
   empty.ptr = 0;
   empty.len = 0;
   user.ptr = connection->user;
   user.len = connection->userSize;
   sharkSshAuditEx(
      connection, SharkSshAuditServiceStopped, status, 0,
      connection->authMethod, connection->channel.serviceType, user,
      connection->authMethod == SharkSshAuthPublicKey ?
         connection->publicKeyFingerprint : 0,
      empty, connection->channel.exitStatus,
      connection->channel.exitStatusSent);
}

static void
sharkSshCloseChannel(SharkSshCon* connection, int status)
{
   if( ! connection->channel.open)
      return;
   if( ! connection->channel.closeNotified &&
      connection->config->services.close)
   {
      connection->config->services.close(
         connection->config->services.context, &connection->channel);
      connection->channel.closeNotified = 1;
   }
   sharkSshAuditServiceStopped(connection, status);
   sharkSshAuditChannel(
      connection, SharkSshAuditChannelClosed, status);
   connection->channel.open = 0;
}

static int
sharkSshOpenChannel(SharkSshCon* connection, SharkSshReader* reader)
{
   SharkSshSpan type = sharkSshReader_string(reader);
   U32 sender = sharkSshReader_u32(reader);
   U32 window = sharkSshReader_u32(reader);
   U32 packetLen = sharkSshReader_u32(reader);
   SharkSshWriter writer;
   SharkSshSpan user;
   int status = SharkSshOk;

   if( ! sharkSshReader_done(reader) || ! packetLen)
      return SharkSshErrProtocol;
   if( ! sharkSshSpanEqual(type, "session") || connection->channel.open)
   {
      sharkSshAuditChannel(
         connection, SharkSshAuditChannelRejected, SharkSshErrService);
      if(connection->channel.open)
      {
         sharkSshAuditResource(
            connection, SharkSshErrBounds, SharkSshResourceChannelLimit);
         /* This rejection does not end the connection. */
         connection->resourceAudited = 0;
      }
      sharkSshWriter_constructor(&writer, connection->output + 5,
                                 SHARKSSH_MAX_PACKET_LEN);
      sharkSshWriter_byte(&writer, SHARKSSH_MSG_CHANNEL_OPEN_FAILURE);
      sharkSshWriter_u32(&writer, sender);
      sharkSshWriter_u32(&writer, 1);
      sharkSshWriter_cstring(&writer, "Only one session channel is supported");
      sharkSshWriter_cstring(&writer, "");
      return writer.status ? writer.status :
         sharkSshSendPacket(connection, writer.begin,
                            sharkSshWriter_size(&writer));
   }

   connection->channel.remoteId = sender;
   connection->channel.remoteWindow = window;
   connection->channel.remotePacketLen = packetLen;
   connection->channel.localWindow = SHARKSSH_CHANNEL_WINDOW;
   user.ptr = connection->user;
   user.len = connection->userSize;
   if(connection->config->services.open)
      status = connection->config->services.open(
         connection->config->services.context, &connection->channel, user);
   if(status)
   {
      sharkSshAuditChannel(
         connection, SharkSshAuditChannelRejected, status);
      sharkSshWriter_constructor(&writer, connection->output + 5,
                                 SHARKSSH_MAX_PACKET_LEN);
      sharkSshWriter_byte(&writer, SHARKSSH_MSG_CHANNEL_OPEN_FAILURE);
      sharkSshWriter_u32(&writer, sender);
      sharkSshWriter_u32(&writer, 1);
      sharkSshWriter_cstring(&writer, "Session rejected");
      sharkSshWriter_cstring(&writer, "");
      return writer.status ? writer.status :
         sharkSshSendPacket(connection, writer.begin,
                            sharkSshWriter_size(&writer));
   }
   connection->channel.open = 1;
   sharkSshAuditChannel(
      connection, SharkSshAuditChannelOpened, SharkSshOk);

   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_CHANNEL_OPEN_CONFIRMATION);
   sharkSshWriter_u32(&writer, sender);
   sharkSshWriter_u32(&writer, connection->channel.localId);
   sharkSshWriter_u32(&writer, connection->channel.localWindow);
   sharkSshWriter_u32(&writer, SHARKSSH_CHANNEL_PACKET_LEN);
   return writer.status ? writer.status :
      sharkSshSendPacket(connection, writer.begin,
                         sharkSshWriter_size(&writer));
}

static int
sharkSshAuthorizeService(SharkSshCon* connection, U8 serviceType,
                         SharkSshSpan request)
{
   SharkSshAuthorization authorization;
   if( ! connection->config->services.authorize)
      return SharkSshOk;
   authorization.user.ptr = connection->user;
   authorization.user.len = connection->userSize;
   authorization.authMethod = connection->authMethod;
   authorization.serviceType = serviceType;
   authorization.request = request;
   if(connection->authMethod == SharkSshAuthPublicKey)
   {
      authorization.publicKeyFingerprint.ptr =
         connection->publicKeyFingerprint;
      authorization.publicKeyFingerprint.len =
         sizeof(connection->publicKeyFingerprint);
   }
   else
   {
      authorization.publicKeyFingerprint.ptr = 0;
      authorization.publicKeyFingerprint.len = 0;
   }
   return connection->config->services.authorize(
      connection->config->services.context, &connection->channel,
      &authorization);
}

static int
sharkSshHandleChannelRequest(SharkSshCon* connection,
                             SharkSshReader* reader)
{
   U32 recipient = sharkSshReader_u32(reader);
   SharkSshSpan request = sharkSshReader_string(reader);
   SharkSshSpan auditRequest;
   U8 wantReply = sharkSshReader_byte(reader);
   SharkSshServices const* services = &connection->config->services;
   U8 requestedService = 0;
   int accepted = 0;
   int status = SharkSshOk;

   auditRequest.ptr = 0;
   auditRequest.len = 0;

   if(reader->status || wantReply > 1 ||
      recipient != connection->channel.localId ||
      ! connection->channel.open)
      return SharkSshErrProtocol;

   if(sharkSshSpanEqual(request, "pty-req"))
   {
      SharkSshSpan terminal = sharkSshReader_string(reader);
      U32 columns = sharkSshReader_u32(reader);
      U32 rows = sharkSshReader_u32(reader);
      U32 width = sharkSshReader_u32(reader);
      U32 height = sharkSshReader_u32(reader);
      SharkSshSpan modes = sharkSshReader_string(reader);
      if(sharkSshReader_done(reader) &&
         ! connection->channel.closeSent &&
         ! connection->channel.serviceType &&
         services->pty)
         accepted = services->pty(services->context, &connection->channel,
                                  terminal, columns, rows, width, height,
                                  modes) == 0;
   }
   else if(sharkSshSpanEqual(request, "window-change"))
   {
      U32 columns = sharkSshReader_u32(reader);
      U32 rows = sharkSshReader_u32(reader);
      U32 width = sharkSshReader_u32(reader);
      U32 height = sharkSshReader_u32(reader);
      if(sharkSshReader_done(reader) &&
         ! connection->channel.closeSent && services->windowChange)
         accepted = services->windowChange(
            services->context, &connection->channel,
            columns, rows, width, height) == 0;
   }
   else if(sharkSshSpanEqual(request, "shell"))
   {
      SharkSshSpan empty = {0, 0};
      requestedService = SharkSshServiceShell;
      if(sharkSshReader_done(reader) &&
         ! connection->channel.closeSent &&
         ! connection->channel.serviceType &&
         services->shell &&
         sharkSshAuthorizeService(connection, SharkSshServiceShell,
                                  empty) == 0)
      {
         accepted = services->shell(services->context,
                                    &connection->channel) == 0;
         connection->channel.serviceType = accepted ?
            SharkSshServiceShell : 0;
      }
   }
   else if(sharkSshSpanEqual(request, "exec"))
   {
      SharkSshSpan command = sharkSshReader_string(reader);
      auditRequest = command;
      requestedService = SharkSshServiceExec;
      if(sharkSshReader_done(reader) &&
         ! connection->channel.closeSent &&
         ! connection->channel.serviceType &&
         services->exec &&
         sharkSshAuthorizeService(connection, SharkSshServiceExec,
                                  command) == 0)
      {
         status = services->exec(services->context, &connection->channel,
                                 command);
         accepted = status == 0;
         connection->channel.serviceType = accepted ?
            SharkSshServiceExec : 0;
      }
   }
   else if(sharkSshSpanEqual(request, "subsystem"))
   {
      SharkSshSpan name = sharkSshReader_string(reader);
      auditRequest = name;
      requestedService = SharkSshServiceSubsystem;
      if(sharkSshReader_done(reader) &&
         ! connection->channel.closeSent &&
         ! connection->channel.serviceType &&
         services->subsystem &&
         sharkSshAuthorizeService(connection, SharkSshServiceSubsystem,
                                  name) == 0)
         accepted = services->subsystem(
            services->context, &connection->channel, name,
            connection->config->fileSystem) == 0;
      connection->channel.serviceType = accepted ?
         SharkSshServiceSubsystem : 0;
   }

   if(reader->status)
      return SharkSshErrProtocol;
   /* Channel requests can already be in flight when our CLOSE is sent. */
   if(connection->channel.closeSent)
      return SharkSshOk;
   if(requestedService)
   {
      SharkSshSpan user;
      user.ptr = connection->user;
      user.len = connection->userSize;
      sharkSshAuditEx(
         connection,
         accepted ? SharkSshAuditServiceStarted :
                    SharkSshAuditServiceDenied,
         accepted ? SharkSshOk : SharkSshErrService, 0,
         connection->authMethod, requestedService, user,
         connection->authMethod == SharkSshAuthPublicKey ?
            connection->publicKeyFingerprint : 0,
         auditRequest, 0, 0);
   }
   if(wantReply)
   {
      status = sharkSshSendChannelReply(
         connection, accepted ? SHARKSSH_MSG_CHANNEL_SUCCESS :
                                SHARKSSH_MSG_CHANNEL_FAILURE);
      if(status)
         return status;
   }
   if(accepted && connection->channel.serviceType && services->writable)
   {
      status = services->writable(services->context, &connection->channel);
      if(status == SharkSshTimeout)
         status = SharkSshOk;
      return status;
   }
   return SharkSshOk;
}

static int
sharkSshHandleChannelData(SharkSshCon* connection,
                          SharkSshReader* reader)
{
   U32 recipient = sharkSshReader_u32(reader);
   SharkSshSpan data = sharkSshReader_string(reader);
   SharkSshWriter writer;
   int status;
   if( ! sharkSshReader_done(reader) ||
       recipient != connection->channel.localId ||
       data.len > connection->channel.localWindow ||
       connection->channel.remoteEof ||
       (connection->channel.closeSent && data.len) ||
       ! connection->channel.serviceType)
      return SharkSshErrProtocol;
   if(connection->channel.closeSent)
      return SharkSshOk;
   connection->channel.localWindow -= data.len;
   if(connection->config->services.data)
      status = connection->config->services.data(
         connection->config->services.context, &connection->channel, data);
   else
      status = SharkSshErrService;
   if(status == SharkSshTimeout)
      status = SharkSshOk;
   if(status)
      return status;
   if( ! data.len || connection->channel.closeSent)
   {
      connection->channel.localWindow += data.len;
      return SharkSshOk;
   }

   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_CHANNEL_WINDOW_ADJUST);
   sharkSshWriter_u32(&writer, connection->channel.remoteId);
   sharkSshWriter_u32(&writer, data.len);
   connection->channel.localWindow += data.len;
   return writer.status ? writer.status :
      sharkSshSendPacket(connection, writer.begin,
                         sharkSshWriter_size(&writer));
}

static int
sharkSshHandleConnectionPacket(SharkSshCon* connection,
                               U8* payload, U32 payloadSize)
{
   SharkSshReader reader;
   U8 message;
   int status;

   sharkSshReader_constructor(&reader, payload, payloadSize);
   message = sharkSshReader_byte(&reader);
   switch(message)
   {
         case SHARKSSH_MSG_KEXINIT:
            status = sharkSshKeyExchange(
               connection, payload, payloadSize);
            break;

         case SHARKSSH_MSG_GLOBAL_REQUEST:
            status = sharkSshHandleGlobalRequest(connection, &reader);
            break;

         case SHARKSSH_MSG_REQUEST_SUCCESS:
         case SHARKSSH_MSG_REQUEST_FAILURE:
            status = sharkSshHandleGlobalReply(connection, &reader);
            break;

         case SHARKSSH_MSG_CHANNEL_OPEN:
            status = sharkSshOpenChannel(connection, &reader);
            break;

         case SHARKSSH_MSG_CHANNEL_REQUEST:
            status = sharkSshHandleChannelRequest(connection, &reader);
            break;

         case SHARKSSH_MSG_CHANNEL_DATA:
            status = sharkSshHandleChannelData(connection, &reader);
            break;

         case SHARKSSH_MSG_CHANNEL_WINDOW_ADJUST:
         {
            U32 recipient = sharkSshReader_u32(&reader);
            U32 increment = sharkSshReader_u32(&reader);
            if( ! sharkSshReader_done(&reader) ||
                recipient != connection->channel.localId ||
               ! increment ||
               0xFFFFFFFFU - connection->channel.remoteWindow < increment)
               status = SharkSshErrProtocol;
            else
            {
               connection->channel.remoteWindow += increment;
               status = SharkSshOk;
               if(connection->channel.serviceType &&
                  ! connection->channel.closeSent &&
                  connection->config->services.writable)
               {
                  status = connection->config->services.writable(
                     connection->config->services.context,
                     &connection->channel);
                  if(status == SharkSshTimeout)
                     status = SharkSshOk;
               }
            }
            break;
         }

         case SHARKSSH_MSG_CHANNEL_EOF:
            if(sharkSshReader_u32(&reader) !=
                  connection->channel.localId ||
               ! sharkSshReader_done(&reader) ||
               connection->channel.remoteEof ||
               ! connection->channel.serviceType)
               status = SharkSshErrProtocol;
            else
            {
               connection->channel.remoteEof = 1;
               status = ! connection->channel.closeSent &&
                        connection->config->services.eof &&
                        connection->channel.serviceType ?
                  connection->config->services.eof(
                     connection->config->services.context,
                     &connection->channel) : SharkSshOk;
               if(status == SharkSshTimeout)
                  status = SharkSshOk;
            }
            break;

         case SHARKSSH_MSG_CHANNEL_CLOSE:
            status = sharkSshReader_u32(&reader) ==
                     connection->channel.localId &&
                     sharkSshReader_done(&reader) ? SharkSshOk :
                                                   SharkSshErrProtocol;
            if( ! status)
            {
               if(connection->channel.open &&
                  ! connection->channel.closeSent)
                  (void)sharkSshSendChannelReply(
                     connection, SHARKSSH_MSG_CHANNEL_CLOSE);
               sharkSshCloseChannel(connection, SharkSshOk);
               return SHARKSSH_CHANNEL_COMPLETE;
            }
            break;

         case SHARKSSH_MSG_DISCONNECT:
         case SHARKSSH_MSG_IGNORE:
         case SHARKSSH_MSG_DEBUG:
            status = sharkSshHandleTransportMessage(
               connection, message, &reader);
            if(status == SharkSshClosed)
               return status;
            break;

         default:
         {
            SharkSshWriter writer;
            sharkSshWriter_constructor(&writer, connection->output + 5,
                                       SHARKSSH_MAX_PACKET_LEN);
            sharkSshWriter_byte(&writer, SHARKSSH_MSG_UNIMPLEMENTED);
            sharkSshWriter_u32(&writer, connection->receiveSequence - 1);
            status = writer.status ? writer.status :
               sharkSshSendPacket(connection, writer.begin,
                                  sharkSshWriter_size(&writer));
            break;
         }
   }
   return status;
}

static int
sharkSshConnectionLoop(SharkSshCon* connection)
{
   U8* payload;
   U32 payloadSize;
   int status;
   for(;;)
   {
      int rekeyDue =
         (connection->config->rekeyBytes &&
          (connection->bytesReceived - connection->rekeyReceivedAt >=
              connection->config->rekeyBytes ||
           connection->bytesSent - connection->rekeySentAt >=
              connection->config->rekeyBytes)) ||
         (connection->config->rekeyPackets &&
          (connection->packetsReceived -
              connection->rekeyPacketsReceivedAt >=
                 connection->config->rekeyPackets ||
           connection->packetsSent - connection->rekeyPacketsSentAt >=
              connection->config->rekeyPackets)) ||
         (connection->config->rekeyTime &&
          connection->config->platform.now &&
          sharkSshNow(connection) - connection->rekeyStartedAt >=
             connection->config->rekeyTime);
      if(rekeyDue)
      {
         status = sharkSshKeyExchange(connection, 0, 0);
         if(status)
            return status == SharkSshClosed ? SharkSshOk : status;
      }
      else if(connection->config->keepAliveInterval &&
              connection->config->platform.now &&
              sharkSshNow(connection) - connection->keepAliveAt >=
                 connection->config->keepAliveInterval)
      {
         status = sharkSshSendKeepAlive(connection);
         if(status)
            return status;
      }
      status = sharkSshReceivePacketEx(
         connection, &payload, &payloadSize, 1);
      if(status == SHARKSSH_MAINTENANCE)
         continue;
      if(status)
         return status;
      status = sharkSshHandleConnectionPacket(
         connection, payload, payloadSize);
      if(status)
         return status == SHARKSSH_CHANNEL_COMPLETE ? SharkSshOk : status;
   }
}

static int
sharkSshChannelWriteSomeType(SharkSshChannel* channel, const void* data,
                             U32 size, U32* written, U8 extended)
{
   SharkSshCon* connection;
   const U8* ptr = (const U8*)data;
   if( ! written)
      return SharkSshErrArgument;
   *written = 0;
   if( ! channel || ! channel->connection || (size && ! data))
      return SharkSshErrArgument;
   connection = channel->connection;
   if( ! channel->open || channel->localEof)
      return SharkSshErrState;

   while(size)
   {
      SharkSshWriter writer;
      U32 chunk = size;
      U32 headerSize = extended ? 13 : 9;
      int status;
      if( ! channel->remoteWindow)
         break;
      if(chunk > channel->remoteWindow)
         chunk = channel->remoteWindow;
      if(chunk > channel->remotePacketLen)
         chunk = channel->remotePacketLen;
      if(chunk > SHARKSSH_MAX_PACKET_LEN - headerSize)
         chunk = SHARKSSH_MAX_PACKET_LEN - headerSize;
      if( ! chunk)
         return SharkSshErrBounds;

      sharkSshWriter_constructor(&writer, connection->output + 5,
                                 SHARKSSH_MAX_PACKET_LEN);
      sharkSshWriter_byte(&writer, extended ?
                          SHARKSSH_MSG_CHANNEL_EXTENDED_DATA :
                          SHARKSSH_MSG_CHANNEL_DATA);
      sharkSshWriter_u32(&writer, channel->remoteId);
      if(extended)
         sharkSshWriter_u32(&writer, 1);
      sharkSshWriter_string(&writer, ptr, chunk);
      status = writer.status ? writer.status :
         sharkSshSendPacket(connection, writer.begin,
                            sharkSshWriter_size(&writer));
      if(status)
         return status;
      channel->remoteWindow -= chunk;
      ptr += chunk;
      size -= chunk;
      *written += chunk;
   }
   return size ? SharkSshTimeout : SharkSshOk;
}

int
SharkSshChannel_write(SharkSshChannel* channel, const void* data, U32 size)
{
   U32 written;
   if(channel && size > channel->remoteWindow)
      return SharkSshTimeout;
   return sharkSshChannelWriteSomeType(channel, data, size, &written, 0);
}

int
SharkSshChannel_writeError(SharkSshChannel* channel,
                           const void* data, U32 size)
{
   U32 written;
   if(channel && size > channel->remoteWindow)
      return SharkSshTimeout;
   return sharkSshChannelWriteSomeType(channel, data, size, &written, 1);
}

int
SharkSshChannel_writeSome(SharkSshChannel* channel, const void* data,
                          U32 size, U32* written)
{
   return sharkSshChannelWriteSomeType(channel, data, size, written, 0);
}

int
SharkSshChannel_writeErrorSome(SharkSshChannel* channel,
                               const void* data, U32 size, U32* written)
{
   return sharkSshChannelWriteSomeType(channel, data, size, written, 1);
}

int
SharkSshChannel_sendExitStatus(SharkSshChannel* channel, U32 exitStatus)
{
   SharkSshWriter writer;
   SharkSshCon* connection;
   int status;
   if( ! channel || ! channel->connection || ! channel->open ||
      ! channel->serviceType || channel->closeSent ||
      channel->exitStatusSent)
      return SharkSshErrState;
   connection = channel->connection;
   sharkSshWriter_constructor(&writer, connection->output + 5,
                              SHARKSSH_MAX_PACKET_LEN);
   sharkSshWriter_byte(&writer, SHARKSSH_MSG_CHANNEL_REQUEST);
   sharkSshWriter_u32(&writer, channel->remoteId);
   sharkSshWriter_cstring(&writer, "exit-status");
   sharkSshWriter_byte(&writer, 0);
   sharkSshWriter_u32(&writer, exitStatus);
   if(writer.status)
      return writer.status;
   status = sharkSshSendPacket(connection, writer.begin,
                               sharkSshWriter_size(&writer));
   if( ! status)
   {
      channel->exitStatusSent = 1;
      channel->exitStatus = exitStatus;
   }
   return status;
}

int
SharkSshChannel_sendEof(SharkSshChannel* channel)
{
   int status;
   if( ! channel || ! channel->connection || ! channel->open)
      return SharkSshErrState;
   if(channel->localEof)
      return SharkSshOk;
   status = sharkSshSendChannelReply(channel->connection,
                                     SHARKSSH_MSG_CHANNEL_EOF);
   if( ! status)
      channel->localEof = 1;
   return status;
}

int
SharkSshChannel_close(SharkSshChannel* channel)
{
   int status;
   if( ! channel || ! channel->connection || ! channel->open)
      return SharkSshErrState;
   if(channel->closeSent)
      return SharkSshOk;
   status = SharkSshChannel_sendEof(channel);
   if( ! status)
   {
      status = sharkSshSendChannelReply(channel->connection,
                                        SHARKSSH_MSG_CHANNEL_CLOSE);
      if( ! status)
         channel->closeSent = 1;
   }
   return status;
}

void
SharkSshConfig_constructor(SharkSshConfig* config)
{
   if(config)
   {
      memset(config, 0, sizeof(*config));
      config->ioTimeout = SHARKSSH_TIMEOUT_INFINITE;
      config->rekeyBytes = SHARKSSH_DEFAULT_REKEY_BYTES;
      config->maxAuthAttempts = SHARKSSH_MAX_AUTH_ATTEMPTS;
      config->maxAuthRequests = SHARKSSH_MAX_AUTH_REQUESTS;
      config->maxGlobalRequests = SHARKSSH_MAX_GLOBAL_REQUESTS;
      config->keepAliveMaxMissed = SHARKSSH_DEFAULT_KEEPALIVE_MISSES;
   }
}

void
SharkSshCon_constructor(SharkSshCon* connection,
                        const SharkSshConfig* config
#if ! SHARKSSL_BA
                        ,
                        SeCtx* socketContext)
#else
                        )
#endif
{
   memset(connection, 0, sizeof(*connection));
   connection->config = config;
   connection->channel.connection = connection;
   connection->channel.localId = 0;
#if ! SHARKSSL_BA
   SOCKET_constructor(&connection->socket, socketContext);
#endif
}

static int
sharkSshSocketValid(SharkSshCon* connection)
{
#if SHARKSSL_BA
   return SoDispCon_isValid(&connection->socket);
#else
   return se_sockValid(&connection->socket);
#endif
}

int
SharkSshCon_run(SharkSshCon* connection)
{
   SharkSshSpan user;
   int status;
   if( ! connection || ! connection->config ||
       ! sharkSshSocketValid(connection))
      return SharkSshErrArgument;

   if(connection->config->platform.now)
   {
      connection->startedAt = sharkSshNow(connection);
      connection->phaseStartedAt = connection->startedAt;
      connection->lastActivityAt = connection->startedAt;
      connection->keepAliveAt = connection->startedAt;
   }
   user.ptr = 0;
   user.len = 0;
   sharkSshAudit(connection, SharkSshAuditConnectionAccepted, SharkSshOk,
                 0, SharkSshAuthNone, 0, user, 0);
   sharkSshAudit(connection, SharkSshAuditSessionStart, SharkSshOk, 0,
                 SharkSshAuthNone, 0, user, 0);
   if(connection->config->abuse.admit)
   {
      status = connection->config->abuse.admit(
         connection->config->abuse.context, connection) ?
            SharkSshErrAuth : SharkSshOk;
      if(status)
      {
         sharkSshAudit(
            connection, SharkSshAuditConnectionRejected, status, 0,
            SharkSshAuthNone, 0, user, 0);
         goto done;
      }
      connection->abuseAdmitted = 1;
   }
   connection->state = SharkSshStateVersion;
   status = sharkSshIdentification(connection);
   if(status)
      goto done;
   connection->state = SharkSshStateKeyExchange;
   status = sharkSshKeyExchange(connection, 0, 0);
   if(status)
      goto done;
   connection->state = SharkSshStateAuthentication;
   if(connection->config->platform.now)
      connection->phaseStartedAt = sharkSshNow(connection);
   status = sharkSshAuthenticate(connection);
   if(status)
      goto done;
   connection->state = SharkSshStateConnection;
   status = sharkSshConnectionLoop(connection);

done:
   user.ptr = connection->user;
   user.len = connection->userSize;
   if(status == SharkSshErrProtocol)
      sharkSshAudit(
         connection, SharkSshAuditProtocolFailure, status, 0,
         connection->authMethod, connection->channel.serviceType, user,
         connection->authMethod == SharkSshAuthPublicKey ?
            connection->publicKeyFingerprint : 0);
   if(status == SharkSshErrBounds && ! connection->resourceAudited)
      sharkSshAuditResource(
         connection, status, SharkSshResourceUnspecified);
   if((status < 0 ||
       (status == SharkSshClosed &&
        connection->cancelMode == SharkSshCancelGraceful)) &&
      sharkSshSocketValid(connection) &&
      connection->state != SharkSshStateNew)
   {
      SharkSshSpan empty;
      U32 disconnectReason =
         connection->cancelMode == SharkSshCancelGraceful ||
         status == SharkSshErrAuth ? SHARKSSH_DISCONNECT_BY_APPLICATION :
         status == SharkSshErrCrypto &&
         connection->state == SharkSshStateKeyExchange ?
            SHARKSSH_DISCONNECT_KEY_EXCHANGE_FAILED :
         status == SharkSshErrCrypto ? SHARKSSH_DISCONNECT_MAC_ERROR :
                                       SHARKSSH_DISCONNECT_PROTOCOL_ERROR;
      empty.ptr = 0;
      empty.len = 0;
      sharkSshAuditEx(
         connection, SharkSshAuditDisconnect, status, 0,
         connection->authMethod, connection->channel.serviceType, user,
         connection->authMethod == SharkSshAuthPublicKey ?
            connection->publicKeyFingerprint : 0,
         empty, disconnectReason, 1);
      connection->sendingDisconnect = 1;
      (void)sharkSshSendDisconnect(
         connection, disconnectReason,
         "SharkSSH session terminated");
      connection->sendingDisconnect = 0;
   }
   sharkSshCloseChannel(connection, status);
   user.ptr = connection->user;
   user.len = connection->userSize;
   sharkSshAudit(connection, SharkSshAuditSessionEnd, status, 0,
                 connection->authMethod, connection->channel.serviceType,
                 user,
                 connection->authMethod == SharkSshAuthPublicKey ?
                    connection->publicKeyFingerprint : 0);
   if(connection->abuseAdmitted && connection->config->abuse.release)
      connection->config->abuse.release(
         connection->config->abuse.context, connection);
   connection->abuseAdmitted = 0;
   return status;
}

void
SharkSshCon_destructor(SharkSshCon* connection)
{
   if( ! connection)
      return;
   if(connection->channel.open && connection->config)
      sharkSshCloseChannel(connection, SharkSshClosed);
   else
      connection->channel.open = 0;
   if(sharkSshSocketValid(connection))
#if SHARKSSL_BA
      SoDispCon_destructor(&connection->socket);
#else
      se_close(&connection->socket);
#endif
   SharkSslAesCtx_destructor(&connection->receiveAes);
   SharkSslAesCtx_destructor(&connection->sendAes);
   sharkSshZero(connection->receiveCounter,
                sizeof(connection->receiveCounter));
   sharkSshZero(connection->sendCounter, sizeof(connection->sendCounter));
   sharkSshZero(connection->receiveMacKey,
                sizeof(connection->receiveMacKey));
   sharkSshZero(connection->sendMacKey, sizeof(connection->sendMacKey));
   sharkSshZero(connection->sessionId, sizeof(connection->sessionId));
   sharkSshZero(connection->publicKeyFingerprint,
                sizeof(connection->publicKeyFingerprint));
   sharkSshZero(connection->user, sizeof(connection->user));
   sharkSshZero(connection->input, sizeof(connection->input));
   sharkSshZero(connection->output, sizeof(connection->output));
   sharkSshZero(connection->clientKex, sizeof(connection->clientKex));
   sharkSshZero(connection->serverKex, sizeof(connection->serverKex));
   sharkSshZero(connection->hostKey, sizeof(connection->hostKey));
   connection->encryptedInput = 0;
   connection->encryptedOutput = 0;
   connection->authenticated = 0;
   connection->abuseData = 0;
   connection->authAttempts = 0;
   connection->authRequests = 0;
   connection->globalRequests = 0;
   connection->authMethod = SharkSshAuthNone;
   connection->userSize = 0;
   connection->keepAliveOutstanding = 0;
   connection->cancelMode = SharkSshCancelNone;
   connection->sendingDisconnect = 0;
   connection->abuseAdmitted = 0;
   connection->resourceAudited = 0;
   connection->state = SharkSshStateClosed;
}

#if SHARKSSL_BA

static void
sharkSshServerThread(Thread* thread)
{
   SharkSshCon* connection = (SharkSshCon*)thread;
   SharkSshServer* server = connection->server;
   ThreadMutex* mutex;
   (void)SharkSshCon_run(connection);
   SharkSshCon_destructor(connection);
#if !defined(BA_FREERTOS)
   Thread_destructor(thread);
#endif /* !BA_FREERTOS */
   mutex = SoDisp_getMutex(server->dispatcher);
   if(mutex)
      ThreadMutex_set(mutex);
   baAssert(server->activeConnections);
   if(server->activeConnections)
      --server->activeConnections;
   ++server->completedConnections;
   if(mutex)
      ThreadMutex_release(mutex);
   if(server->allocator.release)
      server->allocator.release(server->allocator.context, connection);
   else
      baFree(connection);
#if defined(BA_FREERTOS)
   vTaskDelete(0);
   baAssert(0);
#endif /* BA_FREERTOS */
}

static void
sharkSshServerAccept(HttpServCon* listener, HttpConnection* temporary)
{
   SharkSshServer* server = (SharkSshServer*)listener;
   SharkSshCon* connection;
   int status;
   if(server->activeConnections >= server->maxConnections)
   {
      ++server->rejectedConnections;
      sharkSshAuditConfig(
         server->config, SharkSshAuditConnectionRejected,
         SharkSshErrBounds, SharkSshResourceConnectionLimit);
      sharkSshAuditConfig(
         server->config, SharkSshAuditResourceRejected,
         SharkSshErrBounds, SharkSshResourceConnectionLimit);
      return;
   }
   if(server->allocator.allocate)
      connection = (SharkSshCon*)server->allocator.allocate(
         server->allocator.context, sizeof(*connection));
   else
      connection = (SharkSshCon*)baMalloc(sizeof(*connection));
   if( ! connection)
   {
      ++server->rejectedConnections;
      sharkSshAuditConfig(
         server->config, SharkSshAuditConnectionRejected,
         SharkSshErrBounds, SharkSshResourceConnectionAllocation);
      sharkSshAuditConfig(
         server->config, SharkSshAuditResourceRejected,
         SharkSshErrBounds, SharkSshResourceConnectionAllocation);
      return;
   }
   SharkSshCon_constructor(connection, server->config);
   Thread_constructor(&connection->thread, sharkSshServerThread,
                      ThreadPrioNormal, SHARKSSH_THREAD_STACK_SIZE);
   status = SoDispCon_moveCon((SoDispCon*)temporary, &connection->socket);
   if(status)
   {
      Thread_destructor(&connection->thread);
      if(server->allocator.release)
         server->allocator.release(server->allocator.context, connection);
      else
         baFree(connection);
      ++server->rejectedConnections;
      sharkSshAuditConfig(
         server->config, SharkSshAuditConnectionRejected,
         SharkSshErrSocket, 0);
      return;
   }
   connection->socket.dispatcher = ((SoDispCon*)temporary)->dispatcher;
   connection->server = server;
   ++server->activeConnections;
   if(server->peakConnections < server->activeConnections)
      server->peakConnections = server->activeConnections;
   Thread_start(&connection->thread);
}

void
SharkSshServer_constructor(SharkSshServer* server,
                           const SharkSshConfig* config,
                           HttpServer* httpServer)
{
   memset(server, 0, sizeof(*server));
   server->config = config;
   server->httpServer = httpServer;
   server->dispatcher = httpServer ? HttpServer_getDispatcher(httpServer) : 0;
   server->maxConnections = SHARKSSH_DEFAULT_MAX_CONNECTIONS;
}

int
SharkSshServer_setConnectionAllocator(
   SharkSshServer* server, const SharkSshConnectionAllocator* allocator)
{
   if( ! server)
      return SharkSshErrArgument;
   if(server->listening || server->activeConnections)
      return SharkSshErrState;
   if(allocator && ( ! allocator->allocate || ! allocator->release))
      return SharkSshErrArgument;
   if(allocator)
      server->allocator = *allocator;
   else
      memset(&server->allocator, 0, sizeof(server->allocator));
   return SharkSshOk;
}

int
SharkSshServer_setMaxConnections(SharkSshServer* server,
                                 U16 maxConnections)
{
   if( ! server || ! maxConnections)
      return SharkSshErrArgument;
   if(server->listening || server->activeConnections)
      return SharkSshErrState;
   server->maxConnections = maxConnections;
   return SharkSshOk;
}

int
SharkSshServer_bind(SharkSshServer* server, U16 port)
{
   if( ! server || ! server->config || ! server->httpServer ||
       ! server->dispatcher)
      return SharkSshErrArgument;
   if(server->listening)
      return SharkSshErrState;
   HttpServCon_constructor(&server->listener, server->httpServer,
                           server->dispatcher, port, FALSE, 0,
                           sharkSshServerAccept);
   if( ! HttpServCon_isValid(&server->listener))
      return SharkSshErrSocket;
   server->port = port;
   server->listening = 1;
   sharkSshAuditConfigEx(
      server->config, SharkSshAuditServerStarted, SharkSshOk, 0,
      server->port, 1);
   return SharkSshOk;
}

static U32
sharkSshServerGetCount(SharkSshServer* server, volatile U32* count)
{
   ThreadMutex* mutex;
   U32 value;
   int setMutex = 0;
   if( ! server || ! server->dispatcher)
      return 0;
   mutex = SoDisp_getMutex(server->dispatcher);
   if(mutex && ! ThreadMutex_isOwner(mutex))
   {
      ThreadMutex_set(mutex);
      setMutex = 1;
   }
   value = *count;
   if(setMutex)
      ThreadMutex_release(mutex);
   return value;
}

U32
SharkSshServer_activeConnections(SharkSshServer* server)
{
   if( ! server)
      return 0;
   return sharkSshServerGetCount(server, &server->activeConnections);
}

U32
SharkSshServer_completedConnections(SharkSshServer* server)
{
   if( ! server)
      return 0;
   return sharkSshServerGetCount(server, &server->completedConnections);
}

U32
SharkSshServer_rejectedConnections(SharkSshServer* server)
{
   if( ! server)
      return 0;
   return sharkSshServerGetCount(server, &server->rejectedConnections);
}

U32
SharkSshServer_peakConnections(SharkSshServer* server)
{
   if( ! server)
      return 0;
   return sharkSshServerGetCount(server, &server->peakConnections);
}

void
SharkSshServer_stop(SharkSshServer* server)
{
   if(server && server->listening)
   {
      HttpServCon_destructor(&server->listener);
      server->listening = 0;
      sharkSshAuditConfigEx(
         server->config, SharkSshAuditServerStopped, SharkSshOk, 0,
         server->port, 1);
   }
}

void
SharkSshServer_destructor(SharkSshServer* server)
{
   if( ! server)
      return;
   SharkSshServer_stop(server);
   baAssert( ! server->activeConnections);
}

#else

void
SharkSshServer_constructor(SharkSshServer* server,
                           const SharkSshConfig* config,
                           SeCtx* socketContext)
{
   memset(server, 0, sizeof(*server));
   server->config = config;
   SOCKET_constructor(&server->socket, socketContext);
}

int
SharkSshServer_bind(SharkSshServer* server, U16 port)
{
   int status;
   if( ! server || ! server->config)
      return SharkSshErrArgument;
   if(server->listening)
      return SharkSshErrState;
   status = se_bind(&server->socket, port);
   if(status)
      return SharkSshErrSocket;
   server->port = port;
   server->listening = 1;
   sharkSshAuditConfigEx(
      server->config, SharkSshAuditServerStarted, SharkSshOk, 0,
      server->port, 1);
   return SharkSshOk;
}

int
SharkSshServer_accept(SharkSshServer* server, SharkSshCon* connection,
                      SeCtx* socketContext, U32 timeout)
{
   SOCKET* listenSocket;
   SOCKET* connectionSocket;
   int status;
   if( ! server || ! connection || ! server->listening)
      return SharkSshErrArgument;
   SharkSshCon_constructor(connection, server->config, socketContext);
   listenSocket = &server->socket;
   connectionSocket = &connection->socket;
   status = se_accept(&listenSocket, timeout, &connectionSocket);
   if(status == 0)
      return SharkSshTimeout;
   if(status < 0)
      return SharkSshErrSocket;
   return SharkSshOk;
}

void
SharkSshServer_stop(SharkSshServer* server)
{
   if(server && server->listening)
   {
      se_close(&server->socket);
      server->listening = 0;
      sharkSshAuditConfigEx(
         server->config, SharkSshAuditServerStopped, SharkSshOk, 0,
         server->port, 1);
   }
}

void
SharkSshServer_destructor(SharkSshServer* server)
{
   if( ! server)
      return;
   SharkSshServer_stop(server);
}

#endif
