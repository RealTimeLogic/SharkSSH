/* Bounded SFTP version 3 plugin for SharkSSH. */

#include "SharkSshSftp.h"
#include <string.h>

#define SFTP_FXP_INIT       1
#define SFTP_FXP_VERSION    2
#define SFTP_FXP_OPEN       3
#define SFTP_FXP_CLOSE      4
#define SFTP_FXP_READ       5
#define SFTP_FXP_WRITE      6
#define SFTP_FXP_LSTAT      7
#define SFTP_FXP_FSTAT      8
#define SFTP_FXP_SETSTAT    9
#define SFTP_FXP_FSETSTAT  10
#define SFTP_FXP_OPENDIR   11
#define SFTP_FXP_READDIR   12
#define SFTP_FXP_REMOVE    13
#define SFTP_FXP_MKDIR     14
#define SFTP_FXP_RMDIR     15
#define SFTP_FXP_REALPATH  16
#define SFTP_FXP_STAT      17
#define SFTP_FXP_RENAME    18
#define SFTP_FXP_READLINK  19
#define SFTP_FXP_SYMLINK   20
#define SFTP_FXP_STATUS   101
#define SFTP_FXP_HANDLE   102
#define SFTP_FXP_DATA     103
#define SFTP_FXP_NAME     104
#define SFTP_FXP_ATTRS    105
#define SFTP_FXP_EXTENDED 200
#define SFTP_FXP_EXTENDED_REPLY 201

#define SFTP_FXF_READ   0x00000001U
#define SFTP_FXF_WRITE  0x00000002U
#define SFTP_FXF_APPEND 0x00000004U
#define SFTP_FXF_CREAT  0x00000008U
#define SFTP_FXF_TRUNC  0x00000010U
#define SFTP_FXF_EXCL   0x00000020U

#define SFTP_ATTR_SIZE        0x00000001U
#define SFTP_ATTR_UIDGID      0x00000002U
#define SFTP_ATTR_PERMISSIONS 0x00000004U
#define SFTP_ATTR_ACMODTIME   0x00000008U
#define SFTP_ATTR_EXTENDED    0x80000000U

#define SFTP_HANDLE_READ   0x01
#define SFTP_HANDLE_WRITE  0x02
#define SFTP_HANDLE_APPEND 0x04
#define SFTP_HANDLE_DIR    0x08

typedef struct
{
   const U8* ptr;
   const U8* end;
   int status;
} SftpReader;

typedef struct
{
   U8* begin;
   U8* ptr;
   U8* end;
   int status;
} SftpWriter;

typedef struct
{
   SharkSshFsStat stat;
   U8 flags;
} SftpAttributes;

static void
sftpWriteU32(U8* target, U32 value)
{
   target[0] = (U8)(value >> 24);
   target[1] = (U8)(value >> 16);
   target[2] = (U8)(value >> 8);
   target[3] = (U8)value;
}

static U32
sftpReadU32(const U8* source)
{
   return ((U32)source[0] << 24) | ((U32)source[1] << 16) |
          ((U32)source[2] << 8) | source[3];
}

static void
sftpReaderConstruct(SftpReader* reader, const U8* data, U32 size)
{
   reader->ptr = data;
   reader->end = data + size;
   reader->status = SharkSshOk;
}

static U8
sftpReaderByte(SftpReader* reader)
{
   if(reader->status || reader->ptr == reader->end)
   {
      reader->status = SharkSshErrProtocol;
      return 0;
   }
   return *reader->ptr++;
}

static U32
sftpReaderU32(SftpReader* reader)
{
   U32 value;
   if(reader->status || (U32)(reader->end - reader->ptr) < 4)
   {
      reader->status = SharkSshErrProtocol;
      return 0;
   }
   value = sftpReadU32(reader->ptr);
   reader->ptr += 4;
   return value;
}

static void
sftpReaderU64(SftpReader* reader, U32* high, U32* low)
{
   *high = sftpReaderU32(reader);
   *low = sftpReaderU32(reader);
}

static SharkSshSpan
sftpReaderString(SftpReader* reader)
{
   SharkSshSpan span;
   U32 size = sftpReaderU32(reader);
   span.ptr = 0;
   span.len = 0;
   if(reader->status || size > (U32)(reader->end - reader->ptr))
   {
      reader->status = SharkSshErrProtocol;
      return span;
   }
   span.ptr = reader->ptr;
   span.len = size;
   reader->ptr += size;
   return span;
}

static int
sftpReaderDone(const SftpReader* reader)
{
   return ! reader->status && reader->ptr == reader->end;
}

static void
sftpWriterConstruct(SftpWriter* writer, U8* data, U32 size)
{
   writer->begin = data;
   writer->ptr = data;
   writer->end = data + size;
   writer->status = SharkSshOk;
}

static void
sftpWriterData(SftpWriter* writer, const void* data, U32 size)
{
   if(writer->status || size > (U32)(writer->end - writer->ptr))
   {
      writer->status = SharkSshErrBounds;
      return;
   }
   if(size)
      memcpy(writer->ptr, data, size);
   writer->ptr += size;
}

static void
sftpWriterByte(SftpWriter* writer, U8 value)
{
   sftpWriterData(writer, &value, 1);
}

static void
sftpWriterU32(SftpWriter* writer, U32 value)
{
   U8 data[4];
   sftpWriteU32(data, value);
   sftpWriterData(writer, data, sizeof(data));
}

static void
sftpWriterU64(SftpWriter* writer, U32 high, U32 low)
{
   sftpWriterU32(writer, high);
   sftpWriterU32(writer, low);
}

static void
sftpWriterString(SftpWriter* writer, const void* data, U32 size)
{
   sftpWriterU32(writer, size);
   sftpWriterData(writer, data, size);
}

static void
sftpWriterText(SftpWriter* writer, const char* text)
{
   sftpWriterString(writer, text, (U32)strlen(text));
}

static SftpWriter
sftpResponse(SharkSshSftp* sftp, U8 type)
{
   SftpWriter writer;
   sftpWriterConstruct(&writer, sftp->output, sizeof(sftp->output));
   sftpWriterU32(&writer, 0);
   sftpWriterByte(&writer, type);
   return writer;
}

static int
sftpFinishResponse(SharkSshSftp* sftp, SftpWriter* writer)
{
   U32 size;
   if(writer->status)
      return writer->status;
   size = (U32)(writer->ptr - writer->begin);
   if(size < 5 || size > 0xFFFFU)
      return SharkSshErrBounds;
   sftpWriteU32(writer->begin, size - 4);
   sftp->outputSize = (U16)size;
   sftp->outputOffset = 0;
   return SharkSshOk;
}

static U8
sftpFsStatus(int status)
{
   switch(status)
   {
      case SharkSshFsOk:
         return SharkSshSftpFxOk;
      case SharkSshFsEnd:
         return SharkSshSftpFxEof;
      case SharkSshFsNotFound:
      case SharkSshFsInvalidName:
         return SharkSshSftpFxNoSuchFile;
      case SharkSshFsDenied:
         return SharkSshSftpFxPermissionDenied;
      case SharkSshFsUnsupported:
         return SharkSshSftpFxUnsupported;
      default:
         return SharkSshSftpFxFailure;
   }
}

static const char*
sftpStatusText(U8 status)
{
   switch(status)
   {
      case SharkSshSftpFxOk: return "OK";
      case SharkSshSftpFxEof: return "End of file";
      case SharkSshSftpFxNoSuchFile: return "No such file";
      case SharkSshSftpFxPermissionDenied: return "Permission denied";
      case SharkSshSftpFxBadMessage: return "Bad message";
      case SharkSshSftpFxUnsupported: return "Operation unsupported";
      default: return "Failure";
   }
}

static int
sftpQueueStatus(SharkSshSftp* sftp, U32 id, U8 status)
{
   SftpWriter writer = sftpResponse(sftp, SFTP_FXP_STATUS);
   sftpWriterU32(&writer, id);
   sftpWriterU32(&writer, status);
   sftpWriterText(&writer, sftpStatusText(status));
   sftpWriterText(&writer, "");
   return sftpFinishResponse(sftp, &writer);
}

static SharkSshSpan
sftpTextSpan(const char* text)
{
   SharkSshSpan span;
   span.ptr = (const U8*)text;
   span.len = (U32)strlen(text);
   return span;
}

static int
sftpNormalize(SharkSshSpan source,
              char target[SHARKSSH_MAX_PATH_LEN + 1])
{
   U32 cursor = 0;
   U16 size = 1;
   if(( ! source.ptr && source.len) || source.len > SHARKSSH_MAX_PATH_LEN)
      return SharkSshErrBounds;
   target[0] = '/';
   while(cursor < source.len)
   {
      U32 start;
      U16 componentSize;
      while(cursor < source.len &&
            (source.ptr[cursor] == '/' || source.ptr[cursor] == '\\'))
         ++cursor;
      if(cursor == source.len)
         break;
      start = cursor;
      while(cursor < source.len && source.ptr[cursor] != '/' &&
            source.ptr[cursor] != '\\')
         ++cursor;
      componentSize = (U16)(cursor - start);
      if(memchr(source.ptr + start, 0, componentSize) ||
         memchr(source.ptr + start, ':', componentSize))
         return SharkSshFsInvalidName;
      if(componentSize == 1 && source.ptr[start] == '.')
         continue;
      if(componentSize == 2 && source.ptr[start] == '.' &&
         source.ptr[start + 1] == '.')
      {
         while(size > 1 && target[size - 1] != '/')
            --size;
         if(size > 1)
            --size;
         continue;
      }
      if(size > 1)
      {
         if(size >= SHARKSSH_MAX_PATH_LEN)
            return SharkSshErrBounds;
         target[size++] = '/';
      }
      if((U32)size + componentSize > SHARKSSH_MAX_PATH_LEN)
         return SharkSshErrBounds;
      memcpy(target + size, source.ptr + start, componentSize);
      size = (U16)(size + componentSize);
   }
   target[size] = 0;
   return SharkSshOk;
}

static int
sftpResolvePath(SharkSshSftp* sftp, SharkSshSpan source,
                char internal[SHARKSSH_MAX_PATH_LEN + 1],
                char visible[SHARKSSH_MAX_PATH_LEN + 1])
{
   U16 visibleSize;
   int status = sftpNormalize(source, visible);
   if(status)
      return status;
   visibleSize = (U16)strlen(visible);
   if(sftp->rootSize)
   {
      U32 suffix = visibleSize > 1 ? visibleSize : 0;
      if((U32)sftp->rootSize + suffix > SHARKSSH_MAX_PATH_LEN)
         return SharkSshErrBounds;
      memcpy(internal, sftp->root, sftp->rootSize);
      if(suffix)
         memcpy(internal + sftp->rootSize, visible, suffix);
      internal[sftp->rootSize + suffix] = 0;
   }
   else if(visibleSize > 1)
   {
      memcpy(internal, visible + 1, visibleSize);
      internal[visibleSize - 1] = 0;
   }
   else
      internal[0] = 0;
   return SharkSshOk;
}

static void
sftpVisiblePath(SharkSshSftp* sftp, const char* internal,
                char visible[SHARKSSH_MAX_PATH_LEN + 1])
{
   const char* suffix = internal;
   if(sftp->rootSize && ! memcmp(internal, sftp->root, sftp->rootSize) &&
      (internal[sftp->rootSize] == 0 || internal[sftp->rootSize] == '/'))
      suffix = internal + sftp->rootSize;
   if(*suffix == '/')
      ++suffix;
   visible[0] = '/';
   strcpy(visible + 1, suffix);
}

static int
sftpAuthorized(SharkSshSftp* sftp, U8 operation, const char* visible)
{
   if( ! sftp->config->authorize)
      return 1;
   return sftp->config->authorize(
      sftp->config->context, sftp->channel, operation,
      sftpTextSpan(visible)) == SharkSshOk;
}

static void
sftpAudit(SharkSshSftp* sftp, U8 operation, U8 status,
          const char* visible)
{
   SharkSshSftpEvent event;
   if( ! sftp->config->audit)
      return;
   event.channel = sftp->channel;
   event.path = sftpTextSpan(visible ? visible : "/");
   event.operation = operation;
   event.status = status;
   sftp->config->audit(sftp->config->context, &event);
}

static int
sftpReadAttributes(SftpReader* reader, SftpAttributes* attributes)
{
   U32 flags;
   U32 value;
   U32 i;
   memset(attributes, 0, sizeof(*attributes));
   flags = sftpReaderU32(reader);
   if(flags & ~(SFTP_ATTR_SIZE | SFTP_ATTR_UIDGID |
                SFTP_ATTR_PERMISSIONS | SFTP_ATTR_ACMODTIME |
                SFTP_ATTR_EXTENDED))
      reader->status = SharkSshErrProtocol;
   if(flags & SFTP_ATTR_SIZE)
   {
      sftpReaderU64(reader, &attributes->stat.sizeHi,
                   &attributes->stat.sizeLo);
      attributes->flags |= SharkSshFsSetSize;
   }
   if(flags & SFTP_ATTR_UIDGID)
   {
      (void)sftpReaderU32(reader);
      (void)sftpReaderU32(reader);
   }
   if(flags & SFTP_ATTR_PERMISSIONS)
   {
      value = sftpReaderU32(reader);
      attributes->stat.permissions = (U16)(value & 07777U);
      attributes->flags |= SharkSshFsSetPermissions;
   }
   if(flags & SFTP_ATTR_ACMODTIME)
   {
      (void)sftpReaderU32(reader);
      attributes->stat.modifiedTime = sftpReaderU32(reader);
      attributes->flags |= SharkSshFsSetModifiedTime;
   }
   if(flags & SFTP_ATTR_EXTENDED)
   {
      U32 count = sftpReaderU32(reader);
      if(count > 16)
         reader->status = SharkSshErrBounds;
      for(i = 0; ! reader->status && i < count; ++i)
      {
         (void)sftpReaderString(reader);
         (void)sftpReaderString(reader);
      }
   }
   return reader->status;
}

static void
sftpWriteAttributes(SftpWriter* writer, const SharkSshFsStat* stat)
{
   U32 mode = stat->permissions & 07777U;
   if( ! mode)
      mode = stat->type == SharkSshFsTypeDirectory ? 0755U : 0644U;
   if(stat->type == SharkSshFsTypeDirectory)
      mode |= 0040000U;
   else if(stat->type == SharkSshFsTypeFile)
      mode |= 0100000U;
   sftpWriterU32(writer, SFTP_ATTR_SIZE | SFTP_ATTR_PERMISSIONS |
                          SFTP_ATTR_ACMODTIME);
   sftpWriterU64(writer, stat->sizeHi, stat->sizeLo);
   sftpWriterU32(writer, mode);
   sftpWriterU32(writer, stat->modifiedTime);
   sftpWriterU32(writer, stat->modifiedTime);
}

static SharkSshSftpHandle*
sftpFindHandle(SharkSshSftp* sftp, SharkSshSpan encoded)
{
   U32 token;
   U16 i;
   if(encoded.len != 4)
      return 0;
   token = sftpReadU32(encoded.ptr);
   for(i = 0; i < SHARKSSH_SFTP_MAX_HANDLES; ++i)
      if(sftp->handles[i].object && sftp->handles[i].token == token)
         return &sftp->handles[i];
   return 0;
}

static SharkSshSftpHandle*
sftpAllocateHandle(SharkSshSftp* sftp)
{
   U16 i;
   for(i = 0; i < SHARKSSH_SFTP_MAX_HANDLES; ++i)
   {
      if( ! sftp->handles[i].object)
      {
         SharkSshSftpHandle* handle = &sftp->handles[i];
         memset(handle, 0, sizeof(*handle));
         do
            ++sftp->nextToken;
         while( ! sftp->nextToken);
         handle->token = sftp->nextToken;
         return handle;
      }
   }
   return 0;
}

static void
sftpAbortStaged(SharkSshSftp* sftp, SharkSshSftpHandle* handle)
{
   SharkSshSpan stagePath = sftpTextSpan(handle->path);
   SharkSshSpan target = sftpTextSpan(handle->target);
   if(sftp->config->abortUpload)
      sftp->config->abortUpload(sftp->config->context, stagePath, target);
   else if(sftp->config->fileSystem->remove)
      (void)sftp->config->fileSystem->remove(
         sftp->config->fileSystem->context, stagePath);
}

static int
sftpReleaseHandle(SharkSshSftp* sftp, SharkSshSftpHandle* handle,
                  int commit)
{
   const SharkSshFileSystem* fs = sftp->config->fileSystem;
   int status;
   if(handle->flags & SFTP_HANDLE_DIR)
      status = fs->closeDirectory ? fs->closeDirectory(
         fs->context, handle->object) : SharkSshFsUnsupported;
   else
      status = fs->close ? fs->close(fs->context, handle->object) :
                           SharkSshFsUnsupported;
   handle->object = 0;
   if(handle->staged)
   {
      if(commit && status == SharkSshFsOk)
      {
         SharkSshSpan stagePath = sftpTextSpan(handle->path);
         SharkSshSpan target = sftpTextSpan(handle->target);
         status = sftp->config->commitUpload ?
            sftp->config->commitUpload(
               sftp->config->context, stagePath, target) :
            fs->rename ? fs->rename(fs->context, stagePath, target) :
                         SharkSshFsUnsupported;
      }
      if( ! commit || status != SharkSshFsOk)
         sftpAbortStaged(sftp, handle);
   }
   memset(handle, 0, sizeof(*handle));
   return status;
}

static int
sftpQueueHandle(SharkSshSftp* sftp, U32 id,
                const SharkSshSftpHandle* handle)
{
   U8 encoded[4];
   SftpWriter writer = sftpResponse(sftp, SFTP_FXP_HANDLE);
   sftpWriteU32(encoded, handle->token);
   sftpWriterU32(&writer, id);
   sftpWriterString(&writer, encoded, sizeof(encoded));
   return sftpFinishResponse(sftp, &writer);
}

static int
sftpQueueAttrs(SharkSshSftp* sftp, U32 id,
               const SharkSshFsStat* stat)
{
   SftpWriter writer = sftpResponse(sftp, SFTP_FXP_ATTRS);
   sftpWriterU32(&writer, id);
   sftpWriteAttributes(&writer, stat);
   return sftpFinishResponse(sftp, &writer);
}

static int
sftpQueueName(SharkSshSftp* sftp, U32 id, const char* name,
              const SharkSshFsStat* stat)
{
   SftpWriter writer = sftpResponse(sftp, SFTP_FXP_NAME);
   sftpWriterU32(&writer, id);
   sftpWriterU32(&writer, 1);
   sftpWriterText(&writer, name);
   sftpWriterText(&writer, name);
   if(stat)
      sftpWriteAttributes(&writer, stat);
   else
      sftpWriterU32(&writer, 0);
   return sftpFinishResponse(sftp, &writer);
}

static int
sftpQueueVersion(SharkSshSftp* sftp)
{
   SftpWriter writer = sftpResponse(sftp, SFTP_FXP_VERSION);
   sftpWriterU32(&writer, 3);
   sftpWriterText(&writer, "limits@openssh.com");
   sftpWriterText(&writer, "1");
   return sftpFinishResponse(sftp, &writer);
}

static int
sftpHandleOpen(SharkSshSftp* sftp, SftpReader* reader, U32 id)
{
   const SharkSshFileSystem* fs = sftp->config->fileSystem;
   SharkSshSpan requested = sftpReaderString(reader);
   U32 pflags = sftpReaderU32(reader);
   SftpAttributes attributes;
   SharkSshSftpHandle* handle;
   char internal[SHARKSSH_MAX_PATH_LEN + 1];
   char visible[SHARKSSH_MAX_PATH_LEN + 1];
   U8 fsFlags = 0;
   U8 operation;
   U8 fx;
   int status;
   sftpReadAttributes(reader, &attributes);
   if( ! sftpReaderDone(reader) || ! (pflags & (SFTP_FXF_READ |
       SFTP_FXF_WRITE)) || (pflags & ~(SFTP_FXF_READ | SFTP_FXF_WRITE |
       SFTP_FXF_APPEND | SFTP_FXF_CREAT | SFTP_FXF_TRUNC |
       SFTP_FXF_EXCL)) ||
      ((pflags & (SFTP_FXF_TRUNC | SFTP_FXF_EXCL)) &&
       ! (pflags & SFTP_FXF_CREAT)))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   status = sftpResolvePath(sftp, requested, internal, visible);
   if(status)
      return sftpQueueStatus(sftp, id, sftpFsStatus(status));
   operation = pflags & (SFTP_FXF_WRITE | SFTP_FXF_APPEND |
                         SFTP_FXF_CREAT | SFTP_FXF_TRUNC) ?
      SharkSshSftpOpenWrite : SharkSshSftpOpenRead;
   if((sftp->config->readOnly && operation == SharkSshSftpOpenWrite) ||
      ! sftpAuthorized(sftp, operation, visible))
   {
      sftpAudit(sftp, operation, SharkSshSftpFxPermissionDenied, visible);
      return sftpQueueStatus(sftp, id, SharkSshSftpFxPermissionDenied);
   }
   handle = sftpAllocateHandle(sftp);
   if( ! handle)
   {
      sftpAudit(sftp, operation, SharkSshSftpFxFailure, visible);
      return sftpQueueStatus(sftp, id, SharkSshSftpFxFailure);
   }
   if(pflags & SFTP_FXF_READ)
   {
      fsFlags |= SharkSshFsOpenRead;
      handle->flags |= SFTP_HANDLE_READ;
   }
   if(pflags & SFTP_FXF_WRITE)
   {
      fsFlags |= SharkSshFsOpenWrite;
      handle->flags |= SFTP_HANDLE_WRITE;
   }
   if(pflags & SFTP_FXF_CREAT)
      fsFlags |= SharkSshFsOpenCreate;
   if(pflags & SFTP_FXF_TRUNC)
      fsFlags |= SharkSshFsOpenTruncate;
   if(pflags & SFTP_FXF_APPEND)
   {
      fsFlags |= SharkSshFsOpenAppend | SharkSshFsOpenWrite;
      handle->flags |= SFTP_HANDLE_WRITE | SFTP_HANDLE_APPEND;
   }
   if(pflags & SFTP_FXF_EXCL)
      fsFlags |= SharkSshFsOpenExclusive;
   if(sftp->config->stageUpload && ! (pflags & SFTP_FXF_EXCL) &&
      operation == SharkSshSftpOpenWrite &&
      (pflags & (SFTP_FXF_CREAT | SFTP_FXF_TRUNC)))
   {
      U16 stageSize = 0;
      status = sftp->config->stageUpload(
         sftp->config->context, sftpTextSpan(internal), handle->token,
         (U8*)handle->path, SHARKSSH_MAX_PATH_LEN, &stageSize);
      if(status || stageSize > SHARKSSH_MAX_PATH_LEN ||
         memchr(handle->path, 0, stageSize))
      {
         memset(handle, 0, sizeof(*handle));
         fx = status ? sftpFsStatus(status) : SharkSshSftpFxFailure;
         sftpAudit(sftp, operation, fx, visible);
         return sftpQueueStatus(sftp, id, fx);
      }
      handle->path[stageSize] = 0;
      strcpy(handle->target, internal);
      handle->staged = 1;
   }
   else
      strcpy(handle->path, internal);
   status = fs->open ? fs->open(fs->context, sftpTextSpan(handle->path),
                                fsFlags, &handle->object) :
                       SharkSshFsUnsupported;
   if(status == SharkSshFsOk && attributes.flags && fs->setStat)
      status = fs->setStat(fs->context, sftpTextSpan(handle->path),
                           &attributes.stat, attributes.flags);
   if(status == SharkSshFsOk && ! handle->object)
      status = SharkSshErrService;
   if(status != SharkSshFsOk)
   {
      if(handle->object)
         (void)sftpReleaseHandle(sftp, handle, 0);
      else
      {
         if(handle->staged)
            sftpAbortStaged(sftp, handle);
         memset(handle, 0, sizeof(*handle));
      }
      fx = sftpFsStatus(status);
      sftpAudit(sftp, operation, fx, visible);
      return sftpQueueStatus(sftp, id, fx);
   }
   sftpAudit(sftp, operation, SharkSshSftpFxOk, visible);
   return sftpQueueHandle(sftp, id, handle);
}

static int
sftpHandleClose(SharkSshSftp* sftp, SftpReader* reader, U32 id)
{
   SharkSshSpan encoded = sftpReaderString(reader);
   SharkSshSftpHandle* handle;
   char visible[SHARKSSH_MAX_PATH_LEN + 1];
   U8 fx;
   int status;
   if( ! sftpReaderDone(reader))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   handle = sftpFindHandle(sftp, encoded);
   if( ! handle)
      return sftpQueueStatus(sftp, id, SharkSshSftpFxFailure);
   sftpVisiblePath(sftp, handle->staged ? handle->target : handle->path,
                   visible);
   status = sftpReleaseHandle(sftp, handle, 1);
   fx = sftpFsStatus(status);
   sftpAudit(sftp, SharkSshSftpClose, fx, visible);
   return sftpQueueStatus(sftp, id, fx);
}

static int
sftpHandleRead(SharkSshSftp* sftp, SftpReader* reader, U32 id)
{
   const SharkSshFileSystem* fs = sftp->config->fileSystem;
   SharkSshSftpHandle* handle = sftpFindHandle(
      sftp, sftpReaderString(reader));
   U32 high;
   U32 low;
   U32 requested;
   U32 size = 0;
   char visible[SHARKSSH_MAX_PATH_LEN + 1];
   SftpWriter writer;
   U8 fx;
   int status;
   sftpReaderU64(reader, &high, &low);
   requested = sftpReaderU32(reader);
   if( ! sftpReaderDone(reader))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   if( ! handle || (handle->flags & (SFTP_HANDLE_READ | SFTP_HANDLE_DIR)) !=
                    SFTP_HANDLE_READ)
      return sftpQueueStatus(sftp, id, SharkSshSftpFxFailure);
   sftpVisiblePath(sftp, handle->staged ? handle->target : handle->path,
                   visible);
   if( ! sftpAuthorized(sftp, SharkSshSftpRead, visible))
   {
      sftpAudit(sftp, SharkSshSftpRead,
                SharkSshSftpFxPermissionDenied, visible);
      return sftpQueueStatus(sftp, id, SharkSshSftpFxPermissionDenied);
   }
   if(requested > SHARKSSH_SFTP_READ_SIZE)
      requested = SHARKSSH_SFTP_READ_SIZE;
   status = fs->seek ? fs->seek(fs->context, handle->object, high, low) :
                       SharkSshFsUnsupported;
   if(status == SharkSshFsOk)
      status = fs->read ? fs->read(fs->context, handle->object,
                                   sftp->output + 13, requested, &size) :
                          SharkSshFsUnsupported;
   if(status != SharkSshFsOk || ! size)
   {
      fx = status == SharkSshFsOk ? SharkSshSftpFxEof :
                                    sftpFsStatus(status);
      sftpAudit(sftp, SharkSshSftpRead, fx, visible);
      return sftpQueueStatus(sftp, id, fx);
   }
   writer = sftpResponse(sftp, SFTP_FXP_DATA);
   sftpWriterU32(&writer, id);
   sftpWriterU32(&writer, size);
   writer.ptr += size;
   sftpAudit(sftp, SharkSshSftpRead, SharkSshSftpFxOk, visible);
   return sftpFinishResponse(sftp, &writer);
}

static int
sftpHandleWrite(SharkSshSftp* sftp, SftpReader* reader, U32 id)
{
   const SharkSshFileSystem* fs = sftp->config->fileSystem;
   SharkSshSftpHandle* handle = sftpFindHandle(
      sftp, sftpReaderString(reader));
   U32 high;
   U32 low;
   SharkSshSpan data;
   U32 written = 0;
   char visible[SHARKSSH_MAX_PATH_LEN + 1];
   U8 fx;
   int status;
   sftpReaderU64(reader, &high, &low);
   data = sftpReaderString(reader);
   if( ! sftpReaderDone(reader))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   if( ! handle || ! (handle->flags & SFTP_HANDLE_WRITE) ||
      (handle->flags & SFTP_HANDLE_DIR))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxFailure);
   sftpVisiblePath(sftp, handle->staged ? handle->target : handle->path,
                   visible);
   if(sftp->config->readOnly ||
      ! sftpAuthorized(sftp, SharkSshSftpWrite, visible))
   {
      sftpAudit(sftp, SharkSshSftpWrite,
                SharkSshSftpFxPermissionDenied, visible);
      return sftpQueueStatus(sftp, id, SharkSshSftpFxPermissionDenied);
   }
   status = SharkSshFsOk;
   if( ! (handle->flags & SFTP_HANDLE_APPEND))
      status = fs->seek ? fs->seek(fs->context, handle->object, high, low) :
                          SharkSshFsUnsupported;
   if(status == SharkSshFsOk)
      status = fs->write ? fs->write(fs->context, handle->object,
                                     data.ptr, data.len, &written) :
                           SharkSshFsUnsupported;
   if(status == SharkSshFsOk && written != data.len)
      status = SharkSshFsNoSpace;
   fx = sftpFsStatus(status);
   sftpAudit(sftp, SharkSshSftpWrite, fx, visible);
   return sftpQueueStatus(sftp, id, fx);
}

static int
sftpHandleStat(SharkSshSftp* sftp, SftpReader* reader, U32 id,
               int byHandle)
{
   const SharkSshFileSystem* fs = sftp->config->fileSystem;
   SharkSshSftpHandle* handle = 0;
   SharkSshFsStat stat;
   char internal[SHARKSSH_MAX_PATH_LEN + 1];
   char visible[SHARKSSH_MAX_PATH_LEN + 1];
   int status;
   if(byHandle)
   {
      handle = sftpFindHandle(sftp, sftpReaderString(reader));
      if( ! handle)
         return sftpQueueStatus(sftp, id, SharkSshSftpFxFailure);
      strcpy(internal, handle->path);
      sftpVisiblePath(sftp, handle->staged ? handle->target : handle->path,
                      visible);
   }
   else
   {
      SharkSshSpan path = sftpReaderString(reader);
      status = sftpResolvePath(sftp, path, internal, visible);
      if(status)
         return sftpQueueStatus(sftp, id, sftpFsStatus(status));
   }
   if( ! sftpReaderDone(reader))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   if( ! sftpAuthorized(sftp, SharkSshSftpStat, visible))
   {
      sftpAudit(sftp, SharkSshSftpStat,
                SharkSshSftpFxPermissionDenied, visible);
      return sftpQueueStatus(sftp, id, SharkSshSftpFxPermissionDenied);
   }
   status = fs->stat ? fs->stat(fs->context, sftpTextSpan(internal), &stat) :
                       SharkSshFsUnsupported;
   sftpAudit(sftp, SharkSshSftpStat, sftpFsStatus(status), visible);
   return status == SharkSshFsOk ? sftpQueueAttrs(sftp, id, &stat) :
                                   sftpQueueStatus(
                                      sftp, id, sftpFsStatus(status));
}

static int
sftpHandleSetStat(SharkSshSftp* sftp, SftpReader* reader, U32 id,
                  int byHandle)
{
   const SharkSshFileSystem* fs = sftp->config->fileSystem;
   SharkSshSftpHandle* handle = 0;
   SftpAttributes attributes;
   char internal[SHARKSSH_MAX_PATH_LEN + 1];
   char visible[SHARKSSH_MAX_PATH_LEN + 1];
   U8 fx;
   int status;
   if(byHandle)
   {
      handle = sftpFindHandle(sftp, sftpReaderString(reader));
      if( ! handle)
         return sftpQueueStatus(sftp, id, SharkSshSftpFxFailure);
      strcpy(internal, handle->path);
      sftpVisiblePath(sftp, handle->staged ? handle->target : handle->path,
                      visible);
   }
   else
   {
      SharkSshSpan path = sftpReaderString(reader);
      status = sftpResolvePath(sftp, path, internal, visible);
      if(status)
         return sftpQueueStatus(sftp, id, sftpFsStatus(status));
   }
   sftpReadAttributes(reader, &attributes);
   if( ! sftpReaderDone(reader))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   if(sftp->config->readOnly ||
      ! sftpAuthorized(sftp, SharkSshSftpSetStat, visible))
      status = SharkSshFsDenied;
   else if( ! attributes.flags)
      status = SharkSshFsOk;
   else
      status = fs->setStat ? fs->setStat(
         fs->context, sftpTextSpan(internal), &attributes.stat,
         attributes.flags) : SharkSshFsUnsupported;
   fx = sftpFsStatus(status);
   sftpAudit(sftp, SharkSshSftpSetStat, fx, visible);
   return sftpQueueStatus(sftp, id, fx);
}

static int
sftpHandleOpenDirectory(SharkSshSftp* sftp, SftpReader* reader, U32 id)
{
   const SharkSshFileSystem* fs = sftp->config->fileSystem;
   SharkSshSpan requested = sftpReaderString(reader);
   SharkSshSftpHandle* handle;
   char internal[SHARKSSH_MAX_PATH_LEN + 1];
   char visible[SHARKSSH_MAX_PATH_LEN + 1];
   U8 fx;
   int status;
   if( ! sftpReaderDone(reader))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   status = sftpResolvePath(sftp, requested, internal, visible);
   if(status)
      return sftpQueueStatus(sftp, id, sftpFsStatus(status));
   if( ! sftpAuthorized(sftp, SharkSshSftpOpenDirectory, visible))
   {
      sftpAudit(sftp, SharkSshSftpOpenDirectory,
                SharkSshSftpFxPermissionDenied, visible);
      return sftpQueueStatus(sftp, id, SharkSshSftpFxPermissionDenied);
   }
   handle = sftpAllocateHandle(sftp);
   if( ! handle)
      return sftpQueueStatus(sftp, id, SharkSshSftpFxFailure);
   strcpy(handle->path, internal);
   handle->flags = SFTP_HANDLE_DIR | SFTP_HANDLE_READ;
   status = fs->openDirectory ? fs->openDirectory(
      fs->context, sftpTextSpan(internal), &handle->object) :
      SharkSshFsUnsupported;
   if(status == SharkSshFsOk && ! handle->object)
      status = SharkSshErrService;
   if(status != SharkSshFsOk)
   {
      memset(handle, 0, sizeof(*handle));
      fx = sftpFsStatus(status);
      sftpAudit(sftp, SharkSshSftpOpenDirectory, fx, visible);
      return sftpQueueStatus(sftp, id, fx);
   }
   sftpAudit(sftp, SharkSshSftpOpenDirectory,
             SharkSshSftpFxOk, visible);
   return sftpQueueHandle(sftp, id, handle);
}

static int
sftpHandleReadDirectory(SharkSshSftp* sftp, SftpReader* reader, U32 id)
{
   const SharkSshFileSystem* fs = sftp->config->fileSystem;
   SharkSshSftpHandle* handle = sftpFindHandle(
      sftp, sftpReaderString(reader));
   SharkSshFsStat stat;
   U8 name[SHARKSSH_MAX_PATH_LEN + 1];
   U16 nameSize = 0;
   char visible[SHARKSSH_MAX_PATH_LEN + 1];
   U8 fx;
   int status;
   if( ! sftpReaderDone(reader))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   if( ! handle || (handle->flags & SFTP_HANDLE_DIR) == 0)
      return sftpQueueStatus(sftp, id, SharkSshSftpFxFailure);
   sftpVisiblePath(sftp, handle->path, visible);
   if( ! sftpAuthorized(sftp, SharkSshSftpReadDirectory, visible))
      status = SharkSshFsDenied;
   else
      status = fs->readDirectory ? fs->readDirectory(
         fs->context, handle->object, name, SHARKSSH_MAX_PATH_LEN,
         &nameSize, &stat) : SharkSshFsUnsupported;
   fx = sftpFsStatus(status);
   sftpAudit(sftp, SharkSshSftpReadDirectory, fx, visible);
   if(status != SharkSshFsOk)
      return sftpQueueStatus(sftp, id, fx);
   name[nameSize] = 0;
   return sftpQueueName(sftp, id, (const char*)name, &stat);
}

static int
sftpHandlePathOperation(SharkSshSftp* sftp, SftpReader* reader,
                        U32 id, U8 operation)
{
   const SharkSshFileSystem* fs = sftp->config->fileSystem;
   SharkSshSpan requested = sftpReaderString(reader);
   SftpAttributes attributes;
   char internal[SHARKSSH_MAX_PATH_LEN + 1];
   char visible[SHARKSSH_MAX_PATH_LEN + 1];
   U8 fx;
   int status;
   memset(&attributes, 0, sizeof(attributes));
   if(operation == SharkSshSftpMakeDirectory)
      sftpReadAttributes(reader, &attributes);
   if( ! sftpReaderDone(reader))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   status = sftpResolvePath(sftp, requested, internal, visible);
   if(status)
      return sftpQueueStatus(sftp, id, sftpFsStatus(status));
   if(sftp->config->readOnly || ! sftpAuthorized(sftp, operation, visible))
      status = SharkSshFsDenied;
   else if(operation == SharkSshSftpRemove)
      status = fs->remove ? fs->remove(
         fs->context, sftpTextSpan(internal)) : SharkSshFsUnsupported;
   else if(operation == SharkSshSftpMakeDirectory)
      status = fs->makeDirectory ? fs->makeDirectory(
         fs->context, sftpTextSpan(internal),
         attributes.stat.permissions) : SharkSshFsUnsupported;
   else
      status = fs->removeDirectory ? fs->removeDirectory(
         fs->context, sftpTextSpan(internal)) : SharkSshFsUnsupported;
   fx = sftpFsStatus(status);
   sftpAudit(sftp, operation, fx, visible);
   return sftpQueueStatus(sftp, id, fx);
}

static int
sftpHandleRename(SharkSshSftp* sftp, SftpReader* reader, U32 id)
{
   const SharkSshFileSystem* fs = sftp->config->fileSystem;
   SharkSshSpan oldRequested = sftpReaderString(reader);
   SharkSshSpan newRequested = sftpReaderString(reader);
   char oldInternal[SHARKSSH_MAX_PATH_LEN + 1];
   char newInternal[SHARKSSH_MAX_PATH_LEN + 1];
   char oldVisible[SHARKSSH_MAX_PATH_LEN + 1];
   char newVisible[SHARKSSH_MAX_PATH_LEN + 1];
   U8 fx;
   int status;
   if( ! sftpReaderDone(reader))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   status = sftpResolvePath(
      sftp, oldRequested, oldInternal, oldVisible);
   if( ! status)
      status = sftpResolvePath(
         sftp, newRequested, newInternal, newVisible);
   if(status)
      return sftpQueueStatus(sftp, id, sftpFsStatus(status));
   if(sftp->config->readOnly ||
      ! sftpAuthorized(sftp, SharkSshSftpRename, oldVisible) ||
      ! sftpAuthorized(sftp, SharkSshSftpRename, newVisible))
      status = SharkSshFsDenied;
   else
      status = fs->rename ? fs->rename(
         fs->context, sftpTextSpan(oldInternal),
         sftpTextSpan(newInternal)) : SharkSshFsUnsupported;
   fx = sftpFsStatus(status);
   sftpAudit(sftp, SharkSshSftpRename, fx, oldVisible);
   return sftpQueueStatus(sftp, id, fx);
}

static int
sftpHandleRealPath(SharkSshSftp* sftp, SftpReader* reader, U32 id)
{
   SharkSshSpan requested = sftpReaderString(reader);
   char internal[SHARKSSH_MAX_PATH_LEN + 1];
   char visible[SHARKSSH_MAX_PATH_LEN + 1];
   int status;
   if( ! sftpReaderDone(reader))
      return sftpQueueStatus(sftp, id, SharkSshSftpFxBadMessage);
   status = sftpResolvePath(sftp, requested, internal, visible);
   if(status)
      return sftpQueueStatus(sftp, id, sftpFsStatus(status));
   if( ! sftpAuthorized(sftp, SharkSshSftpRealPath, visible))
   {
      sftpAudit(sftp, SharkSshSftpRealPath,
                SharkSshSftpFxPermissionDenied, visible);
      return sftpQueueStatus(sftp, id, SharkSshSftpFxPermissionDenied);
   }
   sftpAudit(sftp, SharkSshSftpRealPath, SharkSshSftpFxOk, visible);
   return sftpQueueName(sftp, id, visible, 0);
}

static int
sftpHandleExtended(SharkSshSftp* sftp, SftpReader* reader, U32 id)
{
   SharkSshSpan name = sftpReaderString(reader);
   static const char limits[] = "limits@openssh.com";
   if(name.len == sizeof(limits) - 1 &&
      ! memcmp(name.ptr, limits, sizeof(limits) - 1) &&
      sftpReaderDone(reader))
   {
      SftpWriter writer = sftpResponse(sftp, SFTP_FXP_EXTENDED_REPLY);
      sftpWriterU32(&writer, id);
      sftpWriterU64(&writer, 0, SHARKSSH_SFTP_PACKET_SIZE + 4);
      sftpWriterU64(&writer, 0, SHARKSSH_SFTP_READ_SIZE);
      sftpWriterU64(&writer, 0, SHARKSSH_SFTP_PACKET_SIZE - 32);
      sftpWriterU64(&writer, 0, SHARKSSH_SFTP_MAX_HANDLES);
      return sftpFinishResponse(sftp, &writer);
   }
   return sftpQueueStatus(sftp, id, SharkSshSftpFxUnsupported);
}

static int
sftpProcessPacket(SharkSshSftp* sftp, const U8* data, U32 size)
{
   SftpReader reader;
   U8 type;
   U32 id;
   sftpReaderConstruct(&reader, data, size);
   type = sftpReaderByte(&reader);
   if( ! sftp->initialized)
   {
      U32 version;
      if(type != SFTP_FXP_INIT)
         return SharkSshErrProtocol;
      version = sftpReaderU32(&reader);
      if(reader.status || version < 3)
         return SharkSshErrProtocol;
      sftp->initialized = 1;
      return sftpQueueVersion(sftp);
   }
   if(type == SFTP_FXP_INIT || type == SFTP_FXP_VERSION ||
      size < 5)
      return SharkSshErrProtocol;
   id = sftpReaderU32(&reader);
   switch(type)
   {
      case SFTP_FXP_OPEN:
         return sftpHandleOpen(sftp, &reader, id);
      case SFTP_FXP_CLOSE:
         return sftpHandleClose(sftp, &reader, id);
      case SFTP_FXP_READ:
         return sftpHandleRead(sftp, &reader, id);
      case SFTP_FXP_WRITE:
         return sftpHandleWrite(sftp, &reader, id);
      case SFTP_FXP_LSTAT:
      case SFTP_FXP_STAT:
         return sftpHandleStat(sftp, &reader, id, 0);
      case SFTP_FXP_FSTAT:
         return sftpHandleStat(sftp, &reader, id, 1);
      case SFTP_FXP_SETSTAT:
         return sftpHandleSetStat(sftp, &reader, id, 0);
      case SFTP_FXP_FSETSTAT:
         return sftpHandleSetStat(sftp, &reader, id, 1);
      case SFTP_FXP_OPENDIR:
         return sftpHandleOpenDirectory(sftp, &reader, id);
      case SFTP_FXP_READDIR:
         return sftpHandleReadDirectory(sftp, &reader, id);
      case SFTP_FXP_REMOVE:
         return sftpHandlePathOperation(
            sftp, &reader, id, SharkSshSftpRemove);
      case SFTP_FXP_MKDIR:
         return sftpHandlePathOperation(
            sftp, &reader, id, SharkSshSftpMakeDirectory);
      case SFTP_FXP_RMDIR:
         return sftpHandlePathOperation(
            sftp, &reader, id, SharkSshSftpRemoveDirectory);
      case SFTP_FXP_RENAME:
         return sftpHandleRename(sftp, &reader, id);
      case SFTP_FXP_REALPATH:
         return sftpHandleRealPath(sftp, &reader, id);
      case SFTP_FXP_EXTENDED:
         return sftpHandleExtended(sftp, &reader, id);
      case SFTP_FXP_READLINK:
      case SFTP_FXP_SYMLINK:
      default:
         return sftpQueueStatus(sftp, id, SharkSshSftpFxUnsupported);
   }
}

static int
sftpProcessInput(SharkSshSftp* sftp)
{
   U32 packetSize;
   U32 total;
   int status;
   if(sftp->outputSize || sftp->inputSize < 4)
      return SharkSshOk;
   packetSize = sftpReadU32(sftp->input);
   if( ! packetSize || packetSize > SHARKSSH_SFTP_PACKET_SIZE)
      return SharkSshErrBounds;
   total = packetSize + 4;
   if(sftp->inputSize < total)
      return SharkSshOk;
   status = sftpProcessPacket(sftp, sftp->input + 4, packetSize);
   if(status)
      return status;
   if(sftp->inputSize > total)
      memmove(sftp->input, sftp->input + total,
              sftp->inputSize - (U16)total);
   sftp->inputSize = (U16)(sftp->inputSize - total);
   return SharkSshOk;
}

void
SharkSshSftp_constructor(SharkSshSftp* sftp,
                         const SharkSshSftpConfig* config)
{
   if(sftp)
   {
      memset(sftp, 0, sizeof(*sftp));
      sftp->config = config;
   }
}

void
SharkSshSftp_destructor(SharkSshSftp* sftp)
{
   U16 i;
   if( ! sftp || ! sftp->config || ! sftp->config->fileSystem)
      return;
   for(i = 0; i < SHARKSSH_SFTP_MAX_HANDLES; ++i)
      if(sftp->handles[i].object)
         (void)sftpReleaseHandle(sftp, &sftp->handles[i], 0);
   sftp->channel = 0;
}

int
SharkSshSftp_start(SharkSshSftp* sftp, SharkSshChannel* channel)
{
   SharkSshSpan root;
   char normalized[SHARKSSH_MAX_PATH_LEN + 1];
   int status;
   if( ! sftp || ! channel || ! sftp->config ||
      ! sftp->config->fileSystem)
      return SharkSshErrArgument;
   root = sftpTextSpan(sftp->config->root ? sftp->config->root : "");
   status = sftpNormalize(root, normalized);
   if(status)
      return status;
   if(normalized[1])
      strcpy(sftp->root, normalized + 1);
   else
      sftp->root[0] = 0;
   sftp->rootSize = (U16)strlen(sftp->root);
   sftp->channel = channel;
   return SharkSshOk;
}

int
SharkSshSftp_writable(SharkSshSftp* sftp, SharkSshChannel* channel)
{
   int status;
   if( ! sftp || sftp->channel != channel)
      return SharkSshErrState;
   for(;;)
   {
      if(sftp->outputOffset < sftp->outputSize)
      {
         U32 written = 0;
         status = SharkSshChannel_writeSome(
            channel, sftp->output + sftp->outputOffset,
            sftp->outputSize - sftp->outputOffset, &written);
         sftp->outputOffset = (U16)(sftp->outputOffset + written);
         if(status)
            return status;
      }
      sftp->outputOffset = 0;
      sftp->outputSize = 0;
      status = sftpProcessInput(sftp);
      if(status)
         return status;
      if(sftp->outputSize)
         continue;
      if(sftp->eof == 1)
      {
         sftp->eof = 2;
         status = SharkSshChannel_sendExitStatus(channel, 0);
         if( ! status)
            status = SharkSshChannel_close(channel);
         return status;
      }
      return SharkSshOk;
   }
}

int
SharkSshSftp_data(SharkSshSftp* sftp, SharkSshChannel* channel,
                  SharkSshSpan data)
{
   int pendingStatus = SharkSshOk;
   if( ! sftp || sftp->channel != channel || sftp->eof ||
      (data.len && ! data.ptr))
      return SharkSshErrState;
   while(data.len)
   {
      U32 available = sizeof(sftp->input) - sftp->inputSize;
      U32 size;
      int status;
      if( ! available)
         return SharkSshErrBounds;
      size = data.len < available ? data.len : available;
      memcpy(sftp->input + sftp->inputSize, data.ptr, size);
      sftp->inputSize = (U16)(sftp->inputSize + size);
      data.ptr += size;
      data.len -= size;
      status = SharkSshSftp_writable(sftp, channel);
      if(status == SharkSshTimeout)
         pendingStatus = status;
      else if(status)
         return status;
   }
   return pendingStatus;
}

int
SharkSshSftp_eof(SharkSshSftp* sftp, SharkSshChannel* channel)
{
   U16 i;
   if( ! sftp || sftp->channel != channel)
      return SharkSshErrState;
   for(i = 0; i < SHARKSSH_SFTP_MAX_HANDLES; ++i)
      if(sftp->handles[i].object)
         (void)sftpReleaseHandle(sftp, &sftp->handles[i], 0);
   sftp->eof = 1;
   return SharkSshSftp_writable(sftp, channel);
}
