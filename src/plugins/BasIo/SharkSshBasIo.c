/*
 *                 SharkSSH Embedded SSH Server
 ****************************************************************************
 *   BAS IOINTF FILESYSTEM PLUGIN
 ****************************************************************************
 */

#include "SharkSshBasIo.h"

static int
sharkSshBasIo_status(int status)
{
   if(status == IOINTF_OK)
      return SharkSshFsOk;
   switch(status)
   {
      case IOINTF_NOTFOUND:
      case IOINTF_ENOENT:
         return SharkSshFsNotFound;
      case IOINTF_EXIST:
         return SharkSshFsExists;
      case IOINTF_NOACCESS:
      case IOINTF_LOCKED:
         return SharkSshFsDenied;
      case IOINTF_NOSPACE:
         return SharkSshFsNoSpace;
      case IOINTF_NOIMPLEMENTATION:
         return SharkSshFsUnsupported;
      case IOINTF_INVALIDNAME:
         return SharkSshFsInvalidName;
      case IOINTF_BUFTOOSMALL:
         return SharkSshErrBounds;
      default:
         return SharkSshErrService;
   }
}

static int
sharkSshBasIo_path(SharkSshSpan source,
                   char target[SHARKSSH_MAX_PATH_LEN + 1])
{
   U32 i;
   if(( ! source.ptr && source.len) || source.len > SHARKSSH_MAX_PATH_LEN)
      return SharkSshErrBounds;
   for(i = 0; i < source.len; ++i)
   {
      if(source.ptr[i] == 0)
         return IOINTF_INVALIDNAME;
      target[i] = (char)source.ptr[i];
   }
   target[source.len] = 0;
   return SharkSshFsOk;
}

static SharkSshBasIo*
sharkSshBasIo_adapter(void* context)
{
   SharkSshBasIo* adapter = (SharkSshBasIo*)context;
   return adapter && adapter->io ? adapter : 0;
}

static int
sharkSshBasIo_open(void* context, SharkSshSpan name, U8 flags,
                   void** file)
{
   SharkSshBasIo* adapter = sharkSshBasIo_adapter(context);
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   const char* ecode = 0;
   ResIntfPtr resource;
   U32 mode = 0;
   int status;
   U8 validFlags = SharkSshFsOpenRead | SharkSshFsOpenWrite |
      SharkSshFsOpenCreate | SharkSshFsOpenTruncate |
      SharkSshFsOpenAppend | SharkSshFsOpenExclusive;

   if( ! adapter || ! file)
      return SharkSshErrArgument;
   *file = 0;
   if((flags & ~validFlags) ||
      ((flags & SharkSshFsOpenAppend) &&
       (flags & SharkSshFsOpenTruncate)))
      return SharkSshErrArgument;
   if(flags & SharkSshFsOpenExclusive)
      return SharkSshFsUnsupported;
   if(flags & SharkSshFsOpenWrite)
   {
      if(flags & SharkSshFsOpenAppend)
      {
         if( ! (flags & SharkSshFsOpenCreate))
            return SharkSshFsUnsupported;
      }
      else if((flags & (SharkSshFsOpenCreate |
                        SharkSshFsOpenTruncate)) !=
              (SharkSshFsOpenCreate | SharkSshFsOpenTruncate))
         return SharkSshFsUnsupported;
   }
   else if(flags & (SharkSshFsOpenCreate | SharkSshFsOpenTruncate |
                    SharkSshFsOpenAppend))
      return SharkSshErrArgument;
   if(flags & SharkSshFsOpenRead)
      mode |= OpenRes_READ;
   if(flags & SharkSshFsOpenWrite)
      mode |= OpenRes_WRITE;
   if(flags & SharkSshFsOpenAppend)
      mode |= OpenRes_APPEND;
   if( ! mode || ! adapter->io->openResFp)
      return IOINTF_NOIMPLEMENTATION;
   status = sharkSshBasIo_path(name, path);
   if(status)
      return status;
   resource = adapter->io->openResFp(adapter->io, path, mode,
                                     &status, &ecode);
   (void)ecode;
   if( ! resource)
      return status ? sharkSshBasIo_status(status) : IOINTF_IOERROR;
   *file = resource;
   return SharkSshFsOk;
}

static int
sharkSshBasIo_close(void* context, void* file)
{
   ResIntfPtr resource = (ResIntfPtr)file;
   if( ! sharkSshBasIo_adapter(context) || ! resource || ! resource->closeFp)
      return SharkSshErrArgument;
   return sharkSshBasIo_status(resource->closeFp(resource));
}

static int
sharkSshBasIo_read(void* context, void* file, U8* data, U32 capacity,
                   U32* size)
{
   ResIntfPtr resource = (ResIntfPtr)file;
   size_t request = (size_t)capacity;
   size_t readSize = 0;
   int status;
   if( ! sharkSshBasIo_adapter(context) || ! resource ||
       ! resource->readFp || ! data || ! size)
      return SharkSshErrArgument;
   if(sizeof(size_t) < sizeof(U32) && (U32)request != capacity)
      request = (size_t)-1;
   status = resource->readFp(resource, data, request, &readSize);
   if(readSize > capacity)
      return SharkSshErrBounds;
   *size = (U32)readSize;
   return status == IOINTF_EOF ? SharkSshFsOk :
      sharkSshBasIo_status(status);
}

static int
sharkSshBasIo_write(void* context, void* file, const U8* data, U32 size,
                    U32* written)
{
   ResIntfPtr resource = (ResIntfPtr)file;
   U32 remaining = size;
   if( ! sharkSshBasIo_adapter(context) || ! resource ||
       ! resource->writeFp || ( ! data && size) || ! written)
      return SharkSshErrArgument;
   *written = 0;
   while(remaining)
   {
      size_t chunk = (size_t)remaining;
      int status;
      if(sizeof(size_t) < sizeof(U32) && (U32)chunk != remaining)
         chunk = (size_t)-1;
      status = resource->writeFp(resource, data, chunk);
      if(status)
         return sharkSshBasIo_status(status);
      data += chunk;
      remaining -= (U32)chunk;
      *written += (U32)chunk;
   }
   return SharkSshFsOk;
}

static int
sharkSshBasIo_seek(void* context, void* file, U32 offsetHi, U32 offsetLo)
{
   ResIntfPtr resource = (ResIntfPtr)file;
   U64 value = ((U64)offsetHi << 32) | offsetLo;
   BaFileSize offset = (BaFileSize)value;
   if( ! sharkSshBasIo_adapter(context) || ! resource || ! resource->seekFp)
      return SharkSshErrArgument;
   if((U64)offset != value)
      return SharkSshErrBounds;
   return sharkSshBasIo_status(resource->seekFp(resource, offset));
}

static void
sharkSshBasIo_setStat(SharkSshFsStat* target, const IoStat* source)
{
   U64 size = (U64)source->size;
   target->sizeHi = (U32)(size >> 32);
   target->sizeLo = (U32)size;
   if(source->lastModified <= 0)
      target->modifiedTime = 0;
   else if((U64)source->lastModified > 0xFFFFFFFFULL)
      target->modifiedTime = 0xFFFFFFFFU;
   else
      target->modifiedTime = (U32)source->lastModified;
   target->permissions = 0;
   target->type = source->isDir ? SharkSshFsTypeDirectory :
                                  SharkSshFsTypeFile;
}

static int
sharkSshBasIo_stat(void* context, SharkSshSpan name,
                   SharkSshFsStat* stat)
{
   SharkSshBasIo* adapter = sharkSshBasIo_adapter(context);
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   IoStat ioStat;
   int status;
   if( ! adapter || ! stat || ! adapter->io->statFp)
      return SharkSshErrArgument;
   status = sharkSshBasIo_path(name, path);
   if(status)
      return status;
   status = adapter->io->statFp(adapter->io, path, &ioStat);
   if(status)
      return sharkSshBasIo_status(status);
   sharkSshBasIo_setStat(stat, &ioStat);
   return SharkSshFsOk;
}

static int
sharkSshBasIo_remove(void* context, SharkSshSpan name)
{
   SharkSshBasIo* adapter = sharkSshBasIo_adapter(context);
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   const char* ecode = 0;
   int status;
   if( ! adapter || ! adapter->io->removeFp)
      return IOINTF_NOIMPLEMENTATION;
   status = sharkSshBasIo_path(name, path);
   if(status)
      return status;
   status = adapter->io->removeFp(adapter->io, path, &ecode);
   (void)ecode;
   return sharkSshBasIo_status(status);
}

static int
sharkSshBasIo_rename(void* context, SharkSshSpan oldName,
                     SharkSshSpan newName)
{
   SharkSshBasIo* adapter = sharkSshBasIo_adapter(context);
   char oldPath[SHARKSSH_MAX_PATH_LEN + 1];
   char newPath[SHARKSSH_MAX_PATH_LEN + 1];
   const char* ecode = 0;
   int status;
   if( ! adapter || ! adapter->io->renameFp)
      return IOINTF_NOIMPLEMENTATION;
   status = sharkSshBasIo_path(oldName, oldPath);
   if(status)
      return status;
   status = sharkSshBasIo_path(newName, newPath);
   if(status)
      return status;
   status = adapter->io->renameFp(adapter->io, oldPath, newPath, &ecode);
   (void)ecode;
   return sharkSshBasIo_status(status);
}

static int
sharkSshBasIo_makeDirectory(void* context, SharkSshSpan name,
                            U16 permissions)
{
   SharkSshBasIo* adapter = sharkSshBasIo_adapter(context);
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   const char* ecode = 0;
   int status;
   (void)permissions;
   if( ! adapter || ! adapter->io->mkDirFp)
      return IOINTF_NOIMPLEMENTATION;
   status = sharkSshBasIo_path(name, path);
   if(status)
      return status;
   status = adapter->io->mkDirFp(adapter->io, path, &ecode);
   (void)ecode;
   return sharkSshBasIo_status(status);
}

static int
sharkSshBasIo_removeDirectory(void* context, SharkSshSpan name)
{
   SharkSshBasIo* adapter = sharkSshBasIo_adapter(context);
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   const char* ecode = 0;
   int status;
   if( ! adapter || ! adapter->io->rmDirFp)
      return IOINTF_NOIMPLEMENTATION;
   status = sharkSshBasIo_path(name, path);
   if(status)
      return status;
   status = adapter->io->rmDirFp(adapter->io, path, &ecode);
   (void)ecode;
   return sharkSshBasIo_status(status);
}

static int
sharkSshBasIo_openDirectory(void* context, SharkSshSpan name,
                            void** directory)
{
   SharkSshBasIo* adapter = sharkSshBasIo_adapter(context);
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   const char* ecode = 0;
   DirIntfPtr iterator;
   int status;
   if( ! adapter || ! directory || ! adapter->io->openDirFp)
      return SharkSshErrArgument;
   *directory = 0;
   status = sharkSshBasIo_path(name, path);
   if(status)
      return status;
   iterator = adapter->io->openDirFp(adapter->io, path, &status, &ecode);
   (void)ecode;
   if( ! iterator)
      return status ? sharkSshBasIo_status(status) : IOINTF_IOERROR;
   *directory = iterator;
   return SharkSshFsOk;
}

static int
sharkSshBasIo_readDirectory(void* context, void* directory, U8* name,
                            U16 capacity, U16* size,
                            SharkSshFsStat* stat)
{
   DirIntfPtr iterator = (DirIntfPtr)directory;
   const char* entry;
   IoStat ioStat;
   size_t entrySize;
   int status;
   if( ! sharkSshBasIo_adapter(context) || ! iterator || ! name ||
       ! size || ! stat || ! iterator->readFp || ! iterator->getNameFp ||
       ! iterator->statFp)
      return SharkSshErrArgument;
   status = iterator->readFp(iterator);
   if(status == IOINTF_EOF || status == IOINTF_NOTFOUND)
      return SharkSshFsEnd;
   if(status)
      return sharkSshBasIo_status(status);
   entry = iterator->getNameFp(iterator);
   if( ! entry)
      return IOINTF_IOERROR;
   entrySize = strlen(entry);
   if(entrySize > capacity || entrySize > 0xFFFFU)
      return IOINTF_BUFTOOSMALL;
   status = iterator->statFp(iterator, &ioStat);
   if(status)
      return sharkSshBasIo_status(status);
   memcpy(name, entry, entrySize);
   *size = (U16)entrySize;
   sharkSshBasIo_setStat(stat, &ioStat);
   return SharkSshFsOk;
}

static int
sharkSshBasIo_closeDirectory(void* context, void* directory)
{
   SharkSshBasIo* adapter = sharkSshBasIo_adapter(context);
   DirIntfPtr iterator = (DirIntfPtr)directory;
   if( ! adapter || ! iterator || ! adapter->io->closeDirFp)
      return SharkSshErrArgument;
   return sharkSshBasIo_status(
      adapter->io->closeDirFp(adapter->io, &iterator));
}

void
SharkSshBasIo_constructor(SharkSshBasIo* adapter, IoIntfPtr io)
{
   SharkSshFileSystem* fileSystem;
   if( ! adapter)
      return;
   memset(adapter, 0, sizeof(*adapter));
   adapter->io = io;
   fileSystem = &adapter->fileSystem;
   fileSystem->context = adapter;
   fileSystem->open = sharkSshBasIo_open;
   fileSystem->close = sharkSshBasIo_close;
   fileSystem->read = sharkSshBasIo_read;
   fileSystem->write = sharkSshBasIo_write;
   fileSystem->seek = sharkSshBasIo_seek;
   fileSystem->stat = sharkSshBasIo_stat;
   fileSystem->remove = sharkSshBasIo_remove;
   fileSystem->rename = sharkSshBasIo_rename;
   fileSystem->makeDirectory = sharkSshBasIo_makeDirectory;
   fileSystem->removeDirectory = sharkSshBasIo_removeDirectory;
   fileSystem->openDirectory = sharkSshBasIo_openDirectory;
   fileSystem->readDirectory = sharkSshBasIo_readDirectory;
   fileSystem->closeDirectory = sharkSshBasIo_closeDirectory;
}

const SharkSshFileSystem*
SharkSshBasIo_getFileSystem(const SharkSshBasIo* adapter)
{
   return adapter ? &adapter->fileSystem : 0;
}
