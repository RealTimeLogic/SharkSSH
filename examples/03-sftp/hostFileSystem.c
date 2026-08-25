/* Example-only Windows/POSIX adapter for SharkSshFileSystem. */

#include "hostFileSystem.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define HOST_SEPARATOR '\\'
#define HOST_FILE_SHARE \
   (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

/** Heap wrapper around a Windows file handle exposed as an opaque handle. */
typedef struct
{
   HANDLE handle; /**< Native Windows file handle. */
} HostFile;

/** Windows directory iterator, including the first prefetched entry. */
typedef struct
{
   HANDLE find; /**< Native Windows search handle. */
   WIN32_FIND_DATAA data; /**< Current directory entry. */
   U8 first; /**< Nonzero until the prefetched first entry is consumed. */
} HostDirectory;

#else

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>
#define HOST_SEPARATOR '/'

/** Read POSIX metadata without following symbolic links on full host systems. */
static int
hostFileStat(const char* name, struct stat* information)
{
#ifdef ESP_PLATFORM
   return stat(name, information);
#else
   return lstat(name, information);
#endif /* ESP_PLATFORM */
}

/** Heap wrapper around a POSIX descriptor exposed as an opaque handle. */
typedef struct
{
   int descriptor; /**< Native POSIX file descriptor. */
} HostFile;

/** POSIX directory iterator and its canonical parent path. */
typedef struct
{
   DIR* directory; /**< Native POSIX directory stream. */
   char path[SHARKSSH_HOST_PATH_SIZE]; /**< Parent path for child stat calls. */
} HostDirectory;

#endif /* _WIN32 */

/**
 * Convert a client path into a rooted host path without allowing traversal.
 *
 * Empty, dot, dot-dot, backslash, colon, and embedded-NUL components are
 * rejected before the operating-system filesystem sees them.
 */
static int
hostPath(SharkSshHostFileSystem* adapter, SharkSshSpan path,
         char target[SHARKSSH_HOST_PATH_SIZE])
{
   U32 cursor = 0;
   size_t size;
   if( ! adapter || (path.len && ! path.ptr))
      return SharkSshErrArgument;
   size = strlen(adapter->root);
   if(size >= SHARKSSH_HOST_PATH_SIZE)
      return SharkSshErrBounds;
   memcpy(target, adapter->root, size);
   while(cursor < path.len)
   {
      U32 start = cursor;
      U32 componentSize;
      while(cursor < path.len && path.ptr[cursor] != '/')
      {
         U8 ch = path.ptr[cursor];
         if( ! ch || ch == '\\' || ch == ':')
            return SharkSshFsInvalidName;
         ++cursor;
      }
      componentSize = cursor - start;
      if( ! componentSize ||
         (componentSize == 1 && path.ptr[start] == '.') ||
         (componentSize == 2 && path.ptr[start] == '.' &&
          path.ptr[start + 1] == '.'))
         return SharkSshFsInvalidName;
      if(size + 1 + componentSize >= SHARKSSH_HOST_PATH_SIZE)
         return SharkSshErrBounds;
      target[size++] = HOST_SEPARATOR;
      memcpy(target + size, path.ptr + start, componentSize);
      size += componentSize;
      if(cursor < path.len)
         ++cursor;
   }
   target[size] = 0;
   return SharkSshFsOk;
}

#ifdef _WIN32

/** Translate a Windows filesystem error into a portable SharkSSH status. */
static int
hostStatus(DWORD error)
{
   switch(error)
   {
      case ERROR_FILE_NOT_FOUND:
      case ERROR_PATH_NOT_FOUND:
         return SharkSshFsNotFound;
      case ERROR_FILE_EXISTS:
      case ERROR_ALREADY_EXISTS:
         return SharkSshFsExists;
      case ERROR_ACCESS_DENIED:
      case ERROR_SHARING_VIOLATION:
         return SharkSshFsDenied;
      case ERROR_DISK_FULL:
         return SharkSshFsNoSpace;
      case ERROR_INVALID_NAME:
         return SharkSshFsInvalidName;
      default:
         return SharkSshErrService;
   }
}

/** Convert a Windows FILETIME to a bounded Unix timestamp. */
static U32
hostUnixTime(const FILETIME* time)
{
   ULARGE_INTEGER value;
   const ULONGLONG epoch = 116444736000000000ULL;
   value.LowPart = time->dwLowDateTime;
   value.HighPart = time->dwHighDateTime;
   if(value.QuadPart <= epoch)
      return 0;
   value.QuadPart = (value.QuadPart - epoch) / 10000000ULL;
   return value.QuadPart > 0xFFFFFFFFULL ? 0xFFFFFFFFU :
                                          (U32)value.QuadPart;
}

/** Convert Windows entry metadata into the generic SharkSSH representation. */
static void
hostSetStat(SharkSshFsStat* stat, DWORD attributes, DWORD sizeHigh,
            DWORD sizeLow, const FILETIME* modified)
{
   stat->sizeHi = sizeHigh;
   stat->sizeLo = sizeLow;
   stat->modifiedTime = hostUnixTime(modified);
   stat->permissions = attributes & FILE_ATTRIBUTE_READONLY ? 0444 : 0666;
   stat->type = attributes & FILE_ATTRIBUTE_DIRECTORY ?
      SharkSshFsTypeDirectory : SharkSshFsTypeFile;
   if(stat->type == SharkSshFsTypeDirectory)
      stat->permissions = (U16)(stat->permissions | 0111);
}

/** Open a Windows file according to generic SharkSSH open flags. */
static int
hostOpen(void* context, SharkSshSpan path, U8 flags, void** file)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   HostFile* opened;
   char name[SHARKSSH_HOST_PATH_SIZE];
   DWORD access = 0;
   DWORD creation = OPEN_EXISTING;
   HANDLE handle;
   int status;
   U8 valid = SharkSshFsOpenRead | SharkSshFsOpenWrite |
      SharkSshFsOpenCreate | SharkSshFsOpenTruncate |
      SharkSshFsOpenAppend | SharkSshFsOpenExclusive;
   if( ! file || (flags & ~valid) ||
      ! (flags & (SharkSshFsOpenRead | SharkSshFsOpenWrite)))
      return SharkSshErrArgument;
   *file = 0;
   status = hostPath(adapter, path, name);
   if(status)
      return status;
   if(flags & SharkSshFsOpenRead)
      access |= GENERIC_READ;
   if(flags & SharkSshFsOpenAppend)
      access |= FILE_APPEND_DATA;
   else if(flags & SharkSshFsOpenWrite)
      access |= GENERIC_WRITE;
   if(flags & SharkSshFsOpenExclusive)
      creation = CREATE_NEW;
   else if((flags & SharkSshFsOpenCreate) &&
           (flags & SharkSshFsOpenTruncate))
      creation = CREATE_ALWAYS;
   else if(flags & SharkSshFsOpenCreate)
      creation = OPEN_ALWAYS;
   else if(flags & SharkSshFsOpenTruncate)
      creation = TRUNCATE_EXISTING;
   handle = CreateFileA(name, access, HOST_FILE_SHARE, 0, creation,
                        FILE_ATTRIBUTE_NORMAL, 0);
   if(handle == INVALID_HANDLE_VALUE)
      return hostStatus(GetLastError());
   opened = (HostFile*)malloc(sizeof(*opened));
   if( ! opened)
   {
      CloseHandle(handle);
      return SharkSshErrBounds;
   }
   opened->handle = handle;
   *file = opened;
   return SharkSshFsOk;
}

/** Close and release an opaque Windows file handle. */
static int
hostClose(void* context, void* file)
{
   HostFile* opened = (HostFile*)file;
   int status;
   (void)context;
   if( ! opened)
      return SharkSshErrArgument;
   status = CloseHandle(opened->handle) ? SharkSshFsOk :
                                         hostStatus(GetLastError());
   free(opened);
   return status;
}

/** Read bytes from the current position of a Windows file handle. */
static int
hostRead(void* context, void* file, U8* data, U32 capacity, U32* size)
{
   HostFile* opened = (HostFile*)file;
   DWORD received = 0;
   (void)context;
   if( ! opened || ! data || ! size)
      return SharkSshErrArgument;
   if( ! ReadFile(opened->handle, data, capacity, &received, 0))
      return hostStatus(GetLastError());
   *size = received;
   return SharkSshFsOk;
}

/** Write bytes at the current position of a Windows file handle. */
static int
hostWrite(void* context, void* file, const U8* data, U32 size,
          U32* written)
{
   HostFile* opened = (HostFile*)file;
   DWORD count = 0;
   (void)context;
   if( ! opened || (size && ! data) || ! written)
      return SharkSshErrArgument;
   if( ! WriteFile(opened->handle, data, size, &count, 0))
      return hostStatus(GetLastError());
   *written = count;
   return SharkSshFsOk;
}

/** Seek a Windows file handle to an unsigned 64-bit absolute offset. */
static int
hostSeek(void* context, void* file, U32 high, U32 low)
{
   HostFile* opened = (HostFile*)file;
   LARGE_INTEGER offset;
   (void)context;
   if( ! opened)
      return SharkSshErrArgument;
   offset.HighPart = (LONG)high;
   offset.LowPart = low;
   return SetFilePointerEx(opened->handle, offset, 0, FILE_BEGIN) ?
      SharkSshFsOk : hostStatus(GetLastError());
}

/** Read generic metadata for one rooted Windows path. */
static int
hostStat(void* context, SharkSshSpan path, SharkSshFsStat* stat)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   WIN32_FILE_ATTRIBUTE_DATA data;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status;
   if( ! stat)
      return SharkSshErrArgument;
   status = hostPath(adapter, path, name);
   if(status)
      return status;
   if( ! GetFileAttributesExA(name, GetFileExInfoStandard, &data))
      return hostStatus(GetLastError());
   hostSetStat(stat, data.dwFileAttributes, data.nFileSizeHigh,
               data.nFileSizeLow, &data.ftLastWriteTime);
   return SharkSshFsOk;
}

/** Apply selected size, permission, and timestamp changes on Windows. */
static int
hostSetAttributes(void* context, SharkSshSpan path,
                  const SharkSshFsStat* stat, U8 flags)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status;
   if( ! stat)
      return SharkSshErrArgument;
   status = hostPath(adapter, path, name);
   if(status)
      return status;
   if(flags & SharkSshFsSetSize)
   {
      HANDLE file = CreateFileA(name, GENERIC_WRITE, HOST_FILE_SHARE, 0,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
      LARGE_INTEGER size;
      if(file == INVALID_HANDLE_VALUE)
         return hostStatus(GetLastError());
      size.HighPart = (LONG)stat->sizeHi;
      size.LowPart = stat->sizeLo;
      if( ! SetFilePointerEx(file, size, 0, FILE_BEGIN) ||
         ! SetEndOfFile(file))
         status = hostStatus(GetLastError());
      CloseHandle(file);
      if(status)
         return status;
   }
   if(flags & SharkSshFsSetPermissions)
   {
      DWORD attributes = GetFileAttributesA(name);
      if(attributes == INVALID_FILE_ATTRIBUTES)
         return hostStatus(GetLastError());
      if(stat->permissions & 0222)
         attributes &= ~FILE_ATTRIBUTE_READONLY;
      else
         attributes |= FILE_ATTRIBUTE_READONLY;
      if( ! SetFileAttributesA(name, attributes))
         return hostStatus(GetLastError());
   }
   if(flags & SharkSshFsSetModifiedTime)
   {
      HANDLE file = CreateFileA(name, FILE_WRITE_ATTRIBUTES,
                                HOST_FILE_SHARE, 0, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS, 0);
      ULARGE_INTEGER value;
      FILETIME time;
      if(file == INVALID_HANDLE_VALUE)
         return hostStatus(GetLastError());
      value.QuadPart = (ULONGLONG)stat->modifiedTime * 10000000ULL +
                       116444736000000000ULL;
      time.dwLowDateTime = value.LowPart;
      time.dwHighDateTime = value.HighPart;
      if( ! SetFileTime(file, 0, 0, &time))
         status = hostStatus(GetLastError());
      CloseHandle(file);
      if(status)
         return status;
   }
   return SharkSshFsOk;
}

/** Delete one non-directory Windows entry beneath the example root. */
static int
hostRemove(void* context, SharkSshSpan path)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status = hostPath(adapter, path, name);
   if(status)
      return status;
   return DeleteFileA(name) ? SharkSshFsOk : hostStatus(GetLastError());
}

/** Rename one rooted Windows entry without leaving the example root. */
static int
hostRename(void* context, SharkSshSpan oldPath, SharkSshSpan newPath)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   char oldName[SHARKSSH_HOST_PATH_SIZE];
   char newName[SHARKSSH_HOST_PATH_SIZE];
   int status = hostPath(adapter, oldPath, oldName);
   if( ! status)
      status = hostPath(adapter, newPath, newName);
   if(status)
      return status;
   return MoveFileA(oldName, newName) ? SharkSshFsOk :
                                       hostStatus(GetLastError());
}

/** Create one Windows directory; portable permissions are advisory here. */
static int
hostMakeDirectory(void* context, SharkSshSpan path, U16 permissions)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status = hostPath(adapter, path, name);
   (void)permissions;
   if(status)
      return status;
   return CreateDirectoryA(name, 0) ? SharkSshFsOk :
                                      hostStatus(GetLastError());
}

/** Remove one empty Windows directory beneath the example root. */
static int
hostRemoveDirectory(void* context, SharkSshSpan path)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status = hostPath(adapter, path, name);
   if(status)
      return status;
   return RemoveDirectoryA(name) ? SharkSshFsOk :
                                   hostStatus(GetLastError());
}

/** Open a Windows directory iterator that omits dot entries. */
static int
hostOpenDirectory(void* context, SharkSshSpan path, void** directory)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   HostDirectory* iterator;
   char name[SHARKSSH_HOST_PATH_SIZE];
   size_t size;
   int status;
   if( ! directory)
      return SharkSshErrArgument;
   *directory = 0;
   status = hostPath(adapter, path, name);
   if(status)
      return status;
   size = strlen(name);
   if(size + 2 >= sizeof(name))
      return SharkSshErrBounds;
   name[size++] = '\\';
   name[size++] = '*';
   name[size] = 0;
   iterator = (HostDirectory*)calloc(1, sizeof(*iterator));
   if( ! iterator)
      return SharkSshErrBounds;
   iterator->find = FindFirstFileA(name, &iterator->data);
   if(iterator->find == INVALID_HANDLE_VALUE)
   {
      status = hostStatus(GetLastError());
      free(iterator);
      return status;
   }
   iterator->first = 1;
   *directory = iterator;
   return SharkSshFsOk;
}

/** Return the next Windows directory name and its generic metadata. */
static int
hostReadDirectory(void* context, void* directory, U8* name,
                  U16 capacity, U16* size, SharkSshFsStat* stat)
{
   HostDirectory* iterator = (HostDirectory*)directory;
   (void)context;
   if( ! iterator || ! name || ! size || ! stat)
      return SharkSshErrArgument;
   for(;;)
   {
      size_t nameSize;
      if(iterator->first)
         iterator->first = 0;
      else if( ! FindNextFileA(iterator->find, &iterator->data))
         return GetLastError() == ERROR_NO_MORE_FILES ? SharkSshFsEnd :
                                                       hostStatus(GetLastError());
      if( ! strcmp(iterator->data.cFileName, ".") ||
         ! strcmp(iterator->data.cFileName, ".."))
         continue;
      nameSize = strlen(iterator->data.cFileName);
      if(nameSize > capacity || nameSize > 0xFFFFU)
         return SharkSshErrBounds;
      memcpy(name, iterator->data.cFileName, nameSize);
      *size = (U16)nameSize;
      hostSetStat(stat, iterator->data.dwFileAttributes,
                  iterator->data.nFileSizeHigh,
                  iterator->data.nFileSizeLow,
                  &iterator->data.ftLastWriteTime);
      return SharkSshFsOk;
   }
}

/** Close and release a Windows directory iterator. */
static int
hostCloseDirectory(void* context, void* directory)
{
   HostDirectory* iterator = (HostDirectory*)directory;
   int status;
   (void)context;
   if( ! iterator)
      return SharkSshErrArgument;
   status = FindClose(iterator->find) ? SharkSshFsOk :
                                       hostStatus(GetLastError());
   free(iterator);
   return status;
}

#else

/** Translate a POSIX `errno` value into a portable SharkSSH status. */
static int
hostStatus(int error)
{
   switch(error)
   {
      case ENOENT:
      case ENOTDIR:
         return SharkSshFsNotFound;
      case EEXIST:
         return SharkSshFsExists;
      case EACCES:
      case EPERM:
         return SharkSshFsDenied;
      case ENOSPC:
         return SharkSshFsNoSpace;
      case ENAMETOOLONG:
      case EINVAL:
         return SharkSshFsInvalidName;
      default:
         return SharkSshErrService;
   }
}

/** Clamp a POSIX timestamp to SharkSSH's unsigned 32-bit representation. */
static U32
hostUnixTime(time_t value)
{
   return value <= 0 ? 0 :
      (sizeof(value) > sizeof(U32) && (U64)value > 0xFFFFFFFFULL) ?
      0xFFFFFFFFU : (U32)value;
}

/** Convert POSIX stat data into the generic SharkSSH representation. */
static void
hostSetStat(SharkSshFsStat* target, const struct stat* source)
{
   U64 size = source->st_size < 0 ? 0 : (U64)source->st_size;
   target->sizeHi = (U32)(size >> 32);
   target->sizeLo = (U32)size;
   target->modifiedTime = hostUnixTime(source->st_mtime);
   target->permissions = (U16)(source->st_mode & 0777);
   target->type = S_ISDIR(source->st_mode) ? SharkSshFsTypeDirectory :
                                            SharkSshFsTypeFile;
}

/** Open a POSIX file according to generic SharkSSH open flags. */
static int
hostOpen(void* context, SharkSshSpan path, U8 flags, void** file)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   HostFile* opened;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int openFlags = 0;
   int descriptor;
   int status;
   U8 valid = SharkSshFsOpenRead | SharkSshFsOpenWrite |
      SharkSshFsOpenCreate | SharkSshFsOpenTruncate |
      SharkSshFsOpenAppend | SharkSshFsOpenExclusive;
   if( ! file || (flags & ~valid) ||
      ! (flags & (SharkSshFsOpenRead | SharkSshFsOpenWrite)))
      return SharkSshErrArgument;
   *file = 0;
   status = hostPath(adapter, path, name);
   if(status)
      return status;
   if((flags & SharkSshFsOpenRead) && (flags & SharkSshFsOpenWrite))
      openFlags = O_RDWR;
   else if(flags & SharkSshFsOpenWrite)
      openFlags = O_WRONLY;
   else
      openFlags = O_RDONLY;
   if(flags & SharkSshFsOpenCreate)
      openFlags |= O_CREAT;
   if(flags & SharkSshFsOpenTruncate)
      openFlags |= O_TRUNC;
   if(flags & SharkSshFsOpenAppend)
      openFlags |= O_APPEND;
   if(flags & SharkSshFsOpenExclusive)
      openFlags |= O_EXCL;
   descriptor = open(name, openFlags, 0666);
   if(descriptor < 0)
      return hostStatus(errno);
   opened = (HostFile*)malloc(sizeof(*opened));
   if( ! opened)
   {
      close(descriptor);
      return SharkSshErrBounds;
   }
   opened->descriptor = descriptor;
   *file = opened;
   return SharkSshFsOk;
}

/** Close and release an opaque POSIX file handle. */
static int
hostClose(void* context, void* file)
{
   HostFile* opened = (HostFile*)file;
   int status;
   (void)context;
   if( ! opened)
      return SharkSshErrArgument;
   status = close(opened->descriptor) ? hostStatus(errno) : SharkSshFsOk;
   free(opened);
   return status;
}

/** Read bytes from the current position of a POSIX file handle. */
static int
hostRead(void* context, void* file, U8* data, U32 capacity, U32* size)
{
   HostFile* opened = (HostFile*)file;
   ssize_t received;
   (void)context;
   if( ! opened || ! data || ! size)
      return SharkSshErrArgument;
   do
      received = read(opened->descriptor, data, (size_t)capacity);
   while(received < 0 && errno == EINTR);
   if(received < 0)
      return hostStatus(errno);
   *size = (U32)received;
   return SharkSshFsOk;
}

/** Write bytes at the current position of a POSIX file handle. */
static int
hostWrite(void* context, void* file, const U8* data, U32 size,
          U32* written)
{
   HostFile* opened = (HostFile*)file;
   ssize_t count;
   (void)context;
   if( ! opened || (size && ! data) || ! written)
      return SharkSshErrArgument;
   do
      count = write(opened->descriptor, data, (size_t)size);
   while(count < 0 && errno == EINTR);
   if(count < 0)
      return hostStatus(errno);
   *written = (U32)count;
   return SharkSshFsOk;
}

/** Seek a POSIX file descriptor to an unsigned 64-bit absolute offset. */
static int
hostSeek(void* context, void* file, U32 high, U32 low)
{
   HostFile* opened = (HostFile*)file;
   U64 value = ((U64)high << 32) | low;
   off_t offset = (off_t)value;
   (void)context;
   if( ! opened)
      return SharkSshErrArgument;
   if(offset < 0 || (U64)offset != value)
      return SharkSshErrBounds;
   return lseek(opened->descriptor, offset, SEEK_SET) < 0 ?
      hostStatus(errno) : SharkSshFsOk;
}

/** Read generic metadata for one rooted POSIX path. */
static int
hostStat(void* context, SharkSshSpan path, SharkSshFsStat* stat)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   struct stat information;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status;
   if( ! stat)
      return SharkSshErrArgument;
   status = hostPath(adapter, path, name);
   if(status)
      return status;
   if(hostFileStat(name, &information))
      return hostStatus(errno);
#ifndef ESP_PLATFORM
   if(S_ISLNK(information.st_mode))
      return SharkSshFsDenied;
#endif /* !ESP_PLATFORM */
   hostSetStat(stat, &information);
   return SharkSshFsOk;
}

/** Apply supported size, permission, and timestamp changes on POSIX. */
static int
hostSetAttributes(void* context, SharkSshSpan path,
                  const SharkSshFsStat* stat, U8 flags)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status;
   if( ! stat)
      return SharkSshErrArgument;
   status = hostPath(adapter, path, name);
   if(status)
      return status;
#ifdef ESP_PLATFORM
   if(flags & SharkSshFsSetPermissions)
      return SharkSshFsUnsupported;
#endif /* ESP_PLATFORM */
   if(flags & SharkSshFsSetSize)
   {
      U64 value = ((U64)stat->sizeHi << 32) | stat->sizeLo;
      off_t fileSize = (off_t)value;
      if(fileSize < 0 || (U64)fileSize != value)
         return SharkSshErrBounds;
      if(truncate(name, fileSize))
         return hostStatus(errno);
   }
#ifndef ESP_PLATFORM
   if((flags & SharkSshFsSetPermissions) &&
      chmod(name, (mode_t)(stat->permissions & 0777)))
      return hostStatus(errno);
#endif /* !ESP_PLATFORM */
   if(flags & SharkSshFsSetModifiedTime)
   {
      struct stat information;
      struct utimbuf times;
      if(hostFileStat(name, &information))
         return hostStatus(errno);
#ifndef ESP_PLATFORM
      if(S_ISLNK(information.st_mode))
         return SharkSshFsDenied;
#endif /* !ESP_PLATFORM */
      times.actime = information.st_atime;
      times.modtime = (time_t)stat->modifiedTime;
      if(utime(name, &times))
         return hostStatus(errno);
   }
   return SharkSshFsOk;
}

/** Delete one non-directory POSIX entry beneath the example root. */
static int
hostRemove(void* context, SharkSshSpan path)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status = hostPath(adapter, path, name);
   if(status)
      return status;
   return unlink(name) ? hostStatus(errno) : SharkSshFsOk;
}

/** Rename one rooted POSIX entry without leaving the example root. */
static int
hostRename(void* context, SharkSshSpan oldPath, SharkSshSpan newPath)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   char oldName[SHARKSSH_HOST_PATH_SIZE];
   char newName[SHARKSSH_HOST_PATH_SIZE];
   int status = hostPath(adapter, oldPath, oldName);
   if( ! status)
      status = hostPath(adapter, newPath, newName);
   if(status)
      return status;
   return rename(oldName, newName) ? hostStatus(errno) : SharkSshFsOk;
}

/** Create one POSIX directory using the requested portable permissions. */
static int
hostMakeDirectory(void* context, SharkSshSpan path, U16 permissions)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status = hostPath(adapter, path, name);
   if(status)
      return status;
   return mkdir(name, (mode_t)(permissions & 0777)) ?
      hostStatus(errno) : SharkSshFsOk;
}

/** Remove one empty POSIX directory beneath the example root. */
static int
hostRemoveDirectory(void* context, SharkSshSpan path)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status = hostPath(adapter, path, name);
   if(status)
      return status;
   return rmdir(name) ? hostStatus(errno) : SharkSshFsOk;
}

/** Open a POSIX directory iterator rooted beneath the example directory. */
static int
hostOpenDirectory(void* context, SharkSshSpan path, void** directory)
{
   SharkSshHostFileSystem* adapter = (SharkSshHostFileSystem*)context;
   HostDirectory* iterator;
   char name[SHARKSSH_HOST_PATH_SIZE];
   int status;
   if( ! directory)
      return SharkSshErrArgument;
   *directory = 0;
   status = hostPath(adapter, path, name);
   if(status)
      return status;
   iterator = (HostDirectory*)calloc(1, sizeof(*iterator));
   if( ! iterator)
      return SharkSshErrBounds;
   iterator->directory = opendir(name);
   if( ! iterator->directory)
   {
      status = hostStatus(errno);
      free(iterator);
      return status;
   }
   memcpy(iterator->path, name, strlen(name) + 1);
   *directory = iterator;
   return SharkSshFsOk;
}

/** Return the next safe POSIX directory name and its generic metadata. */
static int
hostReadDirectory(void* context, void* directory, U8* name,
                  U16 capacity, U16* size, SharkSshFsStat* stat)
{
   HostDirectory* iterator = (HostDirectory*)directory;
   (void)context;
   if( ! iterator || ! name || ! size || ! stat)
      return SharkSshErrArgument;
   for(;;)
   {
      struct dirent* entry;
      struct stat information;
      char child[SHARKSSH_HOST_PATH_SIZE];
      size_t pathSize;
      size_t nameSize;
      errno = 0;
      entry = readdir(iterator->directory);
      if( ! entry)
         return errno ? hostStatus(errno) : SharkSshFsEnd;
      if( ! strcmp(entry->d_name, ".") || ! strcmp(entry->d_name, ".."))
         continue;
      nameSize = strlen(entry->d_name);
      pathSize = strlen(iterator->path);
      if(nameSize > capacity || nameSize > 0xFFFFU ||
         pathSize + 1 + nameSize >= sizeof(child))
         return SharkSshErrBounds;
      memcpy(child, iterator->path, pathSize);
      child[pathSize++] = '/';
      memcpy(child + pathSize, entry->d_name, nameSize + 1);
      if(hostFileStat(child, &information))
         return hostStatus(errno);
#ifndef ESP_PLATFORM
      if(S_ISLNK(information.st_mode))
         continue;
#endif /* !ESP_PLATFORM */
      memcpy(name, entry->d_name, nameSize);
      *size = (U16)nameSize;
      hostSetStat(stat, &information);
      return SharkSshFsOk;
   }
}

/** Close and release a POSIX directory iterator. */
static int
hostCloseDirectory(void* context, void* directory)
{
   HostDirectory* iterator = (HostDirectory*)directory;
   int status;
   (void)context;
   if( ! iterator)
      return SharkSshErrArgument;
   status = closedir(iterator->directory) ? hostStatus(errno) : SharkSshFsOk;
   free(iterator);
   return status;
}

#endif /* _WIN32 */

/** Resolve the root and populate every generic filesystem callback. */
int
SharkSshHostFileSystem_constructor(SharkSshHostFileSystem* adapter,
                                   const char* root)
{
   SharkSshFileSystem* fileSystem;
   if( ! adapter || ! root)
      return SharkSshErrArgument;
   memset(adapter, 0, sizeof(*adapter));
#ifdef _WIN32
   {
      DWORD attributes;
      if( ! _fullpath(adapter->root, root, sizeof(adapter->root)))
         return SharkSshErrArgument;
      attributes = GetFileAttributesA(adapter->root);
      if(attributes == INVALID_FILE_ATTRIBUTES ||
         ! (attributes & FILE_ATTRIBUTE_DIRECTORY))
         return SharkSshFsNotFound;
   }
#else
   {
      size_t size;
      struct stat information;
#ifdef ESP_PLATFORM
      size = strlen(root);
      if( ! size || root[0] != '/' || size >= sizeof(adapter->root))
         return SharkSshErrArgument;
      memcpy(adapter->root, root, size + 1);
#else
      char* resolved;
      resolved = realpath(root, 0);
      if( ! resolved)
         return hostStatus(errno);
      size = strlen(resolved);
      if(size >= sizeof(adapter->root))
      {
         free(resolved);
         return SharkSshErrBounds;
      }
      memcpy(adapter->root, resolved, size + 1);
      free(resolved);
#endif /* ESP_PLATFORM */
      if(hostFileStat(adapter->root, &information) ||
         ! S_ISDIR(information.st_mode))
         return SharkSshFsNotFound;
   }
#endif /* _WIN32 */
   fileSystem = &adapter->fileSystem;
   fileSystem->context = adapter;
   fileSystem->open = hostOpen;
   fileSystem->close = hostClose;
   fileSystem->read = hostRead;
   fileSystem->write = hostWrite;
   fileSystem->seek = hostSeek;
   fileSystem->stat = hostStat;
   fileSystem->setStat = hostSetAttributes;
   fileSystem->remove = hostRemove;
   fileSystem->rename = hostRename;
   fileSystem->makeDirectory = hostMakeDirectory;
   fileSystem->removeDirectory = hostRemoveDirectory;
   fileSystem->openDirectory = hostOpenDirectory;
   fileSystem->readDirectory = hostReadDirectory;
   fileSystem->closeDirectory = hostCloseDirectory;
   return SharkSshFsOk;
}

/** Return the generic callback table embedded in a valid host adapter. */
const SharkSshFileSystem*
SharkSshHostFileSystem_getFileSystem(const SharkSshHostFileSystem* adapter)
{
   return adapter ? &adapter->fileSystem : 0;
}
