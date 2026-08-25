/*
 *                 SharkSSH Embedded SSH Server
 ****************************************************************************
 *   BAS IOINTF FILESYSTEM PLUGIN
 *
 *   Adapts the generic BAS IoIntf API to SharkSshFileSystem. This header
 *   intentionally depends on no BAS header other than IoIntf.h.
 ****************************************************************************
 */

#ifndef _SharkSshBasIo_h
#define _SharkSshBasIo_h

#include <SharkSSH.h>
#include <IoIntf.h>

typedef struct
{
   SharkSshFileSystem fileSystem;
   IoIntfPtr io;
} SharkSshBasIo;

#ifdef __cplusplus
extern "C" {
#endif

void SharkSshBasIo_constructor(SharkSshBasIo* adapter, IoIntfPtr io);
const SharkSshFileSystem*
SharkSshBasIo_getFileSystem(const SharkSshBasIo* adapter);

#ifdef __cplusplus
}
#endif

#endif
