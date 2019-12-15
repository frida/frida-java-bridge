#include <stdint.h>

typedef enum _PaletteStatus PaletteStatus;

enum _PaletteStatus
{
  kOkay = 0,
  kCheckErrno = 1,
  kInvalidArgument = 2,
  kNotSupported = 3,
  kFailedCheckLog = 4,
};

PaletteStatus
PaletteGetVersion (int32_t * version)
{
  *version = 1;
  return kOkay;
}

PaletteStatus
PaletteSchedSetPriority (int32_t tid, int32_t java_priority)
{
  return kNotSupported;
}

PaletteStatus
PaletteSchedGetPriority (int32_t tid, int32_t * java_priority)
{
  return kNotSupported;
}

PaletteStatus
PaletteWriteCrashThreadStacks (const char * stacks, size_t stacks_len)
{
  return kNotSupported;
}

PaletteStatus
PaletteTraceEnabled (int32_t * enabled)
{
  *enabled = 0;
  return kOkay;
}

PaletteStatus
PaletteTraceBegin (const char * name)
{
  return kOkay;
}

PaletteStatus
PaletteTraceEnd (void)
{
  return kOkay;
}

PaletteStatus
PaletteTraceIntegerValue (const char * name, int32_t value)
{
  return kOkay;
}

PaletteStatus
PaletteAshmemCreateRegion (const char * name, size_t size, int * fd)
{
  return kNotSupported;
}

PaletteStatus
PaletteAshmemSetProtRegion (int fd, int prot)
{
  return kNotSupported;
}
