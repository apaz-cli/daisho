#if __APPLE__
#include <mach-o/dyld.h>
#endif

#if __linux__
static val get_self_path(void)
{
  char self[PATH_MAX] = { 0 };
  int nchar = readlink("/proc/self/exe", self, sizeof self);

  if (nchar < 0 || nchar >= convert(int, sizeof self))
    return nil;
  return string_utf8(self);
}
#elif HAVE_WINDOWS_H
static val get_self_path(void)
{
  wchar_t self[MAX_PATH] = { 0 };
  DWORD nchar;

  SetLastError(0);
  nchar = GetModuleFileNameW(NULL, self, MAX_PATH);

  if (nchar == 0 ||
      (nchar == MAX_PATH &&
       ((GetLastError() == ERROR_INSUFFICIENT_BUFFER) ||
        (self[MAX_PATH - 1] != 0))))
    return nil;

  return string(self);
}
#elif __APPLE__
static val get_self_path(void)
{
  char self[PATH_MAX] = { 0 };
  uint32_t size = sizeof self;

  if (_NSGetExecutablePath(self, &size) != 0)
    return nil;
  return string_utf8(self);
}
#elif HAVE_GETEXECNAME
static val get_self_path(void)
{
  val execname = string_utf8(getexecname());
  if (car(execname) == chr('/'))
    return execname;
  return scat3(getcwd_wrap(), chr('/'), execname);
}
#else
static val get_self_path(void)
{
  char self[PATH_MAX];

  if (argv[0] && realpath(argv[0], self))
    return string_utf8(self);

   return lit(HARD_INSTALLATION_PATH);
}
#endif
