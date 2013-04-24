
#ifndef _SDBG_H
#define _SDBG_H

/**
 * From http://c.learncodethehardway.org/book/ex20.html
 *
 */

#ifdef _DEBUG

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define logdbg(M, ...)  fprintf(stdout, "[DEBUG] " M "\n", ##__VA_ARGS__)

#define logerr(M, ...)  fprintf(stdout, "[ERROR] (%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define logwarn(M, ...) fprintf(stdout, "[WARN]  " M "\n", ##__VA_ARGS__)

#define loginfo(M, ...) fprintf(stdout, "[INFO]  " M "\n", ##__VA_ARGS__)

#else
#define logdbg(x, ...)
#define logerr(x, ...)
#define logwarn(x, ...)
#define loginfo(x, ...)
#endif



#endif // _SDBG_H
