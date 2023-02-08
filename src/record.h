#include <sys/types.h>		       // pid_t

/**
 * @brief Get the cmdline of a process with given PID.
 *
 * @param pid PID of the process
 * @return char* cmdline of the process
 */
void record_start(char *fname);

/**
 * @brief Record entry for a process starting
 *
 * @param pid PID of process
 * @param poutname Process name
 */
void record_process_start(pid_t pid, char *poutname);

/**
 * @brief Record entry for a process's end
 *
 * @param poutname Process
 */
void record_process_end(char *poutname);

/**
 * @brief Record entry for a process's env vars
 *
 * @param poutname Process
 * @param envp Environment Pointer
 */
void record_process_env(char *poutname, char **envp);

/**
 * @brief Record entry for a process renaming a file
 *
 * @param poutname Process
 * @param from_foutname Old file name
 * @param to_foutname New file name
 */
void record_rename(char *poutname, char *from_foutname, char *to_foutname);

/**
 * @brief New record entry for a file.
 *
 * @param foutname File
 * @param path Path of the file as accessed
 * @param abspath Absolute path of the file
 */
void record_file(char *foutname, char *path, char *abspath);

/**
 * @brief Record entry for a process reading/writing from/to a file.
 *
 * @param poutname Process
 * @param foutname File
 * @param purpose What does the process do with the file.
 */
void record_fileuse(char *poutname, char *foutname, int purpose);

/**
 * @brief Record entry for a file content's hash
 *
 * @param foutname File
 * @param hash Hash of the file's contents
 */
void record_hash(char *foutname, char *hash);

/**
 * @brief Record entry for process P1 creating process P2
 *
 * @param p1outname Process 1
 * @param p2outname Process 2
 */
void record_process_create(char *p1outname, char *p2outname);

/**
 * @brief Record entry for an executable being executed.
 *
 * @param poutname Process
 * @param foutname File
 */
void record_exec(char *poutname, char *foutname);
