#ifndef TRACER_H
#define TRACER_H 1

/**
 * @brief Start the execution of the desired process as well as tracer for it.
 *
 * It takes in the argument vector and environmnent pointer for the desired
 * process to execute and executes it as a child process and tracks the
 * interactions it has with other processes and files.
 *
 * @param av Argument Vector
 * @param envp Environment Pointer
 */
void run_and_record_fnames(char **av, char **envp);

#endif