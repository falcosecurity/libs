/* The vfork() function has the same effect as fork(), except that the
 * behavior is undefined if the process created by vfork() either modifies
 * any data other than a variable of type pid_t used to store the return
 * value from vfork(), or returns from the function in which vfork() was
 * called, or calls any other function before successfully calling _exit()
 * or one of the exec() family of functions.
 *
 * For this reason right now we are not able to call the `vfork()` without
 * a segmentation fault...
 */
