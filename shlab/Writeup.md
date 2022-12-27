# Datalab

This is the writeup for CSAPP shlab

## Goals

To help us better understand the concept of exceptional control flow, we are going to make a tiny shell (`tsh`) that can run basic user commands and some built-in commands. It could also manipulate foreground and background jobs like what we have in the `bash`. We could fulfill this goal by finishing some essential missing functions in the `tsh.c` file. 

- `eval` function. To understand how `fork` and `execve` system calls will be used, how foreground and background jobs are set up, and how `sigprocmask` will be used to block/unblock signals in order to manage the process correctly. 
- `do_bgfg` shell builtin function. To understand how to manipulate foreground and background jobs.
- `sig??_handler` a bunch of signal handler functions. To understand how to reap out children using `waitpid` system call and how to send the signal to other processes using the `kill` system call. 

## Evaluate Function
The `eval` function is the first and most basic function we need to implement in this lab. The logic is easy. First, parse the command using provided helper function `parseline`. Then check if it is the built-in command. If not, then we could execute the user command directly by using `fork`, `execve` combo. Easy and straightforward. 

But to fulfill our goal, we should treat each non-built-in command as a **job** (similar to the concept of process in OS's view) to make our life easier in the rest functions. When each user command gets executed, whether it is foreground or background, we should add it to the job list (implementation provided). Since when each child process terminates, it will send `SIGCHLD` to the parent process. We should block this signal before we `fork` the child in case our child terminates before we add the job. Then unblock after adding the job to the job list. We should also unblock it in the child process so that the child process can receive `SIGCHLD` from its child. 

```c
/*
 * eval - Evaluate the command line that the user has just typed in
 *
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.
 */
void eval(char *cmdline)
{
    char *argv[MAXARGS];                    // argv for execve
    int bg;                                 // background job or not
    pid_t cpid;                             // child pid
    int state;                              // process status
    sigset_t mask_all, mask_one, prev_mask; // signal maskes

    bg = parseline(cmdline, argv);

    // ignore blank line
    if (argv[0] == NULL)
        return;

    // execute built-in command directly
    if (!builtin_cmd(argv))
    {
        // fill the mask
        sigfillset(&mask_all);
        sigemptyset(&mask_one);
        sigaddset(&mask_one, SIGCHLD);

        // block SIGCHILD after added the job
        sigprocmask(SIG_BLOCK, &mask_one, &prev_mask);
        // fork child to run command
        cpid = fork();
        if (cpid == -1)
            unix_error("fork error!");

        if (cpid == 0)
        {
            // child
            // unblock signals for child
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);

            if (setpgid(0, 0) < 0)
                unix_error("setpgid error!");

            if (execve(argv[0], argv, environ) < 0)
                unix_error("execve error!");
        }
        else
        {
            // parent
            state = bg ? BG : FG;

            // block all while adding job
            sigprocmask(SIG_BLOCK, &mask_all, NULL);
            if (addjob(jobs, cpid, state, cmdline) == 0)
                unix_error("addjob error!");
            // unblock SIGCHILD after added job
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);

            if (!bg)
                // wait foreground job
                waitfg(cpid);
            else
                // background prompt
                printf("[%d] (%d) %s", pid2jid(cpid), cpid, cmdline);
        }
    }

    return;
}
```

## Background & Foreground

Manipulating background and foreground jobs is relatively easy since the skeleton code already provides us with the `job_t` struct. In the `do_bgfg` function, we only need to modify the `state` field of the job given through the command line. The project provides us with `getjobpid` and `getjobjid`. They can allow us to get the corresponding job very easily. 

After we have the proper job filtered out, we can resume the process by sending `SIGCONT` signal through `kill` system call. 

```c
/*
 * do_bgfg - Execute the builtin bg and fg commands
 */
void do_bgfg(char **argv)
{
    struct job_t *job;
    int id;

    if (argv[1] == NULL)
    {
        printf("%s command requires PID or %%jobid argument\n", argv[0]);
        return;
    }

    // user input jobjid or pid
    if (sscanf(argv[1], "%%%d", &id) > 0)
        job = getjobjid(jobs, id);
    else if (sscanf(argv[1], "%d", &id) > 0)
        job = getjobpid(jobs, id);
    else
    {
        unix_error("sscanf error!");
    }

    if (job != NULL)
    {
        kill(job->pid, SIGCONT);
        if (strcmp(argv[0], "bg") == 0)
        {
            job->state = BG;
            printf("[%d] (%d) %s", job->jid, job->pid, job->cmdline);
        }
        else
        {
            job->state = FG;
            waitfg(job->pid);
        }
    }
    else
        printf("(%d) No such process\n", id);

    return;
}
```

## Signal Handlers

We need to implement total 3 signal handlers: `sigchld_handler`, `sigint_handler`, and `sigtstp_handler`. `sigint_handler` and `sigtstp_handler` are very easy to implement because they both apply to the foreground job. They can get the foreground job pid directly through `fgpid` helper function and send the signal through kill. 

```c
/*
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.
 */
void sigint_handler(int sig)
{
    pid_t pid;
    int olderrno;

    olderrno = errno;

    pid = fgpid(jobs);
    if (pid)
    {
        kill(pid, sig);
    }

    errno = olderrno;
    return;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.
 */
void sigtstp_handler(int sig)
{
    pid_t pid;
    int olderrno;

    olderrno = errno;

    pid = fgpid(jobs);
    if (pid)
    {
        kill(pid, sig);
    }

    errno = olderrno;
    return;
}
```

`sigchld_handler`, on the other hand, is more complicated. We should have a more comprehansive view of how we should use `waitpid` to reap the children. Let's first take look at the man page. 

```
The  waitpid()  system  call suspends execution of the calling thread until a child specified by pid argument has changed state. 
By default, waitpid() waits only for terminated chil‐dren, but this behavior is modifiable via the options argument, as described below.

The value of pid can be:

< -1   meaning wait for any child process whose process group ID is equal to the absolute value of pid.

-1     meaning wait for any child process.

0      meaning wait for any child process whose process group ID is equal to that of the calling process at the time of the call to waitpid().

> 0    meaning wait for the child whose process ID is equal to the value of pid.

The value of options is an OR of zero or more of the following constants:

WNOHANG     return immediately if no child has exited.

WUNTRACED   also return if a child has stopped (but not traced via ptrace(2)).  Status for traced children which have stopped is provided even if this option is not specified.

If wstatus is not NULL, wait() and waitpid() store status information in the int to which it points.  This integer can be inspected with the following macros (which take  the  integer
itself as an argument, not a pointer to it, as is done in wait() and waitpid()!):

WIFEXITED(wstatus)
       returns true if the child terminated normally, that is, by calling exit(3) or _exit(2), or by returning from main().

WEXITSTATUS(wstatus)
       returns  the exit status of the child.  This consists of the least significant 8 bits of the status argument that the child specified in a call to exit(3) or _exit(2) or as the
       argument for a return statement in main().  This macro should be employed only if WIFEXITED returned true.

WIFSIGNALED(wstatus)
       returns true if the child process was terminated by a signal.

WTERMSIG(wstatus)
       returns the number of the signal that caused the child process to terminate.  This macro should be employed only if WIFSIGNALED returned true.

WCOREDUMP(wstatus)
       returns true if the child produced a core dump (see core(5)).  This macro should be employed only if WIFSIGNALED returned true.

WIFSTOPPED(wstatus)
       returns  true  if  the  child  process  was  stopped  by delivery of a signal; this is possible only if the call was done using WUNTRACED or when the child is being traced (see
       ptrace(2)).

WSTOPSIG(wstatus)
       returns the number of the signal which caused the child to stop.  This macro should be employed only if WIFSTOPPED returned true.

WIFCONTINUED(wstatus)
       (since Linux 2.6.10) returns true if the child process was resumed by delivery of SIGCONT.
```

`waitpid` system call gives us various options to reap a child from the parent process. Each time a child is stopped or terminated (received signal or not) will send `SIGCHLD` to the parent. We could identify different cases by functions to the `wstatus`. We will need `WIFEXITED` to represent a normal exit of the child, `WIFSIGNALED` to represent exit by receiving a signal from other processes like `SIGINT` sent by the user through ctrl-c, and `WIFSTOPPED` represents stopped by receiving a signal from other processes like `SIGTSTP` send by the user through ctrl-z. Then, we could wrap those in a while loop to make sure we reap all the children each time we receive a `SIGCHLD` signal. Don't forget to block the signal while deleting the job!

```c
/*
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.
 */
void sigchld_handler(int sig)
{
    struct job_t *job;            // job ptr for a terminated or stopped job
    pid_t pid;                    // child pid
    int status;                   // child status
    sigset_t mask_all, prev_mask; // signal maskes
    int olderrno;                 // save errno

    olderrno = errno;
    sigfillset(&mask_all);

    // reaping children
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0)
    {
        if (WIFEXITED(status))
        {
            // normal exit
            sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
            deletejob(jobs, pid);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        }
        else if (WIFSIGNALED(status))
        {
            // terminated by a signal
            job = getjobpid(jobs, pid);
            sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
            printf("Job [%d] (%d) terminated by singal %d\n", job->jid, job->pid, SIGINT);
            deletejob(jobs, pid);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        }
        else
        {
            // stopped
            job = getjobpid(jobs, pid);
            sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
            printf("Job [%d] (%d) stopped by singal %d\n", job->jid, job->pid, SIGTSTP);
            job->state = ST;
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        }
    }

    errno = olderrno;
    return;
}
```
