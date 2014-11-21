/*      pinentry.c
 *
 *      Copyright 2011 Hans Alves <alves.h88@gmail.com>
 * 
 *      Modified by Andre Simon for mlock
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *      MA 02110-1301, USA.
 */


#include "pinentry.h"

 void pinentry_read_till(int fd, char delim)
{
    while (1)
    {
        char val;
        ssize_t rv = read(fd, &val, 1);
        if (rv <= 0 || val == delim)
            break;
    }
}

 int pinentry_read(int fd, char delim, int max, char * buffer)
{
    int idx;
    ssize_t rv = 1;
    char ch = 0;
    for (idx = 0; (idx < max - 1) && rv > 0 && ch != delim; ++idx)
    {
        rv = read(fd, &ch, 1);
        buffer[idx] = ch;
    }
    buffer[idx ? idx - 1 : 0] = 0;
    return idx ? idx - 1 : 0;
}

//see https://github.com/geany/geany-plugins/blob/master/geanypg/src/pinentry.c
int prompt_pinentry(const char* c_user_salt, uint8_t* input, int max_len){
    int out_pipe[2];
    int in_pipe[2];
    int child_pid=0;
    int status=0;
    int read_cnt=0;
    
    char readbuffer[256] = {0}; /* pinentry should at least support passphrases of up to 2048 characters */
    FILE * child_in;

    if (pipe(out_pipe))
    {
        return 1;
    }
    if (pipe(in_pipe))
    {
        return 1;
    }

    child_pid = fork();
    if (!child_pid)
    { /* pinentry */
        char arg1[] = "pinentry";
        char * argv[] = {NULL, NULL};
        argv[0] = arg1;
        close(out_pipe[READ]);
        dup2(out_pipe[WRITE], STDOUT_FILENO);
        close(in_pipe[WRITE]);
        dup2(in_pipe[READ], STDIN_FILENO);
        execvp(*argv, argv);
	
        /* shouldn't get here */
        fprintf(stderr, "ERROR: %s (%s)\n", "Could not invoke the pinentry program ", strerror(errno));
        exit(1); /* kill the child */
    }

    close(out_pipe[WRITE]);
    close(in_pipe[READ]);
    child_in = fdopen(in_pipe[WRITE], "w");

    pinentry_read(out_pipe[READ], ' ', sizeof readbuffer, readbuffer);
    if (strncmp(readbuffer, "OK", 3))
    {
        fclose(child_in);
        waitpid(child_pid, &status, 0);
        close(out_pipe[READ]);
        return -1;
    }
    pinentry_read_till(out_pipe[READ], '\n'); /* read the rest of the first line after OK */
    fprintf(child_in, "SETTITLE mlock passphrase:\n");
    fflush(child_in);
    pinentry_read_till(out_pipe[READ], '\n');

    fprintf(child_in, "SETPROMPT Passphrase:\n");
    fflush(child_in);
    pinentry_read_till(out_pipe[READ], '\n');

    fprintf(child_in, "SETDESC Please enter your secret passphrase for %s\n", c_user_salt);
    fflush(child_in);
    pinentry_read_till(out_pipe[READ], '\n');

    fprintf(child_in, "GETPIN\n");
    fflush(child_in);

    pinentry_read(out_pipe[READ], ' ', sizeof readbuffer, readbuffer);
    if (!strncmp(readbuffer, "D", 2))
    {
        while (read_cnt<max_len-1)
        {
            char val;
            register ssize_t rv = read(out_pipe[READ], &val, 1);
            if (rv <= 0 || val == '\n')
            {
                break;
            }
	    input[read_cnt] = val; 
	    read_cnt++;
        }
        input[read_cnt] = 0;
    }
    else
    {
        fclose(child_in);
        waitpid(child_pid, &status, 0);
        close(out_pipe[READ]);
        return -1;
    }
    fclose(child_in);
    waitpid(child_pid, &status, 0);
    close(out_pipe[READ]);
    return 0;
}
