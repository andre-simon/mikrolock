/*      pinentry.c
 *
 *      Copyright 2011 Hans Alves <alves.h88@gmail.com>
 *      Modified by André Simon for mlock
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
#ifndef PINENTRY_H
#define PINENTRY_H

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>

#define READ 0
#define WRITE 1

void geanypg_read_till(int fd, char delim);
int geanypg_read(int fd, char delim, int max, char * buffer);
int prompt_pinentry(const char* c_user_salt, uint8_t* input, int max_len);

#endif