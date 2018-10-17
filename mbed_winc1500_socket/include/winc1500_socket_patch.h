/*
This file is needed to prevent the same function name error during compilation 

Id included the file socket.h the following error occurs: 

./PATH_TO_YOUR_SOCKET_FOLDER/socket/include/socket.h:1833:15: error: conflicting declaration of C function 'sint8 close(SOCKET)'
 NMI_API sint8 close(SOCKET sock);
               ^~~~~
In file included from ./mbed-os/platform/mbed_error.h:25:0,
                 from ./mbed-os/rtos/Queue.h:30,
                 from ./mbed-os/rtos/Mail.h:28,
                 from ./mbed-os/rtos/rtos.h:34,
                 from ./mbed-os/mbed.h:22,
                 from ./main.cpp:17:
./mbed-os/platform/mbed_retarget.h:531:9: note: previous declaration 'int close(int)'
     int close(int fildes);
         ^~~~~

If new socket implementation is changed need to replace the socket.c and socket.h files with newer ones.

*/


#ifndef WINC_SOCKET_PATCH_
#define WINC_SOCKET_PATCH_

#define WINC_SOCKET(name)		winc_socket_ ## name


#endif
