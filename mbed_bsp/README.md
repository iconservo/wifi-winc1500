
Two porting issues:

Winc host driver selects it's BSP in nm_bsp_internal.h , with a set of predefined includes.
Selecting the least likely macro ( __APP_APS3_CORTUS__ ) to be used elsewhere results in nm_bsp_aps3_cortus.h being pulled in.
This allows hooking Mbed definitions to be hooked in here.

Second, host driver socket.c contains a definition of symbol `close` which conflicts with Mbed.
To work around that, socket.c compilation is excluded, and patch_socket.c redefines that symbol to `winc_socket_close`

