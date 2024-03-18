#pragma once
#include <windows.h>
#include <stdio.h>


//{{NO_DEPENDENCIES}}
// Microsoft Visual C++ generated include file.
// Used by Resource.rc
//
// Setting the NTSTATUS Code to return as 0x00, since theres so many 

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)



/* Other statements */
#define OKAY(MSG, ...) printf("[+] " MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[i] " MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) printf("[-] " MSG "\n", ##__VA_ARGS__)
#define PROG(MSG, ...) printf("\r[*] " MSG,    ##__VA_ARGS__) /* solely for iterations */

/* Resource */
#define IDR_RCDATA1                     101

// Next default values for new objects
// 
#ifdef APSTUDIO_INVOKED
#ifndef APSTUDIO_READONLY_SYMBOLS
#define _APS_NEXT_RESOURCE_VALUE        102
#define _APS_NEXT_COMMAND_VALUE         40001
#define _APS_NEXT_CONTROL_VALUE         1001
#define _APS_NEXT_SYMED_VALUE           101
#endif
#endif
