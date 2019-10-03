# kernel
Header-only library that assists you with exploiting the Windows kernel

## Features
* Exports kernel functions (with almost full support for proper types)
* Provides a function to steal the SYSTEN token to elevate privileges
* Works safely from kernel context

## Example
```cpp
#define KERNEL_DEBUG // enable verbose kernel mode

#include "kernel.h"

int processId = GetCurrentProcessId();

void main()
{
    InitializeKernel(); // Initialize kernel symbols
    // The next line should be called through kernel context, not from userland
    KernelElevateProcess(processId); // Copies the SYSTEM token from PID 4 to processId
}
```
