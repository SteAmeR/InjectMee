# InjectMee

To remotely inject a specified process, usually use the API CreateRemoteThread provided by Windows to create a remote thread, and then inject dll or execute shellcode.

In a 64-bit system, this method requires special attention. The target process for injection must be consistent with the structure of the program, that is, a 32-bit program can only inject 32-bit processes, and a 64-bit program can only inject 64-bit processes.

![Capture](https://user-images.githubusercontent.com/399791/233868256-aa728939-7a01-477d-96b0-883dd346a7ec.PNG)

However, in some special environments, the structure of the target process cannot be predicted in advance, and it is unrealistic to prepare two different versions of the application

### Process injection steps:
- OpenProcess
- VirtualAllocEx
- WriteProcessMemory
- VirtualProtectEx
- CreateRemoteThread
- WaitForSingleObject

Carry out the following operations in sequence:
- Open the process according to the process ID and get the process handle
- Apply for memory space
- Data input
- Change memory to readable and executable (optional)
- Create thread
- Wait for thread to exit (optional)
