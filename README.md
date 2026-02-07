# SyscallResolver

*SyscallResolver* is a research oriented project that implements multiple techniques for resolving **Windows system call numbers (SSNs)** at **runtime**, which are required for direct/indirect syscalls.

The project focuses mainly in **Windows internals**, **PE parsing**, and different techniques public tools use for **syscall number discovery**. It provides clean, minimal demonstration using non intrusive syscalls. It does **not** pretends to be evasive and lacks obfuscation, if evasion were the goal additional techniques such as **string hashing**, **IAT obfuscation**, **indirect syscalls**, or similar mechanisms would be required.


## Techniques / Tools

- [Syswhispers2/3](https://github.com/jthuraisamy/SysWhispers2) -- Sort array technique
- [HellsGate](https://github.com/am0nsec/HellsGate) -- Stub Inspection
- [Syswhispers](http://github.com/jthuraisamy/SysWhispers) -- Build based technique


## Understanding implementation
Each technique is implemented in its own directory, which contains:
- **README.md** : Detailed explanation of the technique
- **main.c** : SSN resolver implementation
- **WinStructs.h** : Required Windows Internals structures
- **syscalls.h** : Header to export the SSN resolver
- **test_exec.c** : Test usage of resolver 
- **stub.asm** : Minimal syscall stub
 

Note that the implementations were written entirely from scratch. While it follows the same underlying techniques described in existing tools, the internal approaches may differ, as I intentionally did not study or reuse their source code in detail. The goal was to keep the implementation as simple and readable as possible, given that many publicly available implementations tend to be overly complex.


## Compilation
```bash
ml64 stub.asm
cl main.c test_exec.c /link stub.obj
