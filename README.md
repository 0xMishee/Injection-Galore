# Injection Galore

Project to test payloads with different injection techniques. 

## Description

Project is meant to help testing injection techniques in combination with some encryption & decryption, enumeration of host to spot potential issues with some payload. There's some benign payloads already that could be used otherwise just add another in "payloads.h". 

### Injection Techniques (Planned)
* DLL Injection (Remote)                        : Done.
* Shellcode Injection (Remote)                  : Done.
* APC Injection
* Mapping Injection
* Function Stomping
* PE Injections
* Reflective DLL                                : In progress.
* Threadless Injection
* Ghost Process Injection
* Herpaderping
* Herpaderply Hollowing
* Shellcode Reflective DLL
* Patchless Threadless Via Hardware Breakpoints
* Process Hypnosis
* Atom Bombing
* Cross Architecture

### Syscall Support
*Direct
*Indirect
*Unhooking

Use this website when needed to update the SSN [Windows X86-64 System Call Table (XP/2003/Vista/7/8/10/2022/11)](https://j00ru.vexillium.org/syscalls/nt/64/)

### Encryption (Planned)
* AES
* RSA
* XOR

### Enumeration (Planned)
* OS
* Processes
* Registry
* Services
* Hostnames

## Getting Started

Compile it with cmake with a Ninja generator.

Change directory for your ninja.exe file in "CMakePresets.json".

```
cd "Injection Galore"
cmake --preset=Config
cmake --build .\out\build\Config
```

### Executing program

* InjectionGalore.exe <flags> <value>
```
Example:
InjectionGalore.exe --injection rsc -payload calc
```

## Help

Found a bug? Create an issue for it ❤️
```
InjectionGalore.exe --help <options/Default: if left out> 
```

## Authors

Me, myself and I

## Version History

* 0.1
    * Initial Release

## License

This project is licensed under the GPL-3.0 License - see the LICENSE.md file for details