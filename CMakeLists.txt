cmake_minimum_required(VERSION 3.19)
project(InjectionGalore VERSION 0.1.0)

enable_language(C ASM_NASM)

# Gather source files
file(GLOB INJECTION_METHODS_SOURCES "Injection Methods/*.c")
file(GLOB SYSCALL_SOURCES "Syscall/*.c")
set(ASM_SOURCES "Syscall/ds.asm")

# Define executable
add_executable(InjectionGalore
    src/main.c
    ${INJECTION_METHODS_SOURCES}
    enumeration/enumeration.c
    Payloads/payloads.c
    ${SYSCALL_SOURCES}
    ${ASM_SOURCES}
)

# Suppress specific warnings for direct_syscall.c (Syscall isn't kosher)
set_source_files_properties(Syscall/direct_syscall.c PROPERTIES 
    COMPILE_FLAGS "-Wno-implicit-int -Wno-strict-prototypes -Wno-deprecated-non-prototype"
)

# Set properties for NASM assembly sources
set_source_files_properties(${ASM_SOURCES} PROPERTIES 
    LANGUAGE ASM_NASM 
    COMPILE_FLAGS "-f win64"
)

# Include directories
target_include_directories(InjectionGalore PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/Headers
    "${CMAKE_CURRENT_SOURCE_DIR}/Injection Methods"
    ${CMAKE_CURRENT_SOURCE_DIR}/Payloads
    ${CMAKE_CURRENT_SOURCE_DIR}/enumeration
    ${CMAKE_CURRENT_SOURCE_DIR}/Syscall
    ${CMAKE_CURRENT_SOURCE_DIR}/Structs
)

# Add testing capabilities (for later)
include(CTest)
enable_testing()

# Packaging information
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
