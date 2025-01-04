cmake_minimum_required(VERSION 3.19)
project(InjectionGalore VERSION 0.1.0)
enable_language(C ASM_NASM)

## Several .c files in Injection Methods folder
file(GLOB INJECTION_METHODS_SOURCES "Injection\ Methods/*.c")
file(GLOB SYSCALL_SOURCES "Syscall/*.c")

add_executable(InjectionGalore
                src/main.c
                ${INJECTION_METHODS_SOURCES}
                enumeration/enumeration.c
                Payloads/payloads.c
                ${SYSCALL_SOURCES}
                Syscall/ds.asm
                )

set_property(SOURCE Syscall/ds.asm PROPERTY LANGUAGE ASM_NASM)

## Direct Syscalls through Hell´s Gate are hella (ಥ_ಥ) illegal to C coding standards.
set_source_files_properties(Syscall/direct_syscall.c PROPERTIES COMPILE_FLAGS "-Wno-implicit-int -Wno-strict-prototypes -Wno-deprecated-non-prototype")

target_include_directories(InjectionGalore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Headers)
target_include_directories(InjectionGalore PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/Injection\ Methods")
target_include_directories(InjectionGalore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Payloads)
target_include_directories(InjectionGalore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/enumeration)
target_include_directories(InjectionGalore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Syscall)


include(CTest)
enable_testing()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
