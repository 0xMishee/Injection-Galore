cmake_minimum_required(VERSION 3.14)
project(InjectionGalore VERSION 0.1.0 LANGUAGES C)

add_executable(InjectionGalore
                src/main.c
                enumeration/enumeration.c)

target_include_directories(InjectionGalore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Headers)


include(CTest)
enable_testing()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
