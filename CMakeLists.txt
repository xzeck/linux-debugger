cmake_minimum_required (VERSION 3.0)
project (linux-debugger)

add_compile_options(-std=c++14)

include_directories(ext/libelfin ext/linenoise include)
add_executable(debugger src/registers.cpp src/breakpoint.cpp src/debugger.cpp src/main.cpp ext/linenoise/linenoise.c)
set_target_properties(debugger
                     PROPERTIES COMPILE_FLAGS "-g -Wall -Wextra")

add_executable(hello tests/hello.cpp)
set_target_properties(hello
                      PROPERTIES COMPILE_FLAGS "-g -O0 -Wall -Wextra -gdwarf-4 -gstrict-dwarf"
                      RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/out/hello)

add_executable(steps tests/steps.cpp)
set_target_properties(steps
                      PROPERTIES COMPILE_FLAGS "-g -O0 -Wall -Wextra -gdwarf-4 -gstrict-dwarf"
                      RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/out/steps)

add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/ext/libelfin
)
target_link_libraries(debugger
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so)
add_dependencies(debugger libelfin)