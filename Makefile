# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.26

# Default target executed when no arguments are given to make.
default_target: all
.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ajay/de/debugger

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ajay/de/debugger

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/usr/bin/ccmake -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache
.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake --regenerate-during-build -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache
.PHONY : rebuild_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/ajay/de/debugger/CMakeFiles /home/ajay/de/debugger//CMakeFiles/progress.marks
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/ajay/de/debugger/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean
.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named debugger

# Build rule for target.
debugger: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 debugger
.PHONY : debugger

# fast build rule for target.
debugger/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/debugger.dir/build.make CMakeFiles/debugger.dir/build
.PHONY : debugger/fast

#=============================================================================
# Target rules for targets named libelfin

# Build rule for target.
libelfin: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 libelfin
.PHONY : libelfin

# fast build rule for target.
libelfin/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/libelfin.dir/build.make CMakeFiles/libelfin.dir/build
.PHONY : libelfin/fast

ext/linenoise/linenoise.o: ext/linenoise/linenoise.c.o
.PHONY : ext/linenoise/linenoise.o

# target to build an object file
ext/linenoise/linenoise.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/debugger.dir/build.make CMakeFiles/debugger.dir/ext/linenoise/linenoise.c.o
.PHONY : ext/linenoise/linenoise.c.o

ext/linenoise/linenoise.i: ext/linenoise/linenoise.c.i
.PHONY : ext/linenoise/linenoise.i

# target to preprocess a source file
ext/linenoise/linenoise.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/debugger.dir/build.make CMakeFiles/debugger.dir/ext/linenoise/linenoise.c.i
.PHONY : ext/linenoise/linenoise.c.i

ext/linenoise/linenoise.s: ext/linenoise/linenoise.c.s
.PHONY : ext/linenoise/linenoise.s

# target to generate assembly for a file
ext/linenoise/linenoise.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/debugger.dir/build.make CMakeFiles/debugger.dir/ext/linenoise/linenoise.c.s
.PHONY : ext/linenoise/linenoise.c.s

src/main.o: src/main.cpp.o
.PHONY : src/main.o

# target to build an object file
src/main.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/debugger.dir/build.make CMakeFiles/debugger.dir/src/main.cpp.o
.PHONY : src/main.cpp.o

src/main.i: src/main.cpp.i
.PHONY : src/main.i

# target to preprocess a source file
src/main.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/debugger.dir/build.make CMakeFiles/debugger.dir/src/main.cpp.i
.PHONY : src/main.cpp.i

src/main.s: src/main.cpp.s
.PHONY : src/main.s

# target to generate assembly for a file
src/main.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/debugger.dir/build.make CMakeFiles/debugger.dir/src/main.cpp.s
.PHONY : src/main.cpp.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... libelfin"
	@echo "... debugger"
	@echo "... ext/linenoise/linenoise.o"
	@echo "... ext/linenoise/linenoise.i"
	@echo "... ext/linenoise/linenoise.s"
	@echo "... src/main.o"
	@echo "... src/main.i"
	@echo "... src/main.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system
