# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

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
CMAKE_COMMAND = /home/egor/Android/Sdk/cmake/3.22.1/bin/cmake

# The command to remove a file.
RM = /home/egor/Android/Sdk/cmake/3.22.1/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86

# Include any dependencies generated for this target.
include tests/CMakeFiles/test_suite_ecp.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include tests/CMakeFiles/test_suite_ecp.dir/compiler_depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/test_suite_ecp.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/test_suite_ecp.dir/flags.make

tests/test_suite_ecp.c: /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/scripts/generate_test_code.py
tests/test_suite_ecp.c: /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_ecp.function
tests/test_suite_ecp.c: /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_ecp.data
tests/test_suite_ecp.c: /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/main_test.function
tests/test_suite_ecp.c: /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/host_test.function
tests/test_suite_ecp.c: /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/helpers.function
tests/test_suite_ecp.c: library/libmbedtls.so
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating test_suite_ecp.c"
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests && /usr/bin/python3 /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/scripts/generate_test_code.py -f /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_ecp.function -d /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_ecp.data -t /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/main_test.function -p /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/host_test.function -s /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites --helpers-file /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/helpers.function -o .

tests/CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.o: tests/CMakeFiles/test_suite_ecp.dir/flags.make
tests/CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.o: tests/test_suite_ecp.c
tests/CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.o: tests/CMakeFiles/test_suite_ecp.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object tests/CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.o"
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests && /home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=i686-none-linux-android21 --sysroot=/home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT tests/CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.o -MF CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.o.d -o CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.o -c /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests/test_suite_ecp.c

tests/CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.i"
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests && /home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=i686-none-linux-android21 --sysroot=/home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests/test_suite_ecp.c > CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.i

tests/CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.s"
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests && /home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=i686-none-linux-android21 --sysroot=/home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests/test_suite_ecp.c -o CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.s

# Object files for target test_suite_ecp
test_suite_ecp_OBJECTS = \
"CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.o"

# External object files for target test_suite_ecp
test_suite_ecp_EXTERNAL_OBJECTS = \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/asn1_helpers.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/bignum_helpers.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/certs.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/drivers/hash.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/drivers/platform_builtin_keys.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_aead.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_asymmetric_encryption.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_cipher.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_agreement.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_management.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_mac.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_pake.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_signature.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/fake_external_rng_for_test.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/helpers.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/psa_crypto_helpers.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/psa_exercise_key.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/random.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test.dir/tests/src/threading_helpers.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles/mbedtls_test_helpers.dir/tests/src/test_helpers/ssl_helpers.c.o"

tests/test_suite_ecp: tests/CMakeFiles/test_suite_ecp.dir/test_suite_ecp.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/asn1_helpers.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/bignum_helpers.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/certs.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/drivers/hash.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/drivers/platform_builtin_keys.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_aead.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_asymmetric_encryption.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_cipher.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_agreement.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_management.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_mac.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_pake.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_signature.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/fake_external_rng_for_test.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/helpers.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/psa_crypto_helpers.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/psa_exercise_key.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/random.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test.dir/tests/src/threading_helpers.c.o
tests/test_suite_ecp: CMakeFiles/mbedtls_test_helpers.dir/tests/src/test_helpers/ssl_helpers.c.o
tests/test_suite_ecp: tests/CMakeFiles/test_suite_ecp.dir/build.make
tests/test_suite_ecp: library/libmbedtls.so
tests/test_suite_ecp: library/libmbedx509.so
tests/test_suite_ecp: library/libmbedcrypto.so
tests/test_suite_ecp: 3rdparty/everest/libeverest.a
tests/test_suite_ecp: 3rdparty/p256-m/libp256m.a
tests/test_suite_ecp: tests/CMakeFiles/test_suite_ecp.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable test_suite_ecp"
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_suite_ecp.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/test_suite_ecp.dir/build: tests/test_suite_ecp
.PHONY : tests/CMakeFiles/test_suite_ecp.dir/build

tests/CMakeFiles/test_suite_ecp.dir/clean:
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests && $(CMAKE_COMMAND) -P CMakeFiles/test_suite_ecp.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/test_suite_ecp.dir/clean

tests/CMakeFiles/test_suite_ecp.dir/depend: tests/test_suite_ecp.c
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86 /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86/tests/CMakeFiles/test_suite_ecp.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/test_suite_ecp.dir/depend

