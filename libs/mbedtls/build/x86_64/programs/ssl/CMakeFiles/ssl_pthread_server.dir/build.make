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
CMAKE_BINARY_DIR = /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64

# Include any dependencies generated for this target.
include programs/ssl/CMakeFiles/ssl_pthread_server.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include programs/ssl/CMakeFiles/ssl_pthread_server.dir/compiler_depend.make

# Include the progress variables for this target.
include programs/ssl/CMakeFiles/ssl_pthread_server.dir/progress.make

# Include the compile flags for this target's objects.
include programs/ssl/CMakeFiles/ssl_pthread_server.dir/flags.make

programs/ssl/CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.o: programs/ssl/CMakeFiles/ssl_pthread_server.dir/flags.make
programs/ssl/CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.o: /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/programs/ssl/ssl_pthread_server.c
programs/ssl/CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.o: programs/ssl/CMakeFiles/ssl_pthread_server.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object programs/ssl/CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.o"
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/programs/ssl && /home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=x86_64-none-linux-android21 --sysroot=/home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT programs/ssl/CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.o -MF CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.o.d -o CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.o -c /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/programs/ssl/ssl_pthread_server.c

programs/ssl/CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.i"
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/programs/ssl && /home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=x86_64-none-linux-android21 --sysroot=/home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/programs/ssl/ssl_pthread_server.c > CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.i

programs/ssl/CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.s"
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/programs/ssl && /home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=x86_64-none-linux-android21 --sysroot=/home/egor/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/programs/ssl/ssl_pthread_server.c -o CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.s

# Object files for target ssl_pthread_server
ssl_pthread_server_OBJECTS = \
"CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.o"

# External object files for target ssl_pthread_server
ssl_pthread_server_EXTERNAL_OBJECTS = \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/asn1_helpers.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/bignum_helpers.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/certs.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/drivers/hash.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/drivers/platform_builtin_keys.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_aead.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_asymmetric_encryption.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_cipher.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_agreement.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_management.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_mac.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_pake.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_signature.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/fake_external_rng_for_test.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/helpers.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/psa_crypto_helpers.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/psa_exercise_key.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/random.c.o" \
"/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles/mbedtls_test.dir/tests/src/threading_helpers.c.o"

programs/ssl/ssl_pthread_server: programs/ssl/CMakeFiles/ssl_pthread_server.dir/ssl_pthread_server.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/asn1_helpers.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/bignum_helpers.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/certs.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/drivers/hash.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/drivers/platform_builtin_keys.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_aead.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_asymmetric_encryption.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_cipher.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_agreement.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_management.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_mac.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_pake.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_signature.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/fake_external_rng_for_test.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/helpers.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/psa_crypto_helpers.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/psa_exercise_key.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/random.c.o
programs/ssl/ssl_pthread_server: CMakeFiles/mbedtls_test.dir/tests/src/threading_helpers.c.o
programs/ssl/ssl_pthread_server: programs/ssl/CMakeFiles/ssl_pthread_server.dir/build.make
programs/ssl/ssl_pthread_server: library/libmbedtls.so
programs/ssl/ssl_pthread_server: library/libmbedx509.so
programs/ssl/ssl_pthread_server: library/libmbedcrypto.so
programs/ssl/ssl_pthread_server: 3rdparty/everest/libeverest.a
programs/ssl/ssl_pthread_server: 3rdparty/p256-m/libp256m.a
programs/ssl/ssl_pthread_server: programs/ssl/CMakeFiles/ssl_pthread_server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable ssl_pthread_server"
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/programs/ssl && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ssl_pthread_server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
programs/ssl/CMakeFiles/ssl_pthread_server.dir/build: programs/ssl/ssl_pthread_server
.PHONY : programs/ssl/CMakeFiles/ssl_pthread_server.dir/build

programs/ssl/CMakeFiles/ssl_pthread_server.dir/clean:
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/programs/ssl && $(CMAKE_COMMAND) -P CMakeFiles/ssl_pthread_server.dir/cmake_clean.cmake
.PHONY : programs/ssl/CMakeFiles/ssl_pthread_server.dir/clean

programs/ssl/CMakeFiles/ssl_pthread_server.dir/depend:
	cd /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/programs/ssl /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64 /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/programs/ssl /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/build/x86_64/programs/ssl/CMakeFiles/ssl_pthread_server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : programs/ssl/CMakeFiles/ssl_pthread_server.dir/depend

