# Sanitizer.cmake — AddressSanitizer + UndefinedBehaviorSanitizer support
#
# Usage: cmake -B build-san -DSSM_SANITIZE=ON
#
# Adds -fsanitize=address,undefined to compile/link flags for all targets.
# Only tested with clang and gcc. Not compatible with valgrind.

option(SSM_SANITIZE "Enable AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

if(SSM_SANITIZE)
    message(STATUS "Sanitizers enabled: address + undefined")

    set(SANITIZE_FLAGS "-fsanitize=address,undefined -fno-omit-frame-pointer")

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZE_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SANITIZE_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${SANITIZE_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${SANITIZE_FLAGS}")
endif()
