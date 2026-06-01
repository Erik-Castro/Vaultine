find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_SQLCIPHER sqlcipher)
endif()

find_path(SQLCIPHER_INCLUDE_DIR
    NAMES sqlcipher.h sqlcipher/sqlite3.h
    HINTS ${PC_SQLCIPHER_INCLUDE_DIRS}
)

find_library(SQLCIPHER_LIBRARY
    NAMES sqlcipher
    HINTS ${PC_SQLCIPHER_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SQLCipher
    REQUIRED_VARS SQLCIPHER_LIBRARY SQLCIPHER_INCLUDE_DIR
)

if(SQLCipher_FOUND AND NOT TARGET SQLCipher::SQLCipher)
    add_library(SQLCipher::SQLCipher UNKNOWN IMPORTED)
    set_target_properties(SQLCipher::SQLCipher PROPERTIES
        IMPORTED_LOCATION "${SQLCIPHER_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SQLCIPHER_INCLUDE_DIR}"
        # INTERFACE_COMPILE_DEFINITIONS "SQLITE_HAS_CODEC"      # not needed — use PRAGMA key
    )
    if(PC_SQLCIPHER_CFLAGS_OTHER)
        set_target_properties(SQLCipher::SQLCipher PROPERTIES
            INTERFACE_COMPILE_OPTIONS "${PC_SQLCIPHER_CFLAGS_OTHER}"
        )
    endif()
endif()

mark_as_advanced(SQLCIPHER_INCLUDE_DIR SQLCIPHER_LIBRARY)
