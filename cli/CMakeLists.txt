pkg_check_modules(NCURSESW REQUIRED ncursesw)

add_executable(ssm-cli ssm_cli.cc ssm_tui.cc)
target_link_libraries(ssm-cli PRIVATE ssm OpenSSL::SSL OpenSSL::Crypto ${NCURSESW_LIBRARIES})
target_include_directories(ssm-cli PRIVATE ${CMAKE_SOURCE_DIR}/include ${NCURSESW_INCLUDE_DIRS})
target_compile_options(ssm-cli PRIVATE ${NCURSESW_CFLAGS_OTHER})
install(TARGETS ssm-cli RUNTIME DESTINATION bin)
