pkg_check_modules(NCURSESW REQUIRED ncursesw)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)
pkg_check_modules(LIBEVENT REQUIRED libevent libevent_extra)

add_executable(ssm-cli ssm_cli.cc ssm_server.cc ssm_tui.cc)
target_link_libraries(ssm-cli PRIVATE ssm OpenSSL::SSL OpenSSL::Crypto
    ${NCURSESW_LIBRARIES} ${JSONCPP_LIBRARIES} ${LIBEVENT_LIBRARIES})
target_include_directories(ssm-cli PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}
    ${NCURSESW_INCLUDE_DIRS} ${JSONCPP_INCLUDE_DIRS} ${LIBEVENT_INCLUDE_DIRS})
target_compile_options(ssm-cli PRIVATE ${NCURSESW_CFLAGS_OTHER} ${JSONCPP_CFLAGS_OTHER} ${LIBEVENT_CFLAGS_OTHER})
install(TARGETS ssm-cli RUNTIME DESTINATION bin)
