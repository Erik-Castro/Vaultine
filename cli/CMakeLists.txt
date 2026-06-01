add_executable(ssm-cli ssm_cli.cc)
target_link_libraries(ssm-cli PRIVATE ssm OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(ssm-cli PRIVATE ${CMAKE_SOURCE_DIR}/include)
install(TARGETS ssm-cli RUNTIME DESTINATION bin)
