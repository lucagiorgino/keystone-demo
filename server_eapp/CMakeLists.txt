# DEMO CHANGES
include(../macros.cmake)
use_riscv_musl_toolchain(64)
# END DEMO CHANGES

add_executable(server_eapp.eapp_riscv
  server_eapp.c
  edge_wrapper.c
  calculator.c
  channel.c
    # DEMO CHANGES
  ../include/session_context.h
  ../include/session_context.c
  ../include/test_client_key.h
  ../include/eh_shared.h
  services.c
  services.h
    # END DEMO CHANGES  
)

include_directories(include
  ${KEYSTONE_SDK_DIR}/include/app
)

target_link_libraries(server_eapp.eapp_riscv
  ${KEYSTONE_LIB_EDGE}
  ${KEYSTONE_LIB_EAPP}
  # DEMO CHANGES
  ${KEYSTONE_LIB_VERIFIER}
  # END DEMO CHANGES  
  ${LIBSODIUM_DIR}/.libs/libsodium.a
)

# set_target_properties(server_eapp.eapp_riscv
#   PROPERTIES LINK_FLAGS "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")

set_target_properties(server_eapp.eapp_riscv
  PROPERTIES LINK_FLAGS "-static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")