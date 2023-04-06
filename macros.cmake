macro(use_riscv_musl_toolchain bits)
    set(cross_compile riscv${bits}-unknown-linux-musl-)
    execute_process(
        COMMAND which ${cross_compile}gcc
        OUTPUT_VARIABLE CROSSCOMPILE
        RESULT_VARIABLE ERROR)

    if (NOT "${ERROR}" STREQUAL 0)
        message(FATAL_ERROR "RISCV Toochain is not found")
    endif()

    string(STRIP ${CROSSCOMPILE} CROSSCOMPILE)
    string(REPLACE "gcc" "" CROSSCOMPILE ${CROSSCOMPILE})

    message(STATUS "Target triplet: ${CROSSCOMPILE}")

    set(CC              ${CROSSCOMPILE}gcc)
    set(CXX             ${CROSSCOMPILE}g++)
    set(LD              ${CROSSCOMPILE}ld)
    set(AR              ${CROSSCOMPILE}ar)
    set(OBJCOPY         ${CROSSCOMPILE}objcopy)
    set(OBJDUMP         ${CROSSCOMPILE}objdump)
    #set(CFLAGS          "-Wall -Werror")

    set(CMAKE_C_COMPILER        ${CC}${EXT})
    set(CMAKE_ASM_COMPILER      ${CC}${EXT})
    set(CMAKE_CXX_COMPILER      ${CXX}${EXT})
    set(CMAKE_LINKER            ${LD}${EXT})
    set(CMAKE_AR                ${AR}${EXT})
    set(CMAKE_OBJCOPY           ${OBJCOPY}${EXT})
    set(CMAKE_OBJDUMP           ${OBJDUMP}${EXT})
    # set(CMAKE_C_FLAGS           ${CMAKE_C_FLAGS} ${CFLAGS})

    #check_compiler(${CMAKE_C_COMPILER})
    #check_compiler(${CMAKE_CXX_COMPILER})

    #global_set(CMAKE_C_COMPILER_WORKS      1)
    #global_set(CMAKE_CXX_COMPILER_WORKS    1)

    #global_set(CMAKE_SYSTEM_NAME    "Linux")
endmacro()
