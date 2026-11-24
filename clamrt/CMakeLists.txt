# clamrt v4 -- real-time (on-write / on-exec) scan front-end for clamd.
# Self-contained: does not link libclamav; talks to clamd over its INSTREAM protocol.
add_executable(clamrt clamrt_core.c clamrt_obs.c clamrt_trip.c clamrt_intel.c clamrt_sha256.c)
set_target_properties(clamrt PROPERTIES C_STANDARD 99)

if(WIN32)
    target_sources(clamrt PRIVATE clamrt_win.c clamrt_win_ext.c)
    # v2: shell32 (CommandLineToArgvW, UTF-8 argv), advapi32 (protected quarantine-dir ACL, Event Log)
    # v3: tdh/ole32 are not needed (ETW payload is parsed by layout); fltlib for the minifilter port client
    target_link_libraries(clamrt PRIVATE ws2_32 shell32 advapi32 fltlib)
else()
    target_sources(clamrt PRIVATE clamrt_linux.c clamrt_linux_ext.c clamrt_fan.c)
    find_package(Threads REQUIRED)
    target_link_libraries(clamrt PRIVATE Threads::Threads m)
endif()

install(TARGETS clamrt DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT programs)
