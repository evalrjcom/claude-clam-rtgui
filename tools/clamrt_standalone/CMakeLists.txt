# clamrt does not link libclamav (it talks to clamd over INSTREAM), so it builds on its own - no ClamAV tree needed.
cmake_minimum_required(VERSION 3.16)
project(clamrt_standalone C)
include(GNUInstallDirs)
add_subdirectory(${CLAMRT_SRC} clamrt)
