# this file is part of libwaive.
#
# Copyright (c) 2015 Riley Baird
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

cmake_minimum_required(VERSION 3.3)
project(waive)

#Remember to change these for new version numbers
set(SOVER 1)
set(VER 1.0.0)

# Create and install the shared library
add_library(waive_shared SHARED waive.c)
set_target_properties(waive_shared PROPERTIES SOVERSION ${SOVER} VERSION ${VER} OUTPUT_NAME "waive")
install(TARGETS waive_shared DESTINATION lib/${CMAKE_LIBRARY_ARCHITECTURE})

# Create and install the static library
add_library(waive_static STATIC waive.c)
set_target_properties(waive_static PROPERTIES OUTPUT_NAME "waive")
install(TARGETS waive_static DESTINATION lib/${CMAKE_LIBRARY_ARCHITECTURE})

# Install waive.h
install(FILES waive.h DESTINATION include)

# Generate and install the pkg-config file
configure_file(libwaive.pc.in libwaive.pc @ONLY)
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "libwaive.pc")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libwaive.pc DESTINATION lib/${CMAKE_LIBRARY_ARCHITECTURE}/pkgconfig)

