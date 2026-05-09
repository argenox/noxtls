# CMake generated Testfile for 
# Source directory: C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/ut
# Build directory: C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/build-tests-strict/ut
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(noxtls_ct_test "C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/build-tests-strict/ut/Debug/noxtls_ct_test.exe")
  set_tests_properties(noxtls_ct_test PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/ut/CMakeLists.txt;8;add_test;C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/ut/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(noxtls_ct_test "C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/build-tests-strict/ut/Release/noxtls_ct_test.exe")
  set_tests_properties(noxtls_ct_test PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/ut/CMakeLists.txt;8;add_test;C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/ut/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(noxtls_ct_test "C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/build-tests-strict/ut/MinSizeRel/noxtls_ct_test.exe")
  set_tests_properties(noxtls_ct_test PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/ut/CMakeLists.txt;8;add_test;C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/ut/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(noxtls_ct_test "C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/build-tests-strict/ut/RelWithDebInfo/noxtls_ct_test.exe")
  set_tests_properties(noxtls_ct_test PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/ut/CMakeLists.txt;8;add_test;C:/Users/glitovsky/Desktop/Argenox/noxtls-oem/noxtls/ut/CMakeLists.txt;0;")
else()
  add_test(noxtls_ct_test NOT_AVAILABLE)
endif()
