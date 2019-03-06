if (NOT WINDOWS_STORE AND NOT WINDOWS_PHONE)
  find_package(OpenSSL 1.0.0 REQUIRED)

  find_path(STEAM_INCLUDE_DIR NAMES steam/steam_api.h PATHS "./include")
  if (WIN32)
    find_library(STEAM_LIBRARIES NAMES steam_api64.lib PATHS "./lib/steam/win64")
  endif()
  if (APPLE)
    find_library(STEAM_LIBRARIES NAMES libsteam_api.dylib PATHS "./lib/steam/osx32")
  endif()
  message(STATUS "=======================================================")
  message(STATUS ${OPENSSL_LIBRARIES})
  message(STATUS ${OPENSSL_INCLUDE_DIR})
  message(STATUS ${STEAM_LIBRARIES})
  message(STATUS ${STEAM_INCLUDE_DIR})
  message(STATUS "=======================================================")

  add_executable(gamelibclient
    GamelibClient.cpp
  )

  target_link_libraries(gamelibclient cpprest ${OPENSSL_LIBRARIES} ${STEAM_LIBRARIES})
  target_include_directories(gamelibclient PRIVATE ${OPENSSL_INCLUDE_DIR} ${STEAM_INCLUDE_DIR})
endif()
