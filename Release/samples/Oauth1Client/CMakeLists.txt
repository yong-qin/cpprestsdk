if (NOT WINDOWS_STORE AND NOT WINDOWS_PHONE)
  add_executable(oauth1client
    Oauth1Client.cpp
  )
  target_link_libraries(oauth1client cpprest)

  find_package(OpenSSL 1.0.0 REQUIRED)
  message(STATUS "=======================================================")
  message(STATUS ${OPENSSL_LIBRARIES})
  message(STATUS ${OPENSSL_INCLUDE_DIR})
  message(STATUS "=======================================================")

  #include_directories(${OPENSSL_INCLUDE_DIR})

  add_executable(gamelibclient
    GamelibClient.cpp
  )

  target_link_libraries(gamelibclient cpprest ${OPENSSL_LIBRARIES})
  target_include_directories(gamelibclient PRIVATE "${OPENSSL_INCLUDE_DIR}")
endif()
