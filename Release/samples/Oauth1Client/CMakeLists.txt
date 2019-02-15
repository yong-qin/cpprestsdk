if (NOT WINDOWS_STORE AND NOT WINDOWS_PHONE)
  add_executable(oauth1client
    Oauth1Client.cpp
    )
  add_executable(gamelibclient
    GamelibClient.cpp
    )

  target_link_libraries(oauth1client cpprest)
  target_link_libraries(gamelibclient cpprest)
endif()
