cmake_minimum_required (VERSION 3.11)
project(messagerie_cpp LANGUAGES CXX VERSION 1.0.0)
find_package(ftxui 5 REQUIRED)
file(GLOB SOURCES "src/*.cpp")
include_directories(include)
add_executable(messagerie ${SOURCES})
target_link_libraries(messagerie
  PRIVATE ftxui::screen
  PRIVATE ftxui::dom
  PRIVATE ftxui::component
)