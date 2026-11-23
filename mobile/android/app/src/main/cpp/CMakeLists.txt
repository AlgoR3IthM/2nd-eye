cmake_minimum_required(VERSION 3.22.1)
project("scamshield_llm")

set(LLAMA_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_SERVER OFF CACHE BOOL "" FORCE)
set(GGML_OPENMP OFF CACHE BOOL "" FORCE)

add_subdirectory(llama.cpp)

add_library(scamshield_llm SHARED llama_jni.cpp)
target_include_directories(scamshield_llm PRIVATE llama.cpp/include llama.cpp/ggml/include)
target_link_libraries(scamshield_llm llama ggml log android)