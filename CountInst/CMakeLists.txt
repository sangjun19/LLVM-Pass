add_llvm_library(CountInstPass MODULE
  CountInstPass.cpp 
  PARTIAL_SOURCES_INTENDED
  PLUGIN_TOOL opt
)