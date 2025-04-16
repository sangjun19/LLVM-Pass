add_llvm_library(FuncNamePass MODULE
  FuncNamePass.cpp  
  PARTIAL_SOURCES_INTENDED
  PLUGIN_TOOL opt
)