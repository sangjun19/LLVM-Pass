add_llvm_library(MyPass MODULE
  MyPass.cpp
  
  PLUGIN_TOOL
  opt
)
