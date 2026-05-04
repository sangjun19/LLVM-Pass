add_custom_target(MyPass
  DEPENDS FuncNamePass CountInstPass DetectSwitchPass CallInstCountPass
          LoopAnalysisPass MostFreqPass DummyFuncPass FindDispatcherPass
          FindHubBlocksPass VMTagPass FuncArgPass
)

add_subdirectory(FuncName)
add_subdirectory(CountInst)
add_subdirectory(DetectSwitch)
add_subdirectory(CallInstCount)
add_subdirectory(LoopAnalysis)
add_subdirectory(MostFreq)
add_subdirectory(DummyFunc)
add_subdirectory(FindDispatcher)
add_subdirectory(FindHubBlocks)
add_subdirectory(VMTag)
add_subdirectory(FuncArg)
