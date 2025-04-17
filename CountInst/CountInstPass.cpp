// InstCountPass.cpp
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
struct CountInstPass : PassInfoMixin<CountInstPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    unsigned instCount = 0;
    
    for (BasicBlock &BB : F) {
      instCount += BB.size();
    }
    
    errs() << "Instruction count for " << F.getName() 
           << ": " << instCount << "\n";
    return PreservedAnalyses::all();
  }
};
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION, "CountInstPass", LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        PB.registerPipelineParsingCallback(
            [](StringRef Name, FunctionPassManager &FPM,
               ArrayRef<PassBuilder::PipelineElement>) {
              if (Name == "countinst") {
                FPM.addPass(CountInstPass());
                return true;
              }
              return false;
            });
      }};
}
