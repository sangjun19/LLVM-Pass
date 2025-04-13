#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
struct MyPass : public PassInfoMixin<MyPass> {
  // optnone 속성이 있는 함수에서도 실행되도록 설정
  static bool isRequired() { return true; }

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    errs() << "=== Running MyPass on function: " << F.getName() << " ===\n";
    return PreservedAnalyses::all();
  }
};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "MyPass", LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](StringRef Name, FunctionPassManager &FPM,
           ArrayRef<PassBuilder::PipelineElement>) {
          if (Name == "mypass") {
            FPM.addPass(MyPass());
            return true;
          }
          return false;
        });
    }
  };
}
