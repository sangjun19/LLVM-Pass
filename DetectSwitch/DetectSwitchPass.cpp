#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

namespace {
struct SwitchCasePrinterPass : PassInfoMixin<SwitchCasePrinterPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    errs() << "Function: " << F.getName() << "\n";

    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (auto *SI = dyn_cast<SwitchInst>(&I)) {
          errs() << "  Found switch on value: " << *SI->getCondition() << "\n";
          
          // 각 case
          for (auto Case : SI->cases()) {
            ConstantInt *Val = Case.getCaseValue();
            BasicBlock *TargetBB = Case.getCaseSuccessor();
            errs() << "    Case " << Val->getSExtValue() << " -> " << TargetBB->getName() << "\n";
            printBlockInstructions(TargetBB);
          }

          // default case
          BasicBlock *DefaultBB = SI->getDefaultDest();
          errs() << "    Default case -> " << DefaultBB->getName() << "\n";
          printBlockInstructions(DefaultBB);
        }
      }
    }

    return PreservedAnalyses::all();
  }

  void printBlockInstructions(BasicBlock *BB) {
    for (Instruction &Inst : *BB) {
      errs() << "      " << Inst << "\n";
    }
  }
};
} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION, "SwitchCasePrinterPass", LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        PB.registerPipelineParsingCallback(
            [](StringRef Name, FunctionPassManager &FPM,
               ArrayRef<PassBuilder::PipelineElement>) {
              if (Name == "detectswitch") {
                FPM.addPass(SwitchCasePrinterPass());
                return true;
              }
              return false;
            });
      }};
}
