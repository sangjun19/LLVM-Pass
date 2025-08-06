#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

namespace {
class CallInstCountPass : public PassInfoMixin<CallInstCountPass> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        errs() << "[*] Function: " << F.getName() << "\n";

        for (auto &BB : F) {
            for (auto &I : BB) {
                if (auto *CI = dyn_cast<CallInst>(&I)) {
                    if (Function *calledFunc = CI->getCalledFunction()) {
                        errs() << "  Called: " << calledFunc->getName() << "\n";
                    } else {
                        errs() << "  Indirect Call or External Function\n";
                        errs() << "\n";
                    }
                }
            }
        }

        return PreservedAnalyses::all();
    }
};
} // end anonymous namespace

// Plugin registration
extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "CallInstCountPass", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "callinstcount") {
                        FPM.addPass(CallInstCountPass());
                        return true;
                    }
                    return false;
                });
        }
    };
}
