#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"

#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/AbstractCallSite.h"

using namespace llvm;

namespace {
    struct FuncArgPass : public PassInfoMixin<FuncArgPass> {
      static bool isRequired() { return true; }

      PreservedAnalyses run (Module &M, ModuleAnalysisManager &) {
        errs() << "202650291 안상준" << "\n";
        errs() << "=============================\n";
        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            errs() << "Function Name: " << F.getName() << "\n";
            errs() << "Argument Count: " << F.arg_size() << "\n";
            if (F.arg_size()) {
                errs() << "Argument No: " << "\n";
                for (Argument &Arg : F.args()) {
                    errs() << "  %" << Arg.getArgNo() << "\n";
                }
                for (Use &U : F.uses()) {
                    User *Usr = U.getUser();
                    if (CallInst *CI = dyn_cast<CallInst>(Usr)) {
                        errs() << "Caller: " << CI->getFunction()->getName() << "\n";
                        errs() << "Parameter: " << "\n";
                        for (unsigned i = 0; i < CI->arg_size(); i++) {
                            Value *Arg = CI->getArgOperand(i);
                            errs() << "  ";
                            Arg->printAsOperand(errs(), false);
                            errs() << "\n";
                        }
                    }
                }
            }
            errs() << "=============================\n";
        }
        return PreservedAnalyses::all();
      }
    };
}

extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "FuncArgPass", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "funcarg") {
                        MPM.addPass(FuncArgPass());
                        return true;
                    }
                    return false;
                }
            );
        }
    };
}