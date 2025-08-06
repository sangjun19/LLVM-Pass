#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <sstream>

using namespace llvm;

namespace {

class LoopAnalysisPass : public PassInfoMixin<LoopAnalysisPass> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
        LoopInfo &LI = FAM.getResult<LoopAnalysis>(F);
        ScalarEvolution &SE = FAM.getResult<ScalarEvolutionAnalysis>(F);

        for (auto *L : LI)
            analyzeLoop(L, SE);

        return PreservedAnalyses::all();
    }

private:
    void analyzeLoop(Loop *L, ScalarEvolution &SE) {
        BasicBlock *header = L->getHeader();
        errs() << "loop : " << getBlockLabel(header) << "\n";

        if (PHINode *civ = findCIV(L, SE))
            errs() << "CIV  : " << getValueLabel(civ) << "\n";

        for (auto *sub : L->getSubLoops())
            analyzeLoop(sub, SE);
    }

    PHINode* findCIV(Loop *L, ScalarEvolution &SE) {
        BasicBlock *header = L->getHeader();
        for (auto &I : *header) {
            if (auto *phi = dyn_cast<PHINode>(&I)) {
                const SCEV *scev = SE.getSCEV(phi);
                if (auto *addRec = dyn_cast<SCEVAddRecExpr>(scev))
                    if (addRec->getLoop() == L)
                        return phi;
            }
        }
        return nullptr;
    }

    std::string getBlockLabel(BasicBlock *BB) {
        std::string s;
        raw_string_ostream os(s);
        BB->printAsOperand(os, /*PrintType=*/false);
        os.flush();
        // if (!s.empty() && s[0] == '%')
        //     return s.substr(1) +;
        return s;
    }

    std::string getValueLabel(Value *V) {
        std::string s;
        raw_string_ostream os(s);
        V->print(os);
        os.flush();
        return s;
    }
};

} // namespace

extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "LoopAnalysisPass", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name,
                   FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "loopanalysis") {
                        FPM.addPass(LoopAnalysisPass());
                        return true;
                    }
                    return false;
                });
        }
    };
}
