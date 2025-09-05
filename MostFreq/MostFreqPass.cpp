#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassPlugin.h"
#include <map>

using namespace llvm;

namespace {

class MostFreqPass : public PassInfoMixin<MostFreqPass> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        // BasicBlock의 진입 횟수를 저장할 맵
        std::map<const BasicBlock*, unsigned> blockPredecessorCounts;

        // 함수의 모든 BB 순회
        for (auto &BB : F) {
            // 현재 블록의 마지막 명령어를 가져오기(br, ret)
            const Instruction *terminator = BB.getTerminator();

            // 분기할 수 있는 모든 후속 블록을 순회
            for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
                const BasicBlock *successor = terminator->getSuccessor(i);
                
                // 후속 블록의 카운트를 1 증가
                blockPredecessorCounts[successor]++;
            }
        }

        // 가장 많이 참조된 블록 찾기
        const BasicBlock *mostFrequentBlock = nullptr;
        unsigned maxCount = 0;

        for (auto const& [block, count] : blockPredecessorCounts) {
            if (count > maxCount) {
                maxCount = count;
                mostFrequentBlock = block;
            }
        }

        // 최종 결과
        if (mostFrequentBlock) {
            errs() << "[*] 함수 '" << F.getName() << "' 분석 결과:\n";
            errs() << "    가장 많은 진입점을 가진 블록: ";
            if (mostFrequentBlock->hasName()) {
                errs() << mostFrequentBlock->getName() << "\n";
            } else {
                errs() << mostFrequentBlock << "\n";
            }
            errs() << "    진입 횟수: " << maxCount << "\n";
        }

        return PreservedAnalyses::all();
    }
};

}

// Plugin registration
extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "MostFreqPass", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "mostfreq") {
                        FPM.addPass(MostFreqPass());
                        return true;
                    }
                    return false;
                });
        }
    };
}