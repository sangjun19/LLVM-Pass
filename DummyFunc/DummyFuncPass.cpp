#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassPlugin.h"

// IR 수정을 위해 추가된 헤더
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h" // SplitEdge를 위해 필요

#include <map>

using namespace llvm;

namespace {

class FreqBlock : public PassInfoMixin<FreqBlock> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        // 1. 가장 많이 진입하는 블록 찾기 (기존 코드와 동일)
        std::map<const BasicBlock*, unsigned> blockPredecessorCounts;
        for (auto &BB : F) {
            const Instruction *terminator = BB.getTerminator();
            for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
                const BasicBlock *successor = terminator->getSuccessor(i);
                blockPredecessorCounts[successor]++;
            }
        }

        const BasicBlock *mostFrequentBlock = nullptr;
        unsigned maxCount = 0;
        for (auto const& [block, count] : blockPredecessorCounts) {
            if (count > maxCount) {
                maxCount = count;
                mostFrequentBlock = block;
            }
        }

        if (!mostFrequentBlock || maxCount == 0) {
            return PreservedAnalyses::all();
        }

        errs() << "[*] 함수 '" << F.getName() << "' 분석 결과:\n";
        errs() << "    가장 많은 진입점을 가진 블록: ";
        if (mostFrequentBlock->hasName()) {
            errs() << mostFrequentBlock->getName() << "\n";
        } else {
            errs() << mostFrequentBlock << "\n";
        }
        errs() << "    진입 횟수: " << maxCount << "\n";

        LLVMContext &Ctx = F.getContext();
        Module *M = F.getParent();

        FunctionType *dummyFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
        FunctionCallee dummyFunc = M->getOrInsertFunction("dummy_function", dummyFuncType);

        BasicBlock *targetBlock = const_cast<BasicBlock*>(mostFrequentBlock);
        
        // ================== 수정된 부분 시작 ==================
        
        // predecessor 리스트를 복사할 벡터의 이름을 "predecessorVec"으로 변경
        std::vector<BasicBlock*> predecessorVec;
        for (BasicBlock *pred : predecessors(targetBlock)) {
            predecessorVec.push_back(pred);
        }

        // 복사된 벡터(predecessorVec)를 사용하여 순회
        for (BasicBlock *pred : predecessorVec) {
            Instruction *terminator = pred->getTerminator();
            if (terminator->getNumSuccessors() > 1) {
                BasicBlock *newBlock = SplitEdge(pred, targetBlock);
                
                IRBuilder<> builder(newBlock->getFirstNonPHI());
                builder.CreateCall(dummyFunc);
                errs() << "    [+] 크리티컬 엣지 분리 후 '" << pred->getName() << "' -> '" << newBlock->getName() << "'에 dummy_function 호출 삽입\n";

            } else {
                IRBuilder<> builder(terminator);
                builder.CreateCall(dummyFunc);
                errs() << "    [+] '" << pred->getName() << "'에 dummy_function 호출 삽입\n";
            }
        }
        // ================== 수정된 부분 끝 ====================

        return PreservedAnalyses::none();
    }
};

} // end anonymous namespace

// Plugin registration (기존 코드와 동일)
extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "FreqBlock", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "freqblock") {
                        FPM.addPass(FreqBlock());
                        return true;
                    }
                    return false;
                });
        }
    };
}