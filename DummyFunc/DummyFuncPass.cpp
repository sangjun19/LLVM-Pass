#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/IRBuilder.h"

#include <map>
#include <vector>

using namespace llvm;

namespace {

// Pass 클래스
class DummyFunc : public PassInfoMixin<DummyFunc> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        // 각 블럭의 진입횟수 저장할 map
        std::map<const BasicBlock*, unsigned> blockPredecessorCounts;

        // 함수의 모든 BB를 순회하며 진입횟수 저장
        for (auto &BB : F) {
            const Instruction *terminator = BB.getTerminator();
            for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
                const BasicBlock *successor = terminator->getSuccessor(i);
                blockPredecessorCounts[successor]++;
            }
        }

        // 가장 많이 참조된 블럭 찾기
        const BasicBlock *mostFrequentBlock = nullptr;
        unsigned maxCount = 0;

        for (auto const& [block, count] : blockPredecessorCounts) {
            if (count > maxCount) {
                maxCount = count;
                mostFrequentBlock = block;
            }
        }

        // 가장 많이 참조된 블록이 없으면 종료
        if (!mostFrequentBlock || maxCount == 0) {
            return PreservedAnalyses::all();
        }

        // 분석 결과
        errs() << "[*] Function '" << F.getName() << "'\n";
        errs() << "Most Frequent BB: ";
        mostFrequentBlock->printAsOperand(errs(), false);
        errs() << "\n";
        errs() << "Count: " << maxCount << "\n";

        // Context, Module 선언
        LLVMContext &Ctx = F.getContext();
        Module *M = F.getParent();

        // 모듈에 더미함수 선언이 없다면 추가
        FunctionType *dummyFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
        FunctionCallee dummyFunc = M->getOrInsertFunction("dummy_function", dummyFuncType);

        // 수정할 대상 블록
        BasicBlock *targetBlock = const_cast<BasicBlock*>(mostFrequentBlock);

        // 블럭 종료 명렁어 찾기
        Instruction *terminator = targetBlock->getTerminator();
        
        // IRBuilder로 종료 명령어 바로 위에 함수 호출 삽입
        IRBuilder<> builder(terminator);
        builder.CreateCall(dummyFunc);

        errs() << "[+] '";
        targetBlock->printAsOperand(errs(), false);
        errs() << "' Insert dummy_function call\n";
        
        // IR이 수정됐음을 알림
        return PreservedAnalyses::none();
    }
};

}

extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "DummyFunc", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "dummyfunc") {
                        FPM.addPass(DummyFunc());
                        return true;
                    }
                    return false;
                });
        }
    };
}