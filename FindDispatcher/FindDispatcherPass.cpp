#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"

#include <map>

using namespace llvm;

namespace {

// Pass 클래스 정의
class FindDispatcher : public PassInfoMixin<FindDispatcher> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
        
        // 함수가 비어있으면 분석하지 않음
        if (F.isDeclaration()) {
            return PreservedAnalyses::all();
        }

        errs() << "[*] Analyzing function: '" << F.getName() << "'\n";

        // 각 BasicBlock의 선행자 개수를 저장할 map
        std::map<const BasicBlock*, unsigned> predecessorCounts;

        // 함수의 모든 BB를 순회하며 각 BB를 후행자로 가지는 다른 BB들의 개수를 계산
        for (BasicBlock &BB : F) {
            // 현재 BB의 종료 명령어를 가져옴
            const Instruction *terminator = BB.getTerminator();
            if (!terminator) continue;

            // 종료 명령어의 모든 후행자(Successor)를 순회
            for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
                const BasicBlock *successor = terminator->getSuccessor(i);
                
                // 후행자(successor)의 선행자 개수를 1 증가시킴
                predecessorCounts[successor]++;
            }
        }

        // 가장 많은 선행자를 가진 BasicBlock 찾기
        const BasicBlock *dispatcherCandidate = nullptr;
        unsigned maxPreds = 0;

        for (auto const& [block, count] : predecessorCounts) {
            if (count > maxPreds) {
                maxPreds = count;
                dispatcherCandidate = block;
            }
        }

        // 결과 출력
        if (dispatcherCandidate) {
            errs() << "Dispatcher Candidate Found\n";
            errs() << "-> BB: ";
            dispatcherCandidate->printAsOperand(errs(), false);
            errs() << "\n";
            errs() << "Predecessor Count: " << maxPreds << "\n";

            // Context, Module 선언
            LLVMContext &Ctx = F.getContext();
            Module *M = F.getParent();

            // 모듈에 더미함수 선언이 없다면 추가
            FunctionType *dummyFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
            FunctionCallee dummyFunc = M->getOrInsertFunction("dummy_function", dummyFuncType);

            // 수정할 대상 블록
            BasicBlock *targetBlock = const_cast<BasicBlock*>(dispatcherCandidate);

            // 블럭 종료 명렁어 찾기
            Instruction *terminator = targetBlock->getTerminator();
            
            // IRBuilder로 종료 명령어 바로 위에 함수 호출 삽입
            IRBuilder<> builder(terminator);
            builder.CreateCall(dummyFunc);

            errs() << "[+] '";
            targetBlock->printAsOperand(errs(), false);
            errs() << "' Insert dummy_function call\n";
            
            errs() << "----------------------------------------\n";
            // IR이 수정됐음을 알림
            return PreservedAnalyses::none();
        } else {
            errs() << "-> No dispatcher candidate\n";
            errs() << "----------------------------------------\n";
            return PreservedAnalyses::all();
        }
    }
};

} // anonymous namespace

// Pass를 opt에 등록하기 위한 진입점
extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "FindDispatcher", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "finddispatcher") {
                        FPM.addPass(FindDispatcher());
                        return true;
                    }
                    return false;
                });
        }
    };
}