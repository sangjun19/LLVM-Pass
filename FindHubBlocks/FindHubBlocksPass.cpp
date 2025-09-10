#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"

#include <map>
#include <functional>

using namespace llvm;

namespace {

class FindHubBlocksPass : public PassInfoMixin<FindHubBlocksPass> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
        
        if (F.isDeclaration()) {
            return PreservedAnalyses::all();
        }

        errs() << "[*] Analyzing function: '" << F.getName() << "'\n";

        // 선행자/후행자 개수 찾기
        std::map<const BasicBlock*, unsigned> predecessorCounts;
        std::map<const BasicBlock*, unsigned> successorCounts;

        for (BasicBlock &BB : F) {
            const Instruction *terminator = BB.getTerminator();
            
            // 후행자 개수 계산
            unsigned numSuccessors = terminator ? terminator->getNumSuccessors() : 0;
            successorCounts[&BB] = numSuccessors;
            
            // 선행자 개수 계산
            for (unsigned i = 0; i < numSuccessors; ++i) {
                const BasicBlock *successor = terminator->getSuccessor(i);
                predecessorCounts[successor]++;
            }
        }

        // 선행자가 가장 많은 블록 찾기
        const BasicBlock *predCandidate = nullptr;
        unsigned maxPreds = 0;
        for (auto const& [block, count] : predecessorCounts) {
            if (count > maxPreds) {
                maxPreds = count;
                predCandidate = block;
            }
        }

        // 후행자가 가장 많은 블록 찾기
        const BasicBlock *succCandidate = nullptr;
        unsigned maxSuccs = 0;
        for (auto const& [block, count] : successorCounts) {
            if (count > maxSuccs) {
                maxSuccs = count;
                succCandidate = block;
            }
        }
        
        bool irModified = false;
        LLVMContext &Ctx = F.getContext();
        Module *M = F.getParent();

        // 선행자가 가장 많은 블록에 함수 삽입
        if (predCandidate) {
            errs() << "Max Predecessors Found!\n";
            errs() << "-> BB: ";
            predCandidate->printAsOperand(errs(), false);
            errs() << "\n";
            errs() << ", Count: " << maxPreds << "\n";

            FunctionType *dummyFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
            FunctionCallee dummyFunc = M->getOrInsertFunction("dummy_function_pred", dummyFuncType);
            
            BasicBlock *targetBlock = const_cast<BasicBlock*>(predCandidate);
            IRBuilder<> builder(targetBlock->getTerminator());
            builder.CreateCall(dummyFunc);

            errs() << "[+] Inserted dummy_function_pred call.\n";
            irModified = true;
        }

        // 후행자가 가장 많은 블록에 함수 삽입
        if (succCandidate) {
            errs() << "Max Successors Found!\n";
            errs() << "-> BB: ";
            succCandidate->printAsOperand(errs(), false);
            errs() << "\n";
            errs() << "-> Count: " << maxSuccs << "\n";

            FunctionType *dummyFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
            FunctionCallee dummyFunc = M->getOrInsertFunction("dummy_function_succ", dummyFuncType);

            BasicBlock *targetBlock = const_cast<BasicBlock*>(succCandidate);
            IRBuilder<> builder(targetBlock->getTerminator());
            builder.CreateCall(dummyFunc);
            
            errs() << "[+] Inserted dummy_function_succ call.\n";
            irModified = true;
        }

        if (!predCandidate && !succCandidate) {
            errs() << "-> No candidate blocks found.\n";
        }
        
        errs() << "----------------------------------------\n";
        
        return irModified ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

} // anonymous namespace

// Pass 등록 (이름 변경)
extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "FindHubBlocksPass", "v0.1",
        [](PassBuilder &PB) {
            // 아래 부분을 수정합니다.
            using PipelineParsingCallback =
                std::function<bool(StringRef, FunctionPassManager &,
                                   ArrayRef<PassBuilder::PipelineElement>)>;

            PB.registerPipelineParsingCallback(
                PipelineParsingCallback( // std::function으로 람다를 감싸줍니다.
                    [](StringRef Name, FunctionPassManager &FPM,
                       ArrayRef<PassBuilder::PipelineElement>) {
                        if (Name == "findhubblocks") {
                            FPM.addPass(FindHubBlocksPass());
                            return true;
                        }
                        return false;
                    })
            );
        }
    };
}