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

class VMTagPass : public PassInfoMixin<VMTagPass> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
        
        if (F.isDeclaration()) {
            return PreservedAnalyses::all();
        }

        errs() << "[*] Analyzing function: '" << F.getName() << "'\n";
        bool irModified = false;
        LLVMContext &Ctx = F.getContext();
        Module *M = F.getParent();

        // 1. main 함수 시작 및 종료 블럭에 함수 콜 삽입
        if (F.getName() == "main") {
            errs() << "--- Main Function Modification ---\n";
            
            // dummy_function_VM_start 삽입 (시작 블럭의 첫 번째 명령어 직전)
            BasicBlock &entryBlock = F.getEntryBlock();
            IRBuilder<> startBuilder(&entryBlock, entryBlock.begin());
            
            FunctionType *startFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
            FunctionCallee startFunc = M->getOrInsertFunction("dummy_function_VM_start", startFuncType);
            startBuilder.CreateCall(startFunc);
            errs() << "[+] Inserted dummy_function_VM_start call at the start of 'main'.\n";
            irModified = true;

            // dummy_function_VM_end 삽입 (종료 블럭의 Terminator 직전)
            for (BasicBlock &BB : F) {
                Instruction *terminator = BB.getTerminator();
                // ReturnInst는 함수의 종료를 나타내는 대표적인 Terminator.
                if (isa<ReturnInst>(terminator)) {
                    IRBuilder<> endBuilder(terminator);

                    FunctionType *endFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
                    FunctionCallee endFunc = M->getOrInsertFunction("dummy_function_VM_end", endFuncType);
                    
                    endBuilder.CreateCall(endFunc);
                    errs() << "[+] Inserted dummy_function_VM_end call before return in BB: ";
                    BB.printAsOperand(errs(), false);
                    errs() << "\n";
                    irModified = true;
                }
            }
        }
        
        // 후행자 개수 찾기         
        std::map<const BasicBlock*, unsigned> successorCounts;

        for (BasicBlock &BB : F) {
            const Instruction *terminator = BB.getTerminator();
            
            // 후행자 개수 계산
            unsigned numSuccessors = terminator ? terminator->getNumSuccessors() : 0;
            successorCounts[&BB] = numSuccessors;
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
        
        // 2. 후행자가 가장 많은 블록에 함수 삽입 및 그 후행 블럭들에 핸들러 삽입
        if (succCandidate) {
            errs() << "--- Max Successors Block Modification ---\n";
            errs() << "Max Successors Found!\n";
            errs() << "-> BB: ";
            succCandidate->printAsOperand(errs(), false);
            errs() << "\n";
            errs() << "-> Count: " << maxSuccs << "\n";

            // 기존 기능: 후행자가 가장 많은 블록에 dummy_function_dispatch_start 삽입
            FunctionType *dispatchFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
            FunctionCallee dispatchFunc = M->getOrInsertFunction("dummy_function_dispatch_start", dispatchFuncType);

            BasicBlock *targetBlock = const_cast<BasicBlock*>(succCandidate);
            IRBuilder<> dispatchBuilder(targetBlock->getTerminator());
            dispatchBuilder.CreateCall(dispatchFunc);
            
            errs() << "[+] Inserted dummy_function_dispatch_start call.\n";
            irModified = true;

            // 2. 앞서 찾은 후행자가 가장 많은 블록에서 분기하는 모든 블럭에 dummy_function_handler 삽입
            Instruction *terminator = targetBlock->getTerminator();
            if (terminator) {
                FunctionType *handlerFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
                FunctionCallee handlerFunc = M->getOrInsertFunction("dummy_function_handler", handlerFuncType);

                for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
                    BasicBlock *successor = terminator->getSuccessor(i);
                    // 후행 블럭의 Terminator 직전에 삽입
                    IRBuilder<> handlerBuilder(successor->getTerminator());
                    handlerBuilder.CreateCall(handlerFunc);
                    
                    errs() << "[+] Inserted dummy_function_handler call into successor BB: ";
                    successor->printAsOperand(errs(), false);
                    errs() << "\n";
                    irModified = true;
                }
            }
        }

        if (!succCandidate) {
            errs() << "-> No candidate blocks found for successor tagging.\n";
        }
        
        errs() << "----------------------------------------\n";
        
        return irModified ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

}

extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "VMTagPass", "v0.1",
        [](PassBuilder &PB) {
            using PipelineParsingCallback = std::function<bool(StringRef, FunctionPassManager &, ArrayRef<PassBuilder::PipelineElement>)>;

            PB.registerPipelineParsingCallback(
                PipelineParsingCallback(
                    [](StringRef Name, FunctionPassManager &FPM,
                       ArrayRef<PassBuilder::PipelineElement>) {
                        if (Name == "VMTagPass") {
                            FPM.addPass(VMTagPass());
                            return true;
                        }
                        return false;
                    })
            );
        }
    };
}