#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"

#include <map>
#include <functional>
#include <vector> // CallInst 저장을 위해 추가

using namespace llvm;

namespace {

// 함수 콜이 이미 존재하는지 확인하고, CallInst가 있다면 반환하는 헬퍼 함수
// CallInst를 제거해야 하므로, 반환 타입을 CallInst* 로 변경합니다.
CallInst* findCallTo(BasicBlock *BB, StringRef FuncName) {
    // BB의 terminator 직전 명령어부터 역순으로 탐색
    for (Instruction &Inst : llvm::reverse(*BB)) {
        if (CallInst *CI = dyn_cast<CallInst>(&Inst)) {
            if (CI->getCalledFunction() && CI->getCalledFunction()->getName() == FuncName) {
                return CI;
            }
        }
        // Terminator는 건너뜝니다.
        if (BB->getTerminator() == &Inst) {
            continue;
        }
    }
    return nullptr;
}


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
        
        // 함수가 main일 때
        if (F.getName() == "main") {
            errs() << "--- Main Function Modification ---\n";

            // VM_start 삽입
            BasicBlock &entryBlock = F.getEntryBlock();
            IRBuilder<> startBuilder(&entryBlock, entryBlock.begin());
            
            FunctionType *startFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
            FunctionCallee startFunc = M->getOrInsertFunction("dummy_function_VM_start", startFuncType);
            startBuilder.CreateCall(startFunc);
            errs() << "[+] Inserted dummy_function_VM_start call at the start of 'main'.\n";
            irModified = true;

            // VM_end 삽입: 이 로직은 나중에 핸들러 로직에서 덮어쓰거나 수정될 수 있습니다.
            for (BasicBlock &BB : F) {
                Instruction *terminator = BB.getTerminator();
                if (isa<ReturnInst>(terminator)) {
                    // 중복 삽입 방지를 위해 이미 VM_end가 있는지 확인
                    if (!findCallTo(&BB, "dummy_function_VM_end")) {
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


            // 후행자 개수 찾기 및 succCandidate 결정 로직 (이전과 동일)
            std::map<const BasicBlock*, unsigned> successorCounts;
            for (BasicBlock &BB : F) {
                const Instruction *terminator = BB.getTerminator();
                unsigned numSuccessors = terminator ? terminator->getNumSuccessors() : 0;
                successorCounts[&BB] = numSuccessors;
            }
            const BasicBlock *succCandidate = nullptr;
            unsigned maxSuccs = 0;
            for (auto const& [block, count] : successorCounts) {
                if (count > maxSuccs) {
                    maxSuccs = count;
                    succCandidate = block;
                }
            }
            
            // 2. Dispatcher/Handler Tagging
            if (succCandidate) {
                errs() << "--- Dispatcher/Handler Tagging ---\n";

                // Dispatcher 블록에 dummy_function_dispatch_start 삽입
                FunctionType *dispatchFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
                FunctionCallee dispatchFunc = M->getOrInsertFunction("dummy_function_dispatch_start", dispatchFuncType);

                BasicBlock *targetBlock = const_cast<BasicBlock*>(succCandidate);
                // Dispatcher 태그 중복 방지 (만약 여러 패스가 실행될 경우를 대비)
                if (!findCallTo(targetBlock, "dummy_function_dispatch_start")) {
                    IRBuilder<> dispatchBuilder(targetBlock->getTerminator());
                    dispatchBuilder.CreateCall(dispatchFunc);
                    errs() << "[+] Inserted dummy_function_dispatch_start call.\n";
                    irModified = true;
                }
                
                // 후행 블럭들에 dummy_function_handler 삽입
                Instruction *terminator = targetBlock->getTerminator();
                if (terminator) {
                    FunctionType *handlerFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
                    FunctionCallee standardHandlerFunc = M->getOrInsertFunction("dummy_function_handler", handlerFuncType);
                    FunctionCallee endHandlerFunc = M->getOrInsertFunction("dummy_function_VM_end_handler", handlerFuncType);

                    for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
                        BasicBlock *successor = terminator->getSuccessor(i);
                        Instruction *succTerminator = successor->getTerminator();
                        
                        // 1. 중복 확인: 이미 핸들러 태그가 있는지 확인
                        if (findCallTo(successor, "dummy_function_handler") || findCallTo(successor, "dummy_function_VM_end_handler")) {
                             // errs() << "[!] Skipped handler insertion for successor BB: " << successor->getName() << " (Already tagged)\n";
                             continue;
                        }

                        // 2. VM End 태그 확인 및 제거
                        CallInst *vmEndCall = findCallTo(successor, "dummy_function_VM_end");

                        // 3. VM End 태그가 있는 경우 (ReturnInst) 처리
                        if (isa<ReturnInst>(succTerminator)) {
                            // 3-1. 기존 VM_end 태그 제거 (요청 사항)
                            if (vmEndCall) {
                                vmEndCall->eraseFromParent();
                                errs() << "[!] Removed existing dummy_function_VM_end call.\n";
                            }
                            
                            // 3-2. dummy_function_VM_end_handler 삽입
                            IRBuilder<> handlerBuilder(succTerminator);
                            handlerBuilder.CreateCall(endHandlerFunc);
                            
                            errs() << "[+] Inserted dummy_function_VM_end_handler call into successor BB: ";
                            successor->printAsOperand(errs(), false);
                            errs() << "\n";
                        } else {
                            // 4. 일반적인 경우, dummy_function_handler 삽입
                            IRBuilder<> handlerBuilder(succTerminator);
                            handlerBuilder.CreateCall(standardHandlerFunc);
                            
                            errs() << "[+] Inserted dummy_function_handler call into successor BB: ";
                            successor->printAsOperand(errs(), false);
                            errs() << "\n";
                        }
                        
                        irModified = true;
                    }
                }
            } else {
                 errs() << "-> No candidate blocks found for dispatcher tagging in main.\n";
            }
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
                        if (Name == "vmtag") { 
                            FPM.addPass(VMTagPass());
                            return true;
                        }
                        return false;
                    })
            );
        }
    };
}