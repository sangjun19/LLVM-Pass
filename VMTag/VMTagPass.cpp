#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"

#include <map>
#include <functional>
#include <vector>
#include <set>

using namespace llvm;

namespace {

// 함수 콜이 이미 존재하는지 확인하고, CallInst가 있다면 반환
CallInst* findCallTo(BasicBlock *BB, StringRef FuncName) {
    for (Instruction &Inst : llvm::reverse(*BB)) {
        if (CallInst *CI = dyn_cast<CallInst>(&Inst)) {
            if (CI->getCalledFunction() && CI->getCalledFunction()->getName() == FuncName) {
                return CI;
            }
        }
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

            // 후행자 개수 찾기 및 succCandidate (dispatcher) 결정
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
            
            // Dispatcher/Handler Tagging
            if (succCandidate) {
                // errs() << "--- Dispatcher/Handler Tagging ---\n";

                // Dispatcher 블록에 dummy_function_dispatch_start 삽입
                FunctionType *dispatchFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
                FunctionCallee dispatchFunc = M->getOrInsertFunction("dummy_function_dispatch_start", dispatchFuncType);

                BasicBlock *dispatcherBlock = const_cast<BasicBlock*>(succCandidate);
                if (!findCallTo(dispatcherBlock, "dummy_function_dispatch_start")) {
                    IRBuilder<> dispatchBuilder(dispatcherBlock->getTerminator());
                    dispatchBuilder.CreateCall(dispatchFunc);
                    errs() << "[+] Inserted dummy_function_dispatch_start call into BB: ";
                    dispatcherBlock->printAsOperand(errs(), false);
                    errs() << "\n";
                    irModified = true;
                }
                
                // Dispatcher의 후행 블럭들(핸들러들) 수집
                Instruction *dispatcherTerminator = dispatcherBlock->getTerminator();
                std::vector<BasicBlock*> handlers;
                
                if (dispatcherTerminator) {
                    for (unsigned i = 0; i < dispatcherTerminator->getNumSuccessors(); ++i) {
                        handlers.push_back(dispatcherTerminator->getSuccessor(i));
                    }
                }

                FunctionType *handlerFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
                FunctionCallee standardHandlerFunc = M->getOrInsertFunction("dummy_function_handler", handlerFuncType);
                FunctionCallee endHandlerFunc = M->getOrInsertFunction("dummy_function_VM_end_handler", handlerFuncType);

                // 각 핸들러의 종료 명령어 타겟을 수집 (VM_end_handler 후보 찾기 위함)
                std::map<BasicBlock*, std::set<BasicBlock*>> handlerTargets;
                
                for (BasicBlock *handler : handlers) {
                    Instruction *handlerTerminator = handler->getTerminator();
                    
                    // 이미 태그된 핸들러는 스킵
                    if (findCallTo(handler, "dummy_function_handler") || 
                        findCallTo(handler, "dummy_function_VM_end_handler")) {
                        continue;
                    }

                    // Switch 명령어 처리
                    if (SwitchInst *SI = dyn_cast<SwitchInst>(handlerTerminator)) {
                        // Switch의 각 case 블록에 handler 태그 삽입
                        for (unsigned i = 0; i < SI->getNumSuccessors(); ++i) {
                            BasicBlock *caseBlock = SI->getSuccessor(i);
                            
                            // 중복 확인
                            if (!findCallTo(caseBlock, "dummy_function_handler") &&
                                !findCallTo(caseBlock, "dummy_function_VM_end_handler")) {
                                
                                // Dispatcher로 분기하는 경우 스킵
                                // if (caseBlock == dispatcherBlock) {
                                //     continue;
                                // }
                                
                                IRBuilder<> caseBuilder(caseBlock->getTerminator());
                                caseBuilder.CreateCall(standardHandlerFunc);
                                irModified = true;
                            }
                        }
                        
                        // Switch 핸들러 자체는 타겟 수집만 (태그 삽입 안함)
                        for (unsigned i = 0; i < SI->getNumSuccessors(); ++i) {
                            handlerTargets[handler].insert(SI->getSuccessor(i));
                        }
                        continue;
                    }
                    
                    // 일반 핸들러 처리
                    if (handlerTerminator) {
                        // 핸들러의 분기 타겟 수집
                        for (unsigned i = 0; i < handlerTerminator->getNumSuccessors(); ++i) {
                            BasicBlock *target = handlerTerminator->getSuccessor(i);
                            handlerTargets[handler].insert(target);
                            
                            // Dispatcher로 분기하는 경우 핸들러 태그 삽입 안함
                            // if (target == dispatcherBlock) {
                            //     break;
                            // }
                        }
                        
                        // Dispatcher로 분기하지 않는 경우만 핸들러 태그 삽입
                        bool branchesToDispatcher = false;
                        // for (unsigned i = 0; i < handlerTerminator->getNumSuccessors(); ++i) {
                        //     if (handlerTerminator->getSuccessor(i) == dispatcherBlock) {
                        //         branchesToDispatcher = true;
                        //         break;
                        //     }
                        // }
                        
                        if (!branchesToDispatcher &&
                            !findCallTo(uniqueHandler, "dummy_function_VM_end_handler") &&
                            !isa<SwitchInst>(uniqueHandler->getTerminator()) &&
                            (isa<BranchInst>(uniqueTerminator) && !cast<BranchInst>(uniqueTerminator)->isConditional())) {
                                
                                // 기존 dummy_function_handler가 있으면 제거
                            if (CallInst *existingHandler = findCallTo(uniqueHandler, "dummy_function_handler")) {
                                existingHandler->eraseFromParent();
                            }

                            IRBuilder<> endBuilder(uniqueHandler->getTerminator());
                            endBuilder.CreateCall(endHandlerFunc);
                            errs() << "[+] Inserted dummy_function_VM_end_handler into BB: ";
                            uniqueHandler->printAsOperand(errs(), false);
                            errs() << "\n";
                            irModified = true;
                        }
                    }
                }

                // VM_end_handler 후보 찾기: 다른 핸들러들과 다른 곳으로 분기하는 핸들러
                if (handlerTargets.size() > 1) {
                    std::map<std::set<BasicBlock*>, std::vector<BasicBlock*>> targetGroups;
                    
                    for (auto &[handler, targets] : handlerTargets) {
                        targetGroups[targets].push_back(handler);
                    }
                    
                    // 혼자 다른 곳으로 분기하는 핸들러 찾기
                    for (auto &[targets, handlersWithSameTargets] : targetGroups) {
                        if (handlersWithSameTargets.size() == 1) {
                            BasicBlock *uniqueHandler = handlersWithSameTargets[0];
                            
                            // dispatcher로 분기하는지 확인
                            bool branchesToDispatcher = false;
                            Instruction *uniqueTerminator = uniqueHandler->getTerminator();
                            if (uniqueTerminator) {
                                for (unsigned i = 0; i < uniqueTerminator->getNumSuccessors(); ++i) {
                                    if (uniqueTerminator->getSuccessor(i) == dispatcherBlock) {
                                        branchesToDispatcher = true;
                                        break;
                                    }
                                }
                            }
                            
                            // dispatcher로 분기하지 않고, 이미 태그되지 않았고, switch가 아닌 경우
                            if (!branchesToDispatcher &&
                                !findCallTo(uniqueHandler, "dummy_function_VM_end_handler") &&
                                !isa<SwitchInst>(uniqueHandler->getTerminator())) {
                                
                                // 기존 dummy_function_handler가 있으면 제거
                                if (CallInst *existingHandler = findCallTo(uniqueHandler, "dummy_function_handler")) {
                                    existingHandler->eraseFromParent();
                                }
                                
                                IRBuilder<> endBuilder(uniqueHandler->getTerminator());
                                endBuilder.CreateCall(endHandlerFunc);
                                errs() << "[+] Inserted dummy_function_VM_end_handler into BB: ";
                                uniqueHandler->printAsOperand(errs(), false);
                                errs() << "\n";
                                irModified = true;
                            }
                        }
                    }
                }
                
                // VM_start 삽입: dispatcher 직전 블록에 삽입
                FunctionType *startFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
                FunctionCallee startFunc = M->getOrInsertFunction("dummy_function_VM_start", startFuncType);
                
                for (BasicBlock &BB : F) {
                    Instruction *terminator = BB.getTerminator();
                    // terminator가 존재하고, successor가 있는지 확인
                    if (terminator && terminator->getNumSuccessors() > 0) {
                        // 첫 번째 successor가 dispatcher인지 확인
                        if (terminator->getSuccessor(0) == dispatcherBlock) {
                            // 중복 방지
                            if (!findCallTo(&BB, "dummy_function_VM_start")) {
                                // terminator 직전에 삽입
                                IRBuilder<> startBuilder(terminator);
                                startBuilder.CreateCall(startFunc);
                                errs() << "[+] Inserted dummy_function_VM_start call into BB: ";
                                BB.printAsOperand(errs(), false);
                                errs() << "\n";
                                irModified = true;
                                break;
                            }
                        }
                    }
                }
                
            } else {
                errs() << "-> No candidate blocks found for dispatcher\n";
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