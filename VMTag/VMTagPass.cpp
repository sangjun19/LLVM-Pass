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
        // Terminator는 CallInst가 아니므로 건너뜁니다.
        if (BB->getTerminator() == &Inst) {
            continue;
        }
    }
    return nullptr;
}

// 선행 블록이 VM End Handler 호출을 포함하는지 확인하는 헬퍼 함수
bool hasVMEndPredecessor(BasicBlock *BB) {
    for (BasicBlock *Pred : predecessors(BB)) {
        if (findCallTo(Pred, "dummy_function_VM_end_handler")) {
            return true;
        }
    }
    return false;
}

// 블록에 terminator 외에 실제 명령어가 있는지 확인하는 헬퍼 함수
bool hasNonTerminatorInstructions(BasicBlock *BB) {
    unsigned instCount = 0;
    for (Instruction &Inst : *BB) {
        // dummy_function 호출은 제외하고 카운트
        if (CallInst *CI = dyn_cast<CallInst>(&Inst)) {
            if (CI->getCalledFunction()) {
                StringRef funcName = CI->getCalledFunction()->getName();
                if (funcName.starts_with("dummy_function")) {
                    continue;
                }
            }
        }
        instCount++;
    }
    // terminator 1개만 있으면 false (실제 명령어 없음)
    return instCount > 1;
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
                
                // 조건 분기 핸들러의 합류 지점을 추적
                std::set<BasicBlock*> conditionalBranchConvergencePoints;
                
                for (BasicBlock *handler : handlers) {
                    Instruction *handlerTerminator = handler->getTerminator();
                    
                    // 이미 태그된 핸들러는 스킵 (타겟 수집은 계속)
                    if (findCallTo(handler, "dummy_function_handler") || 
                        findCallTo(handler, "dummy_function_VM_end_handler")) {
                        if (handlerTerminator) {
                             for (unsigned i = 0; i < handlerTerminator->getNumSuccessors(); ++i) {
                                handlerTargets[handler].insert(handlerTerminator->getSuccessor(i));
                            }
                        }
                        continue;
                    }

                    // Switch 명령어 처리
                    if (SwitchInst *SI = dyn_cast<SwitchInst>(handlerTerminator)) {
                        // Switch의 각 case 블록에 handler 태그 삽입
                        for (unsigned i = 0; i < SI->getNumSuccessors(); ++i) {
                            BasicBlock *caseBlock = SI->getSuccessor(i);
                            Instruction *caseTerminator = caseBlock->getTerminator();

                            // 선행자 개수 확인
                            unsigned numPredecessors = 0;
                            for (BasicBlock *Pred : predecessors(caseBlock)) {
                                numPredecessors++;
                            }

                            // 1. 기본 조건 검사
                            if (caseBlock != dispatcherBlock &&
                                caseTerminator &&
                                !hasVMEndPredecessor(caseBlock) &&
                                !findCallTo(caseBlock, "dummy_function_handler") &&
                                !findCallTo(caseBlock, "dummy_function_VM_end_handler") &&
                                hasNonTerminatorInstructions(caseBlock)) {
                                
                                // 2. 합류 지점 필터링
                                bool isConvergencePoint = false;
                                if (numPredecessors >= 2) {
                                    for (unsigned j = 0; j < caseTerminator->getNumSuccessors(); ++j) {
                                        if (caseTerminator->getSuccessor(j) == dispatcherBlock) {
                                            isConvergencePoint = true;
                                            errs() << "[*] Skipping convergence point BB: ";
                                            caseBlock->printAsOperand(errs(), false);
                                            errs() << " (predecessors: " << numPredecessors << ", Switch case)\n";
                                            break;
                                        }
                                    }
                                }
                                
                                if (isConvergencePoint) {
                                    continue;
                                }
                                
                                // 3. Dispatcher로 분기하는지 확인
                                bool branchesToDispatcher = false;
                                for (unsigned j = 0; j < caseTerminator->getNumSuccessors(); ++j) {
                                    if (caseTerminator->getSuccessor(j) == dispatcherBlock) {
                                        branchesToDispatcher = true;
                                        break;
                                    }
                                }

                                if (branchesToDispatcher) {
                                    // 종료 명령어 직전에 삽입
                                    IRBuilder<> caseBuilder(caseTerminator);
                                    caseBuilder.CreateCall(standardHandlerFunc);
                                    errs() << "[+] Inserted dummy_function_handler call into BB: ";
                                    caseBlock->printAsOperand(errs(), false);
                                    errs() << " (Switch Successor)\n";
                                    irModified = true;
                                }
                            }
                        }
                        
                        // Switch 핸들러 자체는 타겟 수집만
                        for (unsigned i = 0; i < SI->getNumSuccessors(); ++i) {
                            handlerTargets[handler].insert(SI->getSuccessor(i));
                        }
                        continue;
                    }
                    
                    // 일반 핸들러 처리
                    if (handlerTerminator) {
                        
                        // 현재 핸들러에 태그 삽입 (종료 명령어 직전)
                        bool branchesToDispatcher = false; 
                        
                        // terminator만 있는 블록은 스킵
                        if (!branchesToDispatcher && !hasVMEndPredecessor(handler) && hasNonTerminatorInstructions(handler)) {
                            IRBuilder<> handlerBuilder(handlerTerminator);
                            handlerBuilder.CreateCall(standardHandlerFunc);
                            errs() << "[+] Inserted dummy_function_handler call into BB: ";
                            handler->printAsOperand(errs(), false);
                            errs() << " (Itself)\n";
                            irModified = true;
                        } else if (!hasNonTerminatorInstructions(handler)) {
                            errs() << "[*] Skipping BB with only terminator: ";
                            handler->printAsOperand(errs(), false);
                            errs() << "\n";
                        }
                        
                        // 핸들러의 분기 타겟 수집
                        for (unsigned i = 0; i < handlerTerminator->getNumSuccessors(); ++i) {
                            handlerTargets[handler].insert(handlerTerminator->getSuccessor(i));
                        }
                        
                        // BranchInst인 경우 후행 블록에 태그 삽입
                        if (BranchInst *BI = dyn_cast<BranchInst>(handlerTerminator)) {
                            // 조건 분기인지 확인
                            bool isConditionalBranch = BI->isConditional();
                            
                            // 조건 분기인 경우, 두 후행자의 합류 지점을 기록
                            if (isConditionalBranch && handlerTerminator->getNumSuccessors() == 2) {
                                BasicBlock *succ0 = handlerTerminator->getSuccessor(0);
                                BasicBlock *succ1 = handlerTerminator->getSuccessor(1);
                                
                                // 두 후행자의 공통 후행자 찾기
                                std::set<BasicBlock*> succ0Successors;
                                if (Instruction *succ0Term = succ0->getTerminator()) {
                                    for (unsigned k = 0; k < succ0Term->getNumSuccessors(); ++k) {
                                        succ0Successors.insert(succ0Term->getSuccessor(k));
                                    }
                                }
                                
                                if (Instruction *succ1Term = succ1->getTerminator()) {
                                    for (unsigned k = 0; k < succ1Term->getNumSuccessors(); ++k) {
                                        BasicBlock *succ1Succ = succ1Term->getSuccessor(k);
                                        if (succ0Successors.count(succ1Succ)) {
                                            conditionalBranchConvergencePoints.insert(succ1Succ);
                                            errs() << "[*] Detected conditional branch convergence point: ";
                                            succ1Succ->printAsOperand(errs(), false);
                                            errs() << "\n";
                                        }
                                    }
                                }
                            }
                            
                            for (unsigned i = 0; i < handlerTerminator->getNumSuccessors(); ++i) {
                                BasicBlock *successor = handlerTerminator->getSuccessor(i);
                                Instruction *successorTerminator = successor->getTerminator();
                                
                                // 선행자 개수 확인
                                unsigned numPredecessors = 0;
                                for (BasicBlock *Pred : predecessors(successor)) {
                                    numPredecessors++;
                                }
                                
                                // 1. 기본 조건 검사
                                if (successor != dispatcherBlock && 
                                    successorTerminator &&
                                    !hasVMEndPredecessor(successor) &&
                                    !findCallTo(successor, "dummy_function_handler") &&
                                    !findCallTo(successor, "dummy_function_VM_end_handler") &&
                                    hasNonTerminatorInstructions(successor)) 
                                {
                                    // 2. 합류 지점 필터링 (선행자가 2개 이상이고 dispatcher로 직접 분기)
                                    bool isConvergencePoint = false;
                                    if (numPredecessors >= 2) {
                                        for (unsigned j = 0; j < successorTerminator->getNumSuccessors(); ++j) {
                                            if (successorTerminator->getSuccessor(j) == dispatcherBlock) {
                                                isConvergencePoint = true;
                                                errs() << "[*] Skipping convergence point BB: ";
                                                successor->printAsOperand(errs(), false);
                                                errs() << " (predecessors: " << numPredecessors << ")\n";
                                                break;
                                            }
                                        }
                                    }
                                    
                                    if (isConvergencePoint) {
                                        continue;
                                    }
                                    
                                    // 3. 분기 조건 확인
                                    bool shouldTag = false;
                                    
                                    if (isConditionalBranch) {
                                        // 조건 분기의 경우: 항상 태그 추가
                                        shouldTag = true;
                                        errs() << "[*] Found conditional branch handler. Tagging successor: ";
                                        successor->printAsOperand(errs(), false);
                                        errs() << "\n";
                                    } else {
                                        // 무조건 분기의 경우: dispatcher로 분기하는 경우에만 태그 추가
                                        for (unsigned j = 0; j < successorTerminator->getNumSuccessors(); ++j) {
                                            if (successorTerminator->getSuccessor(j) == dispatcherBlock) {
                                                shouldTag = true;
                                                break;
                                            }
                                        }
                                    }

                                    if (shouldTag) {
                                        IRBuilder<> successorBuilder(successorTerminator); 
                                        successorBuilder.CreateCall(standardHandlerFunc);
                                        errs() << "[+] Inserted dummy_function_handler call into BB: ";
                                        successor->printAsOperand(errs(), false);
                                        errs() << " (Branch Successor - ";
                                        errs() << (isConditionalBranch ? "Conditional" : "Unconditional");
                                        errs() << ")\n";
                                        irModified = true;
                                    }
                                }
                            }
                        }
                    }
                }

                // 조건 분기의 합류 지점에 handler 태그 추가
                for (BasicBlock *convergencePoint : conditionalBranchConvergencePoints) {
                    if (convergencePoint != dispatcherBlock &&
                        !findCallTo(convergencePoint, "dummy_function_handler") &&
                        !findCallTo(convergencePoint, "dummy_function_VM_end_handler") &&
                        hasNonTerminatorInstructions(convergencePoint)) {
                        
                        Instruction *convergenceTerminator = convergencePoint->getTerminator();
                        if (convergenceTerminator) {
                            IRBuilder<> convergenceBuilder(convergenceTerminator);
                            convergenceBuilder.CreateCall(standardHandlerFunc);
                            errs() << "[+] Inserted dummy_function_handler call into convergence point BB: ";
                            convergencePoint->printAsOperand(errs(), false);
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
                            
                            // VM_end_handler 삽입 조건
                            if (!branchesToDispatcher &&
                                !findCallTo(uniqueHandler, "dummy_function_VM_end_handler") &&
                                !isa<SwitchInst>(uniqueTerminator)) 
                            {
                                // 단일 분기(Unconditional Branch) 여부 최종 확인
                                if (uniqueTerminator && isa<BranchInst>(uniqueTerminator) && !cast<BranchInst>(uniqueTerminator)->isConditional()) {
                                    
                                    // 기존 dummy_function_handler가 있으면 제거
                                    if (CallInst *existingHandler = findCallTo(uniqueHandler, "dummy_function_handler")) {
                                        existingHandler->eraseFromParent();
                                    }
                                    
                                    IRBuilder<> endBuilder(uniqueTerminator);
                                    endBuilder.CreateCall(endHandlerFunc);
                                    errs() << "[+] Inserted dummy_function_VM_end_handler into BB: ";
                                    uniqueHandler->printAsOperand(errs(), false);
                                    errs() << "\n";
                                    irModified = true;
                                }
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