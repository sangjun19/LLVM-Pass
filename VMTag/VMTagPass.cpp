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

// ============================================================================
// Helper Functions
// ============================================================================

/// 특정 함수 호출이 블록에 이미 존재하는지 확인
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

/// 선행 블록이 VM_end_handler 호출을 포함하는지 확인
bool hasVMEndPredecessor(BasicBlock *BB) {
    for (BasicBlock *Pred : predecessors(BB)) {
        if (findCallTo(Pred, "dummy_function_VM_end_handler")) {
            return true;
        }
    }
    return false;
}

/// 블록에 terminator 외에 실제 명령어가 있는지 확인
/// dummy_function 호출은 제외하고 카운트
bool hasNonTerminatorInstructions(BasicBlock *BB) {
    unsigned instCount = 0;
    for (Instruction &Inst : *BB) {
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

/// VM_end_handler 블록의 모든 후행자를 재귀적으로 수집
void collectAllSuccessors(BasicBlock *BB, std::set<BasicBlock*> &visited, 
                          std::set<BasicBlock*> &allSuccessors) {
    if (visited.count(BB)) {
        return;
    }
    visited.insert(BB);
    
    Instruction *terminator = BB->getTerminator();
    if (!terminator) {
        return;
    }
    
    for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
        BasicBlock *successor = terminator->getSuccessor(i);
        allSuccessors.insert(successor);
        collectAllSuccessors(successor, visited, allSuccessors);
    }
}

/// 조건 분기 이후의 모든 단일 분기 블록을 재귀적으로 탐색하여 태그 삽입
/// - 조건 분기: 태그하지 않고 후행자 탐색
/// - 단일 분기: 실제 로직이 있으면 태그하고 후행자 탐색 계속
void tagConditionalBranchSuccessors(BasicBlock *BB, BasicBlock *dispatcherBlock,
                                    FunctionCallee &handlerFunc,
                                    std::set<BasicBlock*> &processedBlocks,
                                    bool &irModified, int depth = 0) {
    // 무한 재귀 방지 및 이미 처리된 블록 스킵
    const int MAX_DEPTH = 20;
    if (depth > MAX_DEPTH || processedBlocks.count(BB)) {
        return;
    }
    processedBlocks.insert(BB);
    
    Instruction *terminator = BB->getTerminator();
    if (!terminator) {
        return;
    }
    
    // Switch는 별도 처리하므로 여기서는 스킵
    if (isa<SwitchInst>(terminator)) {
        return;
    }
    
    BranchInst *BI = dyn_cast<BranchInst>(terminator);
    if (!BI) {
        return;
    }
    
    if (BI->isConditional()) {
        // 조건 분기: 이 블록은 태그하지 않고 재귀 탐색 계속
        for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
            BasicBlock *successor = terminator->getSuccessor(i);
            if (successor != dispatcherBlock) {
                tagConditionalBranchSuccessors(successor, dispatcherBlock, handlerFunc, 
                                               processedBlocks, irModified, depth + 1);
            }
        }
    } else {
        // 단일 분기: 실제 로직이 있으면 태그
        if (BB != dispatcherBlock && 
            !hasVMEndPredecessor(BB) &&
            !findCallTo(BB, "dummy_function_handler") &&
            !findCallTo(BB, "dummy_function_VM_end_handler") &&
            hasNonTerminatorInstructions(BB)) {
            
            IRBuilder<> builder(terminator);
            builder.CreateCall(handlerFunc);
            errs() << "[+] Tagged handler: ";
            BB->printAsOperand(errs(), false);
            errs() << "\n";
            irModified = true;
        }
        
        // 단일 분기의 후행자도 계속 탐색 (dispatcher가 아닌 경우)
        BasicBlock *successor = terminator->getSuccessor(0);
        if (successor != dispatcherBlock) {
            tagConditionalBranchSuccessors(successor, dispatcherBlock, handlerFunc, 
                                           processedBlocks, irModified, depth + 1);
        }
    }
}

// ============================================================================
// VMTagPass Implementation
// ============================================================================

class VMTagPass : public PassInfoMixin<VMTagPass> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
        if (F.isDeclaration()) {
            return PreservedAnalyses::all();
        }

        // main 함수만 처리
        if (F.getName() != "main") {
            return PreservedAnalyses::all();
        }

        errs() << "\n[*] Analyzing function: '" << F.getName() << "'\n";
        errs() << "========================================\n";
        
        bool irModified = false;
        LLVMContext &Ctx = F.getContext();
        Module *M = F.getParent();

        // Dispatcher 찾기: 가장 많은 후행자를 가진 블록
        BasicBlock *dispatcherBlock = findDispatcher(F);
        if (!dispatcherBlock) {
            errs() << "[-] No dispatcher block found\n";
            errs() << "========================================\n\n";
            return PreservedAnalyses::all();
        }

        errs() << "[+] Found dispatcher block: ";
        dispatcherBlock->printAsOperand(errs(), false);
        errs() << "\n\n";

        // 함수 선언 준비
        FunctionType *voidFuncType = FunctionType::get(Type::getVoidTy(Ctx), false);
        FunctionCallee dispatchFunc = M->getOrInsertFunction("dummy_function_dispatch_start", voidFuncType);
        FunctionCallee handlerFunc = M->getOrInsertFunction("dummy_function_handler", voidFuncType);
        FunctionCallee endHandlerFunc = M->getOrInsertFunction("dummy_function_VM_end_handler", voidFuncType);
        FunctionCallee startFunc = M->getOrInsertFunction("dummy_function_VM_start", voidFuncType);
        FunctionCallee nonVMFunc = M->getOrInsertFunction("dummy_function_NonVM", voidFuncType);

        // 1. Dispatcher 태그
        tagDispatcher(dispatcherBlock, dispatchFunc, irModified);

        // 2. Handlers 수집 및 태그
        std::vector<BasicBlock*> handlers = getHandlers(dispatcherBlock);
        std::map<BasicBlock*, std::set<BasicBlock*>> handlerTargets;
        std::set<BasicBlock*> processedBlocks;

        tagHandlers(handlers, dispatcherBlock, handlerFunc, handlerTargets, 
                   processedBlocks, irModified);

        // 3. VM_end_handler 찾기 및 태그
        BasicBlock *vmEndHandlerBlock = findAndTagVMEndHandler(
            handlers, dispatcherBlock, handlerTargets, handlerFunc, endHandlerFunc, irModified);

        // 4. VM_start 태그
        tagVMStart(F, dispatcherBlock, startFunc, irModified);

        // 5. NonVM 영역 태그
        if (vmEndHandlerBlock) {
            tagNonVMRegion(vmEndHandlerBlock, nonVMFunc, irModified);
        }

        errs() << "========================================\n";
        errs() << "[*] IR Modified: " << (irModified ? "Yes" : "No") << "\n\n";
        
        return irModified ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

private:
    /// 가장 많은 후행자를 가진 블록을 dispatcher로 식별
    BasicBlock* findDispatcher(Function &F) {
        const BasicBlock *candidate = nullptr;
        unsigned maxSuccs = 0;

        for (BasicBlock &BB : F) {
            const Instruction *terminator = BB.getTerminator();
            unsigned numSuccessors = terminator ? terminator->getNumSuccessors() : 0;
            
            if (numSuccessors > maxSuccs) {
                maxSuccs = numSuccessors;
                candidate = &BB;
            }
        }

        return const_cast<BasicBlock*>(candidate);
    }

    /// Dispatcher 블록에 태그 삽입
    void tagDispatcher(BasicBlock *dispatcher, FunctionCallee &dispatchFunc, bool &irModified) {
        if (!findCallTo(dispatcher, "dummy_function_dispatch_start")) {
            IRBuilder<> builder(dispatcher->getTerminator());
            builder.CreateCall(dispatchFunc);
            errs() << "[+] Tagged dispatcher\n";
            irModified = true;
        }
    }

    /// Dispatcher의 직접 후행자들(handlers) 수집
    std::vector<BasicBlock*> getHandlers(BasicBlock *dispatcher) {
        std::vector<BasicBlock*> handlers;
        Instruction *terminator = dispatcher->getTerminator();
        
        if (terminator) {
            for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
                handlers.push_back(terminator->getSuccessor(i));
            }
        }

        errs() << "[*] Found " << handlers.size() << " handler(s)\n\n";
        return handlers;
    }

    /// Handler 블록들 태그
    void tagHandlers(std::vector<BasicBlock*> &handlers, BasicBlock *dispatcher,
                    FunctionCallee &handlerFunc, 
                    std::map<BasicBlock*, std::set<BasicBlock*>> &handlerTargets,
                    std::set<BasicBlock*> &processedBlocks, bool &irModified) {
        
        errs() << "--- Tagging Handlers ---\n";

        for (BasicBlock *handler : handlers) {
            Instruction *terminator = handler->getTerminator();
            
            // 이미 태그된 핸들러는 타겟만 수집
            if (findCallTo(handler, "dummy_function_handler") || 
                findCallTo(handler, "dummy_function_VM_end_handler")) {
                collectTargets(handler, terminator, handlerTargets);
                continue;
            }

            // Switch 명령어 처리
            if (SwitchInst *SI = dyn_cast<SwitchInst>(terminator)) {
                tagSwitchHandler(SI, handler, dispatcher, handlerFunc, 
                               handlerTargets, irModified);
                continue;
            }

            // Branch 명령어 처리
            if (terminator) {
                collectTargets(handler, terminator, handlerTargets);
                tagBranchHandler(handler, dispatcher, terminator, handlerFunc, 
                               processedBlocks, irModified);
            }
        }

        errs() << "\n";
    }

    /// 타겟 수집
    void collectTargets(BasicBlock *handler, Instruction *terminator,
                       std::map<BasicBlock*, std::set<BasicBlock*>> &handlerTargets) {
        if (terminator) {
            for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
                handlerTargets[handler].insert(terminator->getSuccessor(i));
            }
        }
    }

    /// Switch 핸들러 처리
    void tagSwitchHandler(SwitchInst *SI, BasicBlock *handler, BasicBlock *dispatcher,
                         FunctionCallee &handlerFunc,
                         std::map<BasicBlock*, std::set<BasicBlock*>> &handlerTargets,
                         bool &irModified) {
        
        // Switch 블록 자체는 태그하지 않고, 각 case 블록에 태그
        for (unsigned i = 0; i < SI->getNumSuccessors(); ++i) {
            BasicBlock *caseBlock = SI->getSuccessor(i);
            Instruction *caseTerminator = caseBlock->getTerminator();

            if (caseBlock != dispatcher &&
                caseTerminator &&
                !hasVMEndPredecessor(caseBlock) &&
                !findCallTo(caseBlock, "dummy_function_handler") &&
                !findCallTo(caseBlock, "dummy_function_VM_end_handler") &&
                hasNonTerminatorInstructions(caseBlock)) {
                
                IRBuilder<> builder(caseTerminator);
                builder.CreateCall(handlerFunc);
                errs() << "[+] Tagged handler: ";
                caseBlock->printAsOperand(errs(), false);
                errs() << "\n";
                irModified = true;
            }
        }

        // 타겟 수집
        for (unsigned i = 0; i < SI->getNumSuccessors(); ++i) {
            handlerTargets[handler].insert(SI->getSuccessor(i));
        }
    }

    /// Branch 핸들러 처리
    void tagBranchHandler(BasicBlock *handler, BasicBlock *dispatcher, 
                         Instruction *terminator, FunctionCallee &handlerFunc,
                         std::set<BasicBlock*> &processedBlocks, bool &irModified) {
        
        BranchInst *BI = dyn_cast<BranchInst>(terminator);
        if (!BI) {
            return;
        }

        if (BI->isConditional()) {
            // 조건 분기: 핸들러 자체는 태그하지 않고 재귀 탐색
            for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
                BasicBlock *successor = terminator->getSuccessor(i);
                if (successor != dispatcher) {
                    tagConditionalBranchSuccessors(successor, dispatcher, handlerFunc, 
                                                   processedBlocks, irModified, 0);
                }
            }
        } else {
            // 단일 분기: 핸들러 자체에 태그
            if (!hasVMEndPredecessor(handler) && hasNonTerminatorInstructions(handler)) {
                IRBuilder<> builder(terminator);
                builder.CreateCall(handlerFunc);
                errs() << "[+] Tagged handler: ";
                handler->printAsOperand(errs(), false);
                errs() << "\n";
                irModified = true;
            }
        }
    }

    /// VM_end_handler 찾기 및 태그
    BasicBlock* findAndTagVMEndHandler(std::vector<BasicBlock*> &handlers,
                                       BasicBlock *dispatcher,
                                       std::map<BasicBlock*, std::set<BasicBlock*>> &handlerTargets,
                                       FunctionCallee &handlerFunc,
                                       FunctionCallee &endHandlerFunc,
                                       bool &irModified) {
        
        errs() << "--- Finding VM End Handler ---\n";
        BasicBlock *vmEndHandlerBlock = nullptr;

        // 1. 고유한 분기 타겟을 가진 핸들러 찾기
        if (handlerTargets.size() > 1) {
            vmEndHandlerBlock = findUniqueTargetHandler(
                handlerTargets, dispatcher, handlerFunc, endHandlerFunc, irModified);
        }

        // 2. ret 명령어를 가진 핸들러 찾기
        if (!vmEndHandlerBlock) {
            vmEndHandlerBlock = findReturnHandler(
                handlers, handlerFunc, endHandlerFunc, irModified);
        }

        if (vmEndHandlerBlock) {
            errs() << "[+] Tagged VM_end_handler at BB: ";
            vmEndHandlerBlock->printAsOperand(errs(), false);
            errs() << "\n\n";
        } else {
            errs() << "[-] No VM end handler found\n\n";
        }

        return vmEndHandlerBlock;
    }

    /// 고유한 분기 타겟을 가진 핸들러 찾기
    BasicBlock* findUniqueTargetHandler(std::map<BasicBlock*, std::set<BasicBlock*>> &handlerTargets,
                                        BasicBlock *dispatcher,
                                        FunctionCallee &handlerFunc,
                                        FunctionCallee &endHandlerFunc,
                                        bool &irModified) {
        
        std::map<std::set<BasicBlock*>, std::vector<BasicBlock*>> targetGroups;
        
        for (auto &[handler, targets] : handlerTargets) {
            targetGroups[targets].push_back(handler);
        }

        for (auto &[targets, handlersWithSameTargets] : targetGroups) {
            if (handlersWithSameTargets.size() == 1) {
                BasicBlock *uniqueHandler = handlersWithSameTargets[0];
                Instruction *terminator = uniqueHandler->getTerminator();

                // dispatcher로 분기하는지 확인
                bool branchesToDispatcher = false;
                if (terminator) {
                    for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
                        if (terminator->getSuccessor(i) == dispatcher) {
                            branchesToDispatcher = true;
                            break;
                        }
                    }
                }

                // VM_end_handler 조건 확인
                if (!branchesToDispatcher &&
                    !findCallTo(uniqueHandler, "dummy_function_VM_end_handler") &&
                    !isa<SwitchInst>(terminator) &&
                    terminator && isa<BranchInst>(terminator) &&
                    !cast<BranchInst>(terminator)->isConditional()) {
                    
                    // 기존 handler 태그 제거 후 end_handler 태그 삽입
                    if (CallInst *existingHandler = findCallTo(uniqueHandler, "dummy_function_handler")) {
                        existingHandler->eraseFromParent();
                    }
                    
                    IRBuilder<> builder(terminator);
                    builder.CreateCall(endHandlerFunc);
                    // errs() << "[+] Tagged VM_end_handler\n";
                    irModified = true;
                    
                    return uniqueHandler;
                }
            }
        }

        return nullptr;
    }

    /// Return 명령어를 가진 핸들러 찾기
    BasicBlock* findReturnHandler(std::vector<BasicBlock*> &handlers,
                                  FunctionCallee &handlerFunc,
                                  FunctionCallee &endHandlerFunc,
                                  bool &irModified) {
        
        for (BasicBlock *handler : handlers) {
            Instruction *terminator = handler->getTerminator();
            
            if (terminator && isa<ReturnInst>(terminator)) {
                if (!findCallTo(handler, "dummy_function_VM_end_handler")) {
                    // 기존 handler 태그 제거 후 end_handler 태그 삽입
                    if (CallInst *existingHandler = findCallTo(handler, "dummy_function_handler")) {
                        existingHandler->eraseFromParent();
                    }
                    
                    IRBuilder<> builder(terminator);
                    builder.CreateCall(endHandlerFunc);
                    errs() << "[+] Tagged VM_end_handler (return instruction)\n";
                    irModified = true;
                    
                    return handler;
                }
            }
        }

        return nullptr;
    }

    /// VM_start 태그 (dispatcher 직전 블록)
    void tagVMStart(Function &F, BasicBlock *dispatcher, 
                   FunctionCallee &startFunc, bool &irModified) {
        
        errs() << "--- Tagging VM Start ---\n";

        for (BasicBlock &BB : F) {
            Instruction *terminator = BB.getTerminator();
            
            if (terminator && terminator->getNumSuccessors() > 0) {
                if (terminator->getSuccessor(0) == dispatcher) {
                    if (!findCallTo(&BB, "dummy_function_VM_start")) {
                        IRBuilder<> builder(terminator);
                        builder.CreateCall(startFunc);
                        errs() << "[+] Tagged VM_start at BB: ";
                        BB.printAsOperand(errs(), false);
                        errs() << "\n\n";
                        irModified = true;
                        return;
                    }
                }
            }
        }

        errs() << "[-] No VM_start location found\n\n";
    }

    /// NonVM 영역 태그 (VM_end_handler 이후)
    void tagNonVMRegion(BasicBlock *vmEndHandler, FunctionCallee &nonVMFunc, 
                       bool &irModified) {
        
        errs() << "--- Tagging Non-VM Region ---\n";

        std::set<BasicBlock*> visited;
        std::set<BasicBlock*> nonVMBlocks;
        
        collectAllSuccessors(vmEndHandler, visited, nonVMBlocks);
        
        // errs() << "[*] Found " << nonVMBlocks.size() << " non-VM block(s)\n";

        for (BasicBlock *nonVMBlock : nonVMBlocks) {
            if (findCallTo(nonVMBlock, "dummy_function_NonVM")) {
                continue;
            }
            
            Instruction *terminator = nonVMBlock->getTerminator();
            if (terminator) {
                IRBuilder<> builder(terminator);
                builder.CreateCall(nonVMFunc);
                irModified = true;
            }
        }

        errs() << "[+] Tagged " << nonVMBlocks.size() << " non-VM blocks\n\n";
    }
};

} // anonymous namespace

// ============================================================================
// Pass Registration
// ============================================================================

extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "VMTagPass",
        "v0.2",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "vmtag") {
                        FPM.addPass(VMTagPass());
                        return true;
                    }
                    return false;
                }
            );
        }
    };
}