#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CFG.h"

#include <vector>
#include <set>
#include <algorithm>

using namespace llvm;

namespace {

class VMTagPass : public PassInfoMixin<VMTagPass> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {
        if (F.isDeclaration() || F.getName() != "main") return PreservedAnalyses::all();

        errs() << "\n[*] Analyzing function: '" << F.getName() << "'\n";

        // 1. 핵심 구조 식별 (사용자 기준: 진출점 최다 = Dispatcher, 진입점 최다 = Latch)
        BasicBlock *dispatcherBlock = findBlockWithMostSuccessors(F);
        BasicBlock *latchBlock = findBlockWithMostPredecessors(F);

        if (!dispatcherBlock || !latchBlock) return PreservedAnalyses::all();

        bool irModified = false;
        LLVMContext &Ctx = F.getContext();
        Module *M = F.getParent();

        // 함수 선언
        FunctionType *voidFTy = FunctionType::get(Type::getVoidTy(Ctx), false);
        FunctionCallee dispatchTag = M->getOrInsertFunction("dummy_function_dispatch_start", voidFTy);
        FunctionCallee handlerTag = M->getOrInsertFunction("dummy_function_handler", voidFTy);
        FunctionCallee vmEndTag = M->getOrInsertFunction("dummy_function_VM_end_handler", voidFTy);
        FunctionCallee vmStartTag = M->getOrInsertFunction("dummy_function_VM_start", voidFTy);
        FunctionCallee nonVMTag = M->getOrInsertFunction("dummy_function_NonVM", voidFTy);

        // 2. Dispatcher 태그 (종료 명령어 직전)
        if (!findCallTo(dispatcherBlock, "dummy_function_dispatch_start")) {
            IRBuilder<> builder(dispatcherBlock->getTerminator());
            builder.CreateCall(dispatchTag);
            irModified = true;
        }

        // 3. 핸들러 및 VM_End 판별 및 태깅
        std::set<BasicBlock*> detectedVMEndBlocks;
        for (BasicBlock *Succ : successors(dispatcherBlock)) {
            if (Succ == latchBlock) continue;

            std::set<BasicBlock*> visited;
            if (reachesTarget(Succ, latchBlock, visited)) {
                // 핸들러 태그 삽입 (종료 명령어 직전으로 일관성 유지)
                tagBlockAtEnd(Succ, handlerTag, "handler", irModified);
            } else {
                // VM_End 태그 삽입
                tagBlockAtEnd(Succ, vmEndTag, "VM_end_handler", irModified);
                detectedVMEndBlocks.insert(Succ);
            }
        }

        // 4. VM_start 태그 (Dispatcher 진입 직전 블록의 끝)
        tagVMStart(F, dispatcherBlock, vmStartTag, irModified);

        // 5. Non_VM 태그
        // VM_End 이후 경로에 있으면서 Dispatcher보다 물리적으로 앞에 있는 블록들
        if (!detectedVMEndBlocks.empty()) {
            tagNonVMRegion(F, detectedVMEndBlocks, dispatcherBlock, nonVMTag, irModified);
        }

        return irModified ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

private:
    // 태그 삽입 함수: 종료 명령어(Terminator) 바로 직전에 삽입 (일관성 유지)
    void tagBlockAtEnd(BasicBlock *BB, FunctionCallee &tagFunc, StringRef name, bool &modified) {
        if (findCallTo(BB, "dummy_function_handler") || 
            findCallTo(BB, "dummy_function_VM_end_handler") ||
            findCallTo(BB, "dummy_function_NonVM"))
            return;
            
        IRBuilder<> builder(BB->getTerminator());
        builder.CreateCall(tagFunc);
        errs() << "[+] Tagged " << name << " at: ";
        BB->printAsOperand(errs(), false);
        errs() << "\n";
        modified = true;
    }

    void tagNonVMRegion(Function &F, const std::set<BasicBlock*> &endBlocks, 
                        BasicBlock *dispatcher, FunctionCallee &tagFunc, bool &modified) {
        std::set<BasicBlock*> reachableFromEnd;
        std::set<BasicBlock*> visited;

        for (BasicBlock *EB : endBlocks) {
            collectAllSuccessors(EB, visited, reachableFromEnd);
        }

        for (BasicBlock *NB : reachableFromEnd) {
            if (isBefore(NB, dispatcher)) {
                // NonVM 태그도 동일하게 블록 끝에 삽입
                tagBlockAtEnd(NB, tagFunc, "Non_VM", modified);
            }
        }
    }

    bool isBefore(BasicBlock *BB1, BasicBlock *BB2) {
        if (BB1 == BB2) return false;
        for (const BasicBlock &BB : *BB1->getParent()) {
            if (&BB == BB1) return true;
            if (&BB == BB2) return false;
        }
        return false;
    }

    void collectAllSuccessors(BasicBlock *BB, std::set<BasicBlock*> &visited, std::set<BasicBlock*> &result) {
        if (!visited.insert(BB).second) return;
        for (BasicBlock *Succ : successors(BB)) {
            result.insert(Succ);
            collectAllSuccessors(Succ, visited, result);
        }
    }

    BasicBlock* findBlockWithMostSuccessors(Function &F) {
        BasicBlock *maxSuccBlock = nullptr;
        unsigned maxSuccs = 0;
        for (BasicBlock &BB : F) {
            unsigned count = BB.getTerminator()->getNumSuccessors();
            if (count > maxSuccs) { maxSuccs = count; maxSuccBlock = &BB; }
        }
        return maxSuccBlock;
    }

    BasicBlock* findBlockWithMostPredecessors(Function &F) {
        BasicBlock *maxPredBlock = nullptr;
        unsigned maxPreds = 0;
        for (BasicBlock &BB : F) {
            unsigned count = 0;
            for (BasicBlock *Pred : predecessors(&BB)) { (void)Pred; count++; }
            if (count > maxPreds) { maxPreds = count; maxPredBlock = &BB; }
        }
        return maxPredBlock;
    }

    bool reachesTarget(BasicBlock *BB, BasicBlock *Target, std::set<BasicBlock*> &visited) {
        if (BB == Target) return true;
        if (visited.count(BB) || isa<ReturnInst>(BB->getTerminator())) return false;
        visited.insert(BB);
        for (BasicBlock *Succ : successors(BB)) {
            if (reachesTarget(Succ, Target, visited)) return true;
        }
        return false;
    }

    void tagVMStart(Function &F, BasicBlock *dispatcher, FunctionCallee &tagFunc, bool &modified) {
        for (BasicBlock &BB : F) {
            if (&BB == dispatcher || findCallTo(&BB, "dummy_function_handler")) continue;
            Instruction *TI = BB.getTerminator();
            for (unsigned i = 0; i < TI->getNumSuccessors(); ++i) {
                if (TI->getSuccessor(i) == dispatcher) {
                    if (!findCallTo(&BB, "dummy_function_VM_start")) {
                        IRBuilder<> builder(TI);
                        builder.CreateCall(tagFunc);
                        modified = true;
                        return;
                    }
                }
            }
        }
    }

    CallInst* findCallTo(BasicBlock *BB, StringRef FuncName) {
        for (Instruction &Inst : *BB) {
            if (CallInst *CI = dyn_cast<CallInst>(&Inst)) {
                if (CI->getCalledFunction() && CI->getCalledFunction()->getName() == FuncName) return CI;
            }
        }
        return nullptr;
    }
};

} // namespace

extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "VMTagPass", "v0.11",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM, ...) {
                    if (Name == "vmtag") { FPM.addPass(VMTagPass()); return true; }
                    return false;
                }
            );
        }
    };
}