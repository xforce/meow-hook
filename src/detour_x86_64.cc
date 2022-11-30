#if _M_X64 == 100
#include "meow_hook/detour.h"

#include <Windows.h>

#include <Zydis/Utils.h>
#include <Zydis/Zydis.h>
#include <asmjit/asmjit.h>

namespace meow_hook::detail
{

static inline bool is_relative_jump(const ZydisDecodedInstruction& instruction)
{
    return instruction.meta.branch_type == ZydisBranchType::ZYDIS_BRANCH_TYPE_SHORT
           || instruction.meta.branch_type == ZYDIS_BRANCH_TYPE_NEAR;
}

static inline void RelocateInstruction(intptr_t source_base, intptr_t target_base,
                                       intptr_t                 new_instruction_location,
                                       ZydisDecodedInstruction& instruction, intptr_t offset,
                                       asmjit::CodeHolder& code)
{
    const auto& imm  = instruction.raw.imm[0];
    const auto& disp = instruction.raw.disp;
    if (imm.size != 0) {
        auto* target_code = code.textSection()->buffer().data() + offset + imm.offset;
        switch (imm.size) {
            case 8: {
                *(int8_t*)(target_code) =
                    static_cast<int8_t>(new_instruction_location - offset - instruction.length);
            } break;
            case 16: {
                *(int16_t*)(target_code) =
                    static_cast<int16_t>(new_instruction_location - offset - instruction.length);
            } break;
            case 32: {
                *(int32_t*)(target_code) =
                    static_cast<int32_t>(new_instruction_location - offset - instruction.length);
            } break;
            case 64: {
                *(int64_t*)(target_code) =
                    static_cast<int64_t>(new_instruction_location - offset - instruction.length);
            } break;
            default: {
                // Unsupported
                __debugbreak();
            }
        }
    }

    if (disp.size != 0) {
        auto* target_code = code.textSection()->buffer().data() + offset + disp.offset;
        //if (instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_LEA) {
        //    return;
        //}
        switch (disp.size) {
            case 8: {
                // This will break anyways...
                // const auto old_abs =
                //    source_base + offset + instruction.length + *(int8_t*)(target_code);
                // const auto new_abs      = old_abs - (target_base + offset + instruction.length);
                //*(int8_t*)(target_code) = static_cast<int8_t>(new_abs);
            } break;
            case 16: {
                // This will break anyways...
                /* const auto old_abs =
                     source_base + offset + instruction.length + *(int16_t*)(target_code);
                 const auto new_abs       = old_abs - (target_base + offset + instruction.length);
                 *(int16_t*)(target_code) = static_cast<int16_t>(new_abs);*/
            } break;
            case 32: {
                 const auto old_abs =
                     source_base + offset + instruction.length + *(int32_t*)(target_code);
                 const auto new_abs       = old_abs - (target_base + offset + instruction.length);
                 *(int32_t*)(target_code) = static_cast<int32_t>(new_abs);
            } break;
            case 64: {
                const auto old_abs =
                    source_base + offset + instruction.length + *(int64_t*)(target_code);
                const auto new_abs       = old_abs - (target_base + offset + instruction.length);
                *(int64_t*)(target_code) = static_cast<int64_t>(new_abs);
            } break;
            default: {
                // Unsupported
                __debugbreak();
            }
        }
    }
    // target_address
}

void detour_base::hook()
{
    struct RelocationInfo {
        uintptr_t               offset;
        ZydisDecodedInstruction instruction;
    };
    std::vector<RelocationInfo> reloaction_info;

    auto jump_buffer = create_absolute_jump();

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    ZydisDecodedInstruction instruction;
    ZyanUSize               offset = 0;
    const ZyanUSize         length = 0x80;

    uintptr_t fill_nops_to = 0;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(address_ + offset),
                                                 length - offset, &instruction))) {
        //
        offset += instruction.length;

        if (fill_nops_to == 0 && offset >= jump_buffer.size()) {
            fill_nops_to = offset;
        }
        if (is_relative_jump(instruction)) {

            if ((offset - instruction.length) + instruction.operands[0].imm.value.s
                <= (fill_nops_to == 0 ? jump_buffer.size() : fill_nops_to)) {
                // Jump into prologue
                reloaction_info.emplace_back(
                    RelocationInfo{offset - instruction.length, instruction});
                if (fill_nops_to != 0) {
                    fill_nops_to = offset;
                }
            } else if ((offset - instruction.length)
                       <= (fill_nops_to == 0 ? jump_buffer.size() : fill_nops_to)) {
                // Jump out of prologue
                reloaction_info.emplace_back(
                    RelocationInfo{offset - instruction.length, instruction});
                if (fill_nops_to != 0) {
                    fill_nops_to = offset;
                }
            }
        } else if (offset <= (fill_nops_to == 0 ? jump_buffer.size() : fill_nops_to)
                   && instruction.raw.disp.offset > 0 && instruction.raw.disp.size > 0x10) {
            // Displacement thingy
            reloaction_info.emplace_back(RelocationInfo{offset - instruction.length, instruction});
        }
        // We end here, let's just hope there is no jump into our copied prologue after this
        // but there shouldn't be tbh
        if (offset > length) {
            break;
        }
    }

    const auto buffer_size = jump_buffer.size();
    if (fill_nops_to > buffer_size) {
        for (int i = 0; i < fill_nops_to - buffer_size; ++i) {
            jump_buffer.emplace_back(0x90); // Write a NOP
        }
    }

    asmjit::CodeHolder trampoline_code;

    constexpr auto kRequired64bitJumpSize = 17;
    constexpr auto kRelocationEntrySize   = 5; // 5 is 32 bit relative jump

    const auto trampoline_size = kRequired64bitJumpSize + jump_buffer.size()
                                 + (reloaction_info.size() * kRelocationEntrySize);

    const auto trampoline_2gb = Allocate2GBRange(address_, trampoline_size);
    if (trampoline_2gb) {
        using namespace asmjit::x86;

        trampoline_code.init(asmjit::Environment::host(),
                             reinterpret_cast<uintptr_t>(trampoline_2gb));

        asmjit::x86::Assembler trampoline_assembler(&trampoline_code);

        // Success
        trampoline_assembler.embed((void*)(address_), static_cast<uint32_t>(jump_buffer.size()));
        const Mem       b              = ptr(rip, 0);
        const uintptr_t return_address = address_ + jump_buffer.size();
        trampoline_assembler.jmp(b);
        trampoline_assembler.embed((void*)(&return_address), sizeof(return_address));

        // Do the relocation stuff
        for (auto& reloc_info : reloaction_info) {

            //
            ZyanU64 target_address = 0;
            // Can be null, only used for jump table entries
            intptr_t relocation_target = 0;

            if (is_relative_jump(reloc_info.instruction)) {
                ZydisCalcAbsoluteAddress(&reloc_info.instruction,
                                         &reloc_info.instruction.operands[0],
                                         address_ + reloc_info.offset, &target_address);
                relocation_target = trampoline_code.textSection()->buffer().size();
                trampoline_assembler.jmp(target_address);
            }
            RelocateInstruction(address_, reinterpret_cast<intptr_t>(trampoline_2gb),
                                relocation_target, reloc_info.instruction, reloc_info.offset,
                                trampoline_code);
        }

        memcpy(trampoline_2gb, trampoline_code.textSection()->buffer().data(),
               trampoline_code.textSection()->buffer().size());
        trampoline_ = trampoline_2gb;
    } else {
        if (reloaction_info.size() > 0) {
            // Relocation outside of 2gb region is currently not supported
            __debugbreak();
        }

        using namespace asmjit::x86;

        trampoline_code.init(asmjit::Environment::host(),
                             reinterpret_cast<uintptr_t>(trampoline_2gb));

        asmjit::x86::Assembler trampoline_assembler(&trampoline_code);

        // Success
        trampoline_assembler.embed((void*)(address_), static_cast<uint32_t>(jump_buffer.size()));
        const Mem       b              = ptr(rip, 0);
        const uintptr_t return_address = address_ + jump_buffer.size();
        trampoline_assembler.jmp(b);
        trampoline_assembler.embed((void*)(&return_address), sizeof(return_address));

        auto trampoline =
            VirtualAlloc(0, trampoline_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(trampoline, trampoline_code.textSection()->buffer().data(),
               trampoline_code.textSection()->buffer().size());
        DWORD old_protect = 0;
        VirtualProtect((LPVOID)trampoline, trampoline_size, PAGE_EXECUTE_READ, &old_protect);
        trampoline_ = trampoline;
    }

    { // This writes the code to jump to the hook callback function
        DWORD old_protect;
        VirtualProtect((LPVOID)address_, jump_buffer.size(), PAGE_EXECUTE_READWRITE, &old_protect);
        original_code_.resize(jump_buffer.size());
        memcpy(original_code_.data(), (void*)address_, original_code_.size());
        memcpy((void*)address_, jump_buffer.data(), jump_buffer.size());
        VirtualProtect((LPVOID)address_, jump_buffer.size(), old_protect, &old_protect);
    }
}

std::vector<uint8_t> detour_base::create_absolute_jump() const
{
    using namespace asmjit::x86;

    asmjit::CodeHolder jump_code;
    jump_code.init(asmjit::Environment::host());

    asmjit::x86::Assembler jump_assembler(&jump_code);

    Mem b = ptr(rip, 0);
    jump_assembler.jmp(b);
    jump_assembler.embed((void*)(&function_), sizeof(function_));

    asmjit::CodeBuffer& jump_buffer = jump_code.textSection()->buffer();
    return {jump_buffer.data(), jump_buffer.data() + jump_buffer.size()};
}

} // namespace meow_hook::detail
#endif