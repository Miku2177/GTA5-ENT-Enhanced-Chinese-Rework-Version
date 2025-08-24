#pragma once
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include "misc.h"
#include "..\debug\debuglog.h"

enum class FunctionID {
    RegisterFile,
    GetModelInfo,
};

enum class GameVariant: int {
    GTA5Legacy = 0,
    GTA5Enhanced,
    COUNT
};

inline const char* ToString(FunctionID id) {
    switch (id) {
    case FunctionID::RegisterFile: return "RegisterFile";
    case FunctionID::GetModelInfo: return "GetModelInfo";
    default:                       return "Unknown";
    }
}

inline const char* ToString(GameVariant id) {
    switch (id) {
    case GameVariant::GTA5Legacy:   return "GTA5Legacy";
    case GameVariant::GTA5Enhanced: return "GTA5Enhanced";
    default:                        return "Unknown";
    }
}

template <FunctionID>
struct FunctionTraits;  // forward declaration

template <>
struct FunctionTraits<FunctionID::RegisterFile> {
    using type = uint32_t * (*)(int* textureID, const char* fullPath, bool load, const char* name, bool strictAssert);
};

template <>
struct FunctionTraits<FunctionID::GetModelInfo> {
    using type = __int64 (*)(unsigned int modelHash, int* index);
};

namespace FunctionResolver::detail {
    inline GameVariant resolved_game_variant;
    inline bool resolved_game_variant_valid = false;

    struct PatternVariant {
        const char* bytes;
        const char* mask;
    };

    struct PatternDef {
        FunctionID func;
        bool did_search;
        intptr_t resolved_address;
        PatternVariant variants[static_cast<size_t>(GameVariant::COUNT)];
    };

    inline PatternDef g_Patterns[] = {
        {
            FunctionID::RegisterFile,
            false,
            0,
            {
                { "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x7C\x24\x00\x41\x54\x41\x56\x41\x57\x48\x83\xEC\x50\x48\x8B\xEA\x4C\x8B\xFA\x48\x8B\xD9\x4D\x85\xC9", "xxxx?xxxx?xxxx?xxxxxxxxxxxxxxxxxxxxxx" }, // GTA V Legacy
                { "\x41\x57\x41\x56\x56\x57\x55\x53\x48\x83\xEC\x58\x4C\x89\xCF\x48\x89\xD6\x49\x89\xCE", "xxxxxxxxxxxxxxxxxxxxx" }, // GTA V Enhanced
            }
        },
        {
            FunctionID::GetModelInfo,
            false,
            0,
            {
                { "\x0F\xB7\x05\x00\x00\x00\x00\x45\x33\xC9\x4C\x8B\xDA\x66\x85\xC0\x0F\x84\x00\x00\x00\x00\x44\x0F\xB7\xC0\x33\xD2\x8B\xC1\x41\xF7\xF0\x48\x8B\x05\x00\x00\x00\x00\x4C\x8B\x14\xD0\xEB\x09\x41\x3B\x0A\x74\x54", "xxx????xxxxxxxxxxx????xxxxxxxxxxxxxx????xxxxxxxxxxx" }, // GTA V Legacy
                { "\x44\x0F\xB7\x00\x00\x00\x00\x00\x45\x85\x00\x74\x00\x49\x89\x00\x4C\x8B\x1D\x00\x00\x00\x00\x45\x31\x00", "xxx?????xx?x?xx?xxx????xx?" }, // GTA V Enhanced
            }
        }
    };
}

inline GameVariant GetGameVariant() {
    using namespace FunctionResolver::detail;

    if (resolved_game_variant_valid) {
        return resolved_game_variant;
    }
    auto& entry = g_Patterns[0];

    for (size_t i = 0; i < static_cast<size_t>(GameVariant::COUNT); i++) {
        auto& variant = entry.variants[i];
        intptr_t found = FindPatternJACCO(variant.bytes, variant.mask);
        if (found) {
            resolved_game_variant = (GameVariant)i;
            resolved_game_variant_valid = true;
            write_text_to_log_file("Found game variant " + std::string(ToString(resolved_game_variant)));
            break;
        }
    }

    if (!resolved_game_variant_valid) {
        write_text_to_log_file("[ERROR] Failed finding game variant");
        resolved_game_variant = GameVariant::GTA5Legacy;
        resolved_game_variant_valid = true;
    }
    return resolved_game_variant;
}

template <FunctionID ID>
typename FunctionTraits<ID>::type ResolveFunction()
{
    using namespace FunctionResolver::detail;
    intptr_t addr = 0;

    for (auto& entry : g_Patterns) {
        if (entry.func != ID) {
            continue;
        }

        if (entry.did_search) {
            return reinterpret_cast<typename FunctionTraits<ID>::type>(entry.resolved_address);
        }

        auto& variant = entry.variants[static_cast<size_t>(GetGameVariant())];
        intptr_t found = FindPatternJACCO(variant.bytes, variant.mask);
        if (found) {
            write_text_to_log_file(
                (std::ostringstream{}
                    << "Found address 0x"
                    << std::hex << std::uppercase
                    << static_cast<std::uintptr_t>(found)
                    << " to function "
                    << ToString(entry.func)
                    ).str()
            );
            entry.did_search = true;
            entry.resolved_address = found;
            addr = found;
            break;
        }

        if (!addr) {
            write_text_to_log_file("[ERROR] Failed finding address to function " + std::string(ToString(entry.func)));
            entry.did_search = true;
        }
    }

    return reinterpret_cast<typename FunctionTraits<ID>::type>(addr);
}