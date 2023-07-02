#pragma once

#include <stdint.h>

/// @brief Finds a YARA signature in the specificed modules .text section.
/// @param module The module to search in.
/// @param pattern The YARA signature to search for.
/// @return A pointer to the signature if found, otherwise 0x0.
uintptr_t find_signature( const char* module, const char* pattern );
