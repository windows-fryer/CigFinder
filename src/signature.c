#include "signature.h"

#include <Windows.h>

uintptr_t find_signature( const char* module, const char* signature )
{
	uintptr_t found_address = 0x0;

	const uintptr_t module_base_address = ( uintptr_t )GetModuleHandleA( module );

	if ( !module_base_address )
		return found_address;

	const IMAGE_DOS_HEADER* dos_header = ( const IMAGE_DOS_HEADER* )module_base_address;
	const IMAGE_NT_HEADERS* nt_headers = ( const IMAGE_NT_HEADERS* )( module_base_address + dos_header->e_lfanew );

	// Get the start of the .text section and the end of the .text section.
	const uintptr_t module_code_start = module_base_address + nt_headers->OptionalHeader.BaseOfCode;
	const uintptr_t module_code_end   = module_code_start + nt_headers->OptionalHeader.SizeOfCode;

	// 3 because we're reading 2 chars at a time, plus a space.
	const size_t signature_length = strlen( signature );
	const size_t byte_count       = ( signature_length + 1 ) / 3;

	uint8_t* bytes = alloca( byte_count );

	if ( !bytes )
		return found_address;

	// Clear out memory out so we can use it as a hack inside of loop.
	memset( bytes, 0, byte_count );

	for ( size_t i = 0; i < signature_length; i += 3 ) {
		if ( signature[ i ] == '?' )
			continue;

		const char byte[ 3 ] = { signature[ i ], signature[ i + 1 ], '\0' };

		bytes[ i / 3 ] = ( uint8_t )strtoul( byte, 0, 16 );
	}

	for ( uintptr_t i = module_code_start; i < module_code_end; i++ ) {
		char found = 1;

		for ( size_t j = 0; j < byte_count; j++ ) {
			// If it's 0, it's a wildcard.
			if ( !bytes[ j ] )
				continue;

			if ( bytes[ j ] != *( uint8_t* )( i + j ) ) {
				found = 0;

				break;
			}
		}

		if ( found ) {
			found_address = i;

			break;
		}
	}

	return found_address;
}