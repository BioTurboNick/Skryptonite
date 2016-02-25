#include "pch.h"
#include "DetectInstructionSet.h"

using namespace Skryptonite;

// for future: determine cache line size in case it changes from 64 bytes

InstructionSet DetectInstructionSet::_maxLevel = InstructionSet::Unknown;

#if defined(_M_IX86) || defined(_M_X64)
union Registers
{
	int registers[4];
	struct
	{
		unsigned eax;
		unsigned ebx;
		unsigned ecx;
		unsigned edx;
	};
};

void DetectInstructionSet::Detect()
{
	Registers reg;

	__cpuid(reg.registers, 1);

	// in ECX
	unsigned ssse3_mask = (1 << 9);
	unsigned sse41_mask = (1 << 19);
	unsigned avx_mask = (1 << 26) | (1 << 27) | (1 << 28);
	
	bool is_ssse3_supported = (reg.ecx & ssse3_mask) == ssse3_mask;
	if (!is_ssse3_supported)
	{
		_maxLevel = InstructionSet::SSE2;
		return;
	}

	bool is_sse41_supported = (reg.ecx & sse41_mask) == sse41_mask;
	if (!is_sse41_supported)
	{
		_maxLevel = InstructionSet::SSSE3;
		return;
	}

	bool is_avx_supported = (reg.ecx & avx_mask) == avx_mask;
	if (!is_avx_supported)
	{
		_maxLevel = InstructionSet::SSE41;
		return;
	}


	// check the control register
	// this determines if xmm and ymm states are enabled. Not sure what this does exactly, but Intel says to do it.
	unsigned long long xcr0 = _xgetbv(0);
	if ((xcr0 & 6) != 6)
	{
		_maxLevel = InstructionSet::AVX;
		return;
	}


	__cpuidex(reg.registers, 7, 0);

	// in EBX
	unsigned avx2_mask = (1 << 5); // Required for enabling AVX2 generally, 256-bit intrinsics

	bool is_avx2_supported = (reg.ebx & avx2_mask) == avx2_mask;
	if (!is_avx2_supported)
	{
		_maxLevel = InstructionSet::AVX;
		return;
	}
	
	_maxLevel = InstructionSet::AVX2;
}
#endif

#if defined(_M_ARM)
void DetectInstructionSet::Detect()
{
	_maxLevel = InstructionSet::NEON;
}
#endif