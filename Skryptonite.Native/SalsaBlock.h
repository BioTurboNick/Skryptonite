#pragma once
#include <intrin.h>

namespace Skryptonite
{
	namespace Native
	{
#if defined(_M_IX86) || defined(_M_X64)
		/**
		<summary>A 64-byte Salsa20 block stored in 256-bit registers.</summary>
		*/
		typedef struct
		{
			__m256i rows01;
			__m256i rows23;
		} SalsaBlock256x2;

		/**
		<summary>A 64-byte Salsa20 block stored in 128-bit registers.</summary>
		*/
		typedef struct
		{
			__m128i row0;
			__m128i row1;
			__m128i row2;
			__m128i row3;
		} SalsaBlock128x4;
#endif

#if defined(_M_ARM)
		/**
		<summary>A 64-byte Salsa20 block stored in 128-bit registers.</summary>
		*/
		typedef struct
		{
			__n128 row0;
			__n128 row1;
			__n128 row2;
			__n128 row3;
		} SalsaBlock128x4;
#endif

		/**
		<summary>A 64-byte Salsa20 block stored in memory.</summary>
		*/
		typedef union
		{
			unsigned integers[16];
			unsigned char bytes[64];
		} SalsaBlock;
	}
}
