/**
* Skryptonite - Scrypt library for UWP
* Copyright © 2016 Nicholas C. Bauer, Ph.D.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include "SalsaBlock.h"
#include <intrin.h>

#if defined(_M_IX86) || defined(_M_X64)
#define _MM_SHUFFLE_ARG(i0, i1, i2, i3)		_MM_SHUFFLE(i3, i2, i1, i0)
#endif

namespace Skryptonite
{
	namespace Native
	{
		/**
		<summary>Hashes a 64-byte block from 128-bit registers using the Salsa20 algorithm with the given number of iterations.</summary>
		<param name="block">The 64-byte block to hash.</param>
		<param name="iterations">The number of iterations.</param>
		<remarks>
		Salsa20 is described here: http://cr.yp.to/snuffle.html
		In brief, Salsa20/n performs n iterations of mixing on a 64-byte block viewed as a 4x4 matrix of 32-bit unsigned integers.
		One iteration operates on each column in parallel:
		1. Sum the elements above the diagonal with the elements along the diagonal.
		2. Left-rotate the result by 7 bits.
		3. Xor the result into the elements below the diagonal.
		4. Repeat 1-3 shifted one line down 3 times, using left-rotations of 9, 13, and 18. The final iteration concludes by changing the diagonal elements.
		5. Transpose the block.
		Element-wise add the mixing result to the input and return.
		</remarks>
		*/
		class Salsa20Core
		{
		public:
			/**
			<summary>Hashes a 64-byte block from 128-bit registers using the Salsa20 algorithm with the given number of iterations.</summary>
			<param name="block">The 64-byte block to hash. Contains the result.</param>
			<param name="iterations">The number of iterations.</param>
			<remarks>
			Requires that the block be organized so that the diagonal is stored as row 1, and the other elements be arranged accordingly.
			</remarks>
			*/
			static __forceinline void __vectorcall Hash(SalsaBlock128x4& block, unsigned iterations)
			{
				SalsaBlock128x4 inputBlock = block;

				SalsaIterations(block, iterations);
				AddBlock(block, inputBlock);
			}

#if defined(_M_IX86) || defined(_M_X64)
			/**
			<summary>Hashes a 64-byte block from 256-bit registers using the Salsa20 algorithm with the given number of iterations.</summary>
			<param name="block">The 64-byte block to hash. Contains the result.</param>
			<param name="iterations">The number of iterations.</param>
			<remarks>
			Requires that the block be organized so that the diagonal is stored as row 1, and the other elements be arranged accordingly.
			</remarks>
			*/
			static __forceinline void __vectorcall Hash(SalsaBlock256x2& block, unsigned iterations)
			{
				SalsaBlock256x2 inputBlock = block;
				SalsaBlock128x4 block128;

				Unpack256To128(block128, inputBlock);
				SalsaIterations(block128, iterations);
				Pack128To256(inputBlock, block128);
				AddBlock(block, inputBlock);
			}

			/**
			<summary>Converts a 64-byte block stored in 256-bit registers to 128-bit registers.</summary>
			<param name="unpackedBlock">The 128-bit unpacked block.</param>
			<param name="packedBlock">The 256-bit packed block.</param>
			*/
			static __forceinline void __vectorcall Unpack256To128(SalsaBlock128x4& unpackedBlock, SalsaBlock256x2 packedBlock)
			{
				unpackedBlock.row0 = _mm256_extracti128_si256(packedBlock.rows01, 0);
				unpackedBlock.row1 = _mm256_extracti128_si256(packedBlock.rows01, 1);
				unpackedBlock.row2 = _mm256_extracti128_si256(packedBlock.rows23, 0);
				unpackedBlock.row3 = _mm256_extracti128_si256(packedBlock.rows23, 1);
			}

			/**
			<summary>Converts a 64-byte block stored in 128-bit registers to 256-bit registers.</summary>
			<param name="packedBlock">The 256-bit packed block.</param>
			<param name="unpackedBlock">The 128-bit unpacked block.</param>
			*/
			static __forceinline void __vectorcall Pack128To256(SalsaBlock256x2& packedBlock, SalsaBlock128x4 unpackedBlock)
			{
				packedBlock.rows01 = _mm256_setr_m128i(unpackedBlock.row0, unpackedBlock.row1);
				packedBlock.rows23 = _mm256_setr_m128i(unpackedBlock.row2, unpackedBlock.row3);
			}
#endif

		private:
			/**
			<summary>Perform the requested number of Salsa20 iterations.</summary>
			<param name="block">The 64-byte block to hash. Contains the result.</param>
			<param name="iterations">The number of iterations.</param>
			*/
			static __forceinline void __vectorcall SalsaIterations(SalsaBlock128x4& block, unsigned iterations)
			{
				for (unsigned j = 0; j < iterations; j++)
				{
					block.row2 = SalsaOperation(block.row0, block.row1, block.row2, 7);
					block.row3 = SalsaOperation(block.row1, block.row2, block.row3, 9);
					block.row0 = SalsaOperation(block.row2, block.row3, block.row0, 13);
					block.row1 = SalsaOperation(block.row3, block.row0, block.row1, 18);

					Transpose(block);
				}
			}

#if defined(_M_IX86) || defined(_M_X64)
			/**
			<summary>Perform a single Salsa20 operation.</summary>
			<param name="addend1">The first addend.</param>
			<param name="addend2">The second addend.</param>
			<param name="xorOperand">The destination to be xored.</param>
			<param name="rotateMagnitude">The number of bits to rotate by.</param>
			<returns>The result of the operation.</returns>
			*/
			static __forceinline __m128i __vectorcall SalsaOperation(__m128i addend1, __m128i addend2, __m128i xorOperand, unsigned char rotateMagnitude)
			{
				__m128i sum = _mm_add_epi32(addend1, addend2);
				__m128i rot = _mm_or_si128(_mm_slli_epi32(sum, rotateMagnitude), _mm_srli_epi32(sum, sizeof(unsigned) * 8 - rotateMagnitude));
				return _mm_xor_si128(xorOperand, rot);
			}

			/**
			<summary>Transposes the block.</summary>
			<param name="block">The block to transpose.</param>
			*/
			static __forceinline void __vectorcall Transpose(SalsaBlock128x4& block)
			{
				__m128i toLine2 = _mm_shuffle_epi32(block.row0, _MM_SHUFFLE_ARG(1, 2, 3, 0));
				block.row0 = _mm_shuffle_epi32(block.row2, _MM_SHUFFLE_ARG(3, 0, 1, 2));
				block.row2 = toLine2;
				block.row3 = _mm_shuffle_epi32(block.row3, _MM_SHUFFLE_ARG(2, 3, 0, 1));
			}

			/**
			<summary>Adds one block into the other using 128-bit registers.</summary>
			<param name="destinationBlock">The block to add into.</param>
			<param name="sourceBlock">The block to add.</param>
			*/
			static __forceinline void __vectorcall AddBlock(SalsaBlock128x4& destinationBlock, SalsaBlock128x4 sourceBlock)
			{
				destinationBlock.row0 = _mm_add_epi32(destinationBlock.row0, sourceBlock.row0);
				destinationBlock.row1 = _mm_add_epi32(destinationBlock.row1, sourceBlock.row1);
				destinationBlock.row2 = _mm_add_epi32(destinationBlock.row2, sourceBlock.row2);
				destinationBlock.row3 = _mm_add_epi32(destinationBlock.row3, sourceBlock.row3);
			}

			/**
			<summary>Adds one block into the other using 256-bit registers.</summary>
			<param name="destinationBlock">The block to add into.</param>
			<param name="sourceBlock">The block to add.</param>
			*/
			static __forceinline void __vectorcall AddBlock(SalsaBlock256x2& destinationBlock, SalsaBlock256x2 sourceBlock)
			{
				destinationBlock.rows01 = _mm256_add_epi32(destinationBlock.rows01, sourceBlock.rows01);
				destinationBlock.rows23 = _mm256_add_epi32(destinationBlock.rows23, sourceBlock.rows23);
			}
#endif

#if defined(_M_ARM)
			/**
			<summary>Perform a single Salsa20 operation.</summary>
			<param name="addend1">The first addend.</param>
			<param name="addend2">The second addend.</param>
			<param name="xorOperand">The destination to be xored.</param>
			<param name="rotateMagnitude">The number of bits to rotate by.</param>
			<returns>The result of the operation.</returns>
			*/
			static __forceinline __n128 __vectorcall SalsaOperation(__n128 addend1, __n128 addend2, __n128 xorOperand, unsigned char rotateMagnitude)
			{
				__n128 leftShiftVector = vdupq_n_u32(rotateMagnitude);
				__n128 rightShiftVector = vdupq_n_u32(rotateMagnitude - sizeof(unsigned) * 8);

				__n128 sum = vaddq_u32(addend1, addend2);
				__n128 rot = vorrq_u32(vshlq_u32(sum, leftShiftVector), vshlq_u32(sum, rightShiftVector));
				return veorq_u32(xorOperand, rot);
			}

			/**
			<summary>Transposes the block.</summary>
			<param name="block">The block to transpose.</param>
			*/
			static __forceinline void __vectorcall Transpose(SalsaBlock128x4& block)
			{
				__n128 toLine2 = vextq_u32(block.row0, block.row0, 1);
				block.row0 = vextq_u32(block.row2, block.row2, 3);
				block.row2 = toLine2;
				block.row3 = vextq_u64(block.row3, block.row3, 1);
			}

			/**
			<summary>Adds one block into the other using 128-bit registers.</summary>
			<param name="destinationBlock">The block to add into.</param>
			<param name="sourceBlock">The block to add.</param>
			*/
			static __forceinline void __vectorcall AddBlock(SalsaBlock128x4& destinationBlock, SalsaBlock128x4 sourceBlock)
			{
				destinationBlock.row0 = vaddq_u32(destinationBlock.row0, sourceBlock.row0);
				destinationBlock.row1 = vaddq_u32(destinationBlock.row1, sourceBlock.row1);
				destinationBlock.row2 = vaddq_u32(destinationBlock.row2, sourceBlock.row2);
				destinationBlock.row3 = vaddq_u32(destinationBlock.row3, sourceBlock.row3);
			}
#endif
		};
	}
}