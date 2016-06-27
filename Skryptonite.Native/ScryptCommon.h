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
#include "ScryptElement.h"
#include "Salsa20Core.h"
#include <crtdbg.h>

namespace Skryptonite
{
	namespace Native
	{
		/**
		<summary>Modes which can be used for MixBlocks.</summary>
		*/
		enum MixBlocksMode
		{
			None,
			Copy,
			Xor
		};

		/**
		<summary>Provides common methods for Scrypt. Allows for custom compilation for various instruction set architectures (e.g. AVX2, AVX) using a common code base.</summary>
		*/
		class ScryptCommon
		{
		public:
			/**
			<summary>Rearranges the input data in an optimal format for SMix.</summary>
			<typeparam name="TSalsaBlock">The type into which the 64-byte blocks will be loaded and managed.</typeparam>
			<param name="workingBuffer">A pointer to the SMix working buffer into which the data will be loaded. Must be aligned to at least the cache line size (e.g. 64 bytes).</param>
			<param name="source">A pointer to the buffer from which the data will be loaded.</param>
			<param name="blockCount">The length of the buffers in 64-byte blocks.</param>
			<param name="prepareBlock">A pointer to a function which rearranges the data of a 64-byte block into a format amenable to the Salsa20 hash function.</param>
			<remarks>
			Moves the critical last 64-byte block to the front.
			<paramref name="prepareBlock"/> shifts the data so that the diagonals become rows:
			0	1	2	3			12	1	6	11
			4	5	6	7	----->	0	5	10	15
			8	9	10	11	----->	4	9	14	3
			12	13	14	15			8	13	2	7
			</remarks>
			*/
			template<class TSalsaBlock>
			static __forceinline void __vectorcall PrepareData(ScryptElementPtr& workingBuffer, SalsaBlock* source, void(*prepareBlock)(TSalsaBlock& arrangedBlock, TSalsaBlock& block))
			{
				_ASSERT(workingBuffer != nullptr && workingBuffer->Data() != nullptr);
				_ASSERT(workingBuffer->BlockCount() > 0);
				_ASSERT(source != nullptr);
				_ASSERT(prepareBlock != nullptr);

				SalsaBlock* destination = workingBuffer->Data() + 1;

				for (unsigned i = 0; i < workingBuffer->BlockCount() - 1; i++, source++, destination++)
					LoadAndPrepareBlock<TSalsaBlock>(destination, source, prepareBlock);

				LoadAndPrepareBlock<TSalsaBlock>(workingBuffer->Data(), source, prepareBlock);
			}

			/**
			<summary>Restores the SMix-optimized data to its original ordering.</summary>
			<typeparam name="TSalsaBlock">The type into which the 64-byte blocks were loaded and managed.</typeparam>
			<param name="destination">A pointer to the buffer to which the data will be returned.</param>
			<param name="workingBuffer">A pointer to the SMix working buffer from which the data will be returned. Must be aligned to at least the cache line size (e.g. 64 bytes).</param>
			<param name="blockCount">The length of the buffers in 64-byte blocks.</param>
			<param name="prepareBlock">A pointer to a function which rearranges the data of a 64-byte block from a format amenable to the Salsa20 hash function into its original ordering.</param>
			<remarks>
			Restores the critical last 64-byte block from the front.
			<paramref name="restoreBlock"/> shifts the data so that the rows become diagonals:
			12	1	6	11			0	1	2	3
			0	5	10	15	----->	4	5	6	7
			4	9	14	3	----->	8	9	10	11
			8	13	2	7			12	13	14	15
			</remarks>
			*/
			template<class TSalsaBlock>
			static __forceinline void __vectorcall RestoreData(SalsaBlock* destination, ScryptElementPtr& workingBuffer, void(*restoreBlock)(TSalsaBlock& block, TSalsaBlock& arrangedBlock))
			{
				_ASSERT(destination != nullptr);
				_ASSERT(workingBuffer != nullptr && workingBuffer->Data() != nullptr);
				_ASSERT(workingBuffer->BlockCount() > 0);
				_ASSERT(restoreBlock != nullptr);

				TSalsaBlock arrangedLastBlock, lastBlock;

				SalsaBlock* currentBlockPosition = workingBuffer->Data();

				LoadFromAligned(arrangedLastBlock, currentBlockPosition++);

				for (unsigned i = 0; i < workingBuffer->BlockCount() - 1; i++, currentBlockPosition++, destination++)
					LoadAndRestoreBlock<TSalsaBlock>(destination, currentBlockPosition, restoreBlock);

				restoreBlock(lastBlock, arrangedLastBlock);
				StoreToUnaligned(destination, lastBlock);
			}

			/**
			<summary>The Scrypt BlockMix function. Mixes a buffer of an even number of 64-byte blocks.</summary>
			<typeparam name="TSalsaBlock">The type into which the 64-byte blocks are loaded and managed.</typeparam>
			<param name="workingBuffer">A pointer to the SMix working buffer containing the optimally-arranged data. Must be aligned to at least the cache line size (e.g. 64 bytes).</param>
			<param name="otherBuffer">A pointer to a buffer which is used according to <paramref name="mode"/>. Must be aligned to at least the cache line size (e.g. 64 bytes).</param>
			<param name="shuffleBuffer">A pointer to the buffer into which the results will be stored. Must be aligned to at least the cache line size (e.g. 64 bytes).</param>
			<param name="blockCount">The length of the buffers in 64-byte blocks.</param>
			<param name="mode">Controls how <paramref name="otherBuffer"/> is treated.
			<see cref="MixBlocksMode::None"/> only does the standard block mixing.
			<see cref="MixBlocksMode::Copy"/> copies the input data into <paramref name="otherBuffer"/>.
			<see cref="MixBlocksMode::Xor"/> xors <paramref name="otherBuffer"/> with <paramref name="workingBuffer"/> before mixing each 64-byte block.</param>
			<remarks>
			Results are temporarily stored in <paramref name="shuffleBuffer"/>, but it is swapped with <paramref name="workingBuffer"/> at the end. As a result, <paramref name="workingBuffer"/> will always
			contain the output, and <paramref name="shuffleBuffer"/> will always contain the previous input. This mode reduces data copying over the alternative.
			Relies on the input data being arranged such that the nominal last 64-byte block is placed first in the buffers.
			When possible, <see cref="MixBlocksMode::Copy"/> uses streaming store instructions to send the data directly into main memory. This avoids polluting or thrashing the cache during large block generation, since
			the block is unlikely to fit into any cache. This also helps defeat cache-timing attacks.
			When possible, <see cref="MixBlocksMode::Xor"/> uses non-temporal prefetching of the first half of the <paramref name="blockCount"/> 64-byte blocks of <paramref name="otherBuffer"/> before doing anything
			and then prefetches one additional 64-byte block at the start of each mixing round up to <paramref name="blockCount"/>. WHen possible, after using a block from <paramref name="otherBuffer"/>, it is
			flushed from the cache to avoid polluting or thrashing the cache, since the likelihood is high that any given block will not be used again. This also helps defeat cache-timing attacks.
			</remarks>
			*/
			template<class TSalsaBlock>
			static __forceinline void __vectorcall MixBlocks(ScryptElementPtr& workingBuffer, SalsaBlock* otherBuffer, ScryptElementPtr& shuffleBuffer, MixBlocksMode mode)
			{
				_ASSERT(workingBuffer != nullptr && workingBuffer->Data() != nullptr);
				_ASSERT(workingBuffer->BlockCount() > 0);
				_ASSERT(shuffleBuffer != nullptr && shuffleBuffer->Data() != nullptr);
				_ASSERT(shuffleBuffer->BlockCount() > 0);
				_ASSERT(workingBuffer->BlockCount() == shuffleBuffer->BlockCount());
				_ASSERT(mode == MixBlocksMode::None || otherBuffer != nullptr);

				SalsaBlock* currentBlockPosition = workingBuffer->Data();
				SalsaBlock* otherCurrentBlockPosition = otherBuffer;
				SalsaBlock* otherFutureBlockPosition = otherBuffer;

				unsigned halfSalsaBlockCount = workingBuffer->BlockCount() / 2;

				if (mode == MixBlocksMode::Xor)
					for (unsigned i = 0; i < halfSalsaBlockCount; i++, otherFutureBlockPosition++)
						ScryptCommon::PrefetchNonTemporal(otherFutureBlockPosition);

				TSalsaBlock lastBlock;
				LoadFromAligned(lastBlock, currentBlockPosition++);

				switch (mode)
				{
				case MixBlocksMode::Copy:
					StreamToAligned(otherCurrentBlockPosition++, lastBlock);
					break;
				case MixBlocksMode::Xor:
					LoadXorFlush<TSalsaBlock>(lastBlock, otherCurrentBlockPosition++);
					break;
				}

				TSalsaBlock previousBlock = lastBlock;

				for (unsigned i = 0; i < workingBuffer->BlockCount() - 1; i++, currentBlockPosition++, otherCurrentBlockPosition++)
				{
					TSalsaBlock currentBlock;
					LoadFromAligned(currentBlock, currentBlockPosition);

					switch (mode)
					{
					case MixBlocksMode::Copy:
						StreamToAligned(otherCurrentBlockPosition, currentBlock);
						break;
					case MixBlocksMode::Xor:
						if (i < halfSalsaBlockCount)
							ScryptCommon::PrefetchNonTemporal(otherFutureBlockPosition++);
						LoadXorFlush<TSalsaBlock>(currentBlock, otherCurrentBlockPosition);
						break;
					}

					// sort evens to the left half and odds to the right half
					SalsaBlock* destination = shuffleBuffer->Data() + i / 2 + 1;
					destination += (i % 2 == 0) ? 0 : halfSalsaBlockCount;

					MixBlock(destination, currentBlock, previousBlock);

					previousBlock = currentBlock;
				}

				MixBlock(shuffleBuffer->Data(), lastBlock, previousBlock);

				workingBuffer.swap(shuffleBuffer);
			}

#if defined(_M_IX86) || defined(_M_X64)
			/**
			<summary>Prefetches data from main memory non-temporally.</summary>
			<param name="blockPosition">The memory location to prefetch.</param>
			<remarks>
			The non-temporal hint causes the data to be loaded into the least-recently-used cache line so that it will be evicted quickly
			and not overwrite other needed data, reducing cache pollution.
			</remarks>
			*/
			static __forceinline void __vectorcall PrefetchNonTemporal(SalsaBlock* blockPosition)
			{
				_mm_prefetch(reinterpret_cast<char*>(blockPosition), _MM_HINT_NTA);
			}

			/**
			<summary>Flushes data from the cache.</summary>
			<param name="blockPosition">The memory location to flush.</param>
			<remarks>
			Protects against cache-timing attacks.
			</remarks>
			*/
			static __forceinline void __vectorcall Flush(SalsaBlock* blockPosition)
			{
				_mm_clflush(blockPosition); // look into detecting and using CLFLUSHOPT eventually; Sky Lake and later
			}

#pragma region 256_Vector_Manipulation
			/**
			<summary>Loads a 64-byte block from memory using 256-bit registers.</summary>
			<param name="block">The block to load into.</param>
			<param name="source">The memory location of the block to load. Must be aligned to the maximum instruction set requirements.</param>
			*/
			static __forceinline void __vectorcall LoadFromAligned(SalsaBlock256x2& block, SalsaBlock* source)
			{
				__m256i* source256 = reinterpret_cast<__m256i*>(source);

				block.rows01 = _mm256_load_si256(source256);
				block.rows23 = _mm256_load_si256(source256 + 1);
			}

			/**
			<summary>Loads a 64-byte block from memory using 256-bit registers.</summary>
			<param name="block">The block to load into.</param>
			<param name="source">The memory location of the block to load.</param>
			*/
			static __forceinline void __vectorcall LoadFromUnaligned(SalsaBlock256x2& block, SalsaBlock* source)
			{
				__m256i* source256 = reinterpret_cast<__m256i*>(source);

				block.rows01 = _mm256_loadu_si256(source256);
				block.rows23 = _mm256_loadu_si256(source256 + 1);
			}

			/**
			<summary>Saves a 64-byte block to memory using 256-bit registers.</summary>
			<param name="destination">The memory location of the block to store to. Must be aligned to the maximum instruction set requirements.</param>
			<param name="block">The block to store.</param>
			*/
			static __forceinline void __vectorcall StoreToAligned(SalsaBlock* destination, SalsaBlock256x2 block)
			{
				__m256i* destination256 = reinterpret_cast<__m256i*>(destination);

				_mm256_store_si256(destination256, block.rows01);
				_mm256_store_si256(destination256 + 1, block.rows23);
			}

			/**
			<summary>Saves a 64-byte block to memory using 256-bit registers.</summary>
			<param name="destination">The memory location of the block to store to.</param>
			<param name="block">The block to store.</param>
			*/
			static __forceinline void __vectorcall StoreToUnaligned(SalsaBlock* destination, SalsaBlock256x2 block)
			{
				__m256i* destination256 = reinterpret_cast<__m256i*>(destination);

				_mm256_storeu_si256(destination256, block.rows01);
				_mm256_storeu_si256(destination256 + 1, block.rows23);
			}

			/**
			<summary>Streams a 64-byte block to memory using 256-bit registers.</summary>
			<param name="destination">The memory location of the block to store to. Must be aligned to the maximum instruction set requirements.</param>
			<param name="block">The block to store.</param>
			<remarks>
			Streaming store instructions bypass the cache, avoiding cache pollution and providing a shortcut to main memory.
			</remarks>
			*/
			static __forceinline void __vectorcall StreamToAligned(SalsaBlock* destination, SalsaBlock256x2 block)
			{
				__m256i* destination256 = reinterpret_cast<__m256i*>(destination);

				_mm256_stream_si256(destination256, block.rows01);
				_mm256_stream_si256(destination256 + 1, block.rows23);
			}

			/**
			<summary>Xors one 64-byte block into another using 256-bit registers.</summary>
			<param name="destinationBlock">The block to xor into.</param>
			<param name="sourceBlock">The block to xor.</param>
			*/
			static __forceinline void __vectorcall XorBlock(SalsaBlock256x2& destinationBlock, SalsaBlock256x2 sourceBlock)
			{
				destinationBlock.rows01 = _mm256_xor_si256(destinationBlock.rows01, sourceBlock.rows01);
				destinationBlock.rows23 = _mm256_xor_si256(destinationBlock.rows23, sourceBlock.rows23);
			}
#pragma endregion

#pragma region 128_Vector_Manipulation
			/**
			<summary>Loads a 64-byte block from memory using 128-bit registers.</summary>
			<param name="block">The block to load into.</param>
			<param name="source">The memory location of the block to load. Must be aligned to the maximum instruction set requirements.</param>
			*/
			static __forceinline void __vectorcall LoadFromAligned(SalsaBlock128x4& block, SalsaBlock* source)
			{
				__m128i* source128 = reinterpret_cast<__m128i*>(source);

				block.row0 = _mm_load_si128(source128);
				block.row1 = _mm_load_si128(source128 + 1);
				block.row2 = _mm_load_si128(source128 + 2);
				block.row3 = _mm_load_si128(source128 + 3);
			}

			/**
			<summary>Loads a 64-byte block from memory using 128-bit registers.</summary>
			<param name="block">The block to load into.</param>
			<param name="source">The memory location of the block to load.</param>
			*/
			static __forceinline void __vectorcall LoadFromUnaligned(SalsaBlock128x4& block, SalsaBlock* source)
			{
				__m128i* source128 = reinterpret_cast<__m128i*>(source);

				block.row0 = _mm_loadu_si128(source128);
				block.row1 = _mm_loadu_si128(source128 + 1);
				block.row2 = _mm_loadu_si128(source128 + 2);
				block.row3 = _mm_loadu_si128(source128 + 3);
			}

			/**
			<summary>Saves a 64-byte block to memory using 128-bit registers.</summary>
			<param name="destination">The memory location of the block to store to. Must be aligned to the maximum instruction set requirements.</param>
			<param name="block">The block to store.</param>
			*/
			static __forceinline void __vectorcall StoreToAligned(SalsaBlock* destination, SalsaBlock128x4 block)
			{
				__m128i* destination128 = reinterpret_cast<__m128i*>(destination);

				_mm_store_si128(destination128, block.row0);
				_mm_store_si128(destination128 + 1, block.row1);
				_mm_store_si128(destination128 + 2, block.row2);
				_mm_store_si128(destination128 + 3, block.row3);
			}

			/**
			<summary>Saves a 64-byte block to memory using 128-bit registers.</summary>
			<param name="destination">The memory location of the block to store to.</param>
			<param name="block">The block to store.</param>
			*/
			static __forceinline void __vectorcall StoreToUnaligned(SalsaBlock* destination, SalsaBlock128x4 block)
			{
				__m128i* destination128 = reinterpret_cast<__m128i*>(destination);

				_mm_storeu_si128(destination128, block.row0);
				_mm_storeu_si128(destination128 + 1, block.row1);
				_mm_storeu_si128(destination128 + 2, block.row2);
				_mm_storeu_si128(destination128 + 3, block.row3);
			}

			/**
			<summary>Streams a 64-byte block to memory using 128-bit registers.</summary>
			<param name="destination">The memory location of the block to store to. Must be aligned to the maximum instruction set requirements.</param>
			<param name="block">The block to store.</param>
			<remarks>
			Streaming store instructions bypass the cache, avoiding cache pollution and providing a shortcut to main memory.
			</remarks>
			*/
			static __forceinline void __vectorcall StreamToAligned(SalsaBlock* destination, SalsaBlock128x4 block)
			{
				__m128i* destination128 = reinterpret_cast<__m128i*>(destination);

				_mm_stream_si128(destination128, block.row0);
				_mm_stream_si128(destination128 + 1, block.row1);
				_mm_stream_si128(destination128 + 2, block.row2);
				_mm_stream_si128(destination128 + 3, block.row3);
			}

			/**
			<summary>Xors one 64-byte block into another using 128-bit registers.</summary>
			<param name="destinationBlock">The block to xor into.</param>
			<param name="sourceBlock">The block to xor.</param>
			*/
			static __forceinline void __vectorcall XorBlock(SalsaBlock128x4& destinationBlock, SalsaBlock128x4 sourceBlock)
			{
				destinationBlock.row0 = _mm_xor_si128(destinationBlock.row0, sourceBlock.row0);
				destinationBlock.row1 = _mm_xor_si128(destinationBlock.row1, sourceBlock.row1);
				destinationBlock.row2 = _mm_xor_si128(destinationBlock.row2, sourceBlock.row2);
				destinationBlock.row3 = _mm_xor_si128(destinationBlock.row3, sourceBlock.row3);
			}
#pragma endregion
#endif

#if defined(_M_ARM)
			/**
			<summary>Prefetches data from main memory.</summary>
			<remarks>
			ARM architectures do not guarantee that prefetch instructions do anything, and there is no
			ability to mark loads as nontemporal.
			</remarks>
			*/
			static __forceinline void __vectorcall PrefetchNonTemporal(SalsaBlock* blockPosition)
			{
				__prefetch(blockPosition);
			}

			/**
			<summary>Flushes data from the cache.</summary>
			<param name="blockPosition">The memory location to flush.</param>
			<remarks>
			No ARM intrinsics are available to evict cahce lines, so this doesn't do anything. Thus, Scrypt on ARM may be vulnerable
			to cache-timing attacks.
			</remarks>
			*/
			static __forceinline void __vectorcall Flush(SalsaBlock* blockPosition)
			{
			}

			/**
			<summary>Loads a 64-byte block from memory using 128-bit registers.</summary>
			<param name="block">The block to load into.</param>
			<param name="source">The memory location of the block to load. Must be aligned to the maximum instruction set requirements.</param>
			*/
			static __forceinline void __vectorcall LoadFromAligned(SalsaBlock128x4& block, SalsaBlock* source)
			{
				block.row0 = vld1q_u32(source->integers);
				block.row1 = vld1q_u32(source->integers + 4);
				block.row2 = vld1q_u32(source->integers + 8);
				block.row3 = vld1q_u32(source->integers + 12);
			}

			/**
			<summary>Loads a 64-byte block from memory using 128-bit registers.</summary>
			<param name="block">The block to load into.</param>
			<param name="source">The memory location of the block to load.</param>
			*/
			static __forceinline void __vectorcall LoadFromUnaligned(SalsaBlock128x4& block, SalsaBlock* source)
			{
				block.row0 = vld1q_u32(source->integers);
				block.row1 = vld1q_u32(source->integers + 4);
				block.row2 = vld1q_u32(source->integers + 8);
				block.row3 = vld1q_u32(source->integers + 12);
			}

			/**
			<summary>Saves a 64-byte block to memory using 128-bit registers.</summary>
			<param name="destination">The memory location of the block to store to. Must be aligned to the maximum instruction set requirements.</param>
			<param name="block">The block to store.</param>
			*/
			static __forceinline void __vectorcall StoreToAligned(SalsaBlock* destination, SalsaBlock128x4 block)
			{
				vst1q_u32(destination->integers, block.row0);
				vst1q_u32(destination->integers + 4, block.row1);
				vst1q_u32(destination->integers + 8, block.row2);
				vst1q_u32(destination->integers + 12, block.row3);
			}

			/**
			<summary>Saves a 64-byte block to memory using 128-bit registers.</summary>
			<param name="destination">The memory location of the block to store to.</param>
			<param name="block">The block to store.</param>
			*/
			static __forceinline void __vectorcall StoreToUnaligned(SalsaBlock* destination, SalsaBlock128x4 block)
			{
				vst1q_u32(destination->integers, block.row0);
				vst1q_u32(destination->integers + 4, block.row1);
				vst1q_u32(destination->integers + 8, block.row2);
				vst1q_u32(destination->integers + 12, block.row3);
			}

			/**
			<summary>Streams a 64-byte block to memory using 128-bit registers.</summary>
			<param name="destination">The memory location of the block to store to. Must be aligned to the maximum instruction set requirements.</param>
			<param name="block">The block to store.</param>
			<remarks>
			Streaming store instructions bypass the cache, avoiding cache pollution and providing a shortcut to main memory.
			</remarks>
			*/
			static __forceinline void __vectorcall StreamToAligned(SalsaBlock* destination, SalsaBlock128x4 block)
			{
				// ARM doesn't have a stream instruction to bypass the cache, as far as I know. Unsure how to force a cache flush.
				StoreToAligned(destination, block);
			}

			/**
			<summary>Xors one 64-byte block into another using 128-bit registers.</summary>
			<param name="destinationBlock">The block to xor into.</param>
			<param name="sourceBlock">The block to xor.</param>
			*/
			static __forceinline void __vectorcall XorBlock(SalsaBlock128x4& destinationBlock, SalsaBlock128x4 sourceBlock)
			{
				destinationBlock.row0 = veorq_u32(destinationBlock.row0, sourceBlock.row0);
				destinationBlock.row1 = veorq_u32(destinationBlock.row1, sourceBlock.row1);
				destinationBlock.row2 = veorq_u32(destinationBlock.row2, sourceBlock.row2);
				destinationBlock.row3 = veorq_u32(destinationBlock.row3, sourceBlock.row3);
			}
#endif

		private:
			/**
			<summary>Loads a 64-byte block from one location, arranges it optimally for Salsa20, and stores it in another location.</summary>
			<typeparam name="TSalsaBlock">The type into which the 64-byte blocks are loaded and managed.</typeparam>
			<param name="alignedDestination">The address where the arranged 64-byte block will be stored. Must be aligned to the maximum instruction set requirements.</param>
			<param name="source">The address of the 64-byte block to be loaded.</param>
			<param name="prepareBlock">A pointer to a function which rearranges the data of a 64-byte block into a format amenable to the Salsa20 hash function.</param>
			<remarks>
			<paramref name="prepareBlock"/> shifts the data so that the diagonals become rows:
			0	1	2	3			12	1	6	11
			4	5	6	7	----->	0	5	10	15
			8	9	10	11	----->	4	9	14	3
			12	13	14	15			8	13	2	7
			</remarks>
			*/
			template<class TSalsaBlock>
			static __forceinline void __vectorcall LoadAndPrepareBlock(SalsaBlock* alignedDestination, SalsaBlock* source, void(*prepareBlock)(TSalsaBlock& arrangedBlock, TSalsaBlock& block))
			{
				_ASSERT(alignedDestination != nullptr);
				_ASSERT(source != nullptr);
				_ASSERT(prepareBlock != nullptr);

				TSalsaBlock block, arrangedBlock;

				LoadFromUnaligned(block, source);
				prepareBlock(arrangedBlock, block);
				StoreToAligned(alignedDestination, arrangedBlock);
			}

			/**
			<summary>Loads an optimally-arranged 64-byte block from one location, restores it to its original ordering, and stores it in another location.</summary>
			<typeparam name="TSalsaBlock">The type into which the 64-byte blocks are loaded and managed.</typeparam>
			<param name="destination">The address of the 64-byte block to be loaded.</param>
			<param name="alignedSource">The address where the arranged 64-byte block is stored.  Must be aligned to the maximum instruction set requirements.</param>
			<param name="prepareBlock">A pointer to a function which rearranges the data of a 64-byte block from a format amenable to the Salsa20 hash function into its original ordering.</param>
			<remarks>
			<paramref name="restoreBlock"/> shifts the data so that the rows become diagonals:
			12	1	6	11			0	1	2	3
			0	5	10	15	----->	4	5	6	7
			4	9	14	3	----->	8	9	10	11
			8	13	2	7			12	13	14	15
			</remarks>
			*/
			template<class TSalsaBlock>
			static __forceinline void __vectorcall LoadAndRestoreBlock(SalsaBlock* destination, SalsaBlock* alignedSource, void(*restoreBlock)(TSalsaBlock& block, TSalsaBlock& arrangedBlock))
			{
				_ASSERT(destination != nullptr);
				_ASSERT(alignedSource != nullptr);
				_ASSERT(restoreBlock != nullptr);

				TSalsaBlock arrangedBlock, block;

				LoadFromAligned(arrangedBlock, alignedSource);
				restoreBlock(block, arrangedBlock);
				StoreToUnaligned(destination, block);
			}

			/**
			<summary>Loads a 64-byte block from <paramref name="xorBlockPosition"/>, xors it into <paramref name="block"\>, then flushes <paramref name="xorBlockPosition"/> from the cache.</summary>
			<typeparam name="TSalsaBlock">The type into which the 64-byte blocks are loaded and managed.</typeparam>
			<param name="block">The 64-byte block xor operand which will contain the result.</param>
			<param name="xorBlockPosition">A pointer to the location of the block to load, xor, and flush.</param>
			*/
			template<class TSalsaBlock>
			static __forceinline void __vectorcall LoadXorFlush(TSalsaBlock& block, SalsaBlock* xorBlockPosition)
			{
				_ASSERT(xorBlockPosition != nullptr);

				TSalsaBlock xorBlock;

				LoadFromAligned(xorBlock, xorBlockPosition);
				XorBlock(block, xorBlock);
				Flush(xorBlockPosition);
			}

			/**
			<summary>Xors <paramref name="previousBlock"/> into <paramref name="currentBlock"/>, performs Salsa20/8 on the xor result, and stores the final result in <paramref name="destination"/>.</summary>
			<typeparam name="TSalsaBlock">The type into which the 64-byte blocks are loaded and managed.</typeparam>
			<param name="destination">The location into which the result should be stored.</param>
			<param name="currentBlock">The current 64-byte block. The final result is also stored here.</param>
			<param name="previousdBlock">The previous 64-byte block.</param>
			*/
			template<class TSalsaBlock>
			static __forceinline void __vectorcall MixBlock(SalsaBlock* destination, TSalsaBlock& currentBlock, TSalsaBlock previousBlock)
			{
				_ASSERT(destination != nullptr);

				XorBlock(currentBlock, previousBlock);
				Salsa20Core::Hash(currentBlock, 8);
				StoreToAligned(destination, currentBlock);
			}
		};
	}
}