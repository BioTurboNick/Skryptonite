#include "pch.h"
#include "ScryptSSE41.h"
#include "..\Skryptonite.Native\ScryptCommon.h"

using namespace Skryptonite;

void ScryptSSE41::PrepareData(ScryptElementPtr& workingBuffer, SalsaBlock* source)
{
	ScryptCommon::PrepareData<SalsaBlock128x4>(workingBuffer, source, PrepareBlock);
}

void ScryptSSE41::PrepareBlock(SalsaBlock128x4& arrangedBlock, SalsaBlock128x4& block)
{
	arrangedBlock.row0 = _mm_setzero_si128();
	arrangedBlock.row1 = _mm_setzero_si128();
	arrangedBlock.row2 = _mm_setzero_si128();
	arrangedBlock.row3 = _mm_setzero_si128();

	arrangedBlock.row0 = _mm_insert_epi32(arrangedBlock.row0, _mm_extract_epi32(block.row3, 0), 0);
	arrangedBlock.row0 = _mm_insert_epi32(arrangedBlock.row0, _mm_extract_epi32(block.row0, 1), 1);
	arrangedBlock.row0 = _mm_insert_epi32(arrangedBlock.row0, _mm_extract_epi32(block.row1, 2), 2);
	arrangedBlock.row0 = _mm_insert_epi32(arrangedBlock.row0, _mm_extract_epi32(block.row2, 3), 3);
	arrangedBlock.row1 = _mm_insert_epi32(arrangedBlock.row1, _mm_extract_epi32(block.row0, 0), 0);
	arrangedBlock.row1 = _mm_insert_epi32(arrangedBlock.row1, _mm_extract_epi32(block.row1, 1), 1);
	arrangedBlock.row1 = _mm_insert_epi32(arrangedBlock.row1, _mm_extract_epi32(block.row2, 2), 2);
	arrangedBlock.row1 = _mm_insert_epi32(arrangedBlock.row1, _mm_extract_epi32(block.row3, 3), 3);
	arrangedBlock.row2 = _mm_insert_epi32(arrangedBlock.row2, _mm_extract_epi32(block.row1, 0), 0);
	arrangedBlock.row2 = _mm_insert_epi32(arrangedBlock.row2, _mm_extract_epi32(block.row2, 1), 1);
	arrangedBlock.row2 = _mm_insert_epi32(arrangedBlock.row2, _mm_extract_epi32(block.row3, 2), 2);
	arrangedBlock.row2 = _mm_insert_epi32(arrangedBlock.row2, _mm_extract_epi32(block.row0, 3), 3);
	arrangedBlock.row3 = _mm_insert_epi32(arrangedBlock.row3, _mm_extract_epi32(block.row2, 0), 0);
	arrangedBlock.row3 = _mm_insert_epi32(arrangedBlock.row3, _mm_extract_epi32(block.row3, 1), 1);
	arrangedBlock.row3 = _mm_insert_epi32(arrangedBlock.row3, _mm_extract_epi32(block.row0, 2), 2);
	arrangedBlock.row3 = _mm_insert_epi32(arrangedBlock.row3, _mm_extract_epi32(block.row1, 3), 3);
}

void ScryptSSE41::RestoreData(SalsaBlock* destination, ScryptElementPtr& workingBuffer)
{
	ScryptCommon::RestoreData<SalsaBlock128x4>(destination, workingBuffer, RestoreBlock);
}

void ScryptSSE41::RestoreBlock(SalsaBlock128x4& block, SalsaBlock128x4& arrangedBlock)
{
	block.row0 = _mm_setzero_si128();
	block.row1 = _mm_setzero_si128();
	block.row2 = _mm_setzero_si128();
	block.row3 = _mm_setzero_si128();

	block.row0 = _mm_insert_epi32(block.row0, _mm_extract_epi32(arrangedBlock.row1, 0), 0);
	block.row0 = _mm_insert_epi32(block.row0, _mm_extract_epi32(arrangedBlock.row0, 1), 1);
	block.row0 = _mm_insert_epi32(block.row0, _mm_extract_epi32(arrangedBlock.row3, 2), 2);
	block.row0 = _mm_insert_epi32(block.row0, _mm_extract_epi32(arrangedBlock.row2, 3), 3);
	block.row1 = _mm_insert_epi32(block.row1, _mm_extract_epi32(arrangedBlock.row2, 0), 0);
	block.row1 = _mm_insert_epi32(block.row1, _mm_extract_epi32(arrangedBlock.row1, 1), 1);
	block.row1 = _mm_insert_epi32(block.row1, _mm_extract_epi32(arrangedBlock.row0, 2), 2);
	block.row1 = _mm_insert_epi32(block.row1, _mm_extract_epi32(arrangedBlock.row3, 3), 3);
	block.row2 = _mm_insert_epi32(block.row2, _mm_extract_epi32(arrangedBlock.row3, 0), 0);
	block.row2 = _mm_insert_epi32(block.row2, _mm_extract_epi32(arrangedBlock.row2, 1), 1);
	block.row2 = _mm_insert_epi32(block.row2, _mm_extract_epi32(arrangedBlock.row1, 2), 2);
	block.row2 = _mm_insert_epi32(block.row2, _mm_extract_epi32(arrangedBlock.row0, 3), 3);
	block.row3 = _mm_insert_epi32(block.row3, _mm_extract_epi32(arrangedBlock.row0, 0), 0);
	block.row3 = _mm_insert_epi32(block.row3, _mm_extract_epi32(arrangedBlock.row3, 1), 1);
	block.row3 = _mm_insert_epi32(block.row3, _mm_extract_epi32(arrangedBlock.row2, 2), 2);
	block.row3 = _mm_insert_epi32(block.row3, _mm_extract_epi32(arrangedBlock.row1, 3), 3);
}

void ScryptSSE41::CopyAndMixBlocks(SalsaBlock* copyDestination, ScryptElementPtr& workingBuffer, ScryptElementPtr& shuffleBuffer)
{
	ScryptCommon::MixBlocks<SalsaBlock128x4>(workingBuffer, copyDestination, shuffleBuffer, MixBlocksMode::Copy);
}

void ScryptSSE41::XorAndMixBlocks(ScryptElementPtr& workingBuffer, SalsaBlock* xorSource, ScryptElementPtr& shuffleBuffer)
{
	ScryptCommon::MixBlocks<SalsaBlock128x4>(workingBuffer, xorSource, shuffleBuffer, MixBlocksMode::Xor);
}

