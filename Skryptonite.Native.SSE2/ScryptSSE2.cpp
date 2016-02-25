#include "pch.h"
#include "ScryptSSE2.h"
#include "..\Skryptonite.Native\ScryptCommon.h"

using namespace Skryptonite;

void ScryptSSE2::PrepareData(ScryptElementPtr& workingBuffer, SalsaBlock* source)
{
	ScryptCommon::PrepareData<SalsaBlock128x4>(workingBuffer, source, PrepareBlock);
}

void ScryptSSE2::PrepareBlock(SalsaBlock128x4& arrangedBlock, SalsaBlock128x4& block)
{
	arrangedBlock.row0 = _mm_setr_epi32(block.row3.m128i_u32[0], block.row0.m128i_u32[1], block.row1.m128i_u32[2], block.row2.m128i_u32[3]);
	arrangedBlock.row1 = _mm_setr_epi32(block.row0.m128i_u32[0], block.row1.m128i_u32[1], block.row2.m128i_u32[2], block.row3.m128i_u32[3]);
	arrangedBlock.row2 = _mm_setr_epi32(block.row1.m128i_u32[0], block.row2.m128i_u32[1], block.row3.m128i_u32[2], block.row0.m128i_u32[3]);
	arrangedBlock.row3 = _mm_setr_epi32(block.row2.m128i_u32[0], block.row3.m128i_u32[1], block.row0.m128i_u32[2], block.row1.m128i_u32[3]);
}

void ScryptSSE2::RestoreData(SalsaBlock* destination, ScryptElementPtr& workingBuffer)
{
	ScryptCommon::RestoreData<SalsaBlock128x4>(destination, workingBuffer, RestoreBlock);
}

void ScryptSSE2::RestoreBlock(SalsaBlock128x4& block, SalsaBlock128x4& arrangedBlock)
{
	block.row0 = _mm_setr_epi32(arrangedBlock.row1.m128i_u32[0], arrangedBlock.row0.m128i_u32[1], arrangedBlock.row3.m128i_u32[2], arrangedBlock.row2.m128i_u32[3]);
	block.row1 = _mm_setr_epi32(arrangedBlock.row2.m128i_u32[0], arrangedBlock.row1.m128i_u32[1], arrangedBlock.row0.m128i_u32[2], arrangedBlock.row3.m128i_u32[3]);
	block.row2 = _mm_setr_epi32(arrangedBlock.row3.m128i_u32[0], arrangedBlock.row2.m128i_u32[1], arrangedBlock.row1.m128i_u32[2], arrangedBlock.row0.m128i_u32[3]);
	block.row3 = _mm_setr_epi32(arrangedBlock.row0.m128i_u32[0], arrangedBlock.row3.m128i_u32[1], arrangedBlock.row2.m128i_u32[2], arrangedBlock.row1.m128i_u32[3]);
}

void ScryptSSE2::CopyAndMixBlocks(SalsaBlock* copyDestination, ScryptElementPtr& workingBuffer, ScryptElementPtr& shuffleBuffer)
{
	ScryptCommon::MixBlocks<SalsaBlock128x4>(workingBuffer, copyDestination, shuffleBuffer, MixBlocksMode::Copy);
}

void ScryptSSE2::XorAndMixBlocks(ScryptElementPtr& workingBuffer, SalsaBlock* xorSource, ScryptElementPtr& shuffleBuffer)
{
	ScryptCommon::MixBlocks<SalsaBlock128x4>(workingBuffer, xorSource, shuffleBuffer, MixBlocksMode::Xor);
}