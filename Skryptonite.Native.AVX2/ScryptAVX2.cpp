#include "pch.h"
#include "ScryptAVX2.h"
#include "..\Skryptonite.Native\ScryptCommon.h"

#define _MM256_BLEND_ARG(i0, i1, i2, i3, i4, i5, i6, i7)	i0 | (i1 << 1) | (i2 << 2) | (i3 << 3) | (i4 << 4) | (i5 << 5) | (i6 << 6) | (i7 << 7)

using namespace Skryptonite;

const __m256i ElementPermuteArgs = _mm256_setr_epi32(4, 1, 6, 3, 0, 5, 2, 7);
const int ElementBlendArg = _MM256_BLEND_ARG(1, 0, 0, 1, 0, 0, 1, 1);

void ScryptAVX2::PrepareData(ScryptElementPtr& workingBuffer, SalsaBlock* source)
{
	ScryptCommon::PrepareData<SalsaBlock256x2>(workingBuffer, source, PrepareBlock);
}

void ScryptAVX2::PrepareBlock(SalsaBlock256x2& arrangedBlock, SalsaBlock256x2& block)
{
	block.rows01 = _mm256_permutevar8x32_epi32(block.rows01, ElementPermuteArgs);
	block.rows23 = _mm256_permutevar8x32_epi32(block.rows23, ElementPermuteArgs);

	arrangedBlock.rows01 = _mm256_blend_epi32(block.rows01, block.rows23, ElementBlendArg);
	arrangedBlock.rows23 = _mm256_blend_epi32(block.rows23, block.rows01, ElementBlendArg);
}

void ScryptAVX2::RestoreData(SalsaBlock* destination, ScryptElementPtr& workingBuffer)
{
	ScryptCommon::RestoreData<SalsaBlock256x2>(destination, workingBuffer, RestoreBlock);
}

void ScryptAVX2::RestoreBlock(SalsaBlock256x2& block, SalsaBlock256x2& arrangedBlock)
{
	block.rows01 = _mm256_blend_epi32(arrangedBlock.rows01, arrangedBlock.rows23, ElementBlendArg);
	block.rows23 = _mm256_blend_epi32(arrangedBlock.rows23, arrangedBlock.rows01, ElementBlendArg);
	
	block.rows01 = _mm256_permutevar8x32_epi32(block.rows01, ElementPermuteArgs);
	block.rows23 = _mm256_permutevar8x32_epi32(block.rows23, ElementPermuteArgs);
}

void ScryptAVX2::CopyAndMixBlocks(SalsaBlock* copyDestination, ScryptElementPtr& workingBuffer, ScryptElementPtr& shuffleBuffer)
{
	ScryptCommon::MixBlocks<SalsaBlock256x2>(workingBuffer, copyDestination, shuffleBuffer, MixBlocksMode::Copy);
}

void ScryptAVX2::XorAndMixBlocks(ScryptElementPtr& workingBuffer, SalsaBlock* xorSource, ScryptElementPtr& shuffleBuffer)
{
	ScryptCommon::MixBlocks<SalsaBlock256x2>(workingBuffer, xorSource, shuffleBuffer, MixBlocksMode::Xor);
}
