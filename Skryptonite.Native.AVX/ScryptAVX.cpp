#include "pch.h"
#include "ScryptAVX.h"
#include "..\Skryptonite.Native\ScryptCommon.h"

using namespace Skryptonite;

void ScryptAVX::PrepareData(ScryptElementPtr& workingBuffer, SalsaBlock* source)
{
	ScryptCommon::PrepareData<SalsaBlock256x2>(workingBuffer, source, PrepareBlock);
}

void ScryptAVX::PrepareBlock(SalsaBlock256x2& arrangedBlock, SalsaBlock256x2& block)
{
	arrangedBlock.rows01 = _mm256_setr_epi32(block.rows23.m256i_u32[4], block.rows01.m256i_u32[1], block.rows01.m256i_u32[6], block.rows23.m256i_u32[3],
											 block.rows01.m256i_u32[0], block.rows01.m256i_u32[5], block.rows23.m256i_u32[2], block.rows23.m256i_u32[7]);
	arrangedBlock.rows23 = _mm256_setr_epi32(block.rows01.m256i_u32[4], block.rows23.m256i_u32[1], block.rows23.m256i_u32[6], block.rows01.m256i_u32[3],
										     block.rows23.m256i_u32[0], block.rows23.m256i_u32[5], block.rows01.m256i_u32[2], block.rows01.m256i_u32[7]);
}

void ScryptAVX::RestoreData(SalsaBlock* destination, ScryptElementPtr& workingBuffer)
{
	ScryptCommon::RestoreData<SalsaBlock256x2>(destination, workingBuffer, RestoreBlock);
}

void ScryptAVX::RestoreBlock(SalsaBlock256x2& block, SalsaBlock256x2& arrangedBlock)
{
	block.rows01 = _mm256_setr_epi32(arrangedBlock.rows01.m256i_u32[4], arrangedBlock.rows01.m256i_u32[1], arrangedBlock.rows23.m256i_u32[6], arrangedBlock.rows23.m256i_u32[3],
									 arrangedBlock.rows23.m256i_u32[0], arrangedBlock.rows01.m256i_u32[5], arrangedBlock.rows01.m256i_u32[2], arrangedBlock.rows23.m256i_u32[7]);
	block.rows23 = _mm256_setr_epi32(arrangedBlock.rows23.m256i_u32[4], arrangedBlock.rows23.m256i_u32[1], arrangedBlock.rows01.m256i_u32[6], arrangedBlock.rows01.m256i_u32[3],
									 arrangedBlock.rows01.m256i_u32[0], arrangedBlock.rows23.m256i_u32[5], arrangedBlock.rows23.m256i_u32[2], arrangedBlock.rows01.m256i_u32[7]);}

void ScryptAVX::CopyAndMixBlocks(SalsaBlock* copyDestination, ScryptElementPtr& workingBuffer, ScryptElementPtr& shuffleBuffer)
{
	ScryptCommon::MixBlocks<SalsaBlock128x4>(workingBuffer, copyDestination, shuffleBuffer, MixBlocksMode::Copy);
}

void ScryptAVX::XorAndMixBlocks(ScryptElementPtr& workingBuffer, SalsaBlock* xorSource, ScryptElementPtr& shuffleBuffer)
{
	ScryptCommon::MixBlocks<SalsaBlock128x4>(workingBuffer, xorSource, shuffleBuffer, MixBlocksMode::Xor);
}
