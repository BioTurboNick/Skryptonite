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
#include "pch.h"
#include "ScryptNEON.h"
#include "..\Skryptonite.Native\ScryptCommon.h"

using namespace Skryptonite::Native;

void ScryptNEON::PrepareData(ScryptElementPtr& workingBuffer, SalsaBlock* source)
{
	ScryptCommon::PrepareData<SalsaBlock128x4>(workingBuffer, source, PrepareBlock);
}

void ScryptNEON::PrepareBlock(SalsaBlock128x4& arrangedBlock, SalsaBlock128x4& block)
{
	// needs to be checked, no idea if there's a better way
	
	arrangedBlock.row0.n128_u32[0] = block.row3.n128_u32[0];
	arrangedBlock.row0.n128_u32[1] = block.row0.n128_u32[1];
	arrangedBlock.row0.n128_u32[2] = block.row1.n128_u32[2];
	arrangedBlock.row0.n128_u32[3] = block.row2.n128_u32[3];
	arrangedBlock.row1.n128_u32[0] = block.row0.n128_u32[0];
	arrangedBlock.row1.n128_u32[1] = block.row1.n128_u32[1];
	arrangedBlock.row1.n128_u32[2] = block.row2.n128_u32[2];
	arrangedBlock.row1.n128_u32[3] = block.row3.n128_u32[3];
	arrangedBlock.row2.n128_u32[0] = block.row1.n128_u32[0];
	arrangedBlock.row2.n128_u32[1] = block.row2.n128_u32[1];
	arrangedBlock.row2.n128_u32[2] = block.row3.n128_u32[2];
	arrangedBlock.row2.n128_u32[3] = block.row0.n128_u32[3];
	arrangedBlock.row3.n128_u32[0] = block.row2.n128_u32[0];
	arrangedBlock.row3.n128_u32[1] = block.row3.n128_u32[1];
	arrangedBlock.row3.n128_u32[2] = block.row0.n128_u32[2];
	arrangedBlock.row3.n128_u32[3] = block.row1.n128_u32[3];
}

void ScryptNEON::RestoreData(SalsaBlock* destination, ScryptElementPtr& workingBuffer)
{
	ScryptCommon::RestoreData<SalsaBlock128x4>(destination, workingBuffer, RestoreBlock);
}

void ScryptNEON::RestoreBlock(SalsaBlock128x4& block, SalsaBlock128x4& arrangedBlock)
{
	// needs to be checked, no idea if there's a better way

	block.row0.n128_u32[0] = arrangedBlock.row1.n128_u32[0];
	block.row0.n128_u32[1] = arrangedBlock.row0.n128_u32[1];
	block.row0.n128_u32[2] = arrangedBlock.row3.n128_u32[2];
	block.row0.n128_u32[3] = arrangedBlock.row2.n128_u32[3];
	block.row1.n128_u32[0] = arrangedBlock.row2.n128_u32[0];
	block.row1.n128_u32[1] = arrangedBlock.row1.n128_u32[1];
	block.row1.n128_u32[2] = arrangedBlock.row0.n128_u32[2];
	block.row1.n128_u32[3] = arrangedBlock.row3.n128_u32[3];
	block.row2.n128_u32[0] = arrangedBlock.row3.n128_u32[0];
	block.row2.n128_u32[1] = arrangedBlock.row2.n128_u32[1];
	block.row2.n128_u32[2] = arrangedBlock.row1.n128_u32[2];
	block.row2.n128_u32[3] = arrangedBlock.row0.n128_u32[3];
	block.row3.n128_u32[0] = arrangedBlock.row0.n128_u32[0];
	block.row3.n128_u32[1] = arrangedBlock.row3.n128_u32[1];
	block.row3.n128_u32[2] = arrangedBlock.row2.n128_u32[2];
	block.row3.n128_u32[3] = arrangedBlock.row1.n128_u32[3];
}

void ScryptNEON::CopyAndMixBlocks(SalsaBlock* copyDestination, ScryptElementPtr& workingBuffer, ScryptElementPtr& shuffleBuffer)
{
	ScryptCommon::MixBlocks<SalsaBlock128x4>(workingBuffer, copyDestination, shuffleBuffer, MixBlocksMode::Copy);
}

void ScryptNEON::XorAndMixBlocks(ScryptElementPtr& workingBuffer, SalsaBlock* xorSource, ScryptElementPtr& shuffleBuffer)
{
	ScryptCommon::MixBlocks<SalsaBlock128x4>(workingBuffer, xorSource, shuffleBuffer, MixBlocksMode::Xor);
}


