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
#include "..\Skryptonite.Native\SalsaBlock.h"
#include "..\Skryptonite.Native\ScryptElement.h"

namespace Skryptonite
{
	namespace Native
	{
		class ScryptNEON
		{
		public:
			static void PrepareData(ScryptElementPtr& workingBuffer, SalsaBlock* source);
			static void CopyAndMixBlocks(SalsaBlock* copyDestination, ScryptElementPtr& workingBuffer, ScryptElementPtr& shuffleBuffer);
			static void XorAndMixBlocks(ScryptElementPtr& workingBuffer, SalsaBlock* xorSource, ScryptElementPtr& shuffleBuffer);
			static void RestoreData(SalsaBlock* destination, ScryptElementPtr& workingBuffer);

		private:
			static __forceinline void PrepareBlock(SalsaBlock128x4& arrangedBlock, SalsaBlock128x4& block);
			static __forceinline void RestoreBlock(SalsaBlock128x4& block, SalsaBlock128x4& arrangedBlock);
		};
	}
}