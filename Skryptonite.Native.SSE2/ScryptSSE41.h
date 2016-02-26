#pragma once
#include "..\Skryptonite.Native\SalsaBlock.h"
#include "..\Skryptonite.Native\ScryptElement.h"

namespace Skryptonite
{
	namespace Native
	{
		class ScryptSSE41
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

