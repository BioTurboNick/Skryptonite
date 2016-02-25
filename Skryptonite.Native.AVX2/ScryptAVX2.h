#pragma once
#include "..\Skryptonite.Native\SalsaBlock.h"
#include "..\Skryptonite.Native\ScryptElement.h"

namespace Skryptonite
{
	class ScryptAVX2
	{
	public:
		static void PrepareData(ScryptElementPtr& workingBuffer, SalsaBlock* source);
		static void CopyAndMixBlocks(SalsaBlock* copyDestination, ScryptElementPtr& workingBuffer, ScryptElementPtr& shuffleBuffer);
		static void XorAndMixBlocks(ScryptElementPtr& workingBuffer, SalsaBlock* xorSource, ScryptElementPtr& shuffleBuffer);
		static void RestoreData(SalsaBlock* destination, ScryptElementPtr& workingBuffer);

	private:
		static __forceinline void PrepareBlock(SalsaBlock256x2& arrangedBlock, SalsaBlock256x2& block);
		static __forceinline void RestoreBlock(SalsaBlock256x2& block, SalsaBlock256x2& arrangedBlock);
	};
}
