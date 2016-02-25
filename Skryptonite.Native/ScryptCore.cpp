#include "pch.h"
#include "ScryptCore.h"
#include "ScryptElement.h"
#include <wrl.h>
#include <robuffer.h>
#include "DetectInstructionSet.h"

#if defined(_M_IX86) || defined(_M_X64)
#include "..\Skryptonite.Native.SSE2\ScryptSSE2.h"
#include "..\Skryptonite.Native.SSE2\ScryptSSE41.h"
#include "..\Skryptonite.Native.AVX\ScryptAVX.h"
#include "..\Skryptonite.Native.AVX2\ScryptAVX2.h"
#endif

#if defined(_M_ARM)
#include "..\Skryptonite.Native.NEON\ScryptNEON.h"
#endif

using namespace Skryptonite;
using namespace Windows::Storage::Streams;
using namespace Microsoft::WRL;

ScryptCore::ScryptCore(IBuffer^ data, unsigned elementsCount, unsigned processingCost)
{
	if (data == nullptr)
		throw ref new Platform::InvalidArgumentException("data must not be null.");
	if (data->Length == 0)
		throw ref new Platform::InvalidArgumentException("data must be non-empty.");
	if (elementsCount == 0)
		throw ref new Platform::InvalidArgumentException("elementsCount must be greater than 0.");
	if (processingCost == 0)
		throw ref new Platform::InvalidArgumentException("procesingCost must be greater than 0.");
	if (data->Length % (2 * sizeof(SalsaBlock) * elementsCount) > 0)
		throw ref new Platform::InvalidArgumentException("data must be non-empty and contain a number of bytes divisible by 128 * elementsCount.");
	
	_buffer = data;
	_salsaBlockCountPerElement = data->Length / (elementsCount * sizeof(SalsaBlock));
	_elementsCount = elementsCount;
	_processingCost = processingCost;

	GetBufferPointer();
	SetFunctions();
}

void ScryptCore::GetBufferPointer()
{
	ComPtr<IInspectable> p = reinterpret_cast<IInspectable*>(_buffer);
	ComPtr<IBufferByteAccess> buffer;
	p.As(&buffer);
	buffer->Buffer(reinterpret_cast<byte**>(&_data));
}

void ScryptCore::SetFunctions()
{
	switch (DetectInstructionSet::MaxInstructionSet)
	{
#if defined(_M_IX86) || defined(_M_X64)
	case InstructionSet::AVX2:
		PrepareData = ScryptAVX2::PrepareData;
		CopyAndMixBlocks = ScryptAVX2::CopyAndMixBlocks;
		XorAndMixBlocks = ScryptAVX2::XorAndMixBlocks;
		RestoreData = ScryptAVX2::RestoreData;
		break;
	case InstructionSet::AVX:
		PrepareData = ScryptAVX::PrepareData;
		CopyAndMixBlocks = ScryptAVX::CopyAndMixBlocks;
		XorAndMixBlocks = ScryptAVX::XorAndMixBlocks;
		RestoreData = ScryptAVX::RestoreData;
		break;
	case InstructionSet::SSE41:
		PrepareData = ScryptSSE41::PrepareData;
		CopyAndMixBlocks = ScryptSSE41::CopyAndMixBlocks;
		XorAndMixBlocks = ScryptSSE41::XorAndMixBlocks;
		RestoreData = ScryptSSE41::RestoreData;
		break;
	case InstructionSet::SSSE3:
	case InstructionSet::SSE2:
		PrepareData = ScryptSSE2::PrepareData;
		CopyAndMixBlocks = ScryptSSE2::CopyAndMixBlocks;
		XorAndMixBlocks = ScryptSSE2::XorAndMixBlocks;
		RestoreData = ScryptSSE2::RestoreData;
		break;
#endif
#if defined(_M_ARM)
	case InstructionSet::NEON:
		PrepareData = ScryptNEON::PrepareData;
		CopyAndMixBlocks = ScryptNEON::CopyAndMixBlocks;
		XorAndMixBlocks = ScryptNEON::XorAndMixBlocks;
		RestoreData = ScryptNEON::RestoreData;
		break;
#endif
	default:
		// unrecognized instruction set!
		break;
	}
}

void ScryptCore::SMix(unsigned elementIndex)
{
	if (elementIndex >= _elementsCount)
		throw ref new Platform::InvalidArgumentException("elementIndex is out of range.");

	SalsaBlock* const sourceData = _data + elementIndex * _salsaBlockCountPerElement;

	ScryptElementPtr workingBuffer = static_cast<ScryptElementPtr>(std::make_unique<ScryptElement>(_salsaBlockCountPerElement, _processingCost));
	ScryptElementPtr shuffleBuffer = static_cast<ScryptElementPtr>(std::make_unique<ScryptElement>(_salsaBlockCountPerElement, _processingCost));
	ScryptBlockPtr scryptBlock = static_cast<ScryptBlockPtr>(std::make_unique<ScryptBlock>(_salsaBlockCountPerElement, _processingCost));
	
	PrepareData(workingBuffer, sourceData);
	FillScryptBlock(workingBuffer, scryptBlock, shuffleBuffer);
	MixWithScryptBlock(workingBuffer, scryptBlock, shuffleBuffer);
	RestoreData(sourceData, workingBuffer);
}

void ScryptCore::FillScryptBlock(ScryptElementPtr& workingBuffer, const ScryptBlockPtr& scryptBlock, ScryptElementPtr& shuffleBuffer)
{
	_ASSERT(workingBuffer != nullptr);
	_ASSERT(scryptBlock != nullptr);
	_ASSERT(shuffleBuffer != nullptr);
	_ASSERT(workingBuffer->BlockCount() == shuffleBuffer->BlockCount());
	_ASSERT(scryptBlock->ElementCount() == _processingCost);

	for (unsigned i = 0; i < _processingCost; i++)
		CopyAndMixBlocks((*scryptBlock)[i], workingBuffer, shuffleBuffer);
}

void ScryptCore::MixWithScryptBlock(ScryptElementPtr& workingBuffer, const ScryptBlockPtr& scryptBlock, ScryptElementPtr& shuffleBuffer)
{
	_ASSERT(workingBuffer != nullptr);
	_ASSERT(scryptBlock != nullptr);
	_ASSERT(shuffleBuffer != nullptr);
	_ASSERT(workingBuffer->BlockCount() == shuffleBuffer->BlockCount());
	_ASSERT(workingBuffer->IntegerifyDivisor() == scryptBlock->ElementCount());
	_ASSERT(shuffleBuffer->IntegerifyDivisor() == scryptBlock->ElementCount());

	for (unsigned i = 0; i < _processingCost; i++)
	{
		unsigned j = workingBuffer->Integerify();
		XorAndMixBlocks(workingBuffer, (*scryptBlock)[j], shuffleBuffer);
	}
}
