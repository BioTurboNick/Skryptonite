#include "pch.h"
#include <limits>
#include "ScryptBlock.h"

using namespace Skryptonite::Native;

ScryptBlock::ScryptBlock(unsigned blockCountPerElement, unsigned elementCount)
{
	if (blockCountPerElement == 0)
		throw std::out_of_range("blockCountPerElement must be greater than 0.");
	if (elementCount == 0)
		throw std::out_of_range("elementCount must be greater than 0.");
	if ((std::numeric_limits<size_t>::max)() / blockCountPerElement / elementCount < sizeof(SalsaBlock))
		throw std::out_of_range("Block size would be larger than addressable memory!");

	_elementCount = elementCount;
	_blockCountPerElement = blockCountPerElement;
	_length = sizeof(SalsaBlock) * blockCountPerElement * elementCount;
	
	_data = reinterpret_cast<SalsaBlock*>(_aligned_malloc(_length, Alignment));

	if (_data == NULL)
		throw std::bad_alloc();
}

ScryptBlock::~ScryptBlock()
{
	memset(_data, 0, _length);
	_aligned_free(_data);
}

SalsaBlock* ScryptBlock::operator[](unsigned i) const
{
	if (i >= _elementCount)
		throw new std::out_of_range("i must be less than ElementCount.");
	
	return _data + i * _blockCountPerElement;
}