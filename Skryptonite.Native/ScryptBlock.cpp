#include "pch.h"
#include "ScryptBlock.h"

using namespace Skryptonite;

ScryptBlock::ScryptBlock(unsigned blockCountPerElement, unsigned elementCount)
{
	if (blockCountPerElement == 0)
		throw std::out_of_range("blockCountPerElement must be greater than 0.");
	if (elementCount == 0)
		throw std::out_of_range("elementCount must be greater than 0.");

	_elementCount = elementCount;
	_blockCountPerElement = blockCountPerElement;
	_length = sizeof(SalsaBlock) * blockCountPerElement * elementCount;
	
	_data = reinterpret_cast<SalsaBlock*>(_aligned_malloc(_length, Alignment));

	if (_data == NULL)
		throw std::exception("Memory allocation for ScryptBlock failed.");
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