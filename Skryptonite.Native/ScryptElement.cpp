#include "pch.h"
#include <limits>
#include "ScryptElement.h"

using namespace Skryptonite::Native;

ScryptElement::ScryptElement(unsigned blockCount, unsigned integerifyDivisor)
{
	if (blockCount == 0)
		throw std::out_of_range("blockCount must be greater than 0.");
	if (integerifyDivisor == 0)
		throw std::out_of_range("integerifyDivisor must be greater than 0.");
	if ((std::numeric_limits<unsigned>::max)() / blockCount < sizeof(SalsaBlock))
		throw std::out_of_range("Element size would be larger than 2^32 bytes.");

	_blockCount = blockCount;
	_integerifyDivisor = integerifyDivisor;
	_length = sizeof(SalsaBlock) * blockCount;
	
	_data = reinterpret_cast<SalsaBlock*>(_aligned_malloc(_length, Alignment));

	if (_data == NULL)
		throw std::exception("Memory allocation for ScryptElement failed.");
}

ScryptElement::~ScryptElement()
{
	memset(_data, 0, _length);
	_aligned_free(_data);
}

unsigned ScryptElement::Integerify() const
{
	return _data[0].integers[4] % _integerifyDivisor;
}
