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
		throw std::bad_alloc();
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
