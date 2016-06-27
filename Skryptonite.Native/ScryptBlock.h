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
#include "SalsaBlock.h"
#include <memory>

namespace Skryptonite
{
	namespace Native
	{
		/**
		<summary>Encapsulates the large block of memory accessed by the Scrypt SMix function.</summary>
		*/
		class ScryptBlock
		{
		public:
			/**
			<summary>Gets the number of elements in the block.</summary>
			*/
			unsigned ElementCount() { return _elementCount; };

			/**
			<summary>Gets the number of 64-byte blocks in each element.</summary>
			*/
			unsigned BlockCountPerElement() { return _blockCountPerElement; };

			/**
			<summary>Instantiates the memory block.</summary>
			<param name="blockCountPerElement">The number of 64-byte blocks composing the buffer data per element.</param>
			<param name="elementCount">The number of elements composing the memory block.</param>
			<exception cref="std::out_of_range">Thrown when either parameter is 0.</exception>
			<exception cref="std::exception">Thrown when the memory allocation fails.</exception>
			*/
			ScryptBlock(unsigned blockCountPerElement, unsigned elementCount);

			~ScryptBlock();

			/**
			<summary>Obtains a pointer to the ith element of the memory block.</summary>
			<param name="i">The index of the element to obtain.</param>
			<exception cref="std::out_of_range">Thrown when <paramref name="i"/> is greater than or equal to <see cref="ElementCount"/>.</exception>
			<returns>A pointer to the element.</returns>
			*/
			SalsaBlock* operator[](unsigned i) const;

		private:
			const int Alignment = 64;

			unsigned _blockCountPerElement;
			unsigned _elementCount;
			size_t _length;

			SalsaBlock* _data;
		};

		typedef std::unique_ptr<ScryptBlock> ScryptBlockPtr;
	}
}


