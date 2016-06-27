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
		<summary>Encapsulates the working buffer used by the Scrypt SMix function.</summary>
		*/
		class ScryptElement
		{
		public:
			/**
			<summary>Gets the number of 64-byte blocks in the element.</summary>
			*/
			unsigned BlockCount() { return _blockCount; };

			/**
			<summary>Gets the divisor used for Integerify.</summary>
			*/
			unsigned IntegerifyDivisor() { return _integerifyDivisor; };

			/**
			<summary>Gets a pointer to the element data.</summary>
			*/
			SalsaBlock* Data() { return _data; };

			/**
			<summary>Instantiates the buffer.</summary>
			<param name="blockCount">The number of 64-byte blocks composing the buffer data.</param>
			<param name="integerifyDivisor">The divisor to use with <see cref="Integerify"/>.</param>
			<exception cref="std::out_of_range">Thrown when either parameter is 0.</exception>
			<exception cref="std::exception">Thrown when the memory allocation fails.</exception>
			*/
			ScryptElement(unsigned blockCount, unsigned integerifyDivisor);

			~ScryptElement();

			/**
			<summary>Interprets the data of the nominally last 64-byte block as a little-endian unsigned integer
			mod the divisor this object was instantiated with.</summary>
			<remarks>
			Assumes that the buffer has been arranged so that the last block is first, and that the block has been
			internally re-arranged so that that 0th element is located at the 4th element.
			</remarks>
			*/
			unsigned ScryptElement::Integerify() const;

		private:
			const int Alignment = 64;

			unsigned _blockCount;
			unsigned _integerifyDivisor;
			unsigned _length;

			SalsaBlock* _data;
		};

		typedef std::unique_ptr<ScryptElement> ScryptElementPtr;
	}
}
