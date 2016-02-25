#pragma once
#include "SalsaBlock.h"
#include <memory>

namespace Skryptonite
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
