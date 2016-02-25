#pragma once
#include "SalsaBlock.h"
#include <memory>

namespace Skryptonite
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
		unsigned _length;

		SalsaBlock* _data;
	};

	typedef std::unique_ptr<ScryptBlock> ScryptBlockPtr;
}


