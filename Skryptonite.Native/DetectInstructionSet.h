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

namespace Skryptonite
{
	namespace Native
	{
		/**
		<summary>Enumerates possible supported instruction set architectures.</summary>
		*/
		public enum class InstructionSet
		{
			Unknown,
#if defined(_M_IX86) || defined(_M_X64)
			SSE2,
			SSSE3,
			SSE41,
			AVX,
			AVX2
#endif
#if defined(_M_ARM)
			NEON
#endif
		};

		/**
		<summary>Encapsulates routines to detect CPU instruction capabilities.</summary>
		*/
		public ref class DetectInstructionSet sealed
		{
		public:
			/**
			<summary>Gets or sets the active instruction set.</summary>
			<param name="value">The instruction set.</param>
			<returns>The instruction set.</returns>
			<remarks>
			Reading from this for the first time invokes <see cref="Detect"/>.
			Setting this value to a level not supported by the current system may result in exceptions in dependent code.
			</remarks>
			*/
			static property InstructionSet MaxInstructionSet
			{
				InstructionSet get()
				{
					if (_maxLevel == InstructionSet::Unknown)
						Detect();

					return _maxLevel;
				}
				void set(InstructionSet value)
				{
					_maxLevel = value;
				}
			}

			/**
			<summary>Detects the supported instruction set(s), which is available through this class's properties.</summary>
			<remarks>
			Assumes a minimum level of SSE2 for x86-64 and NEON for ARM. These instructions are guaranteed on all
			supported Windows 10 devices.
			</remarks>
			*/
			static void Detect();

		private:
			static InstructionSet _maxLevel;
		};
	}
}


