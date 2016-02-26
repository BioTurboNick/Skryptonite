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


