/**
 * Skryptonite - scrypt library for UWP
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
using Skryptonite.Native;
using System;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.System;
using static Windows.Security.Cryptography.CryptographicBuffer;

namespace Skryptonite
{
    /// <summary>
    /// Implementation of the sequential memory-hard password-based key derivation function invented by Colin Percival,
    /// as described in his paper here: http://www.bsdcan.org/2009/schedule/attachments/87_scrypt.pdf.
    /// 
    /// In brief, the algorithm takes a password (key) and a salt to generate one or more elements. Each element, independently,
    /// is iteratively mixed and copied into a large memory block. The resulting mixed element is then used to look up an element
    /// of the large memory block. The extracted element is mixed into the working element, and the process is repeated many times.
    /// The final product of all independently mixed elements are hashed together to produce a final key of the desired size.
    /// 
    /// The net result of scrypt is that for high performance, it requires relatively fast access to a large block of memory. The
    /// element size provides a sequential aspect to the memory lookups which reduces the impact of memory latency on the performance
    /// of the algorithm on a given device.
    /// </summary>
    /// <remarks>
    /// If you aren't sure about the specific parameters you wish to use, you may use <see cref="CreateOptimal"/> to obtain parameters
    /// targeting the specified performance characteristics.
    /// </remarks>
    public sealed class Scrypt
    {
        #region Private Constants

        const uint DefaultElementLengthMultiplier = 16;
        static readonly KeyDerivationAlgorithmProvider pbkdf2Sha256 = KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithmNames.Pbkdf2Sha256);
        static readonly bool Is64bit = Package.Current.Id.Architecture == ProcessorArchitecture.X64;
        static readonly ulong memoryLimit = Is64bit ? ulong.MaxValue : uint.MaxValue;

        #endregion

        #region Private Fields

        uint processingCost;
        int maxThreads = 1;

        #endregion

        #region Public Properties

        #region Fundamental Parameters

        /// <summary>
        /// Gets the length of the hash function used internally for producing the pseudorandom data to operate on and the final key in bits.
        /// </summary>
        public static uint HashBitLength { get; } = 256;

        /// <summary>
        /// GEts the length of the hash function used internally for producing the pseudorandom data to operate on and the final key in bytes.
        /// </summary>
        public static uint HashLength { get; } = HashBitLength / 8;

        /// <summary>
        /// Gets the length of the base element size in bits.
        /// </summary>
        public static uint ElementUnitBitLength { get; } = 1024;

        /// <summary>
        /// Gets the length of the base element size in bytes.
        /// </summary>
        public static uint ElementUnitLength { get; } = ElementUnitBitLength / 8;

        /// <summary>
        /// Gets the multiplier used to determine the lenth of the elements processed.
        /// </summary>
        public uint ElementLengthMultiplier { get; }

        /// <summary>
        /// Gets the number of memory-hard iterations to undertake.
        /// </summary>
        public uint ProcessingCost
        {
            get
            {
                Contract.Ensures(Contract.Result<uint>() > 0);
                return processingCost;
            }
            private set
            {
                Contract.Requires(value > 0);
                processingCost = value;
            }
        }

        /// <summary>
        /// Gets the number of parallel elements to process.
        /// </summary>
        public uint Parallelization { get; }

        /// <summary>
        /// Gets or sets the number of threads the algorithm will use. Must be between 1 and <see cref="Parallelization"/>, inclusive.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the value to be set is &lt;= 0 or else &gt; <see cref="Parallelization"/></exception>
        public int MaxThreads
        {
            get
            {
                Contract.Ensures(Contract.Result<int>() > 0);
                Contract.Ensures(Contract.Result<int>() <= Parallelization);
                return maxThreads;
            }
            set
            {
                if (value <= 0 || value > Parallelization)
                    throw new ArgumentOutOfRangeException(nameof(value), value, $"Must be between 1 and {nameof(Parallelization)}, inclusive.");

                maxThreads = value;
            }
        }

        #endregion

        #region Derived Parameters

        /// <summary>
        /// Gets the length of each independently-processed element in bytes.
        /// </summary>
        private uint WorkingBufferLength { get; }

        #endregion

        #endregion

        #region Instantiation

        /// <summary>
        /// Initializes a Scrypt algorithm with the given parameters.
        /// </summary>
        /// <param name="elementLengthMultiplier">
        /// The "r" parameter. The base block size, 128 bytes (1024 bits), is multiplied by this parameter.
        /// Currently this value is recommended to be 8 by the algorithm's author, but it may be reduced or increased based on the latency-bandwidth product of the memory subsystem.
        /// If this value is too small, little shuffling of the data occurs in BlockMix, enabling easier precomputation attacks, and attackers could benefit by reducing the latency of main memory while sacrificing bandwidth; r = 1 disables shuffling.
        /// If this value is too large, attackers can benefit by using higher latency, lower cost storage devices, and reduces the number of pseudorandom jumps around the large memory block.
        /// Must be greater than 0.
        /// </param>
        /// <param name="processingCost">
        /// The "N" parameter. Determines how memory- and CPU- intensive the base algorithm is.
        /// Recommended to be large, but may be increased or decreased according to the memory and computing power available.
        /// Must be greater than 0 and less than 2^32 / (<see cref="ElementUnitLength"/> * <paramref name="elementLengthMultiplier"/>) / 64. This is because the large memory block size is limited to 2^32 bytes.
        /// Should be greater than 1. Many implementations of Scrypt limit themselves to powers of 2 for performance reasons, but performance impact is minimized by a suitably large
        /// value of <paramref name="elementLengthMultiplier"/>, so this restriction is not used here; however, using a power of 2 also allows the parameter to be compactly stored as
        /// its logarithm base 2.
        /// </param>
        /// <param name="parallelization">
        /// The "p" parameter. The number of independent operations to perform.
        /// This value was recommended to be 1 by the algorithm's author in 2009 (2-core consumer CPUs were just becoming common then), but it may be increased based on the desired
        /// amount of parallelization. Must be less than or equal to (2^32 - 1) * <see cref="HashLength"/> / (<see cref="ElementUnitLength"/> * <paramref name="elementLengthMultiplier"/>).
        /// This is due to a limitation of the one-round PBKDF2 function used to produce the initial material for the scrypt mixing function.
        /// Note that this implies that for extremely large values of <paramref name="processingCost"/>, parallelization would have to be sacrificed.
        /// However, this would only practically be true when memory requirements reach 512 GB, an amount unlikely to be reached anytime soon.
        /// </param>
        /// <remarks>
        /// Choose <paramref name="elementLengthMultiplier"/> to match your memory subsystem's performance, scale <paramref name="processingCost"/> as large as you can handle/as long as you can handle,
        /// scale <paramref name="parallelization"/> to increase computation time while keeping memory usage (per thread) constant.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the parameters to not match the expectations described.</exception>
        public Scrypt(uint elementLengthMultiplier, uint processingCost, uint parallelization)
        {
            if (elementLengthMultiplier == 0)
                throw new ArgumentOutOfRangeException(nameof(elementLengthMultiplier), elementLengthMultiplier, "Must be > 0.");
            if (processingCost == 0)
                throw new ArgumentOutOfRangeException(nameof(processingCost), processingCost, "Must be > 0.");
            if (parallelization == 0)
                throw new ArgumentOutOfRangeException(nameof(processingCost), processingCost, "Must be > 0.");
            if (Convert.ToUInt64(uint.MaxValue) * HashLength / ElementUnitLength / elementLengthMultiplier < parallelization)
                throw new ArgumentOutOfRangeException($"{nameof(elementLengthMultiplier)}, {nameof(parallelization)}", $"Arguments must satisfy the relationship {nameof(parallelization)} <= {uint.MaxValue} * {HashLength} / ({ElementUnitLength} * {nameof(elementLengthMultiplier)}.");
            if (memoryLimit / processingCost / elementLengthMultiplier < ElementUnitLength)
                throw new ArgumentOutOfRangeException($"{nameof(processingCost)}, {nameof(parallelization)}", $"Arguments must satisfy the relationship {memoryLimit} / ({nameof(processingCost)} * {nameof(parallelization)}) >= {nameof(ElementUnitLength)}.");

            ElementLengthMultiplier = elementLengthMultiplier;
            ProcessingCost = processingCost;
            Parallelization = parallelization;

            WorkingBufferLength = ElementUnitLength * ElementLengthMultiplier * Parallelization;
        }

        /// <summary>
        /// Produces a <see cref="Scrypt"/> with factors optimized for memory usage and time.
        /// </summary>
        /// <param name="desiredMemoryUsage">The desired large memory block size, in bytes.</param>
        /// <param name="desiredComputationTime">The desired amount of computation time to use, in milliseconds.</param>
        /// <returns>The optimized Scrypt object. May be null in the event that your device is severely constrained (less than ~32 kB available
        /// for the large memory block.)</returns>
        /// <remarks>
        /// The amount of memory consumed by the large memory block is guaranteed to be as close to <paramref name="desiredMemoryUsage"/> as possible
        /// without going over, though will not be less than 32 kB. At least 16 MB is recommended.
        /// The desired computation time will be met as closely as possible. Be aware that other processes running on your device can affect the
        /// output parameters; if your system is under heavy load, the parameters chosen will be weaker than those chosen when your system is idle.
        /// The amount of memory consumed by the large memory block will be reduced if necessary to match the time constraint.
        /// Automatically accounts for multithreaded processing.
        /// </remarks>
        public static Scrypt CreateOptimal(uint desiredMemoryUsage, uint desiredComputationTime)
        {
            Contract.Ensures(Contract.Result<Scrypt>() == null || Contract.Result<Scrypt>().ElementLengthMultiplier == DefaultElementLengthMultiplier);
            Contract.Ensures(Contract.Result<Scrypt>() == null || Contract.Result<Scrypt>().ProcessingCost >= 16);

            uint minProcessingCost = 16;
            uint maxProcessingCost = Math.Max(minProcessingCost, desiredMemoryUsage / (ElementUnitLength * DefaultElementLengthMultiplier));
            uint targetProcessingCost = minProcessingCost;

            IBuffer password = ConvertStringToBinary("password", BinaryStringEncoding.Utf8);
            IBuffer salt = ConvertStringToBinary("salt", BinaryStringEncoding.Utf8);

            var timer = new Stopwatch();

            Scrypt scrypt;

            bool noMoreMemory = false;
            uint oneIterationMilliseconds = 0;

            // determine the optimal processing cost parameter
            for (uint i = minProcessingCost; i <= maxProcessingCost; i *= 2)
            {
                scrypt = new Scrypt(DefaultElementLengthMultiplier, i, 1);

                try
                {
                    timer.Restart();
                    scrypt.DeriveKey(password, salt, 32);
                    timer.Stop();

                    Contract.Assume(timer.ElapsedMilliseconds <= uint.MaxValue);

                    oneIterationMilliseconds = (uint)timer.ElapsedMilliseconds;
                    targetProcessingCost = i;

                    if (oneIterationMilliseconds > desiredComputationTime)
                        break;
                }
                catch (OutOfMemoryException)
                {
                    if (i == minProcessingCost)
                        return null;

                    noMoreMemory = true;                    
                    break;
                }
            }

            uint threadedIterationMilliseconds = oneIterationMilliseconds;

            // determine how much parallel processing is possible within memory constraints
            int threads = noMoreMemory ? 1 : Math.Max(1, Environment.ProcessorCount - 1);
            while (threads > 1)
            {
                try
                {
                    scrypt = new Scrypt(DefaultElementLengthMultiplier, targetProcessingCost, (uint)threads) { MaxThreads = threads };
                    timer.Restart();
                    scrypt.DeriveKey(password, salt, 32);
                    timer.Stop();

                    Contract.Assume(timer.ElapsedMilliseconds <= uint.MaxValue);

                    threadedIterationMilliseconds = (uint)timer.ElapsedMilliseconds;

                    break;
                }
                catch (OutOfMemoryException)
                {
                    threads--;
                }
            }

            uint targetParallelization = Math.Max(1, (uint)threads * desiredComputationTime / threadedIterationMilliseconds);

            return new Scrypt(DefaultElementLengthMultiplier, targetProcessingCost, targetParallelization) { MaxThreads = (int)Math.Min(threads, targetParallelization) };
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Derives a stronger key from a weaker key using Scrypt.
        /// </summary>
        /// <param name="key">The input key (e.g. user password).</param>
        /// <param name="salt">The salt. Used to thwart precomputation attacks.</param>
        /// <param name="derivedKeyLength">The desired length of the derived key in bytes. Must be greater than 0.</param>
        /// <returns>A derived key of the desired length.</returns>
        /// <exception cref="ArgumentNullException">Thrown if either <paramref name="key"/> or <paramref name="salt"/> are null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="derivedKeyLength"/> is 0.</exception>
        /// <exception cref="OutOfMemoryException">Thrown if enough memory cannot be allocated to perform Scrypt with the given parameters at this time.</exception>
        public IBuffer DeriveKey(IBuffer key, IBuffer salt, uint derivedKeyLength)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));
            if (derivedKeyLength == 0)
                throw new ArgumentOutOfRangeException(nameof(derivedKeyLength), "Must be > 0.");
            
            Contract.Ensures(Contract.Result<IBuffer>() != null);

            IBuffer bufferData = OneRoundPbkdf2Sha256(key, salt, WorkingBufferLength);

            var scryptCore = new ScryptCore(bufferData, Parallelization, ProcessingCost);

            var options = new ParallelOptions() { MaxDegreeOfParallelism = maxThreads };

            try
            {
                Parallel.For(0, Parallelization, options, (long i) => scryptCore.SMix((uint)i));
            }
            catch (AggregateException ex)
            {
                bool outOfMemory = false;
                foreach (var innerEx in ex.InnerExceptions)
                    if (innerEx is OutOfMemoryException)
                    {
                        outOfMemory = true;
                        break;
                    }

                if (outOfMemory)
                {
                    scryptCore.EraseBuffer();
                    throw new OutOfMemoryException("Unable to allocate enough memory to perform Scrypt for these parameters at this time.");
                }
            }

            IBuffer derivedKey = OneRoundPbkdf2Sha256(key, bufferData, derivedKeyLength);

            scryptCore.EraseBuffer();

            return derivedKey;
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Performs a single iteration of PBKDF2-SHA-256.
        /// </summary>
        /// <param name="keyMaterial">The material from which the key will be derived.</param>
        /// <param name="salt">The salt used to randomize the derived key.</param>
        /// <param name="derivedKeyLength">The length of the derived key in bytes.</param>
        /// <returns>The derived key.</returns>
        static IBuffer OneRoundPbkdf2Sha256(IBuffer keyMaterial, IBuffer salt, uint derivedKeyLength)
        {
            Contract.Requires(keyMaterial != null);
            Contract.Requires(salt != null);
            Contract.Ensures(Contract.Result<IBuffer>() != null);
            Contract.Ensures(Contract.Result<IBuffer>().Length == derivedKeyLength);

            CryptographicKey key = pbkdf2Sha256.CreateKey(keyMaterial);
            var parameters = KeyDerivationParameters.BuildForPbkdf2(salt, 1);
            IBuffer derivedKey = CryptographicEngine.DeriveKeyMaterial(key, parameters, derivedKeyLength);

            return derivedKey;
        }
        
        #endregion

        #region Contract Methods

        [ContractInvariantMethod]
        void ObjectInvariant()
        {
            Contract.Invariant(processingCost > 0);
            Contract.Invariant(ProcessingCost > 0);
            Contract.Invariant(Parallelization > 0);
            Contract.Invariant(ElementLengthMultiplier > 0);
            Contract.Invariant(maxThreads > 0);
            Contract.Invariant(MaxThreads > 0);
            Contract.Invariant(MaxThreads <= Environment.ProcessorCount);
        }

        #endregion
    }
}
