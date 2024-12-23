using Gee.External.Capstone.X86;
using Gee.External.Capstone;
using System.Diagnostics;
using PeNet;
using System.Runtime.InteropServices;
using System.Net;
using System;
using static System.Runtime.InteropServices.JavaScript.JSType;

public class MemoryScanner
{
    public Process Process { get; }
    public ulong ImageBase { get; }
    protected byte[] _memoryDump;
    protected X86Instruction[] _instructions;
    protected Dictionary<X86Instruction, int> _instructionIndex;
    protected Dictionary<long, X86Instruction> _instructionAtAddress;
    protected Dictionary<long, List<X86Instruction>> _ripRelativeReferenceMap;
    protected int _targetBits;

    public long BaseAddress { get; protected set; }

    public MemoryScanner(Process process)
    {
        Process = process;
        BaseAddress = Process.MainModule.BaseAddress;

        _targetBits = process.IsTargetProcess64Bit() ? 64 : 32;
        var environmentBits = Environment.Is64BitProcess ? 64 : 32;
        if (_targetBits != environmentBits)
        {
            throw new Exception($"Target process is {_targetBits}-bit, but MemoryScanner is not. Environments must match. Restart the MemoryScanner in {_targetBits}-bit mode");
        }

        ImageBase = GetPreferredImageBase(process.MainModule.FileName);
        RefreshProcessMemory();
    }

    public void RefreshProcessMemory()
    {
        var processHandle = Win32Api.OpenProcess((uint)(Win32Api.ProcessAccessFlags.PROCESS_QUERY_INFORMATION | Win32Api.ProcessAccessFlags.PROCESS_VM_READ), false, Process.Id);
        try
        {
            if (processHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to open process. Make sure to run as administrator.");
            }

            var moduleSize = (uint)Process.MainModule.ModuleMemorySize;
            _memoryDump = new byte[moduleSize];
            if (!Win32Api.ReadProcessMemory(processHandle, new IntPtr(BaseAddress), _memoryDump, moduleSize, out _))
            {
                throw new InvalidOperationException("Failed to read process memory.");
            }

            var moduleBaseAddress = new IntPtr(BaseAddress);
            var moduleEndAddress = IntPtr.Add(moduleBaseAddress, (int)Process.MainModule.ModuleMemorySize);

            var currentAddress = moduleBaseAddress;
            Win32Api.MEMORY_BASIC_INFORMATION mbi = new Win32Api.MEMORY_BASIC_INFORMATION();

            while (Win32Api.VirtualQueryEx(processHandle, currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(Win32Api.MEMORY_BASIC_INFORMATION))) != 0)
            {
                var regionEndAddress = IntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);

                if (mbi.BaseAddress.ToInt64() >= moduleEndAddress.ToInt64())
                {
                    break; // Stop if we've moved past the module bounds
                }

                if (mbi.BaseAddress.ToInt64() + mbi.RegionSize > moduleBaseAddress.ToInt64())
                {
                    var protection = (Win32Api.MemoryProtection)mbi.Protect;
                    if (protection.HasFlag(Win32Api.MemoryProtection.PAGE_EXECUTE) ||
                        protection.HasFlag(Win32Api.MemoryProtection.PAGE_EXECUTE_READ) ||
                        protection.HasFlag(Win32Api.MemoryProtection.PAGE_EXECUTE_READWRITE) ||
                        protection.HasFlag(Win32Api.MemoryProtection.PAGE_EXECUTE_WRITECOPY))
                    {
                        var startOffset = Math.Max(0, (int)(moduleBaseAddress.ToInt64() - mbi.BaseAddress.ToInt64()));
                        var endOffset = Math.Min((int)mbi.RegionSize, (int)(moduleEndAddress.ToInt64() - mbi.BaseAddress.ToInt64()));
                        var regionSize = endOffset - startOffset;

                        if (regionSize > 0)
                        {
                            var regionBuffer = new byte[regionSize];
                            var regionStartAddress = IntPtr.Add(mbi.BaseAddress, startOffset);
                            if (Win32Api.ReadProcessMemory(processHandle, regionStartAddress, regionBuffer, (uint)regionSize, out _))
                            {
                                PreprocessInstructions(regionBuffer, regionStartAddress);
                            }
                        }
                    }
                }

                currentAddress = regionEndAddress;
            }

            if (!_instructions.Any())
            {
                int errorCode = Marshal.GetLastWin32Error();
                throw new Exception($"VirtualQueryEx failed or no executable memory found. Error Code: {errorCode}");
            }            
        }
        finally
        {
            Win32Api.CloseHandle(processHandle);
        }
    }

    protected void PreprocessInstructions(byte[] codeDump, long startingAddress)
    {
        using (var capstone = CapstoneDisassembler.CreateX86Disassembler(_targetBits == 64 ? X86DisassembleMode.Bit64 : X86DisassembleMode.Bit32))
        {
            capstone.EnableInstructionDetails = true;
            capstone.EnableSkipDataMode = true;
            _instructions = capstone.Disassemble(codeDump, startingAddress);
            _instructionIndex = _instructions.Select((value, index) => new KeyValuePair<X86Instruction, int>(value, index)).ToDictionary(x => x.Key, x => x.Value);
            _instructionAtAddress = _instructions.Select((value, index) => new KeyValuePair<long, X86Instruction>(value.Address, value)).ToDictionary(x => x.Key, x => x.Value);

            _ripRelativeReferenceMap = new Dictionary<long, List<X86Instruction>>();

            foreach (var instruction in _instructions)
            {
                if (instruction.Mnemonic == "lea" || instruction.Mnemonic == "mov")
                {
                    foreach (var detail in instruction.Details.Operands)
                    {
                        if (detail.Type == X86OperandType.Memory && detail.Memory.Base?.Id == X86RegisterId.X86_REG_RIP)
                        {
                            try
                            {
                                var ripOffset = instruction.Address + instruction.Bytes.Length + detail.Memory.Displacement;
                                if (!_ripRelativeReferenceMap.ContainsKey(ripOffset))
                                {
                                    _ripRelativeReferenceMap[ripOffset] = new List<X86Instruction>();
                                }
                                _ripRelativeReferenceMap[ripOffset].Add(instruction);
                            }
                            catch
                            {
                                // swallow exceptions
                            }
                        }
                    }
                }
            }
        }
    }

    public X86Instruction[] GetInstructionRange(X86Instruction start, X86Instruction end)
    {
        if (!_instructionIndex.TryGetValue(start, out var startIndex) || !_instructionIndex.TryGetValue(end, out var endIndex))
        {
            return new X86Instruction[0];
        }

        return _instructions.Skip(startIndex).Take(endIndex - startIndex).ToArray();
    }

    public int[] Search(byte?[] pattern)
    {
        var matches = new List<int>();
        for (var i = 0; i <= _memoryDump.Length - pattern.Length; i++)
        {
            var found = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (pattern[j].HasValue && _memoryDump[i + j] != pattern[j].Value)
                {
                    found = false;
                    break;
                }
            }
            if (found)
                matches.Add(i);
        }
        return matches.ToArray();
    }

    public int GetByteIndexForInstruction(X86Instruction instruction)
    {
        return (int)(instruction.Address - BaseAddress);
    }

    public X86Instruction? ConvertByteIndexToNearestInstruction(int byteIndex)
    {
        if (!_instructions.Any())
        {
            return null;
        }

        var address = ConvertByteIndexToProcessAddress(byteIndex);
        var maxAddress = _instructions.Last().Address;
        for (long seek = address; seek < maxAddress; seek++)
        {
            if (_instructionAtAddress.TryGetValue(seek, out var instruction))
            {
                return instruction;
            }
        }

        return null;
    }

    public List<X86Instruction> FindRIPRelativeReferences(long targetAddress)
    {
        if (_ripRelativeReferenceMap.TryGetValue(targetAddress, out var references))
        {
            return references;
        }
        return new List<X86Instruction>();
    }

    public byte[] GetBytes<T>(T value) where T : unmanaged
    {
        return value switch
        {
            byte b => new[] { b },
            short s => BitConverter.GetBytes(s),
            ushort us => BitConverter.GetBytes(us),
            int i => BitConverter.GetBytes(i),
            uint ui => BitConverter.GetBytes(ui),
            long l => BitConverter.GetBytes(l),
            ulong ul => BitConverter.GetBytes(ul),
            float f => BitConverter.GetBytes(f),
            double d => BitConverter.GetBytes(d),
            _ => throw new NotSupportedException($"Type {typeof(T)} is not supported.")
        };
    }

    public T SetBytes<T>(byte[] bytes) where T : unmanaged
    {
        return typeof(T) switch
        {
            var t when t == typeof(byte) => (T)(object)bytes[0],
            var t when t == typeof(short) => (T)(object)BitConverter.ToInt16(bytes, 0),
            var t when t == typeof(ushort) => (T)(object)BitConverter.ToUInt16(bytes, 0),
            var t when t == typeof(int) => (T)(object)BitConverter.ToInt32(bytes, 0),
            var t when t == typeof(uint) => (T)(object)BitConverter.ToUInt32(bytes, 0),
            var t when t == typeof(long) => (T)(object)BitConverter.ToInt64(bytes, 0),
            var t when t == typeof(ulong) => (T)(object)BitConverter.ToUInt64(bytes, 0),
            var t when t == typeof(float) => (T)(object)BitConverter.ToSingle(bytes, 0),
            var t when t == typeof(double) => (T)(object)BitConverter.ToDouble(bytes, 0),
            _ => throw new NotSupportedException($"Type {typeof(T)} is not supported.")
        };
    }

    public int[] SearchForValue<T>(T value) where T : unmanaged
    {
        var valueBytes = GetBytes(value);
        return Search(valueBytes.Select(b => (byte?)b).ToArray());
    }

    public T ReverseEndianness<T>(T value) where T : unmanaged
    {
        var reversedBytes = GetBytes(value).Reverse().ToArray();
        return SetBytes<T>(reversedBytes);
    }

    public (X86Instruction start, X86Instruction end) FindFunctionBoundaries(X86Instruction anyInstructionWithinFunction)
    {
        var end = FindFirst(anyInstructionWithinFunction, new[] { "ret" }, searchForward: true);
        var start = FindFirst(anyInstructionWithinFunction, new[] { "ret" }, searchForward: false);
        start = FindFirstNonPadding(SeekNextInstruction(start, 1), searchForward: true);

        return (start, end);
    }

    public long ConvertByteIndexToProcessAddress(int byteIndex)
    {
        return BaseAddress + byteIndex;
    }

    protected X86Instruction FindFirstNonPadding(X86Instruction start, bool searchForward)
    {
        return FindFirst(start, x => true, searchForward, true);
    }

    protected X86Instruction FindFirst(X86Instruction start, string[] boundaryOperands, bool searchForward, bool skipPadding = false)
    {
        return FindFirst(start, x => boundaryOperands.Contains(x.Mnemonic), searchForward, skipPadding);
    }

    protected X86Instruction? FindFirst(X86Instruction start, Func<X86Instruction, bool> predicate, bool searchForward, bool skipPadding = false)
    {
        var increment = searchForward ? 1 : -1;
        if (!_instructionIndex.TryGetValue(start, out var instructionIndex))
        {
            return null;
        }

        var idx = instructionIndex;
        while (idx >= 0 && idx < _instructions.Count())
        {
            var instruction = _instructions[idx];
            idx += increment;
            if (skipPadding && instruction.Mnemonic == "int3")
            {
                continue;
            }
            if (predicate(instruction))
            {
                return instruction;
            }
        }

        return null;
    }

    protected X86Instruction SeekNextInstruction(X86Instruction start, int offset = 1)
    {
        if (!_instructionIndex.TryGetValue(start, out var instructionIndex))
        {
            return null;
        }

        return _instructions[Math.Clamp(instructionIndex + offset, 0, _instructions.Count()-1)];
    }

    protected ulong GetPreferredImageBase(string filePath)
    {
        var peFile = new PeFile(filePath);
        return peFile.ImageNtHeaders.OptionalHeader.ImageBase;
    }
}
