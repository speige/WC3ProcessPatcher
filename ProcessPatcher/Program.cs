using System.Diagnostics;
using System.Text;

public class Program
{
    static void Main(string[] args)
    {
        var processName = "World Editor";
        var targetString = "--nopreprocessor";

        var targetProcess = Process.GetProcessesByName(processName).FirstOrDefault();
        if (targetProcess == null)
        {
            Console.WriteLine($"Process '{processName}' not found.");
            return;
        }

        var scanner = new MemoryScanner(targetProcess);

        var functionStartPattern = new byte?[]
        {
            0x44, 0x88, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54,
            0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x57,
            0xB8, 0x30, 0x4E, 0x00, 0x00, null, null, null
        };

        var functionMatches = scanner.Search(functionStartPattern);
        if (functionMatches.Length > 0)
        {
            foreach (var match in functionMatches)
            {
                Console.WriteLine($"Function start found at address: 0x{scanner.ConvertByteIndexToProcessAddress(match).ToString("X")}");

                var instruction = scanner.ConvertByteIndexToNearestInstruction(match);
                var (start, end) = scanner.FindFunctionBoundaries(instruction);
                var disassembly = scanner.GetInstructionRange(start, end);
                Console.WriteLine($"Function boundaries: Start 0x{start.Address.ToString("X")}, End 0x{end.Address.ToString("X")}");
                foreach (var inst in disassembly)
                {
                    Console.WriteLine($"{inst.Address:X}: {inst.Mnemonic} {inst.Operand}");
                }
            }
        }
        else
        {
            Console.WriteLine("No match found for function start pattern.");
        }

        var search = Encoding.ASCII.GetBytes(targetString).Cast<byte?>().ToArray();
        var indices = scanner.Search(search);
        if (indices.Length > 0)
        {
            foreach (var index in indices)
            {
                var foundAddress = scanner.ConvertByteIndexToProcessAddress(index);
                Console.WriteLine($"Found '{targetString}' at address: 0x{foundAddress.ToString("X")}");
                var references = scanner.FindRIPRelativeReferences(foundAddress);
                foreach (var reference in references)
                {
                    Console.WriteLine($"Reference found at: 0x{reference.Address.ToString("X")}");

                    var (startIndex, endIndex) = scanner.FindFunctionBoundaries(reference);
                    Console.WriteLine($"Function boundaries: Start 0x{startIndex.Address.ToString("X")}, End 0x{endIndex.Address.ToString("X")}");
                    var disassembly = scanner.GetInstructionRange(startIndex, endIndex);
                    foreach (var inst in disassembly)
                    {
                        Console.WriteLine($"{inst.Address:X}: {inst.Mnemonic} {inst.Operand}");
                    }
                }
            }
        }
        else
        {
            Console.WriteLine($"'{targetString}' not found.");
        }
    }
}