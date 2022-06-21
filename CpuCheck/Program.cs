using System.Buffers;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Numerics;
using System.ComponentModel;
using System.IO.Compression;
using System.Runtime.Intrinsics.X86;
using System.Text;
using Sentry;

public static class OsPlatformHelpers {

  public static readonly unsafe delegate* <nuint, void> _SetThreadProcessorAffinityMask
    = OperatingSystem.IsWindows()
      ? &WindowsHelpers.SetThreadProcessorAffinityMask
      : &PosixHelpers.SetThreadProcessorAffinityMask;

  [MethodImpl(MethodImplOptions.AggressiveInlining)]
  public static unsafe void SetThreadProcessorAffinityMask(nuint procBits)
    => _SetThreadProcessorAffinityMask(procBits);

}

public static class WindowsHelpers {

  private const string Kernel32 = "Kernel32";

  [DllImport(Kernel32)]
  private static extern nint GetCurrentThread();

  [DllImport(Kernel32, SetLastError = true)]
  private static extern nint SetThreadAffinityMask(nint hThread, nuint dwThreadAffinityMask);

  public static void SetThreadProcessorAffinityMask(nuint procBits) {
    var success = SetThreadAffinityMask(GetCurrentThread(), procBits) != 0;
    if (!success)
      throw new Win32Exception(Marshal.GetLastWin32Error());
  }

}

[SuppressMessage("ReSharper", "IdentifierTypo")]
public static class PosixHelpers {

  [SuppressMessage("ReSharper", "InconsistentNaming")]
  private const string pthread = "pthread";

  [DllImport(pthread)]
  private static extern nint pthread_self();

  [DllImport(pthread)]
  private static extern unsafe int pthread_setaffinity_np(nint thread, nint cpusetsize, void* cpuset);

  public static unsafe void SetThreadProcessorAffinityMask(nuint procBits) {
    var procCount = Environment.ProcessorCount;
    var procCountBytes = (procCount + 7) / 8;
    var procMask = (nuint)((1 << procCount) - 1);
    procBits &= procMask;
    var result = pthread_setaffinity_np(pthread_self(), procCountBytes, &procBits);
    if (result != 0)
      throw new($"Posix error status {result}");
  }

}

public struct ProcessorTopology {

  public readonly int OperatingSystemProcessorId;

  public int ApicId;

  public int PhysicalCoresInProcessorPackage;

  public int LogicalProcessorsInProcessorPackage;

  public int LogicalProcessorsPerPhysicalCore;

  public readonly bool IsHyperThreadingSupported;

  public bool IsHyperThreadingCore;

  public readonly string Vendor;

  public readonly string Name;

  public ProcessorTopology(int operatingSystemProcessorId, int apicId, int physicalCoresInProcessorPackage, int logicalProcessorsInProcessorPackage, int logicalProcessorsPerPhysicalCore, bool isHyperThreadingSupported,
    bool isHyperThreadingCore, string vendor, string name) {
    OperatingSystemProcessorId = operatingSystemProcessorId;
    ApicId = apicId;
    PhysicalCoresInProcessorPackage = physicalCoresInProcessorPackage;
    LogicalProcessorsInProcessorPackage = logicalProcessorsInProcessorPackage;
    LogicalProcessorsPerPhysicalCore = logicalProcessorsPerPhysicalCore;
    IsHyperThreadingSupported = isHyperThreadingSupported;
    IsHyperThreadingCore = isHyperThreadingCore;
    Vendor = vendor;
    Name = name;
  }

}

public class Program {

  public static int PhysicalCoreCount { get; internal set; } = -1;

  public static ulong PhysicalCoreThreadProcessorAffinityMask { get; internal set; }

  internal static readonly Dictionary<int, StrongBox<ProcessorTopology>> ProcessorTopology = new();

  private static int NextLog2(int x) {
    // surely this can be optimized
    if (x <= 0)
      return 0;

    x--;
    uint count = 0;
    while (x > 0) {
      x >>= 1;
      count++;
    }

    return (int)count;
  }

  public static void MakeCpuIdSnapshot() {
    var osProcId = Thread.GetCurrentProcessorId();

    var procCpuId = CpuIdSnapshot.GetOrAdd(osProcId, _ => new());

    var fn0 = X86Base.CpuId(0, 0);
    procCpuId[(0, 0)] = fn0;

    var maxFn = fn0.Eax;

    for (var fn = 1; fn < maxFn; ++fn) {
      procCpuId[(fn, 0)] = X86Base.CpuId(fn, 0);
      var maxSFn = fn switch { 0xB => 5, _ => 1 };

      for (var sfn = 1; sfn < maxSFn; ++sfn)
        procCpuId[(fn, sfn)] = X86Base.CpuId(fn, sfn);
    }

    const int fnX = unchecked((int)0x80000000);

    var fnX0 = X86Base.CpuId(fnX, 0);
    procCpuId[(fnX, 0)] = fnX0;

    maxFn = fnX0.Eax - fnX;

    for (var fn = 1; fn < maxFn; ++fn) {
      procCpuId[(fnX + fn, 0)] = X86Base.CpuId(fnX + fn, 0);

      /*
      var maxSFn = 1;

      for (var sfn = 1; sfn < maxSFn; ++sfn)
        procCpuId[(fn, sfn)] = X86Base.CpuId(fnX + fn, sfn);*/
    }
  }

  public static ConcurrentDictionary<int, Dictionary<(int Fn, int SFn), (int Eax, int Ebx, int Ecx, int Edx)>>
    CpuIdSnapshot = new();

  public static bool CpuIdIsVirtualized = false; //true;

  public static (int Eax, int Ebx, int Ecx, int Edx) CpuId(uint fn, uint sfn) {
    unchecked {
      return CpuIdIsVirtualized
        ? CpuIdSnapshot[Thread.GetCurrentProcessorId()][((int)fn, (int)sfn)]
        : X86Base.CpuId((int)fn, (int)sfn);
    }
  }

  [MethodImpl(MethodImplOptions.AggressiveInlining)]
  public static unsafe int SizeOf<T>(in T _) where T : unmanaged => sizeof(T);

  public static void Main() {
    var debugLock = new object();

    using var sentry = SentrySdk.Init(o => {
      o.Dsn = "https://b9a5fcfc94f94e70ae723eb2a55fb8f4@o1294676.ingest.sentry.io/6519095";
#if DEBUG
      o.Debug = true;
#endif
      o.TracesSampleRate = 1.0;
      o.ReportAssembliesMode = ReportAssembliesMode.None;
      o.DetectStartupTime = StartupTimeDetectionMode.Best;
      o.AttachStacktrace = false;
      o.AutoSessionTracking = true;
      o.DisableAppDomainUnhandledExceptionCapture();
      o.DisableTaskUnobservedTaskExceptionCapture();
      o.SendDefaultPii = false;
      o.SendClientReports = false;
      o.DisableDiagnosticSourceIntegration();
#if DEBUG
      o.Environment = "Development";
#else
      o.Environment = "Production";
#endif
    });
    // App code goes here. Dispose the SDK before exiting to flush events.

#if false
    if (CpuIdIsVirtualized) {
      var src
        = "C0wdgK4GY2Ma9TGjRK1ihVIu+rXh+m/9IYJq+b/e272QfgxwlE9B8n4VFo0OSaWoxliERBgUSmAkwlCPoG2ebxDRlkS60RQGW1uJy8a2rpES3lchnFXnV4vTUPXXW353+ZCFoGvyFbt6NGD5YEACFuSYBPhr/oQTCvBVKGBbS+S248vCyrJNMBjEVycTYAsXnz+9fnbx6OEfR98rAbY2P7qujb/XO6xAX4a+AgNCDVhhhYxtNIACSIAWAL9OxQKd2aC3weCPMQISKkjAiIQWE1IAIyoAVIARGQAZMKIAoAAmPsAMaINVJjKwwVfaBMAaUAEBC7G/45hlWd/P9PVzwLKbF7//ePFmYbl978aNTMBy7+qt2uE1qdq3hYAPS7Zp4rjuU+qWGlQaAjy3XZ7VE7GOVAiAU8DPm46AGzd4/HtK4ztIKpGbAhIEsP6z60IQYyIwZgJjg8DYJDC2CIxtAmOHwNglMPYIjH0C44DAOCQwjgiuHBOw+meB2hMCGlSdErDOMM4IfkfOCbhywQN/egC4RABIAFwmYFPyJv4nEtIJF66EJJJIIinrJYokqcJVIRWpSEWqrFcprZAkOVwZySSTTHLWyxRZUsJVkEIKKaRkvaK0oJLU4aqRmtSkJnXWqylqSROuDulIRzrSZb1OaYciacPVIz3pSU/6rNdT9JIuXAMykIEMZMh6g9IBtaQP14iMZCQjGbPeSDFKhnBNyEQmMpEp601KJzSSMVwzMpOZzGTOejPFbAA=";

      var cb = Convert.FromBase64String(src);
      using var ms = new MemoryStream();

      using var cms = new MemoryStream(cb, false);
      using var cs = new BrotliStream(cms, CompressionMode.Decompress);
      cs.CopyTo(ms);
      ms.Position = 0;
      CpuIdSnapshot.Clear();
      using (var br = new BinaryReader(ms)) {
        var coreCount = br.Read7BitEncodedInt();
        for (var coreIndex = 0; coreIndex < coreCount; ++coreIndex) {
          var coreId = br.Read7BitEncodedInt();
          var snapshotCount = br.Read7BitEncodedInt();
          var snapshot = new Dictionary<(int Fn, int SFn), (int Eax, int Ebx, int Ecx, int Edx)>(snapshotCount);
          CpuIdSnapshot.TryAdd(coreId, snapshot);
          for (var snapshotIndex = 0; snapshotIndex < snapshotCount; ++snapshotIndex) {
            KeyValuePair<(int Fn, int SFn), (int Eax, int Ebx, int Ecx, int Edx)> kvp = default;
            var span = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref kvp, 1));
            if (br.Read(span) != SizeOf(kvp))
              throw new NotImplementedException();

            snapshot.Add(kvp.Key, kvp.Value);
          }
        }
      }
    }

    if (CpuIdIsVirtualized) {
      Debugger.Break();
      return;
    }
#endif

    // https://wiki.osdev.org/Detecting_CPU_Topology_(80x86)
    // https://stackoverflow.com/questions/2901694/how-to-detect-the-number-of-physical-processors-cores-on-windows-mac-and-linu
    // https://github.com/vectorclass/add-on/blob/master/physical_processors/physical_processors.cpp
    var logicalProcs = CpuIdIsVirtualized ? CpuIdSnapshot.Count : Environment.ProcessorCount;
    var cpuAffineThreads = new Thread[logicalProcs];

    var physCpuCount = 0;
    var physPkgCount = 0;

    var topology = new ProcessorTopology[logicalProcs];

    for (var i = 0; i < logicalProcs; ++i) {
      unsafe void ProcessorAffineWorker(object? arg) {
        var procIndex = (int)arg!;
        OsPlatformHelpers.SetThreadProcessorAffinityMask(1u << procIndex);
        // ensure we move to the affine core
        Thread.Sleep(1);

        MakeCpuIdSnapshot();

        const int
          // GenuineIntel
          isIntelEbx = 0x75_6E_65_47, // Genu
          isIntelEdx = 0x49_65_6E_69, // ineI
          isIntelEcx = 0x6C_65_74_6E, // ntel
          // AuthenticAMD
          isAmdEbx = 0x68_74_75_41, // Auth
          isAmdEdx = 0x69_74_6E_65, // enti
          isAmdEcx = 0x44_4D_41_63; // cAMD

        var fn0 = CpuId(0, 0);

        var isIntel = fn0 is (_, isIntelEbx, isIntelEcx, isIntelEdx);
        var isAmd = !isIntel && fn0 is (_, isAmdEbx, isAmdEcx, isAmdEdx);

        Span<sbyte> vendorChars = stackalloc sbyte[12];
        var vendorInts = MemoryMarshal.Cast<sbyte, int>(vendorChars);
        (vendorInts[0], vendorInts[1], vendorInts[2]) = (fn0.Ebx, fn0.Edx, fn0.Ecx);
        var vendorStr = new string((sbyte*)Unsafe.AsPointer(ref vendorChars.GetPinnableReference()), 0, 12, Encoding.Latin1);

        var maxFn = fn0.Eax;

        var cpuName = "<unknown>";
        if ((uint)CpuId(0x80000000, 0).Eax >= 0x80000004) {
          var regs = new int[12];

          for (uint x = 0; x < 3; ++x) {
            (regs[4 * x], regs[4 * x + 1], regs[4 * x + 2], regs[4 * x + 3])
              = CpuId(0x80000002 + x, 0);
          }

          cpuName = Encoding.UTF8.GetString(MemoryMarshal.Cast<int, byte>(regs)).Trim('\0', ' ', '\r', '\n');
        }

        if (isIntel) {
          void ReadIntelProcTopology() {
            // https://www.intel.com/content/dam/develop/external/us/en/documents/intel-64-architecture-processor-topology-enumeration.pdf

            ref var procTopology = ref topology[procIndex];

            var fn1 = CpuId(1, 0);

            // check for HyperThreading
            var ht = (fn1.Edx & (1 << 28)) != 0;

            var apicId = (int)(((uint)fn1.Eax << 24) & 0xFF);

            procTopology = new(procIndex, apicId, 1, 1, 1, ht, false, vendorStr, cpuName);

            // detect HyperThreading support (not enabled state)
            if (!ht) return; // no HT means plain phys proc for intel

            // else if low bit of apic id is set on any proc in the package, HT is on

            //var maxLogCoreInPkg = (fn1.Ebx << 16) & 0x7;

            if (maxFn < 0xB) {
              var fn4 = CpuId(0x4, 0);
              procTopology.LogicalProcessorsInProcessorPackage = (fn4.Eax >> 26) + 1;
              // fixup preceding ApicId and mark as 2 per core when analyzing overall topology
              var isHtCore = ht && (apicId & 1) != 0;
              procTopology.IsHyperThreadingCore = isHtCore;
              procTopology.LogicalProcessorsPerPhysicalCore = isHtCore ? 2 : 0;
              return;
            }

            for (var sfn = 0u; sfn < 5; ++sfn) {
              var fnB = CpuId(0xB, sfn);

              if (sfn == 0) {
                apicId = fnB.Edx;
                procTopology.ApicId = apicId;

                if (ht && (apicId & 1) != 0)
                  procTopology.IsHyperThreadingCore = true;
              }

              var level = (fnB.Ecx >> 8) & 0xFF;

              if (level == 0)
                break;

              switch (level) {
                case 1:
                  // SMT level
                  procTopology.LogicalProcessorsPerPhysicalCore = fnB.Ebx & 0xFFFF;
                  break;
                case >= 2:
                  // core level
                  procTopology.LogicalProcessorsInProcessorPackage = fnB.Ebx & 0xFFFF;
                  break;
              }
            }

            procTopology.PhysicalCoresInProcessorPackage
              = procTopology.LogicalProcessorsInProcessorPackage
              / procTopology.LogicalProcessorsPerPhysicalCore;
          }

          ReadIntelProcTopology();
        }
        else if (isAmd) {
          void ReadAmdProcTopology() {
            ref var procTopology = ref topology[procIndex];

            var fn1 = CpuId(1, 0);

            // check for HyperThreading
            var ht = (fn1.Edx & (1 << 28)) != 0;

            var apicId = (int)(((uint)fn1.Eax << 24) & 0xFF);

            var maxLogCoreInPkg = (fn1.Ebx << 16) & 0x7;

            var fnX = 0x80000000;

            var fnX0 = CpuId(fnX, 0);

            var coreBits = (fnX0.Ecx << 12) & 0x7;
            if (coreBits == 0)
              coreBits = NextLog2(fnX0.Ecx & 0x7F);

            lock (debugLock)
              Console.WriteLine($"AMD Core Bits: {procIndex} {apicId} {ht} {maxLogCoreInPkg} 0x{coreBits:X}");

            procTopology = new(procIndex, apicId, 1, 1, 1, false, false, vendorStr, cpuName);
          }

          ReadAmdProcTopology();
        }
        else {
          ref var procTopology = ref topology[procIndex];
          procTopology = new(procIndex, procIndex, 1, 1, 1, false, false, vendorStr, cpuName);
        }
      }

      cpuAffineThreads[i] = new(ProcessorAffineWorker) { Name = "CPU Affine Worker #" + i, IsBackground = false, Priority = ThreadPriority.Highest };
    }

    // start all of the threads
    for (var i = 0; i < logicalProcs; i++)
      cpuAffineThreads[i].UnsafeStart(i);

    // wait for each of the threads to complete
    for (var i = 0; i < logicalProcs; i++)
      cpuAffineThreads[i].Join();

    for (var proc = 0; proc < topology.Length; proc++) {
      ref var procTopology = ref topology[proc];
      ProcessorTopology.Add(proc, new(procTopology));
    }

    {
      var apicIds = new int[logicalProcs];

      for (var proc = 0; proc < topology.Length; proc++) {
        ref var procTopology = ref topology[proc];
        apicIds[proc] = procTopology.ApicId;
      }

      Array.Sort(apicIds, topology);
    }

    // handle case of HT enabled
    for (var proc = 0; proc < topology.Length; proc++) {
      ref var procTopology = ref topology[proc];
      if (!procTopology.IsHyperThreadingSupported || !procTopology.IsHyperThreadingCore)
        continue;

      if (procTopology.LogicalProcessorsPerPhysicalCore != 0)
        continue;

      ref var otherProcTopology = ref topology[proc - 1];
      if (otherProcTopology.LogicalProcessorsPerPhysicalCore == 0)
        otherProcTopology.LogicalProcessorsPerPhysicalCore = 2;
    }

    // handle case of HT disabled
    for (var proc = 0; proc < topology.Length; proc++) {
      ref var procTopology = ref topology[proc];
      if (!procTopology.IsHyperThreadingSupported)
        continue;
      if (procTopology.IsHyperThreadingCore)
        continue;

      if (procTopology.LogicalProcessorsPerPhysicalCore == 0)
        procTopology.LogicalProcessorsPerPhysicalCore = 1;
    }

    PhysicalCoreThreadProcessorAffinityMask = 0u;

    var packageCpuStart = 0;

    for (var proc = 0; proc < topology.Length; proc++) {
      ref var procTopology = ref topology[proc];
      if (procTopology.IsHyperThreadingCore)
        continue;

      var procIndexInPackage = proc - packageCpuStart;

      // detect last logical proc in package 
      if (procIndexInPackage == procTopology.LogicalProcessorsInProcessorPackage - 1)
        packageCpuStart = proc + 1;

      // physical cores are (most likely) the first in a group of logical processors by APIC ID
      if (procIndexInPackage % procTopology.LogicalProcessorsPerPhysicalCore != 0)
        continue;

      PhysicalCoreThreadProcessorAffinityMask |= (nuint)1uL << procTopology.OperatingSystemProcessorId;
    }

    PhysicalCoreCount = BitOperations.PopCount(PhysicalCoreThreadProcessorAffinityMask);

    Console.WriteLine($"{RuntimeInformation.FrameworkDescription}");
    Console.WriteLine($"RuntimeIdentifier = {RuntimeInformation.RuntimeIdentifier}");
    Console.WriteLine($"OSDescription = {RuntimeInformation.OSDescription}");
    Console.WriteLine($"ProcessorCount = {Environment.ProcessorCount}");
    Console.WriteLine($"PhysicalCoreCount = {PhysicalCoreCount}");
    Console.WriteLine($"PhysicalCoreThreadProcessorAffinityMask = 0x{PhysicalCoreThreadProcessorAffinityMask:X}");

    var vendors = ProcessorTopology.Values
      .Select(t => t.Value.Vendor)
      .Distinct()
      .ToArray();
    Console.WriteLine("Vendor(s) = " + string.Join("\n", vendors));
    var cpus = ProcessorTopology.Values
      .Select(t => t.Value.Name)
      .Distinct()
      .ToArray();
    Console.WriteLine("CPU(s) = " + string.Join("\n", cpus));

    try {
      Console.OutputEncoding = Encoding.UTF8;
      var stdOut = Console.OpenStandardOutput(4096);
      using var ms = new MemoryStream();
      using var bw = new BinaryWriter(ms);
      bw.Write7BitEncodedInt(CpuIdSnapshot.Count);
      foreach (var (coreIndex, snapshot) in CpuIdSnapshot) {
        bw.Write7BitEncodedInt(coreIndex);
        bw.Write7BitEncodedInt(snapshot.Count);
        foreach (var kvp in snapshot) {
          var span = MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef(kvp), 1));
          bw.Write(span);
        }
      }

      bw.Flush();

      if (!ms.TryGetBuffer(out var seg))
        throw new NotImplementedException();

      //Console.WriteLine($"Before compression, size: {seg.Count} bytes, {Base64.GetMaxEncodedToUtf8Length(seg.Count)} B64 chars");
      using var cms = new MemoryStream();
      using var cs = new BrotliStream(cms, CompressionMode.Compress);

      cs.Write(seg);
      cs.Flush();

      if (!cms.TryGetBuffer(out var cseg))
        throw new NotImplementedException();

      if (!CpuIdIsVirtualized)
        SentrySdk.CaptureMessage("CPUID Snapshot",
          s => {
            s.User = null!;
            s.Contexts.Clear();
            s.Contexts["Environment"] = new {
              Environment.ProcessorCount,
              PhysicalCoreCount,
              PhysicalCoreThreadProcessorAffinityMask,
            };
            foreach (var vendor in vendors)
              s.SetTag("Vendor", vendor);
            foreach (var cpu in cpus)
              s.SetTag("CPU", cpu);
            s.AddAttachment(cseg.ToArray(), "Snapshot.bin.br");
          });

      SentrySdk.FlushAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();

      var b64Buf = new byte[Base64.GetMaxEncodedToUtf8Length(cseg.Count)];
      if (Base64.EncodeToUtf8(cseg, b64Buf, out _, out var b64BufUsed) != OperationStatus.Done)
        throw new NotImplementedException();

      var b64Seg = new ArraySegment<byte>(b64Buf, 0, b64BufUsed);

      Console.WriteLine("=== BEGIN CPUID SNAPSHOT BR ===");
      stdOut.Write(b64Seg);
      stdOut.Flush();
      Console.WriteLine();
      Console.WriteLine("=== END CPUID SNAPSHOT BR ===");
      Console.WriteLine();
      Console.WriteLine("Press any key to exit.");

      Console.ReadKey(true);
    }
    catch {
      // no utf8 output
    }
  }

}