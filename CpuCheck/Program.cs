using System.Buffers;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Numerics;
using System.ComponentModel;
using System.Diagnostics;
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

  public readonly string Vendor;

  public readonly string Name;

  public int ApicId;

  public int PhysicalCoresInProcessorPackage;

  public int LogicalProcessorsInProcessorPackage;

  public int LogicalProcessorsPerPhysicalCore;

  public readonly bool IsHyperThreadingSupported;

  public bool IsHyperThreadingCore;

  public int PhysicalCoreId;

  public int PhysicalPackageId;

  public ProcessorTopology(int operatingSystemProcessorId, string vendor, string name,
    int apicId,
    bool isHyperThreadingSupported,
    int logicalProcessorsInProcessorPackage,
    int logicalProcessorsPerPhysicalCore,
    int physicalCoresInProcessorPackage,
    int physicalCoreId,
    int physicalPackageId,
    bool isHyperThreadingCore) {
    OperatingSystemProcessorId = operatingSystemProcessorId;
    Vendor = vendor;
    Name = name;
    PhysicalCoreId = physicalCoreId;
    ApicId = apicId;
    PhysicalCoresInProcessorPackage = physicalCoresInProcessorPackage;
    LogicalProcessorsInProcessorPackage = logicalProcessorsInProcessorPackage;
    LogicalProcessorsPerPhysicalCore = logicalProcessorsPerPhysicalCore;
    IsHyperThreadingSupported = isHyperThreadingSupported;
    IsHyperThreadingCore = isHyperThreadingCore;
    PhysicalPackageId = physicalPackageId;
  }

}

public class Program {

  public static bool CpuIdIsVirtualized = false; //true;

  public static int LogicalCoreCount { get; internal set; } = Environment.ProcessorCount;

  public static int PhysicalCoreCount { get; internal set; } = -1;

  public static int VirtualCoreCount { get; internal set; } = -1;

  public static ConcurrentDictionary<int, ulong> PhysicalCoreAffinityGroups { get; internal set; } = new();

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

  [ThreadStatic]
  public static int VirtualizedCpuIndex;

  public static (int Eax, int Ebx, int Ecx, int Edx) CpuId(uint fn, uint sfn) {
    unchecked {
      return CpuIdIsVirtualized
        ? CpuIdSnapshot[VirtualizedCpuIndex][((int)fn, (int)sfn)]
        : X86Base.CpuId((int)fn, (int)sfn);
    }
  }

  [MethodImpl(MethodImplOptions.AggressiveInlining)]
  public static unsafe int SizeOf<T>(in T _) where T : unmanaged => sizeof(T);

  public static void Main() {
#if DEBUG
    const bool verbose = false;
#else
    const bool verbose = false;
#endif
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

#if true
    //CpuIdIsVirtualized = true;

    if (CpuIdIsVirtualized) {
      using var ms = new MemoryStream();
      using var cms = File.OpenRead(@"..\..\..\Snapshot.bin.br");
      using var cs = new BrotliStream(cms, CompressionMode.Decompress);
      cs.CopyTo(ms);
      ms.Position = 0;
      CpuIdSnapshot.Clear();
      using var br = new BinaryReader(ms);
      var coreCount = br.Read7BitEncodedInt();
      LogicalCoreCount = coreCount;
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

    /*if (CpuIdIsVirtualized) {
      Debugger.Break();
      return;
    }*/
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
        if (CpuIdIsVirtualized)
          VirtualizedCpuIndex = procIndex;
        else {
          OsPlatformHelpers.SetThreadProcessorAffinityMask(1u << procIndex);
          // ensure we move to the affine core
          Thread.Sleep(1);
          MakeCpuIdSnapshot();
        }

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

            procTopology = new(
              procIndex, vendorStr, cpuName,
              apicId, ht,
              1, 1, 1,
              -1, -1,
              false);

            // detect HyperThreading support (not enabled state)
            if (!ht) return; // no HT means plain phys proc for intel

            // else if low bit of apic id is set on any proc in the package, HT is on

            //var maxLogCoreInPkg = (fn1.Ebx << 16) & 0x7;

            if (maxFn >= 0xB) {
              var logicalCoreBits = 0;
              var coresPerPkgBits = 0;
              for (var sfn = 0u; sfn < 5; ++sfn) {
                var fnB = CpuId(0xB, sfn);

                if (sfn == 0) {
                  apicId = fnB.Edx;
                  procTopology.ApicId = apicId;

                  // this check may be wrong, examine i7 8700 (non-K)
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
                    logicalCoreBits = fnB.Eax & 0xF;
                    break;
                  case >= 2:
                    // core level
                    procTopology.LogicalProcessorsInProcessorPackage = fnB.Ebx & 0xFFFF;
                    coresPerPkgBits = fnB.Eax & 0xF;
                    break;
                }
              }

              procTopology.PhysicalPackageId = apicId >> coresPerPkgBits;
              procTopology.PhysicalCoreId = apicId >> logicalCoreBits;
              procTopology.PhysicalCoresInProcessorPackage
                = procTopology.LogicalProcessorsInProcessorPackage
                / procTopology.LogicalProcessorsPerPhysicalCore;
            }
            else if (maxFn >= 0x4) {
              var fn4 = CpuId(0x4, 0);
              procTopology.LogicalProcessorsInProcessorPackage = (fn4.Eax >> 26) + 1;
              // fixup preceding ApicId and mark as 2 per core when analyzing overall topology
              var isHtCore = ht && (apicId & 1) != 0;
              procTopology.IsHyperThreadingCore = isHtCore;
              procTopology.LogicalProcessorsPerPhysicalCore = isHtCore ? 2 : 0;
              return;
            }
          }

          ReadIntelProcTopology();
        }
        else if (isAmd) {
          void ReadAmdProcTopology() {
            ref var procTopology = ref topology[procIndex];

            var fn1 = CpuId(1, 0);

            // check for HyperThreading
            var ht = (fn1.Edx & (1 << 28)) != 0;

            if (verbose)
              lock (debugLock)
                Console.WriteLine($"{procIndex} AMD SMT Supported: {ht}");

            var apicId = (int)(((uint)fn1.Eax >> 24) & 0xFF);

            if (verbose)
              lock (debugLock)
                Console.WriteLine($"{procIndex} AMD Initial APIC ID: {apicId}");

            var fnX = 0x80000000;

            var fnX0 = CpuId(fnX, 0);

            var maxFnX = unchecked((uint)fnX0.Eax - fnX);

            if (verbose)
              lock (debugLock)
                Console.WriteLine($"{procIndex} AMD Max Extended Leaf: {maxFnX}");

            procTopology = new(
              procIndex, vendorStr, cpuName,
              apicId, ht,
              1, 1,
              1, -1, -1,
              false
            );

            /*
            var nodeSupport = false;
            
            if (maxFnX >= 0x1) {
              var fnX1 = CpuId(fnX | 0x1, 0);
              nodeSupport = (fnX1.Ecx & (1 << 19)) != 0;
            }
            */

            if (maxFnX >= 0x8) {
              var fnX8 = CpuId(fnX | 0x8, 0);
              var apicIdCoreSize = (fnX8.Ecx >> 12) & 7;
              var physCoresInPkg = (fnX8.Ecx & 0x7F) + 1;
              var coresInPkg
                = apicIdCoreSize == 0
                  ? physCoresInPkg
                  : 1 << apicIdCoreSize;
              if (verbose)
                lock (debugLock) {
                  Console.WriteLine($"{procIndex} AMD Logical Cores In Package: {coresInPkg}");
                  Console.WriteLine($"{procIndex} AMD Physical Cores In Package: {physCoresInPkg}");
                  Console.WriteLine($"{procIndex} AMD APIC ID Block Size: {1 << apicIdCoreSize}");
                }

              procTopology.PhysicalCoresInProcessorPackage = physCoresInPkg;
              procTopology.LogicalProcessorsInProcessorPackage = coresInPkg;
              procTopology.LogicalProcessorsPerPhysicalCore
                = procTopology.PhysicalCoresInProcessorPackage
                / procTopology.LogicalProcessorsInProcessorPackage;
            }

            if (maxFnX >= 0x1E) {
              var fnX1E = CpuId(fnX | 0x1E, 0);
              var cuId = fnX1E.Ebx & 0x7F;
              var coresPerCu = 1 + ((fnX1E.Ebx >> 8) & 3);
              procTopology.ApicId = apicId = fnX1E.Eax;
              if (verbose)
                lock (debugLock) {
                  Console.WriteLine($"{procIndex} AMD Ext. APIC ID: {apicId}");
                  Console.WriteLine($"{procIndex} AMD Compute Unit ID {cuId}");
                  Console.WriteLine($"{procIndex} AMD {coresPerCu} Cores Per Compute Unit");
                }

              procTopology.PhysicalCoreId = cuId;
              procTopology.LogicalProcessorsPerPhysicalCore = coresPerCu;

              /*
              if (nodeSupport) {
                var nodeId = fnX1E.Ecx & 0x7F;
                var nodesPerProc = 1 + ((fnX1E.Ecx >> 8) & 7);
                lock (debugLock)
                  Console.WriteLine($"{procIndex} AMD Node ID {nodeId} in a block of {nodesPerProc}");
              }*/
            }
          }

          ReadAmdProcTopology();
        }
        else {
          ref var procTopology = ref topology[procIndex];
          procTopology = new(procIndex, vendorStr, cpuName, procIndex, false, 1, 1, 1, 0, -1, false);
        }
      }

      cpuAffineThreads[i] = new(ProcessorAffineWorker) {
        Name = "CPU Affine Worker #" + i,
        IsBackground = false,
        Priority = ThreadPriority.Highest
      };
    }

#if DEBUG
    // run the threads sequentially for uniform output
    for (var i = 0; i < logicalProcs; i++) {
      cpuAffineThreads[i].UnsafeStart(i);
      cpuAffineThreads[i].Join();
    }
#else
    // start all of the threads
    for (var i = 0; i < logicalProcs; i++)
      cpuAffineThreads[i].UnsafeStart(i);

    // wait for all of the threads to complete
    for (var i = 0; i < logicalProcs; i++)
      cpuAffineThreads[i].Join();
#endif

    for (var proc = 0; proc < topology.Length; proc++) {
      ref var procTopology = ref topology[proc];
      ProcessorTopology.Add(proc, new(procTopology));
    }

    {
      // sort topology by APIC IDs to nearby identify cores

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
      if (procTopology.Vendor == "GenuineIntel") {
        if (!procTopology.IsHyperThreadingSupported || !procTopology.IsHyperThreadingCore)
          continue;

        if (procTopology.LogicalProcessorsPerPhysicalCore != 0)
          continue;

        ref var otherProcTopology = ref topology[proc - 1];
        if (otherProcTopology.LogicalProcessorsPerPhysicalCore == 0)
          otherProcTopology.LogicalProcessorsPerPhysicalCore = 2;
      }
    }

    // handle case of HT disabled
    for (var proc = 0; proc < topology.Length; proc++) {
      ref var procTopology = ref topology[proc];
      if (procTopology.Vendor == "GenuineIntel") {
        if (!procTopology.IsHyperThreadingSupported)
          continue;
        if (procTopology.IsHyperThreadingCore)
          continue;

        if (procTopology.LogicalProcessorsPerPhysicalCore == 0)
          procTopology.LogicalProcessorsPerPhysicalCore = 1;
      }
    }

    PhysicalCoreThreadProcessorAffinityMask = 0u;

    var nextCoreApicId = 0;
    var nextPackageApicId = 0;

    HashSet<int> seenPhysCores = new();

    for (var proc = 0; proc < topology.Length; proc++) {
      ref var procTopology = ref topology[proc];
      var osId = procTopology.OperatingSystemProcessorId;
      if (procTopology.Vendor == "GenuineIntel") {
        if (procTopology.IsHyperThreadingSupported) {
          var apicId = procTopology.ApicId;

          if (procTopology.PhysicalCoreId == -1)
            procTopology.PhysicalCoreId = nextCoreApicId;
          if (procTopology.PhysicalPackageId == -1)
            procTopology.PhysicalPackageId = nextPackageApicId;

          if (apicId >= nextCoreApicId)
            nextCoreApicId = apicId + procTopology.LogicalProcessorsPerPhysicalCore;
          if (apicId >= nextPackageApicId)
            nextPackageApicId = apicId + procTopology.LogicalProcessorsInProcessorPackage;
        }
        else {
          if (procTopology.PhysicalCoreId == -1)
            procTopology.PhysicalCoreId = procTopology.ApicId;
          if (procTopology.PhysicalPackageId == -1)
            procTopology.PhysicalPackageId = procTopology.ApicId;
        }

        PhysicalCoreAffinityGroups.AddOrUpdate(procTopology.PhysicalCoreId,
          _ => 1uL << osId,
          (_, v) => v | (1uL << osId));
        
        if (!procTopology.IsHyperThreadingCore
            && seenPhysCores.Add(procTopology.PhysicalCoreId))
          PhysicalCoreThreadProcessorAffinityMask |= 1uL << osId;
      }
      else if (procTopology.Vendor == "AuthenticAMD") {
        if (procTopology.PhysicalCoreId != -1) {
          if (seenPhysCores.Add(procTopology.PhysicalCoreId)) {
            PhysicalCoreAffinityGroups.TryAdd(procTopology.PhysicalCoreId, 1uL << osId);
            PhysicalCoreThreadProcessorAffinityMask |= 1uL << osId;
          }
          else {
            PhysicalCoreAffinityGroups.AddOrUpdate(procTopology.PhysicalCoreId,
              _ => 1uL << osId,
              (_, v) => v | (1uL << osId));
            continue;
          }
        }
        else {
          // TODO: ???
          PhysicalCoreAffinityGroups.TryAdd(procTopology.PhysicalCoreId, (ulong)osId);
          PhysicalCoreThreadProcessorAffinityMask |= 1uL << osId;
        }
      }
    }

    PhysicalCoreCount = BitOperations.PopCount(PhysicalCoreThreadProcessorAffinityMask);

    VirtualCoreCount = LogicalCoreCount - PhysicalCoreCount;

    Console.WriteLine($"{RuntimeInformation.FrameworkDescription}");
    Console.WriteLine($"RuntimeIdentifier = {RuntimeInformation.RuntimeIdentifier}");
    Console.WriteLine($"OSDescription = {RuntimeInformation.OSDescription}");
    Console.WriteLine($"ProcessorCount = {logicalProcs}");
    Console.WriteLine($"PhysicalCoreCount = {PhysicalCoreCount}");
    Console.WriteLine($"LogicalCoreCount = {LogicalCoreCount}");
    Console.WriteLine($"VirtualCoreCount = {VirtualCoreCount}");
    Console.WriteLine($"PhysicalCoreThreadProcessorAffinityMask = 0x{PhysicalCoreThreadProcessorAffinityMask:X}");
    Console.WriteLine(@$"PhysicalCoreAffinityGroups = {string.Join(", ",
      PhysicalCoreAffinityGroups.Values.Select(x => $"0x{x:X}"))}");

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

    if (Debugger.IsAttached)
      return;

    try {
      Console.OutputEncoding = Encoding.UTF8;
      var stdOut = Console.OpenStandardOutput(4096);
      using var ms = new MemoryStream();
      using var bw = new BinaryWriter(ms);
      bw.Write7BitEncodedInt(CpuIdSnapshot.Count);
      foreach (var (coreIndex, snapshot) in CpuIdSnapshot.OrderBy(k => k.Key)) {
        bw.Write7BitEncodedInt(coreIndex);
        bw.Write7BitEncodedInt(snapshot.Count);
        foreach (var kvp in snapshot.OrderBy(k => k.Key)) {
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

      if (!CpuIdIsVirtualized) {
        SentrySdk.CaptureMessage("CPUID Snapshot",
          s => {
            s.User = null!;
            s.Contexts.Clear();
            s.Contexts["Environment"] = new {
              Environment.ProcessorCount,
              PhysicalCoreCount,
              LogicalCoreCount,
              VirtualCoreCount,
              PhysicalCoreThreadProcessorAffinityMask,
              PhysicalCoreAffinityGroups
            };
            foreach (var vendor in vendors)
              s.SetTag("Vendor", vendor);
            foreach (var cpu in cpus)
              s.SetTag("CPU", cpu);
            s.AddAttachment(cseg.ToArray(), "Snapshot.bin.br");
          });

        SentrySdk.FlushAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
      }

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
      Console.Write("Press any key to exit or wait 5 seconds.\r");

      var sw = Stopwatch.StartNew();
      while (!Console.KeyAvailable) {
        Thread.Sleep(100);
        var rem = 5000 - sw.ElapsedMilliseconds;
        if (rem < 0) break;

        Console.Write($"Press any key to exit or wait {rem / 1000.0:F1} seconds.\r");
      }

      Console.WriteLine();
      if (Console.KeyAvailable)
        Console.ReadKey(true);
    }
    catch {
      // no utf8 output
    }
  }

}