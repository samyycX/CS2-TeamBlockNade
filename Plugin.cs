using System.Runtime.InteropServices;
using CounterStrikeSharp.API.Core;
using CounterStrikeSharp.API.Modules.Memory;
using Microsoft.Extensions.Logging;

namespace TeamBlockNade;

class Signature {

  /* 
  maybe "think" function found by string "C:\\buildworker\\csgo_rel_win64\\build\\src\\game\\shared\\cstrike15\\basecsgrenade_projectile.cpp:591"
  where check hit enemy called (write m_bHasEverHitEnemy )
  changing jnz to jmp to ignore the IsDifferentTeam check
  */ 
  public static string Windows = "75 ? 4C 8B 85 ? ? ? ? 44 8B 9D";


  /*
  find the maybe think function CBaseCSGrenadeProjectile vtb idx on windows (currently 218)
  add one to find the maybe think function on linux
  and follow the same step as windows
  */
  public static string Linux = "75 ? 49 83 C6 ? 44 39 B5 ? ? ? ? 0F 8F ? ? ? ?";
}

public class Plugin : BasePlugin
{
  public override string ModuleName => "TeamBlockNade";
  public override string ModuleVersion => "1.0.0";
  public override string ModuleAuthor => "samyycX";

  private nint MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr = 0;

  public override void Load(bool hotReload)
  {
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
      MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr = NativeAPI.FindSignature(Addresses.ServerPath, Signature.Windows);
    }
    else
    {
      MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr = NativeAPI.FindSignature(Addresses.ServerPath, Signature.Linux);
    }
    if (MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr == 0)
    {
      Logger.LogError("Failed to find addr!");
      return;
    }
    MemoryPatch.SetMemAccess(MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr, 1);
    Marshal.WriteByte(MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr, 0xEB);
    Logger.LogInformation($"Patched {MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr:X}");
  }

  public override void Unload(bool hotReload)
  {
    if (MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr != 0)
    {
      MemoryPatch.SetMemAccess(MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr, 1);
      Marshal.WriteByte(MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr, 0x75);
      Logger.LogInformation($"Restored {MaybeThink_CheckHitEnemy_IsDifferentTeam_Addr:X}");
    }
  }


}

// credits to @xstage
// https://discord.com/channels/1160907911501991946/1297699678556524555
static class MemoryPatch {
  [DllImport("libc", EntryPoint = "mprotect")]
  public static extern int MProtect(nint address, int len, int protect);

  [DllImport("kernel32.dll")]
  public unsafe static extern bool VirtualProtect(nint address, int dwSize, int newProtect, int* oldProtect);

  public unsafe static bool SetMemAccess(nint addr, int size)
  {
    if (addr == nint.Zero)
      throw new ArgumentNullException(nameof(addr));

    const int PAGESIZE = 4096;

    nint LALIGN(nint addr) => addr & ~(PAGESIZE - 1);
    int LALDIF(nint addr) => (int)(addr % PAGESIZE);

    int* oldProtect = stackalloc int[1];

    return RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ?
        MProtect(LALIGN(addr), size + LALDIF(addr), 7) == 0 : VirtualProtect(addr, size, 0x40, oldProtect);
  }
}