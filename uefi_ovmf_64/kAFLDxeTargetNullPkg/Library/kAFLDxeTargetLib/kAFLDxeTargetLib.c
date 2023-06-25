#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/BmpSupportLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Library/kAFLAgentLib.h>
#include <Library/kAFLDxeTargetLib.h>

#include <Library/UefiBootServicesTableLib.h>
#include <Library/RngLib.h>
#include <Protocol/Rng.h>

VOID
EFIAPI
InitkAFLTarget (VOID)
{
  /* kAFL debug info */
  // DebugPrint (DEBUG_INFO, "Mapping info: TranslateBmpToGopBlt is at %x\n", (void*)TranslateBmpToGopBlt);
  // DebugPrint (DEBUG_INFO, "Mapping info: DumpCpuContext is at %x\n", (void*)DumpCpuContext);
  //DEBUG ((DEBUG_INFO, "Mapping info: DumpModuleImageInfo is at %x\n", (void*)DumpModuleImageInfo);
  //
  /* Override target's word with autodetection
   *
   * Qemu log indicates the target is detected as 32bit even when OVMF+App are
   * compiled for X64. This overrides the auto-detection and makes Redqueen
   * actually find some bugs instead of just causing timeouts.
   */
#if defined(__x86_64__)
  kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
  DEBUG ((DEBUG_INFO, "HARNESS: 64 bits mode submitted\n"));
#endif
}

EFI_STATUS
EFIAPI
RunkAFLTarget (
    IN VOID *input,
    IN UINTN inputSize
    )
{
  EFI_STATUS Status = EFI_SUCCESS;
  DEBUG ((DEBUG_INFO, "Not dead !\n"));
  char *p = input;
  
  uint32_t rand=0;
  GetRandomNumber32(&rand);
  
  if(rand%2==0 && rand%3==0){
    p[0] = 'd';
    p[1] = 'e';
    p[2] = 'a';
    p[3] = 'd';
  }

  if (inputSize < 4) {
    return Status;
  } else {
    if (p[0] == 'd' && p[1] == 'e' && p[2] == 'a' && p[3] == 'd') {
      hprintf("HYPERCALL_KAFL_PANIC");
      //*((unsigned int*)0) = 0xDEAD;
      kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
      // kAFL_hypercall(HYPERCALL_KAFL_KASAN, 0);
    }
  }
  return Status;
}

