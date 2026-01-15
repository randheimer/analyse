# 🔍 Malware Analysis Report

================================================================================


**File:** `echo-free_1.exe`  

**Analysis Date:** 2026-01-15 22:42:41  

**File Type:** PE  

**Size:** 49.90 MB  



## 📊 Executive Summary

---

| Metric | Value |

|--------|-------|

| **Threat Score** | **100/100** 🔴 CRITICAL |

| **Entropy** | 6.81/8 |

| **YARA Matches** | 97 |

| **Behavioral Indicators** | 82 |

| **IOCs Extracted** | 1295 |



## 🤖 AI-Generated Analysis Explanation

---




## Classification
This file has been classified as **malware** with 95.0% confidence.

## Behavioral Analysis

**Information Stealer**: This file appears to be designed to steal sensitive information such as credentials, cryptocurrency wallets, or personal data.
**Process Injection**: The file uses advanced injection techniques to inject malicious code into legitimate processes, likely to evade detection.
**Keylogger**: The file monitors and records keyboard input, potentially capturing passwords and sensitive information.
**C2 Communication**: The file establishes communication with command and control (C2) servers, indicating it may be part of a botnet or remote access trojan.
**Persistence Mechanisms**: The file implements persistence techniques to ensure it remains on the system after reboot.
**Evasion Techniques**: The file uses anti-analysis and evasion techniques to avoid detection by security tools.
**Cryptocurrency Miner**: The file appears to be a cryptocurrency mining malware that uses system resources to mine digital currency.
**Banking Trojan**: This file targets banking credentials and financial information through form grabbing or browser manipulation.
**Spyware**: The file monitors user activity and collects information without consent.

## Critical Indicators

- **Technique_ReflectiveDLL**: Reflective DLL loading
- **Technique_AtomBombing**: AtomBombing injection technique
- **Injection_ThreadHijacking**: Thread hijacking injection technique
- **Injection_APC**: Asynchronous Procedure Call injection
- **Injection_ModuleStomping**: Module Stomping injection technique

## Network Activity

The file attempts to contact 512 domain(s), indicating potential C2 communication or data exfiltration.
The file connects to 5 IP address(es), suggesting remote server communication.

## Obfuscation

The file is packed or obfuscated using: Themida, VMProtect, RLPack. This is commonly used by malware authors to evade detection.

## File Characteristics

This is a PE file with a size of 49.90 MB.
The file has a high threat score of 100/100, indicating significant malicious behavior.
The file attempts to access Discord token storage, suggesting it may steal Discord authentication tokens.

## Obfuscation Analysis

The file contains 8 obfuscated or encoded strings, suggesting the authors attempted to hide malicious functionality.

## Summary

This malware is designed for information theft, remote control by attackers, keyboard monitoring and cryptocurrency mining. It should be considered highly dangerous and removed immediately.



## 🔐 File Hashes

---

| Hash Type | Value |

|-----------|-------|

| **MD5** | `de3e8cb9d95f781861a229eb8c25bc32` |

| **SHA1** | `872eca8849f58e5eadf6a2bbdf2c8772309710e0` |

| **SHA256** | `4b1bf3981557d9872b0a4e19261d228d83a2a21d1c618fc611f652a095a8a162` |

| **SHA512** | `718724cc59e32cb2122953e7c0b546fd9f229e37fe6dd30114a7471579ee876156b5b799dbccc74d2b636509fc195f802ebda2f6dcb193ca6b4a31969294bf5b` |

| **ImpHash** | `3b923c820aefc79da51dab58507ee3af` |



## 🎭 Behavioral Analysis

---

### 🔓 Information Stealers (1 detections)

| Rule | Severity | Description |

|------|----------|-------------|

| `InfoStealer_Generic_Roblox` | **MEDIUM** | Roblox credential extraction |



### 💉 Process Injection (18 detections)

| Rule | Severity | Description |

|------|----------|-------------|

| `Injection_Shellcode` | **HIGH** | Typical shellcode loading patterns |

| `Injection_ThreadHijacking` | **CRITICAL** | Thread hijacking injection technique |

| `Injection_APC` | **CRITICAL** | Asynchronous Procedure Call injection |

| `Injection_ModuleStomping` | **CRITICAL** | Module Stomping injection technique |

| `Injection_DLL_Sideloading` | **HIGH** | DLL sideloading injection |

| `Injection_TransactedHollowing` | **CRITICAL** | Transacted Hollowing technique |

| `Injection_Loader_Generic` | **HIGH** | Generic loader injection patterns |

| `Injection_Loader_Shellcode` | **CRITICAL** | Shellcode loader patterns |

| `Injection_Hollowing_Advanced` | **CRITICAL** | Advanced process hollowing techniques |

| `Evasion_CodeInjection_Detection` | **HIGH** | Evasion of code injection detection |



### 🛡️ Evasion & Stealth (25 detections)

| Rule | Severity | Description |

|------|----------|-------------|

| `Suspicious_AntiDebug` | **HIGH** | Contains anti-debugging techniques |

| `Anti_Forensics_Evasion` | **HIGH** | Sandbox and VM detection patterns |

| `Timing_Attack` | **MEDIUM** | Detected timing-based sandbox evasion |

| `Evasion_Sleep` | **MEDIUM** | Sleep-based sandbox evasion |

| `Evasion_UserCheck` | **MEDIUM** | User interaction checks |

| `Evasion_FileSystem` | **MEDIUM** | File system-based evasion |

| `Evasion_Network` | **MEDIUM** | Network-based evasion checks |

| `Evasion_AntiVM_Advanced` | **HIGH** | Advanced anti-VM detection techniques |

| `Evasion_AntiVM_MAC` | **HIGH** | VM detection via MAC address |

| `Evasion_AntiVM_Registry` | **HIGH** | VM detection via registry keys |



### 📜 Script Malice (20 detections)

| Rule | Severity | Description |

|------|----------|-------------|

| `LOLBin_Abuse` | **HIGH** | Abuse of legitimate Windows binaries (LOLBins) |

| `Script_Malice` | **MEDIUM** | Malicious script execution patterns (VBS/JS) |

| `Script_Malice_VBS` | **HIGH** | VBScript malicious execution patterns |

| `Script_Malice_HTA` | **HIGH** | HTA (HTML Application) malicious patterns |

| `Script_Malice_JScript` | **HIGH** | JScript malicious execution patterns |

| `Script_Malice_Mshta` | **HIGH** | Mshta script execution |

| `Script_Malice_Rundll32` | **HIGH** | Rundll32 script execution |

| `Script_Malice_BitsAdmin` | **HIGH** | BitsAdmin LOLBin abuse |

| `Script_Malice_InstallUtil` | **HIGH** | InstallUtil.exe abuse |

| `Script_Malice_Obfuscation` | **MEDIUM** | Script obfuscation patterns |



## 🎯 YARA Rule Matches

---

**Total Matches:** 97


| Rule | Severity | Description | Patterns Matched |

|------|----------|-------------|------------------|

| `Suspicious_PowerShell` | **MEDIUM** | Contains PowerShell execution patterns... | IEX |

| `Suspicious_Network` | **LOW** | Contains network-related API calls... | WSAStartup, socket |

| `Suspicious_Process` | **MEDIUM** | Contains process manipulation patterns... | CreateProcess, ShellExecute, VirtualAllocEx (+1 mo |

| `Suspicious_Registry` | **LOW** | Contains registry manipulation patterns... | RegSetValue, RegCreateKey, RegDeleteKey |

| `Suspicious_AntiDebug` | **HIGH** | Contains anti-debugging techniques... | IsDebuggerPresent, NtQueryInformationProcess, Outp |

| `Suspicious_Crypto` | **LOW** | Contains cryptographic API patterns... | CryptDecrypt, CryptAcquireContext, AES |

| `Suspicious_Keylogger` | **HIGH** | Contains keylogging patterns... | GetAsyncKeyState, GetKeyState, SetWindowsHookEx (+ |

| `Suspicious_Screenshot` | **MEDIUM** | Contains screenshot capture patterns... | GetDC, BitBlt, GetDesktopWindow (+1 more) |

| `Suspicious_Persistence` | **HIGH** | Contains persistence mechanism patterns... | startup |

| `Injection_Shellcode` | **HIGH** | Typical shellcode loading patterns... | VirtualAlloc, VirtualAllocEx, CreateThread (+4 mor |

| `Clipboard_Hijacker` | **HIGH** | Crypto address clipboard hijacking patterns... | GetClipboardData, SetClipboardData, OpenClipboard  |

| `Anti_Forensics_Evasion` | **HIGH** | Sandbox and VM detection patterns... | 00:05:69, 00:0C:29, 00:50:56 (+3 more) |

| `Timing_Attack` | **MEDIUM** | Detected timing-based sandbox evasion... | GetTickCount, QueryPerformanceCounter, Sleep (+1 m |

| `LOLBin_Abuse` | **HIGH** | Abuse of legitimate Windows binaries (LOLBins)... | certutil, /transfer, /s |

| `Script_Malice` | **MEDIUM** | Malicious script execution patterns (VBS/JS)... | unescape( |

| `HackTool_Adhesive` | **HIGH** | Adhesive DLL or string indicators... | adhesive |

| `Packer_Themida` | **HIGH** | Themida protector... | .themida, themida |

| `Obfuscation_ControlFlow` | **MEDIUM** | Control flow obfuscation patterns... | jmp, call |

| `Persistence_ScheduledTask` | **HIGH** | Scheduled task persistence... | /create, /tn, /tr |

| `Persistence_Service` | **HIGH** | Windows service persistence... | CreateService, OpenService, StartService (+2 more) |

| `Persistence_Startup` | **HIGH** | Startup folder persistence... | Startup, SHGetSpecialFolderPath |

| `Evasion_Sleep` | **MEDIUM** | Sleep-based sandbox evasion... | Sleep, SleepEx, WaitForSingleObject |

| `Evasion_UserCheck` | **MEDIUM** | User interaction checks... | GetForegroundWindow, GetCursorPos, GetAsyncKeyStat |

| `Evasion_FileSystem` | **MEDIUM** | File system-based evasion... | GetLogicalDrives, GetDriveType, GetDiskFreeSpace ( |

| `Evasion_Network` | **MEDIUM** | Network-based evasion checks... | GetAdaptersInfo, GetHostByName, gethostname |

| `Miner_Crypto` | **HIGH** | Cryptocurrency miner indicators... | mining, pool |

| `Technique_DLL_Sideloading` | **HIGH** | DLL sideloading patterns... | LoadLibrary, GetProcAddress |

| `Technique_ReflectiveDLL` | **CRITICAL** | Reflective DLL loading... | RDI, LoadLibraryA |

| `Technique_AtomBombing` | **CRITICAL** | AtomBombing injection technique... | SetWindowsHookEx, CallNextHookEx |

| `Injection_ThreadHijacking` | **CRITICAL** | Thread hijacking injection technique... | ResumeThread, VirtualAllocEx, VirtualAlloc (+3 mor |



## 🔍 Indicators of Compromise (IOCs)

---

### 🌐 Network IOCs

**IP Addresses (5):**

- `1.3.6.1`

- `1.1.1.1`

- `1.2.1.1`

- `4.112.5.4`

- `5.4.102.5`



**Domains (512):**

- `gopkg.in`

- `charclass.go`

- `deepequal.go`

- `www.dearimgui.org`

- `interfaces.go`

- `image.rectangle.in`

- `0getclipboarddatasetclipboarddatamc.echo.ac`

- `utf16.go`

- `pen.go`

- `env.go`

- `nat.go`

- `asn1.bitstringencoder.len`

- `i`

- `mheap.go`

- `eq.www.velocidex.com`

- `uxtheme.go`

- `http.header.del`

- `image.rectangle.sub`

- `tokenstream.go`

- `mbarrier.go`

- *... and 492 more*



**URLs (22):**

- `http://applicationslink`

- `https://github.com/tokotype/PlusJakartaSans)`

- `http://Descriptionrelatively`

- `http://schemas.microsoft.com/SMI/2016/WindowsSettings`

- `http://crl.sectigo.com/SectigoPublicCodeSigningCAEVR36.crl0`

- `https://scripts.sil.org/OFL`

- `http://www.dearimgui.org/faq/`

- `http://crt.sectigo.com/SectigoPublicCodeSigningRootR46.p7c0#`

- `https://dl.echo.ac/freeHARDWARE_PROFILE_CHANGEbuffer_full_drop_oldestbuffer_full...`

- `https://ico.org.uk/.`

- `http://www.hortcut`

- `http://i`

- `http://interpreted`

- `http://mathematicsmargin-top:eventually`

- `http://www.language=`

- *... and 7 more*



### 📁 File IOCs

**Filenames (57):**

- `VBoxMouse.sysc`

- `prlmouse.sysc`

- `api-ms-win-crt-stdio-l1-1-0.dll`

- `stages.MagnifyAnimation.RenderAnimation`

- `stages.CogsAnimation.RenderAnimation`

- `slides.HideEntry`

- `scanning.go`

- `qemupciserial.sysError`

- `debug.go`

- `slides.HideScanning`

- `api-ms-win-crt-private-l1-1-0.dll`

- `arrows.go`

- `stages.CogsAnimation.HideAnimation`

- `stages.TriggerStageAnimation`

- `vboxservice.exec`

- `api-ms-win-crt-heap-l1-1-0.dll`

- `stages.ArrowsAnimation.TriggerAnimation`

- `OPENGL32.dll`

- `exec.c`

- `time.c`



## 📦 Packer Detection

---

| Packer/Protector |

|------------------|

| 🔴 **Themida** |

| 🔴 **VMProtect** |

| 🔴 **RLPack** |

| 🔴 **FSG** |

| 🔴 **MPRESS** |

| 🔴 **Yoda's Protector** |

| 🔴 **MEW** |

| 🔴 **PEX** |



## 📝 Strings Analysis

---

**Total Strings Extracted:** 50000


### URLs (21)

- `environmental to prevent thehave been usedespecially forunderstand theis essentiallywere the firstis...`

- `:http://crt.sectigo.com/SectigoPublicCodeSigningRootR46.p7c0#`

- `<script type="t<a href='http://www.hortcut icon" href="</div>`

- `<div id="illustratedengineeringterritoriesauthoritiesdistributed6" height="sans-serif;capable of dis...`

- `https://scripts.sil.org/OFL`

- `the current g is not g0schedule: holding locksprocresize: invalid argspan has no free stacksstack gr...`

- `nconformidadline-height:font-family:" : "http://applicationslink" href="specifically//<![CDATA[`

- `Copyright 2020 The Plus Jakarta Sans Project Authors (https://github.com/tokotype/PlusJakartaSans)`

- `such as the influence ofa particularsrc='http://navigation" half of the substantial &nbsp;</div>adva...`

- `<li><a href="http://ator" aria-hidden="tru> <a href="http://www.language="javascript" /option>`



### IP Addresses (6)

- `ArmenianBalineseBopomofoBugineseCherokeeCyrillicDuployanEthiopicGeorgianGujaratiGurmukhiHiraganaJavaneseKatakanaKayah_LiLinear_ALinear_BMahajaniOl_ChikiPhags_PaTagbanwaTai_ThamTai_VietTifinaghUgariticVithkuqiExtenderConfirm?SYN_SENTLAST_ACKEqualSidSetEventIsWindowrecvfromSHA1-RSADSA-SHA1DNS nameenvelopeCategorycriticalCurveID(finishedexecutedUserDataevent_idrtp1.sysrtp2.sys secondsGloriouslog file\|\|\|\|PathhashExitcodesettingsDumping Skipped isRobloxfileSizeprefetchmetadataparseWERreadFileplatformmulti_szlanguageusernameInPixelsProcName\LabyModOptiFineoptifineversions/LabyModprofileskernel32lstrcpyWClassANYQuestionfilenameReceivedif-matchlocationif-rangeNO_PROXYno_proxyInstFailInstRune[:word:]MD5+SHA1SHA3-224SHA3-256SHA3-384SHA3-512SHA2-256SHA2-512DwmFlushAbortDocDeleteDCMoveToExResetDCWlstrlenWoleaut32SetFocusCopyRectPtInRectDrawIconFillRectEndPaintSetTimer2.5.4.102.5.4.112.5.4.17ECDH PCT#fips140CTR_DRBGGOMIPS64rva20u64rva22u64rva23u64.satconv.signextmips64leTypeSpecexporterXButton1XButton2SnapshotMultiplySubtractLControlRControlVolumeUpOEMCommaOEMMinusOEMClearAlt+CtrlLoadIconWalkSyncWSAHtonlWSAHtonsWSANtohlWSANtohsVarRoundVarCyAddVarCyMulVarCySubVarCyAbsVarCyFixVarCyIntVarCyNegVarCyCmpVarR8PowCodeViewReservedFieldPtrParamPtrConstantEventMapEventPtrPropertyFieldRVAAssemblyResourceSecurity_?@$()<>ndis.sysAbsoluteLao (lo)Lnk InfoNotPagedReadableWritablechecksumcertutilOverflow%s-%s-%dERROR - ElfFile`

- `1.3.6.1.4.1.311.2.1.12`

- `crypto/tls.(*certificateMsgTLS13).marshal.func1.marshalCertificate.1.2.1.1`

- `crypto/tls.(*encryptedExtensionsMsg).marshal.func1.1.1.1.1`

- `1.3.6.1.4.1.311.3.3.1`

- `1.3.6.1.4.1.311.2.4.1`



### Suspicious Strings (1010)

- `EVP_PKEY_verify_init`

- `do_pk8pkey`

- `*x509.ExtKeyUsage`

- `github.com/dop251/goja.(*baseJsFuncObject).iterateKeys`

- `setAttr-Token-EMV`

- `8*[8]struct { key string; elem *imgui.MarkdownImageData }`

- `%*struct { key walk.Key; elem string }`

- `gopkg.in/yaml%2ev3.yaml_parser_parse_flow_sequence_entry_mapping_key`

- `crypto/tls.(*Config).encryptTicket`

- `sync/atomic.(*Pointer[go.shape.struct { internal/sync.node = internal/sync.node[...`

- `no time stamp token`

- `crypto/tls.(*encryptedExtensionsMsg).marshal.func1.1.2`

- `)*[]struct { key string; elem *yaml.Node }`

- `keyEncipherment`

- `*func(walk.KeyEventHandler)`

- `crypto/internal/fips140/ecdh.GenerateKey[go.shape.*crypto/internal/fips140/niste...`

- `Starting Echo...invalid exchangeno route to hostinvalid argumentmessage too long...`

- ` Off_CM_KEY_NODE_VirtControlFlags`

- `*goja.binding`

- `crypto/internal/fips140/rsa.checkPublicKey`



## 🔓 Decoded Strings

---

**Total Decoded:** 8


### URL Encoded (2)

| Original | Decoded |

|----------|---------|

| `gopkg.in/yaml%2ev3.yaml_parser_parse_flow_sequence_entry_map...` | `gopkg.in/yaml.v3.yaml_parser_parse_flow_sequence_entry_mapping_key` |

| `gopkg.in/yaml%2ev3.keyList.Swap` | `gopkg.in/yaml.v3.keyList.Swap` |



### Leet Speak (3)

| Original | Decoded |

|----------|---------|

| `syscall.LoadConnectEx.func1.deferwrap1` | `syscall.loadconnectex.funci.deferwrapi` |

| `quer.csssickmeatmin.binddellhirepicsrent:36ZHTTP-201fotowolf...` | `quer.csssickmeatmin.binddellhirepicsrent:e6zhttp-zoifotowolfend xbox:sazbodydick...` |

| `4*struct { F uintptr; R *http.socksUsernamePassword }` | `a*struct { f uintptr; r *http.socksusernamepassword }` |



### ROT13 (2)

| Original | Decoded |

|----------|---------|

| `assertion failed: nkey <= EVP_MAX_KEY_LENGTH` | `nffregvba snvyrq: axrl <= RIC_ZNK_XRL_YRATGU` |

| `github.com/dop251/goja.(*regExpStringIterObject).defineOwnPr...` | `tvguho.pbz/qbc251/tbwn.(*ertRkcFgevatVgreBowrpg).qrsvarBjaCebcreglFge` |



### Base64 Encoded (1)

| Original | Decoded |

|----------|---------|

| `createFunctionBindings` | `rnbpbا` |



## 🏷️ Tags

---

`Evas/Anti-VM` `Miner` `Persistence` `Rootkit` `Hooking` `Stealer` `Malicious Script` `Banking Trojan` `Spyware` `Adhesive` `C2/RAT` `High Risk` `Worm` `Fileless` `Loader` `Keylogger`



---



**Report Generated:** 2026-01-15 22:42:41  

**Generated by:** Malware Analysis Platform  



*This report contains indicators of compromise and should be handled with appropriate security measures.*
