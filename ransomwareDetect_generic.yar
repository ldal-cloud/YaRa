rule CRIME_MAL_Ransomware_Generic_Behavior
{
    meta:
        author       = "LDAL"
        date         = "2026-09-02"
        version      = "1.0"
        description  = "Ransomware de cifrado - deteccion generica por comportamiento"
        family       = "generic"
        malware_type = "ransomware"
        tlp          = "CLEAR"
        confidence   = "medium"
        scope        = "hunting, dfir, memoria"
        attck        = "T1486, T1490, T1489, T1083, T1135"
 
    strings:
        // ---- Pilar 1: destruccion de mecanismos de recuperacion (T1490) ----
        $d1  = "vssadmin" ascii wide nocase
        $d2  = "delete shadows" ascii wide nocase
        $d3  = "shadowcopy delete" ascii wide nocase
        $d4  = "Win32_ShadowCopy" ascii wide nocase
        $d5  = "bcdedit" ascii wide nocase
        $d6  = "recoveryenabled no" ascii wide nocase
        $d7  = "bootstatuspolicy ignoreallfailures" ascii wide nocase
        $d8  = "wbadmin" ascii wide nocase
        $d9  = "delete catalog" ascii wide nocase
        $d10 = "delete systemstatebackup" ascii wide nocase
        $d11 = "wevtutil" ascii wide nocase
        $d12 = "fsutil usn deletejournal" ascii wide nocase
        $d13 = "resize shadowstorage" ascii wide nocase
        $d14 = "SHEmptyRecycleBin" ascii wide
 
        // ---- Pilar 2: primitivas criptograficas de cifrado masivo (T1486) ----
        $c1  = "CryptAcquireContext" ascii wide
        $c2  = "CryptGenRandom" ascii wide
        $c3  = "CryptEncrypt" ascii wide
        $c4  = "CryptImportKey" ascii wide
        $c5  = "CryptDeriveKey" ascii wide
        $c6  = "BCryptGenerateSymmetricKey" ascii wide
        $c7  = "BCryptEncrypt" ascii wide
        $c8  = "RtlGenRandom" ascii wide
        $c9  = "expand 32-byte k" ascii wide          
        $c10 = "expand 16-byte k" ascii wide          
        $c11 = "-----BEGIN PUBLIC KEY-----" ascii wide
        $c12 = "-----BEGIN RSA PUBLIC KEY-----" ascii wide
        $c13 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }   
        $c14 = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }   
 
        // ---- Pilar 3: enumeracion masiva de ficheros, volumenes y red ----
        $e1  = "FindFirstFileW" ascii wide
        $e2  = "FindNextFileW" ascii wide
        $e3  = "GetLogicalDriveStringsW" ascii wide
        $e4  = "GetDriveTypeW" ascii wide
        $e5  = "SetFileAttributesW" ascii wide
        $e6  = "MoveFileExW" ascii wide
        $e7  = "WNetOpenEnumW" ascii wide
        $e8  = "WNetEnumResourceW" ascii wide
        $e9  = "NetShareEnum" ascii wide
        $e10 = "SetFilePointerEx" ascii wide
        $e11 = "FindFirstVolumeW" ascii wide
        $e12 = "GetVolumePathNamesForVolumeNameW" ascii wide
        $e13 = "DeviceIoControl" ascii wide
 
        // ---- Pilar 4: terminacion de servicios y procesos que bloquean ficheros (T1489) ----
        $k1  = "taskkill" ascii wide nocase
        $k2  = "net stop" ascii wide nocase
        $k3  = "sc.exe config" ascii wide nocase
        $k4  = "sqlservr.exe" ascii wide nocase
        $k5  = "sqlwriter.exe" ascii wide nocase
        $k6  = "veeam" ascii wide nocase
        $k7  = "backupexec" ascii wide nocase
        $k8  = "MSExchange" ascii wide nocase
        $k9  = "RestartManager" ascii wide nocase
        $k10 = "RmStartSession" ascii wide             
        $k11 = "RmGetList" ascii wide
        $k12 = "OpenSCManagerW" ascii wide
        $k13 = "ControlService" ascii wide
        $k14 = "memtas" ascii wide nocase             
        $k15 = "svc$" ascii wide nocase
 
        // ---- Pilar 5: nota de rescate y canal de contacto embebidos en el binario ----
        $n1  = "your files have been encrypted" ascii wide nocase
        $n2  = "all your files" ascii wide nocase
        $n3  = "have been encrypted" ascii wide nocase
        $n4  = "sus archivos han sido cifrados" ascii wide nocase
        $n5  = "decryptor" ascii wide nocase
        $n6  = "decryption key" ascii wide nocase
        $n7  = "how to decrypt" ascii wide nocase
        $n8  = "restore your files" ascii wide nocase
        $n9  = "recover your data" ascii wide nocase
        $n10 = "do not rename" ascii wide nocase
        $n11 = "personal id" ascii wide nocase
        $n12 = "unique id" ascii wide nocase
        $n13 = ".onion" ascii wide nocase
        $n14 = "tor browser" ascii wide nocase
        $n15 = "torproject.org" ascii wide nocase
        $n16 = "bitcoin" ascii wide nocase
        $n17 = "README" ascii wide
        $n18 = "HOW_TO" ascii wide nocase
 
        // ---- Exclusiones: fuentes, documentacion y herramientas legitimas ----
        $fp1 = "<PackageReference" ascii wide
        $fp2 = "SPDX-License-Identifier" ascii wide
        $fp3 = "Veeam Software Group" ascii wide
        $fp4 = "Acronis International" ascii wide
        $fp5 = "Microsoft Corporation. All rights reserved" ascii wide
        $fp6 = "yara-rules" ascii wide nocase
        $fp7 = "MITRE ATT&CK" ascii wide nocase
        $fp8 = "#!/bin/" ascii
 
    condition:
        // Sin exigir MZ: cubre volcados de memoria, secciones extraidas y payloads sin cabecera.
        ( uint16(0) != 0x5A4D or filesize < 20MB )
        and not any of ($fp*)
        and
        (
            // A) Anti-recuperacion explicita + criptografia: firma clasica del cifrador
            ( 3 of ($d*) and 2 of ($c*) )
            or
            // B) Anti-recuperacion + nota de rescate embebida
            ( 2 of ($d*) and 3 of ($n*) )
            or
            // C) Cifrado masivo: cripto + recorrido de disco/red + liberacion de handles
            ( 3 of ($c*) and 5 of ($e*) and 2 of ($k*) )
            or
            // D) Nota de rescate completa con canal de pago/contacto y algo de cripto
            ( 5 of ($n*) and 1 of ($n13, $n14, $n15, $n16) and 1 of ($c*) )
            or
            // E) Sabotaje de servicios y backups + cripto + enumeracion
            ( 2 of ($d*) and 3 of ($k*) and 2 of ($c*) and 3 of ($e*) )
        )
}
