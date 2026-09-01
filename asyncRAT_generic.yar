rule APT_CRIME_MAL_AsyncRAT_Generic
{
    meta:
        author      = "LDAL"
        date        = "2026-09-01"
        version     = "1.0"
        description = "AsyncRAT  - deteccion generica (disco y memoria)"
        family      = "AsyncRAT"
        malware_type = "RAT"
        tlp         = "CLEAR"
        confidence  = "medium-high"
        scope       = "hunting, dfir, memoria"
        type:       = "CS"

    strings:
        // ---- Indicadores fuertes: ----
        $f1 = "AsyncMutex_6SI8OkPnk"  ascii wide nocase   
        $f2 = "AsyncRAT"              ascii wide nocase
        $f3 = "AsyncClient"           ascii wide nocase
        $f4 = "Anti_Analysis"         ascii wide           

        // ---- Campos de configuracion (Client/Settings.cs) ----
        $c1 = "Serversignature"       ascii wide
        $c2 = "ServerCertificate"     ascii wide
        $c3 = "Pastebin"              ascii wide
        $c4 = "BDOS"                  ascii wide
        $c5 = "InstallFolder"         ascii wide
        $c6 = "InstallFile"           ascii wide
        $c7 = "Aes256"                ascii wide           
        $c8 = "MsgPack"               ascii wide           
        $c9 = "Hwid"                  ascii wide

        // ---- Anti-analisis y persistencia ----
        $a1 = "DetectSandboxie"       ascii wide
        $a2 = "DetectVirtualMachine"  ascii wide
        $a3 = "DetectDebugger"        ascii wide
        $a4 = "SbieDll.dll"           ascii wide nocase
        $a5 = "Select * from Win32_ComputerSystem" ascii wide nocase
        $a6 = "/create /f /sc onlogon /rl highest /tn" ascii wide nocase

        // ---- Falsos positivos conocidos ----
        $fp1 = "AsyncRAT-C-Sharp"     ascii wide
        $fp2 = "<PackageReference"    ascii wide

    condition:
        ( uint16(0) != 0x5A4D or filesize < 15MB )
        and not any of ($fp*)
        and
        (
            // 1 indicador fuerte + 2 campos de configuracion
            ( 1 of ($f*) and 2 of ($c*) )
            or
            // sin indicador fuerte: exigir mas contexto de config + anti-analisis
            ( 4 of ($c*) and 2 of ($a*) )
            or
            // bloque de anti-analisis completo de AsyncRAT
            ( all of ($a1, $a2, $a3) and 1 of ($c*) )
        )
}
