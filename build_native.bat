@echo off
cd /d "%~dp0"
title Build Native Windows OTP Helper

echo ============================================
echo   Building Native Windows OTP Helper (.NET)
echo ============================================
echo.

:: Hentikan proses OTP-Helper.exe yang sedang berjalan agar file tidak terkunci
taskkill /f /im OTP-Helper.exe >nul 2>&1
timeout /t 1 /nobreak >nul

if exist "OTP-Helper.exe" del /f /q "OTP-Helper.exe" >nul 2>&1
if exist "disuntikkan" del /f /q "disuntikkan" >nul 2>&1

set "CSC="
if exist "%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" (
    set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
) else if exist "%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe" (
    set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)

if "%CSC%"=="" (
    echo [ERROR] Compiler csc.exe tidak ditemukan di Windows.
    pause
    exit /b 1
)

:: Konversi logo.png ke format Win32 logo.ico agar muncul di File Explorer
set "WINICON="
set "RES="
if exist "logo.png" (
    echo [ICON] Mengemas icon untuk Windows File Explorer...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$b=[IO.File]::ReadAllBytes('logo.png'); $ms=New-Object IO.MemoryStream; $w=New-Object IO.BinaryWriter($ms); $w.Write([byte[]]@(0,0,1,0,1,0,0,0,0,0,1,0,32,0)); $w.Write([int]$b.Length); $w.Write([int]22); $w.Write($b,0,$b.Length); [IO.File]::WriteAllBytes('logo.ico',$ms.ToArray())" >nul 2>&1
    if exist "logo.ico" (
        set "WINICON=/win32icon:logo.ico"
    )
    set "RES=/resource:logo.png"
)

echo [1/2] Mengompilasi Program.cs via csc.exe...
"%CSC%" /target:winexe /platform:anycpu /optimize+ /out:OTP-Helper.exe %WINICON% %RES% /r:System.dll,System.Windows.Forms.dll,System.Drawing.dll Program.cs

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Kompilasi gagal!
    pause
    exit /b 1
)

echo.
echo [2/2] Sukses! File biner standalone:
for %%I in (OTP-Helper.exe) do echo [BERHASIL] OTP-Helper.exe siap (Ukuran: %%~zI bytes)
echo.
echo Meluncurkan OTP-Helper.exe...
start "" "%~dp0OTP-Helper.exe"
