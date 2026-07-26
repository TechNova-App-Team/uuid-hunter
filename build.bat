@echo off
setlocal

rem Immer im Ordner dieser .bat arbeiten - beim Doppelklick ist das
rem Arbeitsverzeichnis sonst ein anderes und cl findet die Quelldatei nicht.
cd /d "%~dp0"

echo.
echo   UUID Collision Hunter - Build
echo   -----------------------------
echo.

if not exist "%~dp0uuid_collision.cpp" (
  echo   [!] uuid_collision.cpp nicht gefunden in:
  echo       %~dp0
  goto :fail
)

rem --- MSVC-Umgebung suchen ---------------------------------------------
rem Erst der bekannte Pfad, sonst vswhere fragen. Ohne verschachtelte
rem if-Bloecke, weil "Program Files (x86)" Klammern enthaelt und die einen
rem Block vorzeitig beenden wuerden.

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if exist "%VCVARS%" goto :havevcvars

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :novcvars

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualCpp.Tools.Host.x64 -property installationPath`) do set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
if exist "%VCVARS%" goto :havevcvars

:novcvars
echo   [!] vcvars64.bat nicht gefunden.
echo       Visual Studio Build Tools mit C++-Workload installiert?
goto :fail

:havevcvars
echo   Lade MSVC-Umgebung ...
rem stderr mit unterdruecken - die VS-Skripte melden harmlos fehlendes vswhere
call "%VCVARS%" >nul 2>&1

rem vcvars kann das Arbeitsverzeichnis wechseln - zurueck zur Quelle
cd /d "%~dp0"

where cl.exe >nul 2>&1
if errorlevel 1 (
  echo   [!] cl.exe steht nach vcvars64.bat nicht zur Verfuegung.
  goto :fail
)

rem --- Kompilieren -------------------------------------------------------
echo   Kompiliere ...
echo.

cl /nologo /std:c++20 /O2 /Oi /Ot /GL /EHsc /DNDEBUG /arch:AVX2 ^
   /Fe:"%~dp0uuid_collision.exe" "%~dp0uuid_collision.cpp" /link /LTCG

if errorlevel 1 goto :fail

del /q "%~dp0uuid_collision.obj" >nul 2>&1

echo.
echo   [+] Fertig: %~dp0uuid_collision.exe
echo.
echo   Starten zum Beispiel mit:
echo       .\uuid_collision.exe --ladder
echo       .\uuid_collision.exe --bits 44
echo.
echo   Das ".\" ist in PowerShell Pflicht - es fuehrt Programme aus dem
echo   aktuellen Ordner sonst nicht aus.
echo.
goto :done

:fail
echo.
echo   [!] Build fehlgeschlagen.
echo.
if /i not "%~1"=="nopause" pause
exit /b 1

:done
if /i not "%~1"=="nopause" pause
exit /b 0
