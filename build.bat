@echo off
rem ============================================================
rem  build.bat  -  peres + peview  (MinGW-W64)
rem  Pure C + Win32 API, no CRT (-nostdlib)
rem  Requires gcc on PATH.
rem ============================================================

set CFLAGS=-O2 -std=c11 -Wall -Wextra -Wno-unused-parameter -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident
set LFLAGS=-nostdlib -mwindows -Wl,--entry=WinMainCRTStartup -Wl,--subsystem,windows -Wl,--dynamicbase -Wl,--nxcompat -s
set LIBS=-lkernel32 -luser32 -lgdi32 -lcomdlg32 -lshell32 -lole32 -lversion -lcrypt32 -lwintrust -ladvapi32

if not exist release mkdir release

rem ---- peres.exe (PE resource injector) ----
set PERES_SRC=common\util.c common\buffer.c peres\version.c peres\pe.c peres\log.c peres\rescol.c peres\sign.c peres\updater.c peres\inject.c peres\ui.c peres\cli.c peres\main.c
gcc %CFLAGS% -Icommon -o release\peres.exe %PERES_SRC% %LFLAGS% %LIBS%
if errorlevel 1 goto :err
echo [OK] release\peres.exe

rem ---- peview.exe (PE viewer) ----
set VIEW_SRC=common\util.c common\buffer.c peview\peview_pe.c peview\peview_enum.c peview\peview_sigscan.c peview\peview_ui.c peview\peview_main.c
gcc %CFLAGS% -Icommon -o release\peview.exe %VIEW_SRC% %LFLAGS% %LIBS%
if errorlevel 1 goto :err
echo [OK] release\peview.exe
goto :end

:err
echo [FAIL] build failed
exit /b 1
:end