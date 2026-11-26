@echo off
rem Panoptes installer for Windows.
rem Installs Panoptes into your Python (3.10+, from python.org or the Microsoft Store), builds the small
rem Panoptes.exe launcher and adds Desktop and Start Menu shortcuts. Same as build_exe.bat.
call "%~dp0build_exe.bat" %*
