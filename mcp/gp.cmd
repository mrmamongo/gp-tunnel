@echo off
rem Thin wrapper so `gp <cmd>` works from any shell once mcp\ is on PATH.
python "%~dp0gp.py" %*
