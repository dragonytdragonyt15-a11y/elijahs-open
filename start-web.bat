@echo off
cd /d "%~dp0"
if not exist node_modules call npm install
set /p PASSWORD=Choose a password for your site: 
start "tunnel" cmd /k cloudflared tunnel --url http://localhost:3000
node server.js
pause
