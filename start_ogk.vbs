Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' Tự động lấy thư mục gốc dự án (nơi đặt file .vbs này)
projDir = fso.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = projDir

py = """" & projDir & "\.venv\Scripts\python.exe"""

' 1. OGK-Server
cmdServer = py & " -m server.app.main"

' 2. OGK-Agent
cmdAgent  = py & " -m agent.src.service.windows_service --console"

' 3. OGK Tray UI
cmdTray   = py & " -m agent.src.tray.tray_app"

' Chạy ẩn hoàn toàn (số 0 = ẩn cửa sổ CMD)
WshShell.Run cmdServer, 0, False
WScript.Sleep 2500  ' Đợi 2.5 giây cho Server khởi động xong

WshShell.Run cmdAgent, 0, False
WScript.Sleep 1500  ' Đợi 1.5 giây cho Agent mở cổng IPC

WshShell.Run cmdTray, 0, False

' (Tuỳ chọn) Mở sẵn trình duyệt vào trang Dashboard
WshShell.Run "https://127.0.0.1:8443/dashboard", 1, False