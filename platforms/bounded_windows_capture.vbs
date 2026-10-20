Option Explicit

' Fixed, read-only command runner for the Windows capture batch. It deliberately
' accepts a command ID, never an executable or command line from the caller.
Const DEFAULT_TIMEOUT_SECONDS = 30
Const DEFAULT_MAX_BYTES = 2097152
Const MAX_TIMEOUT_SECONDS = 120
Const MAX_OUTPUT_BYTES = 8388608
Const POLL_MILLISECONDS = 25
Const CLEANUP_SECONDS = 5

Dim fso, sh, args, outputPath, commandId, timeoutSeconds, maxBytes, systemRoot
Dim commandText, sidecarPath, proc, started, elapsed, currentSize, timedOut, overLimit
Dim cleanupOK, resultCode, statusText, sizeError, sizeUnavailable

Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
Set args = WScript.Arguments
systemRoot = fso.GetSpecialFolder(0)

If args.Count < 2 Or args.Count > 4 Then WScript.Quit 2
outputPath = args(0)
commandId = LCase(args(1))
timeoutSeconds = DEFAULT_TIMEOUT_SECONDS
maxBytes = DEFAULT_MAX_BYTES
If args.Count >= 3 Then
  If Not IsPositiveInteger(args(2)) Then WScript.Quit 2
  timeoutSeconds = CLng(args(2))
End If
If args.Count >= 4 Then
  If Not IsPositiveInteger(args(3)) Then WScript.Quit 2
  maxBytes = CLng(args(3))
End If
If timeoutSeconds < 1 Or timeoutSeconds > MAX_TIMEOUT_SECONDS Then WScript.Quit 2
If maxBytes < 1024 Or maxBytes > MAX_OUTPUT_BYTES Then WScript.Quit 2
If Not SafeOutputPath(outputPath) Then WScript.Quit 2

commandText = CommandFor(commandId)
If commandText = "" Then WScript.Quit 2
sidecarPath = fso.BuildPath(fso.GetParentFolderName(outputPath), _
  fso.GetBaseName(outputPath) & ".exit-code.txt")

' Reserve both artifacts exclusively before starting any collector. Existing
' evidence is never replaced, even when a collector cannot start.
On Error Resume Next
Dim reservedOutput, reservedSidecar
Set reservedOutput = fso.CreateTextFile(outputPath, False, False)
If Err.Number <> 0 Then WScript.Quit 3
reservedOutput.Close
Err.Clear
Set reservedSidecar = fso.CreateTextFile(sidecarPath, False, False)
If Err.Number <> 0 Then WScript.Quit 3
reservedSidecar.Close
Err.Clear
On Error GoTo 0

' cmd performs only the fixed command above and redirects byteArray directly to
' the reserved file. Paths reject cmd metacharacters to prevent command injection.
Dim wrapped
wrapped = QuotePath(fso.BuildPath(systemRoot, "System32\cmd.exe")) & _
  " /d /s /c " & Chr(34) & commandText & _
  " > " & Chr(34) & outputPath & Chr(34) & " 2>&1" & Chr(34)
On Error Resume Next
Set proc = sh.Exec(wrapped)
If Err.Number <> 0 Then
  Err.Clear
  If Not WriteSidecar(sidecarPath, 127, "TOOL_START_FAILED") Then WScript.Quit 126
  WScript.Quit 127
End If
On Error GoTo 0

started = Timer
timedOut = False
overLimit = False
sizeUnavailable = False
Do While proc.Status = 0
  WScript.Sleep POLL_MILLISECONDS
  elapsed = Timer - started
  If elapsed < 0 Then elapsed = elapsed + 86400
  If Not TryGetFileSize(outputPath, currentSize, sizeError) Then
    sizeUnavailable = True
    Exit Do
  End If
  If currentSize > maxBytes Then
    overLimit = True
    Exit Do
  End If
  If elapsed >= timeoutSeconds Then
    timedOut = True
    Exit Do
  End If
Loop

' Catch a command that exits between polls after crossing the byte bound.
If Not timedOut And Not overLimit And Not sizeUnavailable Then
  If Not TryGetFileSize(outputPath, currentSize, sizeError) Then
    sizeUnavailable = True
  ElseIf currentSize > maxBytes Then
    overLimit = True
  End If
End If

If timedOut Or overLimit Or sizeUnavailable Then
  cleanupOK = StopProcessTree(proc.ProcessID)
  If Not cleanupOK Then
    resultCode = 126
    statusText = "CLEANUP_FAILED"
  ElseIf sizeUnavailable Then
    resultCode = 74
    statusText = "OUTPUT_SIZE_UNAVAILABLE"
  ElseIf timedOut Then
    resultCode = 124
    statusText = "TIMEOUT"
  Else
    resultCode = 125
    statusText = "OUTPUT_LIMIT_EXCEEDED"
  End If
Else
  resultCode = proc.ExitCode
  If resultCode = 9009 Then
    resultCode = 127
    statusText = "TOOL_MISSING"
  ElseIf resultCode = 0 Then
    statusText = "OK"
  Else
    statusText = "COMMAND_FAILED"
  End If
End If
If resultCode <> 74 And resultCode <> 124 And resultCode <> 125 And resultCode <> 126 Then
  Dim encodingResult, consoleCodePage
  consoleCodePage = QueryConsoleCodePage()
  encodingResult = NormalizeOutput(outputPath, commandId, consoleCodePage, maxBytes, started, timeoutSeconds)
  If encodingResult = "TIMEOUT" Then
    resultCode = 124
    statusText = "TIMEOUT"
  ElseIf encodingResult = "OUTPUT_LIMIT_EXCEEDED" Then
    resultCode = 125
    statusText = "OUTPUT_LIMIT_EXCEEDED"
    Call WriteUtf8Output(outputPath, "OUTPUT_LIMIT_EXCEEDED" & vbCrLf)
  ElseIf encodingResult = "OUTPUT_SIZE_UNAVAILABLE" Then
    resultCode = 74
    statusText = "OUTPUT_SIZE_UNAVAILABLE"
  ElseIf encodingResult <> "OK" Then
    resultCode = 65
    statusText = "PARSE_FAILED_ENCODING_UNKNOWN"
  End If
End If
If Not WriteSidecar(sidecarPath, resultCode, statusText) Then WScript.Quit 126
WScript.Quit resultCode

Function CommandFor(id)
  Dim sys32, wbem, powershellPath
  sys32 = fso.BuildPath(systemRoot, "System32")
  wbem = fso.BuildPath(sys32, "wbem")
  Select Case id
    Case "collection_time"
      powershellPath = fso.BuildPath(sys32, "WindowsPowerShell\v1.0\powershell.exe")
      If fso.FileExists(powershellPath) Then
        ' PowerShell is only a bounded, fixed UTC clock fallback for newer Windows
        ' images where WMIC is absent. This command does not inspect configuration.
        CommandFor = QuotePath(powershellPath) & " -NoLogo -NoProfile -NonInteractive -Command ""[DateTimeOffset]::UtcNow.ToString('o')"""
      Else
        ' Keep the legacy native source for Server 2008 and older PowerShell-less hosts.
        CommandFor = QuotePath(fso.BuildPath(wbem, "wmic.exe")) & " os get localdatetime /value"
      End If
    Case "os_detail": CommandFor = QuotePath(fso.BuildPath(wbem, "wmic.exe")) & " os get Caption,Version,OSArchitecture /value"
    Case "os_architecture": CommandFor = "echo PROCESSOR_ARCHITECTURE=%PROCESSOR_ARCHITECTURE% & echo PROCESSOR_ARCHITEW6432=%PROCESSOR_ARCHITEW6432%"
    Case "cpu": CommandFor = QuotePath(fso.BuildPath(wbem, "wmic.exe")) & " cpu get Name,NumberOfCores,NumberOfLogicalProcessors /value"
    Case "memory": CommandFor = QuotePath(fso.BuildPath(wbem, "wmic.exe")) & " computersystem get TotalPhysicalMemory /value"
    Case "graphics": CommandFor = QuotePath(fso.BuildPath(wbem, "wmic.exe")) & " path Win32_VideoController get Name,AdapterRAM /value"
    Case "disks": CommandFor = QuotePath(fso.BuildPath(wbem, "wmic.exe")) & " logicaldisk get DeviceID,FreeSpace,Size,FileSystem /value"
    Case "services": CommandFor = QuotePath(fso.BuildPath(sys32, "sc.exe")) & " query type= service state= all"
    Case "listeners": CommandFor = QuotePath(fso.BuildPath(sys32, "netstat.exe")) & " -ano"
    Case "firewall": CommandFor = QuotePath(fso.BuildPath(sys32, "netsh.exe")) & " advfirewall show allprofiles"
    Case "os": CommandFor = "ver"
    Case Else: CommandFor = ""
  End Select
End Function

Function QuotePath(path)
  QuotePath = Chr(34) & CStr(path) & Chr(34)
End Function

Function IsPositiveInteger(value)
  Dim s, i, c
  s = CStr(value)
  IsPositiveInteger = False
  If Len(s) = 0 Or Len(s) > 9 Then Exit Function
  For i = 1 To Len(s)
    c = Mid(s, i, 1)
    If c < "0" Or c > "9" Then Exit Function
  Next
  IsPositiveInteger = (CLng(s) > 0)
End Function

Function SafeOutputPath(path)
  Dim forbidden, i
  SafeOutputPath = False
  If Len(path) = 0 Then Exit Function
  If InStr(path, Chr(34)) > 0 Or InStr(path, vbCr) > 0 Or InStr(path, vbLf) > 0 Then Exit Function
  forbidden = Array("&", "|", "<", ">", "^", "%", "!", "(", ")")
  For i = 0 To UBound(forbidden)
    If InStr(path, forbidden(i)) > 0 Then Exit Function
  Next
  SafeOutputPath = True
End Function

Function TryGetFileSize(path, sizeValue, errorCode)
  Dim fileObject, fileStream
  TryGetFileSize = False
  sizeValue = -1
  errorCode = 0
  On Error Resume Next
  Err.Clear
  ' Refresh the cached directory-entry size; growing files may report a stale size until closed.
  ' See https://devblogs.microsoft.com/oldnewthing/20111226-00/?p=8813
  Set fileStream = fso.OpenTextFile(path, 1, False, 0)
  errorCode = Err.Number
  If errorCode = 0 Then
    Err.Clear
    fileStream.Close
    errorCode = Err.Number
  End If
  If errorCode = 0 Then
    Err.Clear
    Set fileObject = fso.GetFile(path)
    errorCode = Err.Number
  End If
  If errorCode = 0 Then
    Err.Clear
    sizeValue = fileObject.Size
    errorCode = Err.Number
  End If
  If errorCode = 0 Then TryGetFileSize = True
  Err.Clear
  On Error GoTo 0
End Function

Function ElapsedSeconds(startValue)
  Dim e
  e = Timer - startValue
  If e < 0 Then e = e + 86400
  ElapsedSeconds = e
End Function

Function QueryConsoleCodePage()
  Dim codePage, cpProc, startedAt, elapsed, output, rx, matches, cmdPath
  QueryConsoleCodePage = 0
  cmdPath = QuotePath(fso.BuildPath(systemRoot, "System32\cmd.exe")) & " /d /c chcp"
  On Error Resume Next
  Set cpProc = sh.Exec(cmdPath)
  If Err.Number <> 0 Then
    Err.Clear
    On Error GoTo 0
    Exit Function
  End If
  On Error GoTo 0
  startedAt = Timer
  Do While cpProc.Status = 0
    WScript.Sleep POLL_MILLISECONDS
    elapsed = ElapsedSeconds(startedAt)
    If elapsed >= 5 Then
      On Error Resume Next
      cpProc.Terminate
      On Error GoTo 0
      Exit Function
    End If
  Loop
  If cpProc.ExitCode <> 0 Then Exit Function
  On Error Resume Next
  output = cpProc.StdOut.ReadAll
  If Err.Number <> 0 Then
    Err.Clear
    On Error GoTo 0
    Exit Function
  End If
  On Error GoTo 0
  Set rx = New RegExp
  rx.Pattern = "[0-9]{3,5}"
  rx.Global = False
  Set matches = rx.Execute(output)
  If matches.Count > 0 Then
    On Error Resume Next
    codePage = CLng(matches(0).Value)
    If Err.Number = 0 Then QueryConsoleCodePage = codePage
    Err.Clear
    On Error GoTo 0
  End If
End Function

Function NormalizeOutput(path, id, codePage, byteLimit, startedAt, timeoutSeconds)
  Dim byteCount, raw, charset, bomLength, textStream, decoded, expectedUtf16
  Dim sizeError, normalizedSize
  NormalizeOutput = "PARSE_FAILED_ENCODING_UNKNOWN"
  If Not TryGetFileSize(path, byteCount, sizeError) Then
    NormalizeOutput = "OUTPUT_SIZE_UNAVAILABLE"
    Exit Function
  End If
  If byteCount > byteLimit Then
    NormalizeOutput = "OUTPUT_LIMIT_EXCEEDED"
    Exit Function
  End If
  If ElapsedSeconds(startedAt) >= timeoutSeconds Then
    NormalizeOutput = "TIMEOUT"
    Exit Function
  End If
  If byteCount = 0 Then
    If WriteUtf8Output(path, "") Then NormalizeOutput = "OK"
    Exit Function
  End If

  On Error Resume Next
  raw = ReadRawLatin1(path)
  If Err.Number <> 0 Then
    Err.Clear
    On Error GoTo 0
    Exit Function
  End If
  On Error GoTo 0
  charset = ""
  bomLength = 0
  expectedUtf16 = ""
  If byteCount >= 3 Then
    If ByteAt(raw, 0) = 239 And ByteAt(raw, 1) = 187 And ByteAt(raw, 2) = 191 Then
      charset = "utf-8": bomLength = 3
    End If
  End If
  If charset = "" And byteCount >= 2 Then
    If ByteAt(raw, 0) = 255 And ByteAt(raw, 1) = 254 Then
      charset = "unicode": bomLength = 2: expectedUtf16 = "LE"
    ElseIf ByteAt(raw, 0) = 254 And ByteAt(raw, 1) = 255 Then
      charset = "unicodeFFFE": bomLength = 2: expectedUtf16 = "BE"
    End If
  End If
  If charset = "" And IsWmicCommand(id) Then
    charset = DetectNoBomUtf16(raw)
    If charset = "unicode" Then expectedUtf16 = "LE"
    If charset = "unicodeFFFE" Then expectedUtf16 = "BE"
  End If
  If charset = "" Then
    If IsSafeAscii(raw) Then
      charset = "us-ascii"
    ElseIf codePage = 65001 Then
      charset = "utf-8"
    Else
      charset = CharsetForCodePage(codePage)
    End If
  End If
  If charset = "" Then Exit Function
  If charset = "utf-8" And Not IsValidUtf8(raw, bomLength) Then Exit Function
  If expectedUtf16 <> "" And Not IsValidUtf16(raw, bomLength, expectedUtf16) Then Exit Function

  On Error Resume Next
  Set textStream = CreateObject("ADODB.Stream")
  If Err.Number <> 0 Then
    Err.Clear: On Error GoTo 0: Exit Function
  End If
  textStream.Type = 2
  textStream.Charset = charset
  textStream.Open
  textStream.LoadFromFile path
  decoded = textStream.ReadText(-1)
  textStream.Close
  If Err.Number <> 0 Then
    Err.Clear: On Error GoTo 0: Exit Function
  End If
  On Error GoTo 0
  If Len(decoded) > 0 Then
    If AscW(Left(decoded, 1)) = -257 Then decoded = Mid(decoded, 2)
  End If
  If Not IsSafeDecodedText(decoded) Then Exit Function
  If ElapsedSeconds(startedAt) >= timeoutSeconds Then NormalizeOutput = "TIMEOUT": Exit Function
  If Utf8ByteLength(decoded) + 3 > byteLimit Then NormalizeOutput = "OUTPUT_LIMIT_EXCEEDED": Exit Function
  If Not WriteUtf8Output(path, decoded) Then Exit Function
  If Not TryGetFileSize(path, normalizedSize, sizeError) Then
    NormalizeOutput = "OUTPUT_SIZE_UNAVAILABLE"
    Exit Function
  End If
  If normalizedSize > byteLimit Then NormalizeOutput = "OUTPUT_LIMIT_EXCEEDED": Exit Function
  If ElapsedSeconds(startedAt) >= timeoutSeconds Then NormalizeOutput = "TIMEOUT": Exit Function
  NormalizeOutput = "OK"
End Function

Function ReadRawLatin1(path)
  Dim stream
  Set stream = CreateObject("ADODB.Stream")
  stream.Type = 2
  stream.Charset = "iso-8859-1"
  stream.Open
  stream.LoadFromFile path
  ReadRawLatin1 = stream.ReadText(-1)
  stream.Close
End Function

Function ByteAt(raw, offset)
  ByteAt = AscW(Mid(raw, offset + 1, 1)) And 255
End Function

Function IsWmicCommand(id)
  IsWmicCommand = (id = "collection_time" Or id = "os_detail" Or id = "cpu" Or id = "memory" Or id = "graphics" Or id = "disks")
End Function

Function DetectNoBomUtf16(raw)
  If IsStrongNoBomUtf16(raw, True) Then
    DetectNoBomUtf16 = "unicode"
  ElseIf IsStrongNoBomUtf16(raw, False) Then
    DetectNoBomUtf16 = "unicodeFFFE"
  Else
    DetectNoBomUtf16 = ""
  End If
End Function

Function IsStrongNoBomUtf16(raw, littleEndian)
  Dim pairs, sample, i, zeroCount, asciiCount, evenByte, oddByte
  IsStrongNoBomUtf16 = False
  If (Len(raw) Mod 2) <> 0 Or Len(raw) < 8 Then Exit Function
  pairs = Len(raw) \ 2
  sample = pairs
  If sample > 256 Then sample = 256
  zeroCount = 0: asciiCount = 0
  For i = 0 To sample - 1
    evenByte = ByteAt(raw, i * 2)
    oddByte = ByteAt(raw, i * 2 + 1)
    If littleEndian Then
      If oddByte = 0 Then zeroCount = zeroCount + 1
      If (evenByte >= 32 And evenByte <= 126) Or evenByte = 9 Or evenByte = 10 Or evenByte = 13 Then asciiCount = asciiCount + 1
    Else
      If evenByte = 0 Then zeroCount = zeroCount + 1
      If (oddByte >= 32 And oddByte <= 126) Or oddByte = 9 Or oddByte = 10 Or oddByte = 13 Then asciiCount = asciiCount + 1
    End If
  Next
  IsStrongNoBomUtf16 = (zeroCount * 4 >= sample And asciiCount * 2 >= sample)
End Function

Function IsValidUtf16(raw, firstIndex, byteOrder)
  Dim i, value, nextValue
  IsValidUtf16 = False
  If ((Len(raw) - firstIndex) Mod 2) <> 0 Then Exit Function
  i = firstIndex
  Do While i < Len(raw)
    If byteOrder = "LE" Then
      value = ByteAt(raw, i) + ByteAt(raw, i + 1) * 256
    Else
      value = ByteAt(raw, i) * 256 + ByteAt(raw, i + 1)
    End If
    If value >= &HD800 And value <= &HDBFF Then
      If i + 3 >= Len(raw) Then Exit Function
      If byteOrder = "LE" Then
        nextValue = ByteAt(raw, i + 2) + ByteAt(raw, i + 3) * 256
      Else
        nextValue = ByteAt(raw, i + 2) * 256 + ByteAt(raw, i + 3)
      End If
      If nextValue < &HDC00 Or nextValue > &HDFFF Then Exit Function
      i = i + 4
    ElseIf value >= &HDC00 And value <= &HDFFF Then
      Exit Function
    Else
      i = i + 2
    End If
  Loop
  IsValidUtf16 = True
End Function

Function IsValidUtf8(raw, firstIndex)
  Dim i, upper, b1, b2, b3, b4
  IsValidUtf8 = False
  upper = Len(raw) - 1
  i = firstIndex
  Do While i <= upper
    b1 = ByteAt(raw, i)
    If b1 <= 127 Then
      If b1 = 0 Or (b1 < 32 And b1 <> 9 And b1 <> 10 And b1 <> 13) Then Exit Function
      i = i + 1
    ElseIf b1 >= 194 And b1 <= 223 Then
      If i + 1 > upper Then Exit Function
      b2 = ByteAt(raw, i + 1)
      If b2 < 128 Or b2 > 191 Then Exit Function
      i = i + 2
    ElseIf b1 >= 224 And b1 <= 239 Then
      If i + 2 > upper Then Exit Function
      b2 = ByteAt(raw, i + 1): b3 = ByteAt(raw, i + 2)
      If b2 < 128 Or b2 > 191 Or b3 < 128 Or b3 > 191 Then Exit Function
      If b1 = 224 And b2 < 160 Then Exit Function
      If b1 = 237 And b2 > 159 Then Exit Function
      i = i + 3
    ElseIf b1 >= 240 And b1 <= 244 Then
      If i + 3 > upper Then Exit Function
      b2 = ByteAt(raw, i + 1): b3 = ByteAt(raw, i + 2): b4 = ByteAt(raw, i + 3)
      If b2 < 128 Or b2 > 191 Or b3 < 128 Or b3 > 191 Or b4 < 128 Or b4 > 191 Then Exit Function
      If b1 = 240 And b2 < 144 Then Exit Function
      If b1 = 244 And b2 > 143 Then Exit Function
      i = i + 4
    Else
      Exit Function
    End If
  Loop
  IsValidUtf8 = True
End Function

Function IsSafeAscii(raw)
  Dim i, b
  IsSafeAscii = False
  For i = 1 To Len(raw)
    b = ByteAt(raw, i - 1)
    If b > 127 Or (b < 32 And b <> 9 And b <> 10 And b <> 13) Then Exit Function
  Next
  IsSafeAscii = True
End Function

Function IsSafeDecodedText(value)
  Dim i, c, n
  IsSafeDecodedText = False
  For i = 1 To Len(value)
    c = Mid(value, i, 1)
    n = AscW(c)
    If n < 0 Then n = n + 65536
    If n = 0 Or (n < 32 And n <> 9 And n <> 10 And n <> 13) Then Exit Function
  Next
  IsSafeDecodedText = True
End Function

Function CharsetForCodePage(codePage)
  Select Case codePage
    Case 437: CharsetForCodePage = "IBM437"
    Case 850: CharsetForCodePage = "IBM850"
    Case 852: CharsetForCodePage = "IBM852"
    Case 866: CharsetForCodePage = "IBM866"
    Case 874: CharsetForCodePage = "windows-874"
    Case 932: CharsetForCodePage = "shift_jis"
    Case 936: CharsetForCodePage = "gb2312"
    Case 949: CharsetForCodePage = "euc-kr"
    Case 950: CharsetForCodePage = "big5"
    Case 1200: CharsetForCodePage = "unicode"
    Case 1201: CharsetForCodePage = "unicodeFFFE"
    Case 1250: CharsetForCodePage = "windows-1250"
    Case 1251: CharsetForCodePage = "windows-1251"
    Case 1252: CharsetForCodePage = "windows-1252"
    Case 1253: CharsetForCodePage = "windows-1253"
    Case 1254: CharsetForCodePage = "windows-1254"
    Case 1255: CharsetForCodePage = "windows-1255"
    Case 1256: CharsetForCodePage = "windows-1256"
    Case 1257: CharsetForCodePage = "windows-1257"
    Case 1258: CharsetForCodePage = "windows-1258"
    Case 65001: CharsetForCodePage = "utf-8"
    Case Else: CharsetForCodePage = ""
  End Select
End Function

Function Utf8ByteLength(value)
  Dim i, n, nextN, total
  total = 0
  i = 1
  Do While i <= Len(value)
    n = AscW(Mid(value, i, 1))
    If n < 0 Then n = n + 65536
    If n <= 127 Then
      total = total + 1
    ElseIf n <= 2047 Then
      total = total + 2
    ElseIf n >= &HD800 And n <= &HDBFF Then
      If i = Len(value) Then
        Utf8ByteLength = MAX_OUTPUT_BYTES + 1
        Exit Function
      End If
      nextN = AscW(Mid(value, i + 1, 1))
      If nextN < 0 Then nextN = nextN + 65536
      If nextN < &HDC00 Or nextN > &HDFFF Then
        Utf8ByteLength = MAX_OUTPUT_BYTES + 1
        Exit Function
      End If
      total = total + 4
      i = i + 1
    ElseIf n >= &HDC00 And n <= &HDFFF Then
      Utf8ByteLength = MAX_OUTPUT_BYTES + 1
      Exit Function
    Else
      total = total + 3
    End If
    i = i + 1
  Loop
  Utf8ByteLength = total
End Function

Function WriteUtf8Output(path, value)
  Dim stream
  WriteUtf8Output = False
  On Error Resume Next
  Set stream = CreateObject("ADODB.Stream")
  If Err.Number <> 0 Then
    Err.Clear
    On Error GoTo 0
    Exit Function
  End If
  stream.Type = 2
  stream.Charset = "utf-8"
  stream.Open
  stream.WriteText value
  stream.SaveToFile path, 2
  stream.Close
  If Err.Number = 0 Then WriteUtf8Output = True
  Err.Clear
  On Error GoTo 0
End Function

Function StopProcessTree(pid)
  Dim killer, killStarted, killElapsed
  StopProcessTree = False
  On Error Resume Next
  Set killer = sh.Exec(QuotePath(fso.BuildPath(systemRoot, "System32\taskkill.exe")) & _
    " /PID " & CLng(pid) & " /T /F")
  If Err.Number <> 0 Then
    Err.Clear
    proc.Terminate
    ' Terminating only the cmd wrapper does not prove its descendants stopped.
    StopProcessTree = False
    On Error GoTo 0
    Exit Function
  End If
  On Error GoTo 0
  killStarted = Timer
  Do While killer.Status = 0
    WScript.Sleep POLL_MILLISECONDS
    killElapsed = Timer - killStarted
    If killElapsed < 0 Then killElapsed = killElapsed + 86400
    If killElapsed >= CLEANUP_SECONDS Then
      On Error Resume Next
      killer.Terminate
      proc.Terminate
      On Error GoTo 0
      Exit Function
    End If
  Loop
  ' Fail closed unless taskkill confirms it terminated the whole process tree.
  StopProcessTree = (killer.ExitCode = 0 And proc.Status <> 0)
End Function

Function WriteSidecar(path, code, status)
  Dim f
  WriteSidecar = False
  On Error Resume Next
  Set f = fso.OpenTextFile(path, 2, False, 0)
  If Err.Number = 0 Then
    f.WriteLine "EXIT_CODE=" & CStr(code)
    f.WriteLine "STATUS=" & status
    f.Close
    If Err.Number = 0 Then WriteSidecar = True
  End If
  Err.Clear
  On Error GoTo 0
End Function
