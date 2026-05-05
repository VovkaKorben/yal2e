program packread;

uses
    Sysutils;

type
    TPckReadData = packed record
        PckID: cardinal;
        PckId2: cardinal;
        PckSize: cardinal;
        PckData: array [0 .. 1024] of byte;
    end;

    PPckReadData = ^TPckReadData;

var
    hMapFile: cardinal;
    pBuf: pointer;
    packets_filename, mapname: string;
    PckReadData: PPckReadData;

    { MMF дамп
      Формат непрерывной записи блоков в packet_dump.bin (Little Endian):
      1. [4 байта] PckID   (uint32)
      2. [4 байта] PckId2  (uint32)
      3. [4 байта] PckSize (uint32) - длина данных пакета
      4. [PckSize байт] PckData - сырые данные пакета
      Любой внешний парсер сможет легко проходить по файлу, читая 12 байт заголовка, а затем смещаясь на PckSize байт вперед, чтобы получить чистую полезную нагрузку пакета.
    }
    hDumpFile, hDumpMap: cardinal;
    pDumpBuf: pointer;
    DumpPos, PckFullSize: cardinal;
    LogPos: integer;
    BlockCount, PacketCount: cardinal;

const
    INVALID_HANDLE_VALUE = cardinal($FFFFFFFF);
    PAGE_READWRITE = $04;
    FILE_MAP_ALL_ACCESS = $F001F;
    FILE_MAP_WRITE = $0002;
    GENERIC_READ = $80000000;
    GENERIC_WRITE = $40000000;
    CREATE_ALWAYS = 2;
    FILE_BEGIN = 0;

    DUMP_SIZE = 52428800; // 50 * 1024 * 1024 (50 Мегабайт)
    LOG_STEP = 1024 * 64; //

function OpenFileMapping(dwDesiredAccess: cardinal; bInheritHandle: boolean; lpName: PWideChar): cardinal; stdcall; external 'kernel32.dll' name 'OpenFileMappingW';
function MapViewOfFile(hFileMappingObject: cardinal; dwDesiredAccess: cardinal; dwFileOffsetHigh: cardinal; dwFileOffsetLow: cardinal; dwNumberOfBytesToMap: cardinal): pointer; stdcall;
  external 'kernel32.dll' name 'MapViewOfFile';
function UnmapViewOfFile(lpBaseAddress: pointer): boolean; stdcall; external 'kernel32.dll' name 'UnmapViewOfFile';
function CloseHandle(hObject: cardinal): boolean; stdcall; external 'kernel32.dll' name 'CloseHandle';

function CreateFile(lpFileName: PWideChar; dwDesiredAccess: cardinal; dwShareMode: cardinal; lpSecurityAttributes: pointer; dwCreationDisposition: cardinal; dwFlagsAndAttributes: cardinal; hTemplateFile: cardinal): cardinal;
  stdcall; external 'kernel32.dll' name 'CreateFileW';
function CreateFileMapping(hFile: cardinal; lpFileMappingAttributes: pointer; flProtect: cardinal; dwMaximumSizeHigh: cardinal; dwMaximumSizeLow: cardinal; lpName: PWideChar): cardinal; stdcall;
  external 'kernel32.dll' name 'CreateFileMappingW';
function SetFilePointer(hFile: cardinal; lDistanceToMove: integer; lpDistanceToMoveHigh: pointer; dwMoveMethod: cardinal): cardinal; stdcall; external 'kernel32.dll' name 'SetFilePointer';
function SetEndOfFile(hFile: cardinal): boolean; stdcall; external 'kernel32.dll' name 'SetEndOfFile';
procedure CopyMemory(Destination: cardinal; Source: cardinal; Length: cardinal); stdcall; external 'kernel32.dll' name 'RtlMoveMemory';

procedure CleanupAll;
begin
    if pBuf <> nil then
    begin
        UnmapViewOfFile(pBuf);
        pBuf := nil;
    end;
    if hMapFile <> 0 then
    begin
        CloseHandle(hMapFile);
        hMapFile := 0;
    end;
    if pDumpBuf <> nil then
    begin
        UnmapViewOfFile(pDumpBuf);
        pDumpBuf := nil;
    end;
    if hDumpMap <> 0 then
    begin
        CloseHandle(hDumpMap);
        hDumpMap := 0;
    end;
    if hDumpFile <> INVALID_HANDLE_VALUE then
    begin
        // Обрезаем файл до реально записанного размера
        if DumpPos > 0 then
            SetFilePointer(hDumpFile, DumpPos, nil, FILE_BEGIN);
        SetEndOfFile(hDumpFile);
        CloseHandle(hDumpFile);
        hDumpFile := INVALID_HANDLE_VALUE;
    end;
end;

procedure OnFree;
begin
    CleanupAll;
end;

begin
    hDumpFile := INVALID_HANDLE_VALUE;
    DumpPos := 0;
    LogPos := 0;
    BlockCount := 0;
    PacketCount := 0;

    packets_filename := script.path() + FormatDateTime('dd-mm hh-nn-ss', Now) + '.packets';
    Print('packets_filename: ' + packets_filename);

    // 1. Создаем физический файл на диске
    hDumpFile := CreateFile(PWIDECHAR(packets_filename), GENERIC_READ or GENERIC_WRITE, 0, nil, CREATE_ALWAYS, 0, 0);
    if hDumpFile <> INVALID_HANDLE_VALUE then
    begin
        // 2. Создаем проекцию
        hDumpMap := CreateFileMapping(hDumpFile, nil, PAGE_READWRITE, 0, DUMP_SIZE, nil);
        if hDumpMap <> 0 then
            // 3. Отображаем проекцию в память скрипта
            pDumpBuf := MapViewOfFile(hDumpMap, FILE_MAP_WRITE, 0, 0, DUMP_SIZE);
    end;

    mapname := 'Global\BOTSM' + user.name;
    hMapFile := OpenFileMapping(FILE_MAP_ALL_ACCESS, false, pchar(mapName));
    pBuf := MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SizeOf(TPckReadData));
    PckReadData := PPckReadData(pBuf);
    try
        while true do
        begin
            Delay(1);
            if (PckReadData <> nil) and (PckReadData^.PckID <> 0) then
            begin
                inc(PacketCount);
                // Вычисляем размер пакета: заголовок 12 байт (ID, ID2, Size) + сама длина данных
                if PckReadData^.PckSize <= 1024 then
                    PckFullSize := 12 + PckReadData^.PckSize
                else
                    PckFullSize := SizeOf(TPckReadData); // Защита от переполнения

                // Быстро переносим данные в память дампа, если хватает места
                if pDumpBuf <> nil then
                begin
                    if (DumpPos + PckFullSize) <= DUMP_SIZE then
                    begin
                        CopyMemory(cardinal(pDumpBuf) + DumpPos, cardinal(PckReadData), PckFullSize);
                        DumpPos := DumpPos + PckFullSize;
                        LogPos := LogPos + PckFullSize;

                        // Периодический вывод в лог, чтобы не грузить консоль
                        if LogPos >= LOG_STEP then
                        begin
                            BlockCount := BlockCount + 1;
                            print(format('Block %d, packets %d', [BlockCount, PacketCount]));
                            LogPos := LogPos - LOG_STEP;
                        end;
                    end else begin
                        print('Внимание: Файл дампа переполнен! Лимит достигнут. Скрипт останавливается...');
                        break; // Выход из бесконечного цикла
                    end;
                end;
              //  print(PacketCount); // DEBUG ONLY
                Print(inttostr(PacketCount)+' PckID: ' + IntToHex(PckReadData.PckID, 2) + '  ' + IntToHex(PCardinal(@PckReadData^.PckData [0])^, 4));
                if (PacketCount > 20) then
                    break;
            end;
            PckReadData^.PckID := 0;
        end;
    finally
        CleanupAll;
    end;

end.
