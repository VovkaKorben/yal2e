program l2conn;

{$APPTYPE CONSOLE}

uses
    Winapi.Windows,

    System.SysUtils,
    System.Classes,
    Blowfish,
    MyFiles,
    l2connEncrypt in 'l2connEncrypt.pas',
    l2connIO in 'l2connIO.pas';

const
        FILENAME = 'DELPHIDUMP.BIN';
    use_stored = True;

    // --- hexdump(data) ---

const
    // Статический Blowfish ключ для хроник Interlude
    INTERLUDE_BLOW_KEY: array[0..15] of Byte = (
        $5F, $40, $4D, $35, $56, $34, $56, $39,
        $56, $38, $56, $31, $56, $30, $5F, $00
        );

    // --- MAIN BLOCK ---
var
    DataStream: TMemoryStream;
    fname: string;
    // BFData: TBlowfishData;    InitKey: RawByteString;
begin
    Writeln('SelfTest: ', BlowfishSelfTest);



    fname := ParentDir(ExePath(), 2) + FILENAME;
    DataStream := TMemoryStream.Create;
    try
        if use_stored then
        begin
            if FileRead(fname, DataStream) then
            begin
                HexDump(DataStream);
                DecryptLoginInit(DataStream);
                HexDump(DataStream);
            end;
        end
        else
        begin
            if SockRead(DataStream) then
                DataWrite(fname, DataStream);
        end;
    finally
        DataStream.Free;
    end;
    Writeln('Готово. Нажми Enter...');
    Readln;
end.

