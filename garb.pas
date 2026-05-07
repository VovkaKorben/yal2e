ls.sendall(encrypt_login_packet(bf_key, b"\x07" + struct.pack("<I", session_id) + b"\x00" * 19))



разбираю на примере питона



это делаю в обработчике логин пакета, он сует данные в исходящий буффер

b"\x07" + struct.pack("<I", session_id) + b"\x00" * 19



это делает некая функция в TPacketBuilder, которая берет наши данные из исходящего, и откусывает по длине и сует этот кусочек в очередь

encrypt_login_packet



это отдельный поток, который из очереди вытаскивает

кодирует их как ей нужно и отсылает

ls.sendall


procedure scKeyInit(engine: TEngine; var reader: TPacketReader);
begin
end;

procedure scMoveToLocation(engine: TEngine; var reader: TPacketReader);
//var    TargetX, TargetY, TargetZ: Integer;
begin
    engine.User.X := Reader.GetD;
    engine.User.Y := Reader.GetD;
    engine.User.Z := Reader.GetD;
    // engine.User.X := TargetX; // Обновляем состояние нашего движка
end;

