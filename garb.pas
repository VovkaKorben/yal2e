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

