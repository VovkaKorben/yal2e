program Project4;

uses
  Vcl.Forms,
  Unit3 in 'Unit3.pas' {Form3},
  L2PacketBase in 'L2PacketBase.pas',
  LoginPackets in 'LoginPackets.pas',
  EngineUnit in 'EngineUnit.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm3, Form3);
  Application.Run;
end.
