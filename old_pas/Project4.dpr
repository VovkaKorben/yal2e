program Project4;

uses
  Vcl.Forms,
  Unit3 in 'Unit3.pas' {FMainForm},
  L2PacketBase in 'L2PacketBase.pas',
  LoginPackets in 'LoginPackets.pas',
  EngineUnit in 'EngineUnit.pas',
  Blowfish in 'Blowfish.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFMainForm, FMainForm);
  Application.Run;
end.
