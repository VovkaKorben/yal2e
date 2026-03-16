unit Unit3;

interface

uses
    Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
    Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, L2PacketBase, EngineUnit;

type
    TFMainForm = class(TForm)
        Edit1: TEdit;
        Edit2: TEdit;
        Button1: TButton;
        Memo1: TMemo;
        procedure FormKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
        procedure Button1Click(Sender: TObject);
        procedure FormCreate(Sender: TObject);
        procedure FormClose(Sender: TObject; var Action: TCloseAction);
    private
        { Private declarations }
    public
        { Public declarations }
    end;

var
    FMainForm: TFMainForm;
    engine: TEngine;

implementation

{$R *.dfm}

procedure TFMainForm.Button1Click(Sender: TObject);
begin
    engine.doLogin();
    Memo1.Lines.Add('Packet Dump: ' + engine.PacketToHex());
    // IdTCPClient1.Host := '51.83.130.113';    IdTCPClient1.Port := 2106;    IdTCPClient1.Connect;
end;

procedure TFMainForm.FormClose(Sender: TObject; var Action: TCloseAction);
begin
    engine.Free;
end;

procedure TFMainForm.FormCreate(Sender: TObject);
begin
    //    InitBlowfish(blowfishKey);
    engine := TEngine.Create(edit1.Text, edit2.Text);
    engine.doLogin();
end;

procedure TFMainForm.FormKeyDown(Sender: TObject; var Key: Word;
    Shift: TShiftState);
begin
    if key = 27 then
        close;
end;

{ TEngine }

end.

