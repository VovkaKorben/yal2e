unit Unit3;

interface

uses
    Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
    Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, L2PacketBase, EngineUnit;

type
    TForm3 = class(TForm)
        Edit1: TEdit;
        Edit2: TEdit;
        Button1: TButton;
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
    Form3: TForm3;
    engine: TEngine;

implementation

{$R *.dfm}

procedure TForm3.Button1Click(Sender: TObject);
begin

    // IdTCPClient1.Host := '51.83.130.113';    IdTCPClient1.Port := 2106;    IdTCPClient1.Connect;
end;

procedure TForm3.FormClose(Sender: TObject; var Action: TCloseAction);
begin
    engine.Free;
end;

procedure TForm3.FormCreate(Sender: TObject);
begin
    engine := TEngine.Create;
    engine.login(edit1.Text, edit2.Text);
end;

procedure TForm3.FormKeyDown(Sender: TObject; var Key: Word;
    Shift: TShiftState);
begin
    if key = 27 then
        close;
end;

{ TEngine }

end.

