object Form3: TForm3
  Left = 0
  Top = 0
  Caption = 'Form3'
  ClientHeight = 299
  ClientWidth = 635
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  OldCreateOrder = False
  Position = poScreenCenter
  OnClose = FormClose
  OnCreate = FormCreate
  OnKeyDown = FormKeyDown
  PixelsPerInch = 96
  TextHeight = 13
  object Edit1: TEdit
    Left = 276
    Top = 32
    Width = 121
    Height = 21
    TabOrder = 0
    Text = 'OTIred3'
  end
  object Edit2: TEdit
    Left = 276
    Top = 56
    Width = 121
    Height = 21
    TabOrder = 1
    Text = 'Pass13'
  end
  object Button1: TButton
    Left = 308
    Top = 96
    Width = 75
    Height = 25
    Caption = 'Button1'
    TabOrder = 2
    OnClick = Button1Click
  end
end
