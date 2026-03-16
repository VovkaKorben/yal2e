object FMainForm: TFMainForm
  Left = 0
  Top = 0
  Caption = 'FMainForm'
  ClientHeight = 425
  ClientWidth = 635
  Color = clBtnFace
  Font.Charset = RUSSIAN_CHARSET
  Font.Color = clWindowText
  Font.Height = -13
  Font.Name = 'Cascadia Code'
  Font.Style = []
  KeyPreview = True
  OldCreateOrder = False
  Position = poScreenCenter
  OnClose = FormClose
  OnCreate = FormCreate
  OnKeyDown = FormKeyDown
  DesignSize = (
    635
    425)
  PixelsPerInch = 96
  TextHeight = 17
  object Edit1: TEdit
    Left = 276
    Top = 32
    Width = 121
    Height = 25
    TabOrder = 0
    Text = 'OTIred3'
  end
  object Edit2: TEdit
    Left = 276
    Top = 56
    Width = 121
    Height = 25
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
  object Memo1: TMemo
    Left = 8
    Top = 172
    Width = 619
    Height = 245
    Anchors = [akLeft, akTop, akRight, akBottom]
    Lines.Strings = (
      'Memo1')
    TabOrder = 3
  end
end
