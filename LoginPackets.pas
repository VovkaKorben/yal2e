{
 отсылает login-сервер
0x01 loginfail2
0x02 accountKicked1
0x03 loginok
0x04 serverlist
0x05 serverfail
0x06 playfail
0x07 playok
0x08 accountKicked
0x09 blockedAccMsg  // бан
0x20 protocol version different
0x00 VersionCheck
 Логин-сервер обрабатывает пакеты:
0x00 - RequestAuthLogin (запрос на авторизацию - содержит логин и пароль)
0x02 - RequestServerLogin (запрос на заход на сервер)
0x05 - RequestServerList (запрос на список серверов)
На остальные он попросту не отвечает, оставляя лишь запись в логах. Клиентом же обрабатываются
пакеты следующих типов:
0x01 - авторизация не прошла
0x03 - вы успешно авторизованы
0x04 - ответ на RequestServerLogin
0x06 - ответ на RequestServerList
}

unit LoginPackets;

interface

uses L2PacketBase;
const
    pckRequestAuthLogin = $00;
    //function RequestAuthLogin(login, pass: string): TL2PacketStream;
procedure RequestAuthLogin(var ms: TL2PacketStream; login, pass: string);
implementation

procedure RequestAuthLogin(var ms: TL2PacketStream; login, pass: string);

begin
    ms.WriteH(0);
    ms.WriteC(pckRequestAuthLogin);
    ms.WriteS(login);
    ms.WriteS(pass);

end;
end.

