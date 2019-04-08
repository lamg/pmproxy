# Descripción de la API

Para poder usar el proxy es necesario hacer consultas a la API, que inicialmente esta en https://localhost:4443, y el certificado no es válido. Cada consulta consiste en comandos que son peticiones POST enviadas a `/api/cmd`, con un objeto JSON en el cuerpo de tipo `cmd`, descrito a continuación:

```go
type cmd struct {
	Cmd        string                 `json:"cmd"`
	User       string                 `json:"user"`
	Manager    string                 `json:"manager"`
	RemoteAddr string                 `json:"remoteAddr"`
	Secret     string                 `json:"secret"`
	IsAdmin    bool                   `json:"isAdmin"`
	Cred       *credentials           `json:"cred"`
	String     string                 `json:"string"`
	Uint64     uint64                 `json:"uint64"`
	Object     map[string]interface{} `json:"object"`
}

type credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}
```

La primera petición que debe hacer el cliente es `discover`, que sirve para descubrir que administradores tiene asignado. Luego con la respuesta, según el tipo de los administradores devueltos, el cliente puede seguir haciendo consultas. En la siguiente tabla se describen los comandos junto con su respuesta al ser enviados a la API.

| comando                           | respuesta   |
|---------------------------------- | ----------- |
| {Cmd:discover,Manager:resourcesK} | discoverRes |

El valor de las constantes `discover` y `resourcesK` está definido en el archivo [constants.go](constants.go). El tipo `discoverRes` se define:

```
type discoverRes struct {
	MatchMng map[string]matchType `json:"matchMng"`
	Result   string               `json:"result"`
}

type matchType struct {
	Match bool   `json:"match"`
	Type  string `json:"type"`
}
```

En el diccionario discoverRes.MatchMng vienen los nombres de los administradores asociados a sus tipos, y al booleano Match que indica cuando admite al cliente. Para mandar un comando a un administrador se debe poner su nombre en cmd.Manager, y el comando que se envía está definido según su tipo. La siguiente tablas especifican los comandos disponibles para cada tipo, junto con su respuesta si es exitosa. Siempre devuelven el código de status HTTP 200 o 400 para consultas exitosas o fallidas respectivamente. Las fallidas pueden venir acompañadas con un texto que es el mensaje de error.

- sessionIPM

| comando                          | respuesta           |
| -------------------------------- | ------------------- |
| {Cmd:open,Cred:credentials}     | JSON Web Token(JWT) |
| {Cmd:clöse,Secret:JWT}           | ∅                   |
| {Cmd:get,IsAdmin:true,Secret:JWT}| map[string]string (diccionario de ip-usuario)   | 
| {Cmd:renew,Secret:JWT}           | JWT                 |
| {Cmd:check,Secret:JWT}           | ∅                   |

- dwnConsR

| comando                                      | respuesta |
| -------------------------------------------- | --------- |
| {Cmd:get,Secret:JWT,IsAdmin:true,String:user}| userInfo  |
| {Cmd:get,Secret:JWT}                         | userInfo  |
| {Cmd:set,Secret:JWT,IsAdmin:true,String:user,Uint64:cons} | ∅ |
| {Cmd:show,Secret:JWT} | map[string]interface{}|
