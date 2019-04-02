
data Server = NetHttp NetHandler NetParams | 
	ValyalaHttp VyHandler VyParams

newtype Running a = Running a

type ReadConf = Fs -> Server

type ChangeConf = (Running Server, Fs) -> (Running Server, Fs)

type Transfer = (Conn, Conn)

type Operation = Running Server -> Conn -> Transfer
