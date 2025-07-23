package network

import (
	"bufio"
	"crypto/tls"
	"net"
	"time"
)

var defaultServices = map[string]string{
	// System ports
	"20":  "ftp-data",
	"21":  "ftp",
	"22":  "ssh",
	"23":  "telnet",
	"25":  "smtp",
	"53":  "dns",
	"67":  "dhcp-server",
	"68":  "dhcp-client",
	"69":  "tftp",
	"80":  "http",
	"88":  "kerberos",
	"110": "pop3",
	"123": "ntp",
	"137": "netbios-ns",
	"138": "netbios-dgm",
	"139": "netbios-ssn",
	"143": "imap",
	"161": "snmp",
	"162": "snmptrap",
	"179": "bgp",
	"389": "ldap",
	"443": "https",
	"445": "microsoft-ds",
	"465": "smtps",
	"514": "syslog",
	"515": "printer",
	"587": "smtp-submission",
	"631": "ipp",
	"636": "ldaps",
	"873": "rsync",
	"990": "ftps",
	"993": "imaps",
	"995": "pop3s",

	// Popular services
	"1080":  "socks",
	"1194":  "openvpn",
	"1433":  "mssql",
	"1521":  "oracle-db",
	"1723":  "pptp",
	"1883":  "mqtt",
	"1900":  "upnp",
	"2049":  "nfs",
	"2082":  "cpanel",
	"2083":  "cpanel-ssl",
	"2086":  "whm",
	"2087":  "whm-ssl",
	"2095":  "webmail",
	"2096":  "webmail-ssl",
	"2181":  "zookeeper",
	"2375":  "docker",
	"2376":  "docker-ssl",
	"2424":  "orientdb",
	"2483":  "oracle-db-ssl",
	"2484":  "oracle-db-ssl",
	"3000":  "nodejs",
	"3306":  "mysql",
	"3389":  "rdp",
	"3690":  "svn",
	"4333":  "mssql-olap",
	"4369":  "epmd",
	"4789":  "docker-swarm",
	"5000":  "upnp",
	"5432":  "postgresql",
	"5601":  "kibana",
	"5672":  "amqp",
	"5900":  "vnc",
	"5938":  "teamviewer",
	"5984":  "couchdb",
	"6379":  "redis",
	"6443":  "kubernetes-api",
	"6666":  "irc",
	"6881":  "bittorrent",
	"6969":  "bittorrent-tracker",
	"8000":  "http-alt",
	"8008":  "http-alt",
	"8080":  "http-proxy",
	"8081":  "http-alt",
	"8088":  "radan-http",
	"8096":  "plex",
	"8443":  "https-alt",
	"8888":  "sun-answerbook",
	"9000":  "php-fpm",
	"9042":  "cassandra",
	"9090":  "prometheus",
	"9091":  "transmission",
	"9100":  "printer",
	"9200":  "elasticsearch",
	"9300":  "elasticsearch-cluster",
	"11211": "memcached",
	"27017": "mongodb",
	"27018": "mongodb-shard",
	"28017": "mongodb-http",
}

var serviceMessager = map[string]func(net.Conn){
	"22":   sshMessager,
	"80":   httpsMessager,
	"443":  httpsMessager,
	"8080": httpsMessager,
	"8443": httpsMessager,
}

type Service struct {
	Name    string
	Version string
}

func DetectService(conn net.Conn, port string) Service {
	conn.SetReadDeadline(time.Now().Add(time.Second * 2))
	if msg, ok := serviceMessager[port]; ok {
		msg(conn)
	}
	banner, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return Service{Name: defaultServices[port], Version: "unknown"}
	}
	return Service{Name: banner, Version: "todo"}
}

func sshMessager(conn net.Conn) {
	conn.Write([]byte("SSH-2.0-netcheck\r\n"))
}

func httpsMessager(conn net.Conn) {
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	tlsConn.Handshake()
	tlsConn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
}
