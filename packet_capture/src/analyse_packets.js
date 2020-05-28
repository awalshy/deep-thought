const dotenv = require('dotenv')
dotenv.config()
const dns = require('dns')
dns.setServers(["8.8.8.8", "208.67.222.222", "1.1.1.1"])

const pcap = require("pcap")
const tcp_tracker = new pcap.TCPTracker()
pcap_session = pcap.createSession(process.env.NETWORK_INTERFACE, { filter: "tcp port 80 or tcp port 443 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)" })

console.log(`Monitoring network ${process.env.NETWORK_INTERFACE}`)

pcap_session.on('packet', (raw) => {
    // console.log(raw.buf, '\n', raw.header, '\n', raw.link_type)
    var arrByte = new Uint8Array(raw.buf)
    var s = [...arrByte].map(e => e > 31 ? String.fromCharCode(e) : '.')
    // console.log("aaaa")
    var str = String.fromCharCode(...s)
    // console.log(s)
    var p = pcap.decode.packet(raw)
    // console.log(p.payload.payload.saddr)
    tcp_tracker.track_packet(p)
    // process.exit()
})

tcp_tracker.on('session', function (session) {
    console.log("Start of session between " + session.src_name + " and " + session.dst_name);
    const lookup = (session.src_name.includes("443") || session.src_name.includes("80")
    ? session.src_name : session.dst_name).split(':')[0]
    dns.reverse(lookup, (err, host) => {
        if (!err)
            console.log(lookup + ' is ' + host)
        else if (err.code === 'ENOTFOUND')
            console.log(lookup + " not found")
        else
            console.error(err)
    })
    session.on('end', function (session) {
        console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
    });
})