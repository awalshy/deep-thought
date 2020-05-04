const dotenv = require('dotenv')
dotenv.config()
const sys = require('util')

const pcap = require("pcap")
const tcp_tracker = new pcap.TCPTracker()
pcap_session = pcap.createSession(process.env.NETWORK_INTERFACE)
const dns = require("dns")

console.log(`Monitoring network ${process.env.NETWORK_INTERFACE}`)

tcp_tracker.on('session', (session) => {
    const src = String(session.src)
    const dst = String(session.dst)
    const src_ip = src.substring(0, src.indexOf(':'))
    const dst_ip = dst.substring(0, dst.indexOf(':'))
    dns.reverse(src_ip, (err, addr) => {
        if (err && err.errno !== undefined)
            console.log(err)
        dns.reverse(dst_ip, (err, addr2) => {
            if (err && err.errno !== undefined)
                console.log(err)
            console.log("SESSION START: " + addr + " (" + src_ip + ") AND "
                        + addr2 + " (" + dst_ip + ")")
        })
    })
                // console.log(sys.inspect(session))
    session.on('end', (s) => {
        console.log("End of TCP session")
    })
})

pcap_session.on('packet', (raw) => {
    const packet = pcap.decode.packet(raw)
    if (process.argv[2] && (process.argv[2] == "--details" || process.argv[2] == "-d")) {
        console.log(packet)
        console.log(`saddr: ${packet.payload.payload.saddr}`)
        console.log(`daddr: ${packet.payload.payload.daddr}`)
        process.exit(0)
    } else {
        tcp_tracker.track_packet(packet)
    }
})