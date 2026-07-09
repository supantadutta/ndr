module Astra.Tests.ParserTests

open Xunit
open Astra.Sensor

// ---------------------------------------------------------------------------
// Zeek TSV parser
// ---------------------------------------------------------------------------

let private zeekConn =
    "#separator \\x09\n" +
    "#set_separator\t,\n" +
    "#empty_field\t(empty)\n" +
    "#unset_field\t-\n" +
    "#path\tconn\n" +
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\n" +
    "1700000000.000000\tCabc123\t10.0.0.5\t44100\t10.0.0.9\t445\ttcp\t-\t0.5\t1000\t2000\tSF\t10\t12\n"

[<Fact>]
let ``Zeek conn log parses 5-tuple and byte counts`` () =
    let events = Zeek.parseText zeekConn
    Assert.Single(events) |> ignore
    let e = List.head events
    Assert.Equal("10.0.0.5", e.SourceIp)
    Assert.Equal("10.0.0.9", e.DestinationIp)
    Assert.Equal(Some 445, e.DestinationPort)
    Assert.Equal(1000L, e.BytesOut)   // orig_bytes
    Assert.Equal(2000L, e.BytesIn)    // resp_bytes
    Assert.Equal("network_connection", e.Category)

let private zeekDns =
    "#separator \\x09\n#unset_field\t-\n#path\tdns\n" +
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype_name\trcode_name\tanswers\n" +
    "1700000000.0\tCx\t10.0.0.5\t51000\t10.0.0.53\t53\tudp\tlongsubdomain.tunnel.example\tTXT\tNOERROR\t-\n"

[<Fact>]
let ``Zeek dns log maps query fields`` () =
    let events = Zeek.parseText zeekDns
    let e = List.head events
    Assert.Equal("dns", e.Category)
    Assert.Equal(Some "longsubdomain.tunnel.example", e.Fields |> Map.tryFind "query")
    Assert.Equal(Some "TXT", e.Fields |> Map.tryFind "query_type")

[<Fact>]
let ``Zeek smb_files marks admin share`` () =
    let smb =
        "#separator \\x09\n#unset_field\t-\n#path\tsmb_files\n" +
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\taction\tpath\tname\tsize\n" +
        "1700000000.0\tCx\t10.0.0.5\t50000\t10.0.0.9\t445\tSMB::FILE_WRITE\tADMIN$\t\\Windows\\Temp\\x.exe\t1024\n"
    let e = Zeek.parseText smb |> List.head
    Assert.Equal(Some "true", e.Fields |> Map.tryFind "is_admin_share")
    Assert.Equal(Some "write", e.Fields |> Map.tryFind "operation")

// ---------------------------------------------------------------------------
// Suricata EVE JSON parser
// ---------------------------------------------------------------------------

[<Fact>]
let ``Suricata EVE alert maps signature fields`` () =
    let line = """{"timestamp":"2026-01-01T00:00:00.000000+0000","event_type":"alert","src_ip":"10.0.0.5","src_port":44100,"dest_ip":"203.0.113.9","dest_port":443,"proto":"TCP","alert":{"signature":"ET MALWARE Test","signature_id":2028371,"rev":3,"category":"A Network Trojan was Detected","severity":1}}"""
    let e = (Suricata.parseEveLine line).Value
    Assert.Equal("ids_signature_alert", e.Category)
    Assert.Equal(Some "2028371", e.Fields |> Map.tryFind "signature_id")
    Assert.Equal(Some "1", e.Fields |> Map.tryFind "ids_severity")
    Assert.Equal("203.0.113.9", e.DestinationIp)

[<Fact>]
let ``Suricata EVE ignores unmapped event types`` () =
    let line = """{"timestamp":"2026-01-01T00:00:00.000000+0000","event_type":"stats"}"""
    Assert.True((Suricata.parseEveLine line).IsNone)

[<Fact>]
let ``Suricata malformed line does not throw`` () =
    Assert.True((Suricata.parseEveLine "{not json").IsNone)

[<Fact>]
let ``Suricata fast.log parses a line`` () =
    let line = "03/09/2026-06:00:00.123456  [**] [1:2013028:6] ET POLICY Suspicious [**] [Classification: x] [Priority: 1] {TCP} 10.0.0.5:1234 -> 203.0.113.9:443"
    let e = (Suricata.parseFastLine line).Value
    Assert.Equal("10.0.0.5", e.SourceIp)
    Assert.Equal("203.0.113.9", e.DestinationIp)
    Assert.Equal(Some "2013028", e.Fields |> Map.tryFind "signature_id")
