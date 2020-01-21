use bcc::core::BPF;
use bcc::table::Table;
use std::sys_common::net::hntohs;
use std::collections::HashMap;
use std::{thread, time};
use std::net::{IPv4Addr, IPv6Addr};
use clap::{App, Arg};
use failure::Error;
use std::process;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{fmt, mem, ptr, thread, time};

extern crate ctrlc;
#[macro_use]
extern crate lazy_static;

lazy_static! {
    let mut TIMESTAMP_ARGUMENT: bool = false;
    let mut UID_ARGUMENT: bool = false;
    let mut START_TIMESTAMP: u64 = 0;
}
/*
 * Define the struct the BPF code writes in Rust
 * This must match the struct in `opensnoop.c` exactly.
 * The important thing to understand about the code in `opensnoop.c` is that it creates structs of
 * type `data_t` and pushes them into a buffer where our Rust code can read them.
 */
#[repr(C)]
struct ipv4_data_t {
    ts_us: u64,
    pid: u32,
    uid: u32,
    saddr: u32,
    daddr: u32,
    ip: u64,
    dport: u16,
    task: [u8; 16] // TASK_COMM_LEN
}

#[repr(C)]
struct ipv6_data_t {
    ts_us: u64,
    pid: u32,
    uid: u32,
    saddr: u128,
    daddr: u128,
    ip: u64,
    dport: u16,
    task: [u8; 16] // TASK_COMM_LEN
}

const DEBUG: bool = false;
const TIMESTAMP_DIVISOR = 1000000;
// lazy borrowing from tcpconnect.py
lazy_static!{
static ref struct_init: HashMap<&str, HashMap<&str, &str>> = [
("ipv4",
    [("count",
        "struct ipv4_flow_key_t flow_key = {};
        flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
        flow_key.daddr = skp->__sk_common.skc_daddr;
        flow_key.dport = ntohs(dport);
        ipv4_count.increment(flow_key);"),
    ("trace",
        "struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
        data4.uid = bpf_get_current_uid_gid();
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.dport = ntohs(dport);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));")].iter().cloned().collect(),
"ipv6",
    [("count",
        "struct ipv6_flow_key_t flow_key = {};
        bpf_probe_read(&flow_key.saddr, sizeof(flow_key.saddr),
           skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&flow_key.daddr, sizeof(flow_key.daddr),
           skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        flow_key.dport = ntohs(dport);
        ipv6_count.increment(flow_key);"),
    ("trace",
        "struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
        data6.uid = bpf_get_current_uid_gid();
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
           skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
           skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.dport = ntohs(dport);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));")].iter().cloned().collect()].iter().cloned().collect()
}

fn hashmap_replace(first_key: &str, second_key: &str, replacement_string: &str, bpf_text: mut &str){
    match struct_init.get(first_key) {
        Some(&code_hash_map) => {
            match code_hash_map.get(second_key) {
                Some(&code) => {
                    bpf_text.replace(replacement_string, code);
                },
                None => {}
            }
        },
        None => {}
    }
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let mut bpf_text = include_str!("tcpconnect.c");
    let matches = App::new("tcpconnect")
        .about("Trace TCP connects")
        .longabout("examples:
./tcpconnect           # trace all TCP connect()s
./tcpconnect -t        # include timestamps
./tcpconnect -p 181    # only trace PID 181
./tcpconnect -P 80     # only trace port 80
./tcpconnect -P 80,81  # only trace port 80 and 81
./tcpconnect -U        # include UID
./tcpconnect -u 1000   # only trace UID 1000")
// ./tcpconnect -c        # count connects per src ip and dest ip/port")
        .arg(
            Arg::with_name("t")
            .longname("timestamp")
            .takes_value(false)
            .help("include timestamp on output")
        )
        .arg(
            Arg::with_name("p")
            .help("trace this PID only")
            .value_name("PID")
            .number_of_values(1)
            .takes_value(true)
        )
        .arg(
            Arg::with_name("P")
            .help("comma-separated list of destination ports to trace.")
            .value_name("PORT")
            .min_values(1)
            .takes_value(true)
        )
        .arg(
            Arg::with_name("U")
            .longname("print-uid")
            .help("include UID on output")
            .value_name("print-uid")
            .takes_value(false)
        )
        .arg(
            Arg::with_name("u")
            .longname("uid")
            .help("trace this UID only")
            .value_name("UID")
            .number_of_values(1)
            .takes_value(true)
        )
        // .arg(
        //     Arg::with_name("c")
        //     .longname("count")
        //     .help("count connects per src ip and dest ip/port")
        //     .value_name("count")
        //     .takes_value(true)
        // )
        .arg(
            Arg::with_name("ebpf")
            .takes_value(false)
        );
        // start replacing BPF code in bpf_text
        let count = false;// matches.is_present("c");
        TIMESTAMP_ARGUMENT = matches.is_present("t");
        if count {
            hashmap_replace(&"ipv4", &"count", &"IPV4_CODE", &bpf_text);
            hashmap_replace(&"ipv6", &"count", &"IPV6_CODE", &bpf_text);
        }
        else{
            hashmap_replace(&"ipv4", &"trace", &"IPV4_CODE", &bpf_text);
            hashmap_replace(&"ipv6", &"trace", &"IPV6_CODE", &bpf_text);
        }
        UID_ARGUMENT = matches.is_present("U");
        let ebpf = matches.is_present("ebpf");
        if let Some(p) = matches.value_of("p") {
            // trace pid
            let pid = p.parse::<u32>();
            bpf_text.replace("FILTER_PID",
            format!("if (pid != %s) { return 0; }", pid);
        }
        if let Some(P) = matches.value_of("P") {
            // trace ports
            let ports_conditions: Vec<str> = P.collect().map(|v| format!("dport != %d", ntohs(v.parse::<u16>())));
            let port_contition_statement = ports_conditions.join(" && ");
            bpf_text.replace("FILTER_PORT", format!("if (%s) { currsock.delete(&pid); return 0; }",port_contition_statement));
        }
        if let Some(u) = matches.value_of("u") {
            // trace uuid
            let uuid = u.parse::<u32>();
            bpf_text.replace("FILTER_UID", format!("if (uid != %s) { return 0; }",uuid);
        }
        bpf_text.replace("FILTER_PID", "");
        bpf_text.replace("FILTER_PORT", "");
        bpf_text.replace("FILTER_UID", "");

        //debug or display ebpf code
        if (DEBUG || ebpf) {
            println!(bpf_text);
            if ebpf {
                process::exit(0x0100);
            }
        }

        // compile the above BPF code!
        let mut module = BPF::new(bpf_text)?;
        // load + attach tracepoints!
        let trace_connect_v4_entry = module.load_kprobe("trace_connect_entry");
        let trace_connect_v6_entry = module.load_kprobe("trace_connect_entry");
        let trace_connect_v4_return = module.load_kprobe("trace_connect_v4_return");
        let trace_connect_v6_return = module.load_kprobe("trace_connect_v6_return");
        module.attach_kprobe("tcp_v4_connect", trace_connect_v4_entry)?;
        module.attach_kprobe("tcp_v6_connect", trace_connect_v6_entry)?;
        module.attach_kretprobe("tcp_v4_connect", trace_connect_v4_return)?;
        module.attach_kretprobe("tcp_v6_connect", trace_connect_v6_return)?;


        println!("Tracing connect ... Hit Ctrl-C to end");
        // count workflow
        // if count {
        //     let ten_millis = time::Duration::from_millis(10);
        //     loop {
        //         let now = time::Instant::now();
        //         thread::sleep(ten_millis);
        //     }
        //     // header
        //     println!("\n{:25} {:25} {:20} {:10}" % (
        //         "LADDR", "RADDR", "RPORT", "CONNECTS"))
        //     let ipv4_table = module.table(&"ipv4_count");
        //     let ipv6_table = module.table(&"ipv6_count");
        //     depict_cnt(&ipv4_table, true);
        //     depict_cnt(&ipv6_table, false);
        // }
        let ipv4_table = module.table("ipv4_events");
        let ipv6_table = module.table("ipv6_events");
        let mut ipv4_perf_map = init_perf_map(ipv4_table, print_ipv4_event)?;
        let mut ipv6_perf_map = init_perf_map(ipv6_table, print_ipv6_event)?;
        // print a header
        let mut header = "";
        if TIMESTAMP_ARGUMENT {
            header += println!("{:-9}", "TIME(s)");
        }
        if UID_ARGUMENT {
            header += println!("{:-6}", "UID");
        }
        header += println!("{:-6} {:-12} {:-2} {:-16} {:-16} {:-4}", "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT");
        print!(header);
        let start = std::time::Instant::now();
        // this `.poll()` loop is what makes our callback get called
        while runnable.load(Ordering::SeqCst) {
            ipv4_perf_map.poll(200);
            ipv6_perf_map.poll(200);
            if let Some(d) = duration {
                if std::time::Instant::now() - start >= d {
                    break;
                }
            }
        }
        Ok(())
}

fn perf_ipv4_data_t_callback() -> Box<FnMut(&[u8]) + Send> {
    Box::new(|x| {
        // This callback
        let data = parse_ipv4_data_t_struct(x);
        let mut string_format: str = "";
        let mut timestamp_tmp: f64 = 0.0;
        if TIMESTAMP_ARGUMENT {
            if START_TIMESTAMP == 0 {
                START_TIMESTAMP = data.ts_us;
            }
            timestamp_tmp = (data.ts_us - START_TIMESTAMP).parse::f64().unwrap() / TIMESTAMP_DIVISOR;
            string_format += format!("{:-9.3} ", timestamp_tmp);
        }
        if UID_ARGUMENT {
            string_format += format!("{:-6} ", data.uid);
        }
        println!(
            "{:-6} {:-12.12} {:-2} {:-16} {:-16} {:-4}",// "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT"
            data.pid,
            data.task,
            data.ip,
            Ipv4Addr::from(data.saddr),
            Ipv4Addr::from(data.daddr),
            data.dport
        );
    })
}

fn perf_ipv6_data_t_callback() -> Box<FnMut(&[u8]) + Send> {
    Box::new(|x| {
        // This callback
        let data = parse_ipv6_data_t_struct(x);
        let mut string_format: str = "";
        let mut timestamp_tmp: f64 = 0.0;
        if TIMESTAMP_ARGUMENT {
            if START_TIMESTAMP == 0 {
                START_TIMESTAMP = data.ts_us;
            }
            timestamp_tmp = (data.ts_us - START_TIMESTAMP).parse::f64().unwrap() / TIMESTAMP_DIVISOR;
            string_format += format!("{:-9.3} ", timestamp_tmp);
        }
        if UID_ARGUMENT {
            string_format += format!("{:-6} ", data.uid);
        }
        println!(
            "{:-6} {:-12} {:-2} {:-16} {:-16} {:-4}",// "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT"
            data.pid,
            data.task,
            data.ip,
            Ipv6Addr::from(data.saddr),
            Ipv6Addr::from(data.daddr),
            data.dport
        );
    })
}

// fn depict_cnt(counts_table: Table, l3prot: bool){
//     let key_size = counts_table.key_size();
//     let leaf_size = counts_table.leaf_size();
//     let leaf = vec![0; leaf_size];
//     if l3prot {
//         // use ipv4addr

//     }
//     else {
//         // use ipv6addr
//     }
    
//     for (key, &value) in counts_table.iter() {
//         println!("Calling {}: {}", contact, call(number)); 
//     }

// }



fn parse_ipv4_data_t_struct(x: &[u8]) -> ipv4_data_t {
    unsafe { ptr::read(x.as_ptr() as *const ipv4_data_t) }
}

fn parse_ipv6_data_t_struct(x: &[u8]) -> ipv6_data_t {
    unsafe { ptr::read(x.as_ptr() as *const ipv6_data_t) }
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    match do_main(runnable) {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}