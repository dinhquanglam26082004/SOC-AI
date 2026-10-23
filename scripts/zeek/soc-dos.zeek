# Standalone sensor policy. Fixed network-time windows; no per-packet handlers.
@load base/frameworks/logging
@load base/protocols/http
@load policy/tuning/json-logs
module SOCDOS;
export {
    redef enum Log::ID += { LOG };
    const window = 10sec &redef;
    const tcp_limit: count = 300 &redef;
    const http_limit: count = 200 &redef;
    const udp_flow_limit: count = 500 &redef;
    const icmp_flow_limit: count = 300 &redef;
    const max_targets: count = 20000 &redef;
    const max_sources: count = 64 &redef;
    # Restrict to victim subnets in production; empty means all visible targets.
    const protected_nets: set[subnet] = {} &redef;
    type Info: record {
        ts: time &log;
        producer: string &log;
        metric: string &log;
        dst: addr &log;
        dst_port: count &log;
        observed: count &log;
        threshold: count &log;
        window_seconds: interval &log;
        source_count: count &log;
        source_count_capped: bool &log;
        msg: string &log;
    };
}
type Bucket: record {
    observed: count;
    sources: set[addr];
    capped: bool;
};
global buckets: table[string, addr, port] of Bucket;
global dropped: count = 0;
global flush: event();

function observe(metric: string, c: connection)
    {
    local dst = c$id$resp_h;
    if ( |protected_nets| > 0 && dst !in protected_nets ) return;
    local p = c$id$resp_p;
    if ( [metric, dst, p] !in buckets )
        {
        if ( |buckets| >= max_targets ) { ++dropped; return; }
        buckets[metric, dst, p] = [$observed=0, $sources=set(), $capped=F];
        }
    local b = buckets[metric, dst, p];
    ++b$observed;
    if ( c$id$orig_h !in b$sources )
        {
        if ( |b$sources| < max_sources ) add b$sources[c$id$orig_h];
        else b$capped = T;
        }
    buckets[metric, dst, p] = b;
    }

event new_connection(c: connection)
    {
    local proto = get_conn_transport_proto(c$id);
    if ( proto == tcp ) observe("tcp_new_connections", c);
    else if ( proto == udp ) observe("udp_new_flows", c);
    else if ( proto == icmp ) observe("icmp_new_flows", c);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    { observe("http_requests", c); }

event flush()
    {
    for ( [metric, dst, p] in buckets )
        {
        local b = buckets[metric, dst, p];
        local limit = tcp_limit;
        if ( metric == "http_requests" ) limit = http_limit;
        else if ( metric == "udp_new_flows" ) limit = udp_flow_limit;
        else if ( metric == "icmp_new_flows" ) limit = icmp_flow_limit;
        if ( b$observed < limit ) next;
        Log::write(LOG, [$ts=network_time(), $producer="soc-ai-dos-v1",
            $metric=metric, $dst=dst, $dst_port=port_to_count(p),
            $observed=b$observed, $threshold=limit, $window_seconds=window,
            $source_count=|b$sources|, $source_count_capped=b$capped,
            $msg=fmt("Suspected DoS: %s to %s:%s, %d observations in %s; threshold %d; availability impact not confirmed",
                     metric, dst, p, b$observed, window, limit)]);
        }
    if ( dropped > 0 )
        Reporter::warning(fmt("SOCDOS target capacity reached: %d observations omitted in this window", dropped));
    buckets = table();
    dropped = 0;
    schedule window { flush() };
    }

event zeek_init()
    {
    Log::create_stream(LOG, [$columns=Info, $path="dos"]);
    schedule window { flush() };
    }
