module Ping

export ping, monitor_subnet, ip_range, ip2tuple, ping_active, monitor_ips, skip_bad_hosts

using Dates, Base.Iterators, Sockets


function ping(results::Channel, jobid::Integer, ip::IPv4; max_ping=999, verbose=false)
    eachping = Iterators.Stateful(eachline(`ping -D -O -W $(max_ping/1000) $ip`))
    # Drop first line (header of ping output):
    line1 = popfirst!(eachping)
    verbose && println(line1)
    for line in eachping
        verbose && println(line)
        ms = max_ping
        m = match(r"time\s*[=<]\s*([0-9]+(\.[0-9]+)?)\s*ms", line)
        if !isnothing(m) 
            ms = min(max_ping, round(Int, parse(Float64, m[1])))
        end
        put!(results, (jobid, ms))
    end
end

function ping(ips::AbstractVector{IPv4}; run_for::TimePeriod=Second(10), update_interval::TimePeriod=Millisecond(1100), max_ping=999, verbose=false, log=true, summarize=false)
    results = Channel{Tuple{Int64, Int64}}(100)
    for (jobid, ip) in enumerate(ips)
        @async ping(results, jobid, ip; max_ping, verbose)
    end
    N = length(ips)
    latest_pings = fill(-1, N)
    max_pings = fill(-1, N)
    min_pings = fill(max_ping, N)
    sum_pings = fill(0, N)
    count = 0
    if summarize
        println("Info: Monitoring these $N IPs for $run_for:")
        summary = ip_summary(ips)
        print(summary)
    end
    start = now()
    fname = "ping_$(start).csv"
    f = open(fname, "w")
    try
        update_time = start + update_interval
        str = string(rpad("Time", 23), ",", join(lpad.(alias.(ips), 3), ","))
        if log
            println(str)
            println(f, str)
        end
        while true
            jobid, ms = take!(results)
            latest_pings[jobid] = ms
            if now() > update_time #&& all(>(0), latest_pings)
                for i in 1:N
                    if latest_pings[i] == -1
                        continue
                    end
                    max_pings[i] = max(max_pings[i], latest_pings[i])
                    min_pings[i] = min(min_pings[i], latest_pings[i])
                    sum_pings[i] += latest_pings[i]
                end
                count += 1
                rm_negatives = [p == -1 ? lpad("", 3) : lpad(p, 3) for p in latest_pings]
                str = string(rpad(now(), 23, "0"), ",", join(rm_negatives, ","))
                if log
                    if summarize && count % 30 == 0
                        println(summary)
                    end
                    println(str)
                    println(f, str)
                end
                update_time = now() + update_interval
            end
            if now() > start + run_for
                break
            end
        end
    finally
        close(f)
        close(results)
    end
    if count == 0
        return []
    end
    avg_pings = round.(Int, sum_pings ./ count)
    return [(min=min_pings[i], avg=avg_pings[i], max=max_pings[i]) for i in 1:N]
end

function ping(ips::AbstractVector{<:AbstractString}; kwargs...)
    ping(getaddrinfo.(ips); kwargs...)
end
function ping(ip; kwargs...)
    ping([ip]; kwargs...)
end
function ping(byte1, byte2, byte3, byte4; kwargs...)
    ping(ip_range(byte1, byte2, byte3, byte4); kwargs...)
end

const T = Union{<:Int,<:OrdinalRange{Int64,Int64}}
function ip_range(byte1::T, byte2::T, byte3::T, byte4::T)
    # Reverse 'product' so fastest iteration index is the leftmost byte
    ips = vec(collect(product(byte4, byte3, byte2, byte1)))
    ips = getaddrinfo.([join(ip[end:-1:1], ".") for ip in ips])
end

function ip2tuple(ip::AbstractString)
    tuple(parse.(Int64, split(ip, "."))...)
end
function tuple2ip(ipt::NTuple{4, Int64})
    join(ipt, ".")
end
function host(ip::IPv4)
    names = getnameinfo.(ip)
    host = first(split(string(names), "."))
end
function alias(ip::IPv4)
    name = host.(ip)
    string(name[1], name[2], name[end])
end
    
function ip_summary(ips::AbstractVector{IPv4})
    lns = getnameinfo.(ips)
    sns = host.(ips)
    als = alias.(ips)
    str = ""
    for (ip, ln, sn, al) in zip(ips, lns, sns, als)
        str *= string("    $(rpad(ip, 15)) $(rpad(ln, 30)) $(rpad(sn, 15)) $(lpad(al, 3))\n")
    end
    return str
end
function ip_summary(ips::AbstractVector{<:AbstractString})
    ip_summary(getaddrinfo.(ips))
end
function ip_summary(ip)
    ip_summary([ips])
end

function skip_bad_hosts(ips::AbstractVector{IPv4}; run_for::TimePeriod=Second(10), max_ping=999, verbose=false, log=false, summarize=false)
    N = length(ips)
    println("Info: Scanning $(N) hosts for $run_for to skip ones with 100% packet loss")
    stats = ping(ips; run_for, verbose, log, summarize)
    #foreach(println, stats)
    skips = ips[(filter(i -> stats[i].min == max_ping, 1:N))]
    setdiff!(ips, skips)
    if length(skips) > 0
        println("Warning: Skipping $(length(skips)) IPs with 100% packet loss after $run_for")
    end
    return ips
end
function skip_bad_hosts(ips::AbstractVector{<:AbstractString}; kwargs...)
    ips = getaddrinfo.(ips)
    skip_bad_hosts(ips; kwargs...)
end
function skip_bad_hosts(byte1, byte2, byte3, byte4; kwargs...)
    ips = ip_range(byte1, byte2, byte3, byte4)
    skip_bad_hosts(ips; kwargs...)
end

function ping_active(ips::AbstractVector{IPv4}; run_for=Second(10), skip_time::TimePeriod=Second(10), repeat_header=30, max_ping=999, log=true, log_skips=false, verbose=false, summarize=true)
    ips = skip_bad_hosts(ips; log=log_skips, run_for=skip_time, verbose)
    stats = ping(ips; run_for, max_ping, verbose, log, summarize)
    [(ip=ips[i], min=stats[i].min, stats[i].avg, stats[i].max) for i in 1:length(ips)]
end
function ping_active(ips::AbstractVector{<:AbstractString}; kwargs...)
    ips = getaddrinfo.(ips)
    ping_active(ips; kwargs...)
end
function ping_active(byte1::T, byte2::T, byte3::T, byte4::T; kwargs...)
    ips = ip_range(byte1, byte2, byte3, byte4)
    ping_active(ips; kwargs...)
end
function ping_active(host; kwargs...)
    ping_active([host]; kwargs...)
end


end # module
