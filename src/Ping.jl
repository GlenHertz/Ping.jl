module Ping

export ping, monitor_subnet, ip_range, ping_active, monitor_ips, skip_bad_hosts, ip_summary

using Dates, Base.Iterators, Sockets


function _ping(results::Channel, jobid::Integer, ip::IPv4; max_ping::Millisecond=Millisecond(999),
                                                           interval::Millisecond=Millisecond(1000),
                                                           delay::Millisecond=Millisecond(0),
                                                           verbose=false)
    sleep(delay)
    interval = Dates.value(Millisecond(interval))/1000
    cmd = `ping -O -i $interval $ip`
    eachping = Iterators.Stateful(eachline(cmd))
    # Drop first line (header of ping output):
    line1 = popfirst!(eachping)
    verbose && println(line1)
    max_ping_int = max_ping.value
    for line in eachping
        verbose && println(line)
        ms = max_ping
        m = match(r"time\s*[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", line)
        if !isnothing(m)
            ms = Millisecond(min(max_ping_int, round(Int, parse(Float64, m[1]))))
        end
        put!(results, (jobid, ms))
    end
end

"""
    ping(ip_addressess; options...)

Ping ip_addresses in parallel and print results to screen in a table format
"""
function ping(ips::AbstractVector{IPv4}; run_for::TimePeriod=Second(10),
                                         update_interval::TimePeriod=Millisecond(1000),
                                         max_ping::Millisecond=Millisecond(999),
                                         rate::Millisecond=Millisecond(200),
                                         verbose=false,
                                         log=true,
                                         summarize=false)
    N = length(ips)
    #results = Channel{Tuple{Int64, Millisecond}}(N)
    results = Channel{Any}(N)
    if rate < Millisecond(200)
        @warn "rate of $rate may flood your network, consider increasing rate"
    end
    interval = N*rate
    println("Monitoring $N hosts with ping interval of $interval and update interval of $update_interval")
    for (jobid, ip) in enumerate(ips)
        @async _ping(results, jobid, ip; max_ping, interval, verbose, delay=(jobid-1)*rate)
    end
    latest_pings = Vector{Union{Missing,Millisecond}}(missing, N)
    max_pings = Vector{Union{Missing,Millisecond}}(missing, N)
    min_pings = Vector{Union{Missing,Millisecond}}(missing, N)
    sum_pings = Vector{Union{Missing,Millisecond}}(missing, N)
    counts = zeros(N)
    if summarize
        println("Info: Monitoring these $N IPs for $run_for:")
        summary = ip_summary(ips)
        print(summary)
    end
    start = now()
    fname = "ping_$(start).csv"
    f = open(fname, "w")
    tpad = 23
    update_time = start + update_interval
    str = string(rpad("Time", tpad), ",", join(lpad.(alias2.(ips), 3), ","))
    if log
        println(str)
        println(f, str)
    end
    while true
        jobid, ms = take!(results)
        latest_pings[jobid] = ms
        if now() > update_time #&& all(>(0), latest_pings)
            for i in 1:N
                p = latest_pings[i]
                if !ismissing(p)
                    counts[i] += 1
                    max_pings[i] = ismissing(max_pings[i]) ? p : max(max_pings[i], p)
                    min_pings[i] = ismissing(min_pings[i]) ? p : min(min_pings[i], p)
                    sum_pings[i] = ismissing(sum_pings[i]) ? p : sum_pings[i] + p
                end
            end
            rm_negatives = [ismissing(p) ? lpad("", 3) : lpad(p.value, 3) for p in latest_pings]
            str = string(rpad(now(), tpad, "0"), ",", join(rm_negatives, ","))
            if log
                if summarize && maximum(counts) % 30 == 0
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
    close(f)
    close(results)
    avg_pings = Vector{Union{Missing,Millisecond}}(missing, N)
    for i in 1:N
        s, c = sum_pings[i], counts[i]
        avg_pings[i] = c == 0 ? missing : Millisecond(round(Int, s.value / c))
    end
    return [(ip=ips[i], min=min_pings[i], avg=avg_pings[i], max=max_pings[i]) for i in 1:N]
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

const T = Union{<:Int, <:OrdinalRange{Int64, Int64}, Array{<:Int, 1}}
function ip_range(byte1::T, byte2::T, byte3::T, byte4::T)
    # Reverse 'product' so fastest iteration index is the leftmost byte
    ips = vec(collect(product(byte4, byte3, byte2, byte1)))
    ips = getaddrinfo.([join(ip[end:-1:1], ".") for ip in ips])
end

function alias(name::AbstractString)
    idxs = [1,min(2, length(name)), length(name)]
    name[idxs]
end
function alias(name::IPv4, fullyqualifiedname::AbstractString)
    n = fullyqualifiedname
    if string(name) == n
        return n[end-2:end]
    end
    hostname = first(split(n, "."))
    alias(hostname)
end
function alias2(name::IPv4)
    string(name)[end-2:end]
end

function ip_summary(ip::IPv4)
    fullyqualifiedname = getnameinfo(ip)
    hostname = first(split(fullyqualifiedname, "."))
    aliases = alias(hostname)
end
function ip_summary(ips::AbstractVector{IPv4})
    N = length(ips)
    fullyqualifiednames = Vector{Any}(undef, N)
    hostnames = Vector{Any}(undef, N)
    aliases = Vector{Any}(undef, N)
    @sync for i in 1:N
        @async begin
            t1 = now()
            fullyqualifiednames[i] = getnameinfo(ips[i])
            hostnames[i] = first(split(fullyqualifiednames[i], "."))
            aliases[i] = alias(ips[i], fullyqualifiednames[i])
            t2 = t1 - now()
            #println("Iteration $i took $(Millisecond(t2).value/1000) seconds")
        end
    end
    ipad = mapreduce(x->length(string(x)), max, ips)
    fpad = mapreduce(length, max, fullyqualifiednames)
    hpad = mapreduce(length, max, hostnames)
    apad = mapreduce(length, max, aliases)

    str = ""
    for (ip, f, h, a) in zip(ips, fullyqualifiednames, hostnames, aliases)
        str *= string("    $(rpad(ip, ipad)) $(rpad(f, fpad)) $(rpad(h, hpad)) $(lpad(a, apad))\n")
    end
    return str
end
function ip_summary(ips::AbstractVector{<:AbstractString})
    ip_summary(getaddrinfo.(ips))
end
function ip_summary(ip)
    ip_summary([ips])
end

function skip_bad_hosts(ips::AbstractVector{IPv4}; run_for::TimePeriod=Second(10), max_ping=Millisecond(999), verbose=false, log=false, summarize=false)
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

function ping_active(ips::AbstractVector{IPv4}; run_for=Second(10), skip_time::TimePeriod=Second(10), repeat_header=30, max_ping=Millisecond(999), log=true, log_skips=false, verbose=false, summarize=true)
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
