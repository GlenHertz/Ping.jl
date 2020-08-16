module Ping

export ping, pping, monitor_subnet, ip_range, ip2tuple, sort_ips, monitor_active, monitor_ips

using Dates, Base.Iterators, Sockets


"""
    ping(ips::AbstractArray; c=1, W=0.1, loss=-0.001, verbose=false, sleeper=()->0)

ping
"""
function ping(ip; c=1, W=0.1, loss=-1, verbose=false)
   try
       s = read(`ping -c $c -W $W $ip`, String)
       m = match(r"([0-9.]+)% packet loss, time (\d.*)+\nrtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s+(\S+)", s)
       if !isnothing(m)
           pct_packet_loss = round(Int, parse(Float64, m[1]))
           mult = 1e3
           if m[7] == "ms"
              mult = 1
           end
           #min = round(Int, parse(Float64, m[3]) * mult)
           #avg = round(Int, parse(Float64, m[4]) * mult)
           max = round(Int, parse(Float64, m[5]) * mult)
           #mdev = round(Int, parse(Float64, m[6]) * mult)
           verbose && println("$ip\t$(pct_packet_loss)%\t$max")
           return (ip=ip, loss=pct_packet_loss, max=max)
       else
           verbose && println("$ip no match: $s")
           return (ip=ip, loss=100, max=Float64(loss))
       end
   catch e
       if verbose
           verbose && println("$ip error: $e")
       end
       return (ip=ip, loss=100, max=Float64(loss))
   end
end

"""
    pping(ips::AbstractArray; c=1, W=0.1, max_default=5000.0, verbose=false, sleeper=()->0)

Parallel ping
"""
function pping(ips::AbstractArray; c=1, W=0.1, loss=999, verbose=false, sleeper=()->0)
    N = length(ips)
    ss = Vector{Any}(undef, N)
    @sync begin
        for i in 1:N
            ip = ips[i]
            @async begin
                sleep(sleeper())
                p = ping(ip; c=c, W=W, loss=loss, verbose=verbose)
                if !isnothing(p) && typeof(p.max) <: Real
                    ss[i] = p
                else
                    #ss[i] = missing
                end
            end
        end
    end
    return ss
end

const T = Union{<:Int,<:OrdinalRange{Int64,Int64}}

function ip_range(byte1::T, byte2::T, byte3::T, byte4::T)
    # Reverse 'product' so fastest iteration index is the leftmost byte
    ips = vec(collect(product(byte4, byte3, byte2, byte1)))
    ips = [join(ip[end:-1:1], ".") for ip in ips]
end

function ip2tuple(ip::AbstractString)
    tuple(parse.(Int64, split(ip, "."))...)
end
function tuple2ip(ipt::NTuple{4, Int64})
    join(ipt, ".")
end
function sort_ips(ips::AbstractVector{<:AbstractString})
    tuple2ip.(sort(ip2tuple.(ips)))
end
function ip_summary(ips)
    lns = ip2long_name.(ips)
    sns = long2short_name.(lns)
    als = short_host2alias.(sns)
    str = ""
    for (ip, ln, sn, al) in zip(ips, lns, sns, als)
        str *= string("    $(rpad(ip, 15)) $(rpad(ln, 30)) $(rpad(sn, 15)) $(lpad(al, 3))\n")
    end
    return str
end

function skip_bad_hosts(ips::AbstractVector; init_pings=10, c=1, W=0.1, loss=999, verbose=false, sleeper=()->0)
    println("Info: Scanning $(length(ips)) hosts to skip ones with 100% packet loss for $init_pings consecutive pings")
    if init_pings > 0
        active_ips = Set{String}()
        for i in 1:init_pings
            pings = pping(ips::AbstractArray; c, W, loss, verbose, sleeper)
            actives = [i.ip for i in filter(p->p.loss != 100, pings)]
            union!(active_ips, actives)
        end
        skips = setdiff(ips, active_ips)
        ips = sort_ips(collect(active_ips))
        if length(skips) > 0
            println("Warning: Skipping $(length(skips)) IPs with 100% packet loss after $init_pings pings")
            println("Info: Monitoring these $(length(ips)) IPs:")
            lns = ip2long_name.(ips)
            sns = long2short_name.(lns)
            print(ip_summary(ips))
        end
    end
    ips = sort_ips(ips)
end

function monitor_active(byte1::T, byte2::T, byte3::T, byte4::T, period=Minute(1); init_pings=10, repeat_header=30, c=1, W=0.1, loss=999, verbose=false, sleeper=()->0)
    ips = ip_range(byte1, byte2, byte3, byte4)
    ips = skip_bad_hosts(ips; init_pings, W, c, loss, verbose, sleeper)
    montior_ips(ips, period; repeat_header, c, W, loss, verbose, sleeper)
    ips 
end
function short_host2alias(short_name::AbstractString)
    if startswith(short_name, r"[0-9]")
        return last(split(short_name, "."))
    else
        return string(short_name[1], short_name[2], short_name[end])
    end
end
function long2short_name(long_name::AbstractString)
    if startswith(long_name, r"[0-9]")
        return long_name
    else
        return first(split(long_name, '.'))
    end
end
function ip2long_name(ip)
    long_names = getnameinfo(IPv4(ip))
end
function montior_ips(ips, period=Minute(1); repeat_header=30, c=1, W=1, loss=999, verbose=false, sleeper=()->0)
    start = now()
    fname = "ping_$(start).csv"
    long_names = ip2long_name.(ips)
    short_names = long2short_name.(long_names)
    aliases = short_host2alias.(short_names)
    alias_header = string(rpad("DateTime",23), ",", join([lpad(al, 3) for al in aliases], ","))
    open(fname, "w") do f
        println(f, alias_header)
        println(alias_header)
        ipst = ip2tuple.(ips)
        ip_sum = ip_summary(ips)
        count = 0
        while now() < start + period
            count += 1
            if count % repeat_header == 0
                print(ip_sum)
                println(alias_header)
            end
            pings = pping(ips; c, W, loss, verbose, sleeper)
            pings = sort(pings, by=x->ip2tuple(x.ip))
            str = string(rpad(now(), 23, "0"), ",", join([lpad(p.max, 3) for p in pings], ","))
            println(f, str)
            println(str)
        end
    end
    ips
end


end # module
