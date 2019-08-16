# mtracecap: A utility for capturing packets concurrently on several network devices to a compressed stream
Original work from https://ant.isi.edu/software/mtracecap/index.html

## Description
This utility captures network traffic from several different sources, merges the output and writes out a single output
stream. The stream may be optionally broken up into different timestamp-named files based on time duration or size.
Further, before saving, the output may be compressed on the fly by piping it out through an external binary compressor.
All compression would be done in a separate process, thus increasing total throughput.

# Dependencies
This package requires Libtrace version 4 or later (https://github.com/LibtraceTeam/libtrace)

# Usage
```
mtracecap flags outputuri traceuri [traceuri...]
  or
mtracecap flags -B baseuri traceuri [traceuri...]

where flags are:
[-B | --baseuri] baseuri
    Output timestamped files to this baseuri
[-F | --filter] bpf
    Discard packets not matching the filter
[-G | --rotate-seconds] seconds
    Rotate output every so often, even if there are no packets
[-S | --rotate-sizemb] sizeMB
    Rotate output when it exceeds sizeMB
[-H | --libtrace-help]
    Print libtrace runtime documentation
[-h | --help]
    Print this help
[-s | --snaplen] bytes
    Capture this much of a packet
[-U | --use-utc]
    Use UTC in timestamping files
[-v | --verbose]
    Verbose output on stderr
[-W | --watchfile] filename
    Wait until the watchfile is created before proceeding with next segment
[-w | --maxwait_ms] wait_ms
[-z | --compress-level] level
    Sets compression level of output
[-Z | --compress-type] type
    Sets compression type
[--file-ext=<extension>]
    Sets output file extension (used with -B)
[--relinquish-privileges=<username>]
    Run capture as <username>
[--pipeout=<command>]
    Pipe output through <command> first
```