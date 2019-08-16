/* -*-  Mode:C++; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * Copyright (C) 2016-2019 by the University of Southern California
 * $Id$
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <cassert>
#include <libtrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <grp.h>
#include <pwd.h>

#include "mtc_log.hh"
#include "mtc_output.hh"

#define MAXWAIT_MS 1 

static void usage(char *prog) {
    fprintf(stderr,"Usage:\n"
            "%s flags outputuri traceuri [traceuri...]\n"
            "  or\n"
            "%s flags -B baseuri traceuri [traceuri...]\n"
            "\n"
            "where flags are:\n"
            "[-B | --baseuri] baseuri\n"
            "    Output timestamped files to this baseuri\n"
            "[-F | --filter] bpf\n"
            "    Discard packets not matching the filter\n"
            "[-G | --rotate-seconds] seconds\n"
            "    Rotate output every so often, even if there are no packets\n"
            "[-S | --rotate-sizemb] sizeMB\n"
            "    Rotate output when it exceeds sizeMB\n"
            "[-H | --libtrace-help]\n"
            "    Print libtrace runtime documentation\n"
            "[-h | --help]\n"
            "    Print this help\n"
            "[-s | --snaplen] bytes\n"
            "    Capture this much of a packet\n"
            "[-U | --use-utc]\n"
            "    Use UTC in timestamping files\n"
            "[-v | --verbose]\n"
            "    Verbose output on stderr\n"
            "[-W | --watchfile] filename\n"
            "    Wait until the watchfile is created before proceeding with next segment\n"
            "[-w | --maxwait_ms] wait_ms\n"
            "[-z | --compress-level] level\n"
            "    Sets compression level of output\n"
            "[-Z | --compress-type] type\n"
            "    Sets compression type\n"
            "[--file-ext=<extension>]\n"
            "    Sets output file extension (used with -B)\n"
            "[--relinquish-privileges=<username>]\n"
            "    Run capture as <username>\n"
            "[--pipeout=<command>]\n"
            "    Pipe output through <command> first\n"
            , prog, prog);
    exit(1);
}

volatile int signalled = 0;

static void cleanup_signal(int sig) {
    if (sig == SIGCHLD) {
        int status = 0;
        waitpid(-1, &status, WNOHANG);
        return;
    }
    signalled = 1;
    trace_interrupt();
}


//struct time_order {
//    bool operator() (const libtrace_packet_t * lhs,
//                     const libtrace_packet_t * rhs) const {
//        return (trace_get_erf_timestamp(lhs) > trace_get_erf_timestamp(rhs));
//    };
//};


static const char * opt_seqnumfile = 0;
static const char * opt_pipe_arg[1024];

int
main(int argc, char *argv[]) {
    MTC_Input *input;
    int i=0;
    struct sigaction sigact;
    trace_option_compresstype_t compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
    int         opt_compress_level = -1;
    const char *opt_compress_type = NULL;
    int         opt_snaplen = 64;
    const char *opt_watchfile = NULL;
    const char *opt_relinquish = NULL;
    const char *opt_extension = NULL;
    const char *opt_filter = NULL;
    char       *opt_basename = NULL;
    char       *opt_pipeout = NULL;
    ulong       opt_segmentsize = 0;
    time_t      opt_rotatesec = 0;
    ulong       opt_maxwait = MAXWAIT_MS;
    int         opt_verbose = MTC_Log::LOG_LEVEL_PANIC;
    bool        opt_useutc = false;

    //    uint64_t total_packets = 0;
    //std::priority_queue<struct libtrace_packet_t *,
    //                    std::vector<struct libtrace_packet_t *>,
    //                    time_order > pqueue;
#define OPT_RELINQUISH_PRIVS    0x01f0
#define OPT_PIPEOUT             0x01f1
#define OPT_FILE_EXT            0x01f2
    while (1) {
        int option_index;
        struct option long_options[] =
            {
             { "libtrace-help",  0, 0, 'H' },
             { "help",           0, 0, 'h' },
             { "baseuri",        1, 0, 'B' },
             { "rotate-seconds", 1, 0, 'G' },
             { "seqfile",        1, 0, 'N' },
             { "rotate-sizemb",  1, 0, 'S' },
             { "snaplen",        1, 0, 's' },
             { "use-utc",        0, 0, 'U' },
             { "verbose",        0, 0, 'v' },
             { "watchfile",      1, 0, 'W' },
             { "maxwait_ms",     1, 0, 'w' },
             { "compress-level", 1, 0, 'z' },
             { "compress-type",  1, 0, 'Z' },
             { "filter",         1, 0, 'F' },
             { "relinquish-privileges",
               1, 0, OPT_RELINQUISH_PRIVS },
             { "pipeout",        1, 0, OPT_PIPEOUT },
             { "file-ext",       1, 0, OPT_FILE_EXT },
             { NULL,             0, 0, 0   },
            };

        int c = getopt_long(argc, argv, "HhF:B:G:N:S:s:Uvz:Z:W:w:",
                            long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
        case 'H': 
            trace_help();
            exit(1);
            break;
        case 'h':
            usage(argv[0]);
            break;
        case 'B':
            opt_basename = optarg;
            break;
        case 'F':
            opt_filter = optarg;
            break;
        case 'G':
            opt_rotatesec = strtoul(optarg, NULL, 10);
            break;
        case 'N':
            opt_seqnumfile = optarg;
            break;
        case 'S':
            opt_segmentsize = strtoul(optarg, NULL, 10);
            break;
        case 's':
            opt_snaplen = atoi(optarg);
            break;
        case 'U':
            opt_useutc = true;
            break;
        case 'v':
            ++opt_verbose;
            break;
        case 'W':
            opt_watchfile = optarg;
            break;
        case 'w':
            opt_maxwait = strtoul(optarg, NULL, 10);
            break;
        case 'z':
            opt_compress_level = atoi(optarg);
            if (opt_compress_level<0 || opt_compress_level>9) {
                fprintf(stderr,"Compression level must be between 0 and 9\n");
                usage(argv[0]);
            }
            break;
        case 'Z':
            opt_compress_type = optarg;
            break;
        case OPT_RELINQUISH_PRIVS:
            opt_relinquish = optarg;
            break;
        case OPT_PIPEOUT:
            opt_pipeout = optarg;
            {
                int ii=0, cc=0;
                opt_pipe_arg[cc] = opt_pipeout;
                for (; opt_pipeout[ii] != '\0'; ++ii) {
                    if (opt_pipeout[ii] == ' ') {
                        opt_pipeout[ii] = '\0';
                        opt_pipe_arg[++cc] = &opt_pipeout[ii+1];
                    }
                }
                opt_pipe_arg[++c] = NULL;
            }
            break;
        case OPT_FILE_EXT:
            opt_extension = optarg;
            break;
        default:
            fprintf(stderr,"unknown option: %c\n",c);
            usage(argv[0]);
        }

    }
    if (opt_basename) {
        if (optind + 1 > argc)
            usage(argv[0]);
    } else {
        if (optind + 2 > argc)
            usage(argv[0]);
    }
    
    MTC_Log tclog;
    tclog.set_log_level(opt_verbose);

    if (opt_compress_type == NULL && opt_compress_level >= 0) {
        fprintf(stderr, "Compression level set, but no compression type was defined, setting to gzip\n");
        compress_type = TRACE_OPTION_COMPRESSTYPE_ZLIB;
    } else if (opt_compress_type == NULL) {
        /* If a level or type is not specified, use the "none"
         * compression module */
        compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
    } else if (strncmp(opt_compress_type, "gz", 2) == 0 ||
               strncmp(opt_compress_type, "zlib", 4) == 0) {
        compress_type = TRACE_OPTION_COMPRESSTYPE_ZLIB;
    } else if (strncmp(opt_compress_type, "bz", 2) == 0) {
        compress_type = TRACE_OPTION_COMPRESSTYPE_BZ2;
    } else if (strncmp(opt_compress_type, "lzo", 3) == 0) {
        compress_type = TRACE_OPTION_COMPRESSTYPE_LZO;
    } else if (strncmp(opt_compress_type, "xz", 2) == 0) {
        compress_type = TRACE_OPTION_COMPRESSTYPE_LZMA;
    } else if (strncmp(opt_compress_type, "no", 2) == 0) {
        compress_type = TRACE_OPTION_COMPRESSTYPE_NONE;
    } else {
        tclog.panic("Unknown compression type: %s\n", opt_compress_type);
    }
    
    timeval now;
    ::gettimeofday(&now, NULL);

    MTC_Output *tco = 0;
    if (opt_basename) {
        // if basename is given, this is a uri
        // to a rotatable file and all our arguments are input uri's
        tco = new MTC_Output(0, opt_basename, now, tclog);
    } else {
        // if no basename, first argument is output uri
        tco = new MTC_Output(argv[optind++], 0, now, tclog);
    }
    //the rest are input uris


    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM,&sigact, NULL);
    sigaction(SIGCHLD, &sigact, NULL);

    int inputs = argc - optind;
    
    input = new MTC_Input[inputs];

    struct libtrace_filter_t *filter = NULL;
    if (opt_filter) {
        filter = trace_create_filter(opt_filter);
    }
    for (i = 0; i < inputs; ++i) {
        //libtrace_packet_t *p = trace_create_packet();
        const char *uri = argv[i+optind];
        libtrace_t *f = ::trace_create(uri);
        if (::trace_is_err(f)) {
            trace_perror(f, "trace_create");
            exit(1);
        }
        if (trace_set_event_realtime(f, true) < 0) {
            trace_get_err(f);
        }
        trace_set_snaplen(f, opt_snaplen);
        if (filter) {
            if (trace_config(f, TRACE_OPTION_FILTER, filter) != 0) {
                trace_perror(f, "Failed to setup filter for %s\n", uri);
                exit(1);
            }
        }
        input[i].in_ = f;
        input[i].uri_= uri;
        input[i].active_ = true;
        if (trace_start(f) == -1) {
            trace_perror(f, "trace_start");
            exit(1);
        }
        libtrace_stat_t *stat = trace_get_statistics(input[i].in_, NULL);
        input[i].segment_drops_ = stat->dropped;
    }

    if (opt_relinquish) {
        struct passwd *pw = getpwnam(opt_relinquish);
        if (!pw) {
            tclog.panic("Can't find user '%s'\n", opt_relinquish);
        }
        if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
            setgid(pw->pw_gid) != 0 ||
            setuid(pw->pw_uid) != 0) {
            tclog.panic("Failed to drop root privileges: %s", strerror(errno));
        }
    }
    if (opt_seqnumfile) {
        tco->set_seqnumfile(opt_seqnumfile);
    }
    if (opt_compress_level >= 0 &&
        compress_type != TRACE_OPTION_COMPRESSTYPE_NONE) {
        tco->set_compression(compress_type, opt_compress_level);
    }

    if (opt_watchfile) {
        tco->set_watchfile(opt_watchfile);
    }
    if (opt_segmentsize) {
        tco->set_segmentsize(1024*1024*opt_segmentsize); //Mbytes to bytes
    }
    if (opt_rotatesec) {
        tco->set_rotatesec(opt_rotatesec);
    }
    if (opt_extension) {
        tco->set_extension(opt_extension);
    }

    tco->set_useutc(opt_useutc);
    if (opt_pipeout) {
        tco->set_pipeout((char* const*)opt_pipe_arg);
    }
    tco->set_inputs(input, inputs);

   
    fd_set rfds;
    timeval maxwait_tv;
    maxwait_tv.tv_sec = (opt_maxwait / 1000);
    maxwait_tv.tv_usec= (opt_maxwait % 1000)*1000;
        
    //int maxfd = -1;
    FD_ZERO(&rfds);
    int active_inputs = inputs;
    libtrace_packet_t *p = 0;
    int ret=0;
    while (active_inputs > 0 && !signalled) {
        timeval wait_tv = maxwait_tv; //not waiting more than that for ALL fds
        gettimeofday(&now, NULL);
        if (opt_rotatesec && (now.tv_sec >= tco->last_rotated().tv_sec + opt_rotatesec)) {
            tco->rotate_trace(now); //force rotation by time
        }
        uint64_t ts;
        uint64_t mintime_erf = -1;
        int      mintime_idx = -1;
        int      sources = 0;
        for (i = 0; i < inputs; ++i) {
            if (!input[i].active_)
                continue;
            if (input[i].packet_) {
                ts = trace_get_erf_timestamp(input[i].packet_);
                ++sources;
                if (ts < mintime_erf) {
                    mintime_erf = ts;
                    mintime_idx = i;
                }
                continue; //already have a packet
            }            
            if (p == 0)
                p = trace_create_packet();
            libtrace_eventobj_t evt = trace_event(input[i].in_, p);
            
            //uint64_t ts = trace_get_erf_timestamp(p);
            switch (evt.type) {
            case TRACE_EVENT_SLEEP:
                tclog.debug("sleep event on %s (%d, for %es)\n",
                            input[i].uri_, i, evt.seconds);
#if 0
                FD_ZERO(&rfds);
                FD_SET(evt.fd, &rfds);
                {
                    struct timeval tv;
                    tv.tv_sec = int(evt.seconds);
                    tv.tv_usec= (evt.seconds - tv.tv_sec)*1e6;
                    select(0, &rfds, NULL, NULL, &tv);
                }
#else
                //--i; //retry immediately
                continue;
#endif

            case TRACE_EVENT_IOWAIT:
                //fprintf(stderr, "iowait, %d\n", i); 
                if ((wait_tv.tv_sec | wait_tv.tv_usec) == 0) {
                    //no more waiting!
                    continue;
                }
                FD_ZERO(&rfds);
                FD_SET(evt.fd, &rfds);
                ret = select(evt.fd + 1, &rfds, NULL, NULL, &wait_tv);
                if (ret == 0) {
                    continue; //timeout
                } else if (ret < 0) {
                    if (errno != EINTR)
                        tclog.warn("select returned error for wating on fd %d (%s)\n",
                                   evt.fd, input[i].uri_);
                    continue;
                }
                assert(ret == 1);
                evt = trace_event(input[i].in_, p);
                if (evt.type != TRACE_EVENT_PACKET) {
                    tclog.warn("event type: %d\n", evt.type);
                    //--i; //retry immediately
                    continue;
                }
                //assert(evt.type == TRACE_EVENT_PACKET);

                /* FALLTHROUGH */
                
            case TRACE_EVENT_PACKET:
                {
                    uint16_t ethertype;
                    uint32_t remaining;
                    void *vp = trace_get_layer3(p, &ethertype, &remaining);
                    if (!vp || ethertype == 0xffff) {
                        tclog.warn("skipping non L3 (ethernet) packet on %s\n", input[i].uri_);
                        --i; /* xxx rerun the same input */
                        continue;
                    }
                }
                //fprintf(stderr, "pushed: %p\n", p);
                input[i].packet_ = p;
                ts = trace_get_erf_timestamp(p);
                ++sources;
                if (ts < mintime_erf) {
                    mintime_erf = ts;
                    mintime_idx = i;
                }
                //                ++total_packets;
                ++input[i].total_packets_;
                ++input[i].segment_packets_;
                if (input[i].prev_ts_ > ts) {
                    tclog.warn("disorder on input %d: %.6f, packet: %llu\n",
                               i,
                               (double)(input[i].prev_ts_-ts)/(1ULL<<32),
                               input[i].total_packets_);
                }
                input[i].prev_ts_ = ts;
                p = 0;
                continue;
            case TRACE_EVENT_TERMINATE:
                //end of trace
                tclog.debug("TERMINATE on %d (%s)\n", i, input[i].uri_);
                input[i].active_ = false;
                assert(input[i].packet_ == 0);
                --active_inputs;
                continue;
            default:
                fprintf(stderr, "Unknown event type occured\n");
                trace_perror(input[i].in_, "%s", argv[i+2]);
                exit(1);
            }

            //oldest_ts>trace_get_erf_timestamp(packet[i]))) {
        }
        if (mintime_idx == -1) {
            //fprintf(stderr, "no packets!\n");
            continue;
        }
        if (p) {
            trace_destroy_packet(p);
            p = 0;
        }
        //fprintf(stderr, "%d\n", sources);
        p = input[mintime_idx].packet_;

        //check if we need to rotate
        timeval ptv = trace_get_timeval(p);
        if (opt_rotatesec && (ptv.tv_sec >= tco->last_rotated().tv_sec + opt_rotatesec)) {
            tco->rotate_trace(ptv); //force rotation by time
        }

        tco->write_packet(p);

        input[mintime_idx].packet_ = 0;
    }
    if (p) {
        trace_destroy_packet(p);
        p = 0;
    }

    if (opt_verbose) {
        tco->dump_seg_stats();
        tco->dump_tot_stats();
    }
    //xxx make sure all packets are done
    gettimeofday(&now, NULL);
    tco->rotate_trace(now);
    
    for (i = 0; i < inputs; ++i) {
        libtrace_stat_t *stat = trace_get_statistics(input[i].in_, NULL);
        tclog.warn("closing input %d, total packets: %llu, drops: %lu\n",
                   i, input[i].total_packets_, stat->dropped);
        trace_destroy(input[i].in_);
        input[i].active_ = false;
        assert(signalled || (input[i].packet_ == 0));
    }
    delete [] input;
    return 0;
}
