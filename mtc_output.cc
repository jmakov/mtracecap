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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <libtrace.h>
#include <cstring>
#include <string>
#include <cassert>

#include "mtc_log.hh"
#include "mtc_output.hh"

//empty pcap file that we dump if there is no traffic
//can't do it in libtrace apparently
static const unsigned char null_pcap[] = {
                                          0324, 0303, 0262, 0241, 0002, 0000, 0004, 0000,
                                          0000, 0000, 0000, 0000, 0000, 0000, 0000, 0000,
                                          0000, 0000, 0004, 0000, 0001, 0000, 0000, 0000
};

bool operator>(const timeval& lhs, const timeval& rhs) {
    return ((lhs.tv_sec > rhs.tv_sec) ||
            ((lhs.tv_sec == rhs.tv_sec) && (lhs.tv_usec > rhs.tv_usec)));
};


MTC_Output::MTC_Output(char *outputfn, char *basename,
                       const timeval &started, const MTC_Log &log) :
    outputfn_(0),
    basename_(0),
    watchfile_(0),
    seqnumfile_(0),
    extension_(0),
    format_(0),
    pipeout_(0),
    inputs_(0),
    inputs_cnt_(0),
    current_seqnum_(0),
    useutc_(true),
    signalled_(false),
    mtclog_(log),
    compress_level_(-1),
    compress_type_(TRACE_OPTION_COMPRESSTYPE_NONE),
    segmentsize_(0),
    current_segsize_(0),
    rotatesec_(0),
    total_disorders_(0),
    total_packets_(0),
    segment_packets_(0),
    segment_disorders_(0),
    output_(0),
    first_ts_(timeval{0,0}),
    last_ts_(timeval{0,0}),
    last_rotated_(started)
{
    //extract format
    char *p, **pp;
    if (basename) {
        p = basename;
        pp= &basename;
    } else {
        p = outputfn;
        pp= &outputfn;
    }
    format_ = p;
    for (;;) {
        if (*p == ':') {
            *p = '\0';
            *pp = p+1;
            break;
        } else if (*p == '\0') {
            mtclog_.panic("malformed output uri\n");
        }
        ++p;
    }
    assert( (basename != 0)^(outputfn != 0) );
   
    is_pcap_ = (std::string(format_) == std::string("pcapfile"));
    outputfn_ = outputfn;
    basename_ = basename;
}

MTC_Output::~MTC_Output() {
    close_trace();
}

/* Sequence numbers */
void
MTC_Output::init_seqnum() {
    /* write _seqnum to a disk */
    char str[128];
    char *endptr = &str[0];

    if (seqnumfile_ == NULL) {
        return;
    }
    int seqnumfd = open(seqnumfile_,
                        O_RDONLY|O_CREAT|O_SYNC,
                        S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (seqnumfd < 0) {
        mtclog_.panic("cannot open seqnum file (%s): %s\n",
                      seqnumfile_, strerror(errno));
    }
    size_t rlen = read(seqnumfd, str, sizeof(str)-1);
    if (rlen < 0) {
        mtclog_.panic("problem reading from seqnum file (%s): %s\n",
                      seqnumfile_, strerror(errno));
    } else if (rlen == 0) {
        mtclog_.warn("seqnum file (%s) is truncated, starting from zero\n",
                     seqnumfile_);
        current_seqnum_ = 0;
    } else {
        /* basic error checking */
        str[rlen] = '\0';
        if (str[rlen-1] != '\n' || strlen(str) != rlen) {
            mtclog_.panic("corrupt seqnum file (%s): %s\n",
                          seqnumfile_, str);
        }
        current_seqnum_ = strtoul(str, &endptr, 10);
        if (*endptr != '\n') {
            mtclog_.panic("corrupt seqnum file (%s): %s [%lu]\n",
                          seqnumfile_, str, current_seqnum_);
        }
        if (++current_seqnum_ > SEQNUM_MAX)
            current_seqnum_ = 0; /* wrap */

    }
    close(seqnumfd);
}

void
MTC_Output::save_seqnum() {
    char str[128];
    if (seqnumfile_ == NULL) {
        return;
    }
    int seqnumfd = open(seqnumfile_,
                        O_WRONLY|O_CREAT|O_SYNC|O_TRUNC,
                        S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);

    if (seqnumfd < 0) {
        fprintf(stderr, "error reopening seqnum file (%s): %s\n",
                seqnumfile_, strerror(errno));
    }
    sprintf(str, "%lu\n", current_seqnum_);
    int wlen = strlen(str);
    if (wlen != write(seqnumfd, str, wlen))
        fprintf(stderr, "error writing seqnum file (%s): %s\n",
                seqnumfile_, strerror(errno));
    close(seqnumfd);
}

void *
MTC_Output::close_trace(void *to) {
    if (to) {
        trace_destroy_output((libtrace_out_t*)to);
    }
    return NULL;
}

void
MTC_Output::close_trace() {
    if (is_pcap_ && output_ && segment_packets_ == 0) {
        //empty files are not allowed
        if (sizeof(null_pcap) != write(STDOUT_FILENO, null_pcap,
                                       sizeof(null_pcap))) {
            mtclog_.warn("Cannot write null file %s\n", namebuf_);
        }
    }
    close_trace(output_);
    output_ = 0;
    ::gettimeofday(&last_rotated_, 0);
    first_ts_.tv_sec = 0;
    first_ts_.tv_usec = 0;
    last_ts_.tv_sec = 0;
    last_ts_.tv_usec = 0;
}

int
MTC_Output::write_packet(libtrace_packet_t *p) {
    timeval ts = trace_get_timeval(p);
    
    if (!output_) {
        open_trace(ts);
    } else {
        //xxx update stats, maybe rotate
        current_segsize_ += trace_get_capture_length(p);
        if (segmentsize_ && current_segsize_ > segmentsize_) {
            //data-driven rotation by size
            //time-driven rotation is handled by calling open_trace()
            //from outside
            open_trace(ts);
        }
    }
    if (last_ts_ > ts) {
        ++segment_disorders_;
        ++total_disorders_;
    }
    last_ts_ = ts;
    
    ++total_packets_;
    ++segment_packets_;
    return trace_write_packet(output_, p);
}

void
MTC_Output::rotate_trace(const timeval& create_ts) {
    if (output_ == NULL) {
        open_trace(create_ts);
    }
    close_trace();
}

void
MTC_Output::open_trace(const timeval& ts) {
    if (output_ != NULL) {
        if (mtclog_.verbose())
            dump_seg_stats(); // has to be done here, before new thread
        /* close previous file: closing NFS files can take a while, so
         * start a new thread to do that. */
#if 0
        pthread_t th;
        pthread_attr_t attr;

        if (pthread_attr_init(&attr) != 0) {
            mtclog_.panic("pthread_attr_init");
        }

        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
            mtclog_.panic("pthread_attr_setdetachstate\n");
        }
        if (pthread_create(&th, &attr, close_trace, output_) != 0) {
            mtclog_.panic("pthread_create\n");
        }
        output_ = NULL;
#else
        close_trace();
#endif
    }

    /* before opening, sleep on a watchfile if any */
    size_t slept = sleep_on_watchfile();
    if (slept > 0)
        mtclog_.warn("slept on %s for %lu seconds\n",
                     watchfile_, (ulong)slept);

    if (basename_) {
        /* make up a new file's name */
        time_t t = (time_t)ts.tv_sec;
        struct tm *tm_ptr = (useutc_) ? gmtime(&t) : localtime(&t);
        
        tm_ptr->tm_year += 1900;
        tm_ptr->tm_mon++;

        sprintf(namebuf_, "%s/%4d%02d%02d-%02d%02d%02d-" SEQNUM_FMT "%s",
                basename_,
                tm_ptr->tm_year, tm_ptr->tm_mon, tm_ptr->tm_mday,
                tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec,
                current_seqnum_, (extension_)?extension_:"");
    } else {
        strncpy(namebuf_, outputfn_, sizeof(namebuf_)-1);
    }
    //namebuf_ now has "pure" (i.e. without format) filename of the output

    int filefd = STDOUT_FILENO;
    if (namebuf_[0] == '-' && namebuf_[1] == '\0') {
        //dumping to stdout in the first place, nothing to do
    } else {
        filefd = open(namebuf_, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        if (filefd < 0) {
            mtclog_.panic("Error opening file '%s': %s\n",
                          namebuf_,
                          strerror(errno));
        }
    }
    if (!pipeout_[0]) {
        ::dup2(filefd, STDOUT_FILENO);
    } else {
        insert_pipe(filefd);
    }
    /* open a new one */
    char stdout_uri[256];
    snprintf(stdout_uri, sizeof(stdout_uri), "%s:-", format_);
    output_ = trace_create_output(stdout_uri);
    if (trace_is_err_output(output_)) {
        trace_perror_output(output_, "trace_create_output");
        exit(1);
    }

    if (compress_level_ >= 0 && 
        trace_config_output(output_, 
                            TRACE_OPTION_OUTPUT_COMPRESS, &compress_level_) == -1) {
        trace_perror_output(output_, "Unable to set compression level");
        exit(1);
    }
    if (compress_type_ != TRACE_OPTION_COMPRESSTYPE_NONE) {
        if (trace_config_output(output_, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
                                &compress_type_) == -1) {
            trace_perror_output(output_, "Unable to set compression type");
            exit(1);
        }
    }

    if (trace_start_output(output_) == -1) {
        trace_perror_output(output_, "trace_start_output");
        exit(1);
    }

    save_seqnum(); /* save last sequence number written */
    if (++current_seqnum_ > SEQNUM_MAX)
        current_seqnum_ = 0; /* wrap */

    reset_segmentstats();
    first_ts_ = ts;
}

size_t
MTC_Output::sleep_on_watchfile() {
    size_t slept = 0;
    if (!watchfile_)
        return slept;

    bool suspended = false;
    for (;;) {
        if (signalled_) {
            //xxx cleanup first
            return slept;
        }
        int fd = open(watchfile_, O_RDONLY);
        if (fd != -1) {
            /* file exists */
            close(fd);
            break;
        } else {
            /* file does not exist: must sleep */
            if (!suspended) {
                fprintf(stderr, "going into sleep on watchfile...\n");
                /* suspend capture */
                //xxx
                //trace_pause(input[i].fs_)
                //xxx
                suspended = 1;
            }
            /* file doesn't exist: sleep then repeat */
            sleep(1);
            ++slept;
        }
    }
    if (suspended) {
        /* resume */
        //xxx
        //trace_start(input[i].fs_);
    }
    return slept;
}

void
MTC_Output::set_compression(trace_option_compresstype_t type, int level) {
    compress_type_ = type;
    compress_level_= level;
}

void
MTC_Output::dump_seg_stats() const {
    mtclog_.warn("uri=%s, packets=%lu, disorders=%lu\n",
                 namebuf_, segment_packets_, segment_disorders_);
    for (size_t i = 0; i<inputs_cnt_; ++i) {
        libtrace_stat_t *stat = trace_get_statistics(inputs_[i].in_, NULL);
        uint64_t segment_drops = stat->dropped - inputs_[i].segment_drops_;
        mtclog_.warn("    input=%lu: packets=%llu, drops=%lu\n", i,
                     inputs_[i].segment_packets_,
                     segment_drops);
        //reset
        inputs_[i].segment_drops_   = stat->dropped;
        inputs_[i].segment_packets_ = 0;
        
    }
}

void
MTC_Output::dump_tot_stats() const {
    mtclog_.warn("TOTAL: packets=%lu, disorders=%lu\n",
                 total_packets_, total_disorders_);
}

void
MTC_Output::insert_pipe(int fdw) {
    int pipefd[2];
#define PIPEBUFSZ (8*1024*1024)

    if (0 != ::socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd)) {
        mtclog_.panic("Error creating pipeout sockets: '%s'\n", strerror(errno));
    }
    for (int i = 0; i<2; ++i) {
        int bufsz = PIPEBUFSZ;
        if (0 != ::setsockopt(pipefd[i], SOL_SOCKET, SO_RCVBUF,
                              &bufsz, sizeof(bufsz))) {
            mtclog_.warn("setsockopt SO_RCVBUF failed\n");
        }
        bufsz = PIPEBUFSZ;
        if (0 != ::setsockopt(pipefd[0], SOL_SOCKET, SO_SNDBUF,
                              &bufsz, sizeof(bufsz))) {
            mtclog_.warn("setsockopt SO_SNDBUF failed\n");
        }
    }
    pid_t pipe_pid = fork();
    if (pipe_pid == -1) {
        mtclog_.panic("Error forking pipe: '%s'\n", strerror(errno));
    }
    if (pipe_pid == 0) {
        /* child */
        ::setpgid(0, 0);
        if (-1 == ::dup2(pipefd[0], STDIN_FILENO)) {
            mtclog_.panic("Error DUP compressor stdin: '%s'\n", strerror(errno));
        }
        close(pipefd[0]);
        if (-1 == ::dup2(fdw, STDOUT_FILENO)) {
            mtclog_.panic("Error DUP compressor stdout: '%s'\n", strerror(errno));
        }
        //close other fds
        int maxfd = getdtablesize();
        for (int i=0; i<maxfd; ++i) {
            if (i != STDIN_FILENO && i != STDOUT_FILENO && i != STDERR_FILENO)
                ::close(i);
        }
        ::execvp(pipeout_[0], pipeout_);
        mtclog_.panic("Failed to execute --pipeout command %s: %s\n",
                      pipeout_[0], strerror(errno));
    } else {
        /* parent */
        ::close(pipefd[0]);               /* read end of the pipe */
        ::dup2(pipefd[1], STDOUT_FILENO); /* write end of the pipe */
        ::close(pipefd[1]);
    }
}
