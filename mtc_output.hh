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

#ifndef MTC_OUTPUT_HH
#define MTC_OUTPUT_HH

class MTC_Input {
public:
    MTC_Input():
        in_(0),
        uri_(0),
        active_(false),
        prev_ts_(0),
        segment_drops_(0),
        segment_packets_(0),
        total_packets_(0),
        packet_(0) {
    }
    struct libtrace_t *in_;
    const char        *uri_;
    bool               active_;
    uint64_t           prev_ts_;
    uint64_t           segment_drops_; // drops at the beginning of a segment
    unsigned long long segment_packets_;           
    unsigned long long total_packets_;

    libtrace_packet_t *packet_;
};

#define SEQNUM_FMT  "%08lu"
#define SEQNUM_MAX  99999999
#define LANDER_DEFAULT_EXT ".erf"

class MTC_Output {
public:
    MTC_Output(char *outputfn, char* basename, const timeval&, const MTC_Log &log);
    ~MTC_Output();


    int  write_packet(libtrace_packet_t *p);
    void open_trace(const timeval& ts);
    void close_trace();
    void rotate_trace(const timeval& ts); //force time-driven rotation
    void signal() { signalled_ = true; }
    void set_compression(trace_option_compresstype_t type, int level);
    void set_useutc(bool utc) { useutc_ = utc; }
    void set_watchfile(const char* watchfile) { watchfile_ = watchfile; }
    void set_seqnumfile(const char* seqnumfile) { seqnumfile_ = seqnumfile; init_seqnum(); }
    void set_segmentsize(ulong ss) { segmentsize_ = ss; }
    void set_rotatesec(ulong s) { rotatesec_ = s; }
    void set_inputs(MTC_Input *inputs, size_t inputs_cnt) { inputs_ = inputs; inputs_cnt_ = inputs_cnt; }
    void set_pipeout(char * const pipeout[]) { pipeout_ = pipeout; }
    void set_extension(const char* extension) { extension_ = extension; }
    void dump_seg_stats() const;
    void dump_tot_stats() const;
    const char* current_filename() { return namebuf_; }
    const timeval &last_rotated() { return last_rotated_; }
protected:
    void init_seqnum();
    void save_seqnum();
    void insert_pipe(int fdw);
    void reset_segmentstats() { segment_packets_ = 0; segment_disorders_ = 0; current_segsize_ = 0; }

    size_t sleep_on_watchfile();
    
    static void *close_trace(void *to);

protected:
    const char *outputfn_;
    const char *basename_;
    const char *watchfile_;
    const char *seqnumfile_;
    const char *extension_;
    const char *format_;
    char * const *pipeout_;
    
    MTC_Input *inputs_;
    size_t   inputs_cnt_;
    uint64_t current_seqnum_;
    bool     useutc_;
    bool     signalled_;
    const MTC_Log
    &mtclog_;
    
    int      compress_level_;
    trace_option_compresstype_t compress_type_;
    ulong    segmentsize_;

    ulong    current_segsize_;
    ulong    rotatesec_;
    
    uint64_t total_disorders_;
    uint64_t total_packets_;
    uint64_t segment_packets_;
    uint64_t segment_disorders_;

    struct libtrace_out_t      *output_;

    timeval  first_ts_;
    timeval  last_ts_;
    timeval  last_rotated_;
        
    char namebuf_[1024];
    bool     is_pcap_;
};

#endif /* MTC_OUTPUT_HH */
