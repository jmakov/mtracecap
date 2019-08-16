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

#ifndef MTC_LOG_H
#define MTC_LOG_H

#include <cstdarg>

static const char *log_strings[] = { "ERROR: ", "INFO : ", "DEBUG: " };
class MTC_Log {
public:
    enum loglvl_t {
                   LOG_LEVEL_PANIC = 0,
                   LOG_LEVEL_VERBOSE = 1,
                   LOG_LEVEL_DEBUG = 2
    };

    MTC_Log() :
        log_level_(LOG_LEVEL_PANIC) {}
    
    void set_log_level(int l) {
        if (l < LOG_LEVEL_PANIC)
            log_level_ = LOG_LEVEL_PANIC;
        else if (l > LOG_LEVEL_DEBUG)
            log_level_ = LOG_LEVEL_DEBUG;
        else
            log_level_ = static_cast<loglvl_t>(l);
    }

    inline bool verbose() const {
        return log_level_ > LOG_LEVEL_PANIC;
    }
    inline void panic(const char *msg, ...) const {
        va_list args;
        va_start(args, msg);
        _log(LOG_LEVEL_PANIC, msg, args);
        va_end(args);
        exit(1);
    }

    inline void warn(const char *msg, ...) const {
        va_list args;
        va_start(args, msg);
        _log(LOG_LEVEL_VERBOSE, msg, args);
        va_end(args);
    }

    inline void debug(const char *msg, ...) const {
        va_list args;
        va_start(args, msg);
        _log(LOG_LEVEL_DEBUG, msg, args);
        va_end(args);
    }

protected:
    inline void
    _log(loglvl_t level, const char *msg, va_list args) const {
        if (log_level_ < level)
            return;
        ::fputs(log_strings[level], stderr);
        ::vfprintf(stderr, msg, args);
    }

    loglvl_t log_level_;
};


#endif
