#include "atlstr.h"

#ifndef _LOG_H_  
#define _LOG_H_  

#include <string>  
#include <iostream>  

#define LOG_INFO(fmt, ...) LOGS(0, 0, mformat(fmt, __VA_ARGS__))
#define LOG_WRAN(fmt, ...) LOGS(1, 0, mformat(fmt, __VA_ARGS__))
#define LOG_ERROR(fmt, ...) LOGS(2, 0, mformat(fmt, __VA_ARGS__))
#define LOG_DEBUG(fmt, ...) LOGS(3, 0, mformat(fmt, __VA_ARGS__))

#define LOG_INFO_LINE(fmt, ...) LOGS(0, 1, mformat(fmt, __VA_ARGS__))
#define LOG_WRAN_LINE(fmt, ...) LOGS(1, 1, mformat(fmt, __VA_ARGS__))
#define LOG_ERROR_LINE(fmt, ...) LOGS(2, 1, mformat(fmt, __VA_ARGS__))
#define LOG_DEBUG_LINE(fmt, ...) LOGS(3, 1, mformat(fmt, __VA_ARGS__))

std::string mformat(const char *fmt, ...);
void LOGS(int type, int wrap, std::string msg);
void getTimestamp();

#endif //_LOG_H_