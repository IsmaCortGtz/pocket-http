#ifndef POCKET_HTTP_LOGS_HPP
#define POCKET_HTTP_LOGS_HPP

#include "pockethttp/Timestamp.hpp"

#if defined(USE_POCKET_HTTP_LOG) || defined(USE_POCKET_HTTP_ERR)
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#endif


#ifdef USE_POCKET_HTTP_LOG
#define pockethttp_log(...)   (std::cout << "[" << pockethttp::Timestamp::getFormatedTimestamp() << "] [POCKETHTTP] [LOG] " << __VA_ARGS__ << std::endl)
#else // USE_POCKET_HTTP_LOG
#define pockethttp_log(...)   ((void)0)
#endif // USE_POCKET_HTTP_LOG


#ifdef USE_POCKET_HTTP_ERR
#define pockethttp_error(...) (std::cerr << "[" << pockethttp::Timestamp::getFormatedTimestamp() << "] [POCKETHTTP] [ERR] " << __VA_ARGS__ << std::endl)
#else // USE_POCKET_HTTP_ERR
#define pockethttp_error(...) ((void)0)
#endif // USE_POCKET_HTTP_ERR


#endif // POCKET_HTTP_LOGS_HPP