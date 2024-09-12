#pragma once

#include <iostream>
#include <cstdint>
#include <string>
#include <chrono>
using namespace std::chrono;

template<typename clock = std::chrono::system_clock>
static int64_t get_tick_count()
{
    auto dur = clock::now().time_since_epoch();
    return duration_cast<std::chrono::milliseconds>(dur).count();
}

// 当前系统时间（单位：毫秒）
static int64_t system_tick()
{
    return get_tick_count();
}

// 稳定计时时间（单位：毫秒）
static int64_t steady_tick()
{
    return get_tick_count<steady_clock>();
}

// 当前系统时间（单位：秒）
static int64_t current_time()
{
    return system_tick() / 1000;
}

struct stopwatch
{
public:
    stopwatch(std::string name, int32_t threshold = -1)
    {
        start_ = steady_tick();
        name_ = std::move(name);
        threshold_ = threshold;
    }

    ~stopwatch()
    {
        auto elapsed = steady_tick() - start_;
        if (elapsed > threshold_)
        {
            std::cout << "stopwatch: run [" << name_
                      << "] cost " << elapsed << " ms." << std::endl;
        }
    }

private:
    int64_t start_;
    std::string name_;
    int32_t threshold_{ -1 };
};
