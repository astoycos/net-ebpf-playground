#!/bin/sh

#mkdir /debug
mount -t debugfs nodev /debug
mount -t debugfs nodev /sys/kernel/debug
echo '*' >/debug/tracing/set_ftrace_filter
echo function_graph >/debug/tracing/current_tracer
echo 1 >/debug/tracing/tracing_on
sleep 20
echo 0 >/debug/tracing/tracing_on
cat /debug/tracing/trace > /tmp/tracing.out$$