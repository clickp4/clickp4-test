#! /bin/bash

for i in `seq 1`
do
{
    sudo ip netns exec h1 iperf -s
} &
done

for i in `seq 1`
do
{
    sudo ip netns exec h2 iperf -s
} &
done

for i in `seq 1`
do
{
    sudo ip netns exec h3 iperf -s
} &
done

for i in `seq 1`
do
{
    sudo ip netns exec h4 iperf -s
} &
done

for i in `seq 1`
do
{
    sudo ip netns exec h1 python large_flow.py h1
} &
done

for i in `seq 1`
do
{
    sudo ip netns exec h2 python large_flow.py h2
} &
done

for i in `seq 1`
do
{
    sudo ip netns exec h3 python large_flow.py h3
} &
done

for i in `seq 1`
do
{
    sudo ip netns exec h4 python large_flow.py h4
} &
done

for i in `seq 1`
do
{
    sudo ip netns exec h1 python small_flow.py h1
} &
done

for i in `seq 1`
do
{
    sudo ip netns exec h2 python small_flow.py h2
} &
done

for i in `seq 1`
do
{
    sudo ip netns exec h3 python small_flow.py h3
} &
done

sudo ip netns exec h4 python small_flow.py h4

sleep 100


