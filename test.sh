#!/bin/bash

num_runs=100
mkdir -p ./server
mkdir -p ./client

# argument 1: gbn or sr

if [ "$1" == "gbn" ]; then
    echo "Testing Go-Back-N"
    for ((i=1; i<=$num_runs; i++)); do
        rm ./server_log
        rm ./client_log
        python ./gbn_server.py 1> ./server_log &
        server_pid=$!

        sleep 1

        python ./gbn_client.py 1> ./client_log

        wait $server_pid

        cmp -s ./server/recv.jpg ./client/data.jpg
        if [ $? -eq 0 ]; then
            echo "Test $i: Files match"
        else
            echo "Test $i: Files do not match"
            break
        fi

        sleep 4
    done
    exit
fi

if [ "$1" == "sr" ]; then
    echo "Testing Selective Repeat"
    for ((i=1; i<=$num_runs; i++)); do
        rm ./server_log
        rm ./client_log
        python ./sr_server.py 1> ./server_log &
        server_pid=$!

        sleep 1

        python ./sr_client.py 1> ./client_log

        wait $server_pid

        cmp -s ./server/recv.jpg ./client/data.jpg
        if [ $? -eq 0 ]; then
            echo "Test $i: Files match"
        else
            echo "Test $i: Files do not match"
            break
        fi

        sleep 4
    done
    exit
fi

echo "Usage: ./test.sh gbn|sr"
exit
