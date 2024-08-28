#!/bin/sh

# $1 = Command to be run
# $2 = Simulation to target
# $3 = Node(s) to target

PIPE_CMD="/netsim/inst/netsim_pipe"

if [ $# -lt 1 ]; then
        echo ""
        echo "ERROR: No command provided as first parameter"
        echo ""
        exit 1
fi

CMD="$1"

if [ $# -ge 2 ]; then
        PIPE_CMD="${PIPE_CMD} -sim $2"
fi

if [ $# -ge 3 ]; then
        PIPE_CMD="${PIPE_CMD} -ne $3"
fi

echo "$CMD" | $PIPE_CMD
