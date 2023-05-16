#!/bin/sh
set -e
set -x

# Launch our service as user 'service'
exec su -s /bin/sh -c '/service/ue' service