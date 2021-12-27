#!/bin/sh

# Ask python and python3 for their versions, if present.
if test $(which python); then
    PYV=$(python  -c "import platform;print(platform.python_version())");
fi
if test $(which python3); then
    PY3V=$(python3 -c "import platform;print(platform.python_version())");
fi

# Cut up the major/minor versions.
PYV1=$(echo $PYV | cut -d. -f1)
PYV2=$(echo $PYV | cut -d. -f2)
PYV3=$(echo $PYV | cut -d. -f3)
PY3V1=$(echo $PY3V | cut -d. -f1)
PY3V2=$(echo $PY3V | cut -d. -f2)
PY3V3=$(echo $PY3V | cut -d. -f3)

# Zero out invalid version numbers.
if test $PYV1  -ne 3; then PYV1='0';  PYV2='0';  PYV3='0';  fi
if test $PY3V1 -ne 3; then PY3V1='0'; PY3V2='0'; PY3V3='0'; fi

# Make sure we have at least one valid version.
if test $PYV1 -ne 3; then
    if test $PY3V1 -ne 3; then
        exit 1
    fi
fi

# Use the one with the greatest version number.
# If they're the same, use just `python`.
if test $PYV1 -ge $PY3V1; then
    if test $PYV2 -ge $PY3V2; then
        if test $PYV3 -ge $PY3V3; then
            echo $(which python)
        else
            echo $(which python3)
        fi
    else
        echo $(which python3)
    fi
else
    echo $(which python3)
fi
