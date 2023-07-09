# Copyright (C) 2023 Fotios Valasiadis
# SPDX-License-Identifier: LGPL-2.1-or-later

BEGIN {
    FS = ":"
    print "Baseline run | Build-recorder run | Comparison %"
    print
}

NR == FNR {
    # Build recorder run
    brrun[$1] = $2
    next
}

{
    if ($1 == "CPU utilization") {
	A = substr($2, 1, length($2) - 1) # Remove the % symbol
	B = substr(brrun[$1], 1, length(brrun[$1]) - 1)
    } else {
        A = $2
	B = brrun[$1]
    }

    if (+A == 0) {
	compare = "N/A"
    } else {
	compare = (B / A) * 100 "%"
    }

    print $1 ": " $2 " | " brrun[$1] " | " compare

}
