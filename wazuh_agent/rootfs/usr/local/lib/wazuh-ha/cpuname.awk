# Works out a CPU name from /proc/cpuinfo, for kernels that do not print one.
#
#   awk -v board="Raspberry Pi 5 Model B Rev 1.0" -v arch=aarch64 -f cpuname.awk /proc/cpuinfo
#
# Wazuh reads the CPU name only from the "model name" line of /proc/cpuinfo (the data provider's
# getCpuName in sysInfoLinux.cpp). x86 kernels print it; ARM kernels never do, so the Wazuh
# dashboard shows no CPU for a Raspberry Pi or any other aarch64 device. This reads what an ARM
# kernel does print (the implementer and part number of each core) and names it.
#
# Prints the name, or nothing when the file already has a "model name" or nothing can be said.
# `board` (optional) is the board's name, as the device tree gives it, added in brackets.
# Uses only POSIX awk, so it runs under mawk.
#
# Part numbers are the ones Linux defines in arch/arm64/include/asm/cputype.h, which is also what
# lscpu's tables follow. Cores of an unknown part keep their numbers, so nothing is hidden.

BEGIN {
    FS = ":"

    # Implementer 0x41 is Arm Ltd. Every Home Assistant OS target board uses their cores.
    split("d01 Cortex-A32 d02 Cortex-A34 d03 Cortex-A53 d04 Cortex-A35 d05 Cortex-A55 d06 Cortex-A65 " \
          "d07 Cortex-A57 d08 Cortex-A72 d09 Cortex-A73 d0a Cortex-A75 d0b Cortex-A76 d0c Neoverse-N1 " \
          "d0d Cortex-A77 d0e Cortex-A76AE d40 Neoverse-V1 d41 Cortex-A78 d42 Cortex-A78AE d43 Cortex-A65AE " \
          "d44 Cortex-X1 d46 Cortex-A510 d47 Cortex-A710 d48 Cortex-X2 d49 Neoverse-N2 d4a Neoverse-E1 " \
          "d4b Cortex-A78C d4c Cortex-X1C d4d Cortex-A715 d4e Cortex-X3 d4f Neoverse-V2 d80 Cortex-A520 " \
          "d81 Cortex-A720 d82 Cortex-X4 d84 Neoverse-V3 d85 Cortex-X925 d87 Cortex-A725 d8e Neoverse-N3",
          pairs, " ")
    for (i = 1; i in pairs; i += 2) {
        arm_part[pairs[i]] = pairs[i + 1]
    }

    split("0x42 Broadcom 0x43 Cavium 0x46 Fujitsu 0x48 HiSilicon 0x4e NVIDIA 0x50 APM 0x51 Qualcomm " \
          "0x53 Samsung 0x61 Apple 0x69 Intel 0xc0 Ampere",
          pairs, " ")
    for (i = 1; i in pairs; i += 2) {
        vendor[pairs[i]] = pairs[i + 1]
    }
}

function trim(text) {
    sub(/^[ \t]+/, "", text)
    sub(/[ \t]+$/, "", text)
    return text
}

{
    key = trim($1)
    value = trim($2)
}

key == "model name" {
    has_model_name = 1
}
key == "CPU implementer" {
    implementer = tolower(value)
}
key == "CPU part" {
    part = tolower(value)
    sub(/^0x/, "", part)
    id = implementer " " part
    if (!(id in seen)) {
        seen[id] = 1
        order[++count] = id
    }
}
key == "Model" && model == "" {
    model = value
}
key == "Hardware" && hardware == "" {
    hardware = value
}

function core_name(id,    pieces) {
    split(id, pieces, " ")
    if (pieces[1] == "0x41" && (pieces[2] in arm_part)) {
        return arm_part[pieces[2]]
    }
    return ((pieces[1] in vendor) ? vendor[pieces[1]] : "ARM") " CPU (implementer " pieces[1] ", part 0x" pieces[2] ")"
}

END {
    if (has_model_name) {
        exit 0
    }

    name = ""
    for (i = 1; i <= count; i++) {
        name = name (i > 1 ? " + " : "") core_name(order[i])
    }

    label = (board != "") ? trim(board) : (model != "" ? model : hardware)
    if (name == "" && label == "") {
        # Nothing the kernel told us names the CPU; the architecture at least says what it is.
        name = arch
    } else if (label != "") {
        name = (name == "") ? label : name " (" label ")"
    }
    if (name != "") {
        print name
    }
}
